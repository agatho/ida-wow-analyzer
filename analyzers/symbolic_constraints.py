"""
Symbolic Constraint Propagation for CMSG Handler Parameters

Performs symbolic constraint propagation on CMSG handler parameters to
determine exact valid input ranges.  Goes beyond "there is a check" to
recover WHAT the valid range actually is: e.g. spell_id in [1, 450000],
bag_slot in {0..4}, flags & 0x7 == expected.

For every Read*() call in a handler's decompiled pseudocode the analyzer:
  1. Assigns an initial type-based constraint domain.
  2. Walks if/else/switch branches to narrow (or widen) constraints.
  3. Propagates constraints through assignments, arithmetic, casts.
  4. Resolves symbolic constants to concrete values where possible.
  5. Compares the recovered constraint against TrinityCore source.

Results stored in session.db kv_store under key "symbolic_constraints".
"""

import json
import re
import time
import collections
import copy

import ida_funcs
import ida_name
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ======================================================================
# Constraint Domain Representation
# ======================================================================

class ConstraintType:
    """Enumeration of constraint kinds."""
    UNCONSTRAINED = "unconstrained"
    RANGE = "range"           # value in [min, max]
    SET = "set"               # value in {v1, v2, ...}
    BITMASK = "bitmask"       # value & mask == expected
    STRING_LENGTH = "string_length"  # len(s) in [min, max]
    BOOLEAN = "boolean"       # true / false only
    NULL_CHECK = "null_check" # non-null required
    COMPOSITE = "composite"   # intersection of multiple constraints


class Constraint:
    """Immutable constraint on a single variable.

    Supports range, set, bitmask, string-length, boolean, null-check,
    and composite (intersection of several) constraint types.
    """

    __slots__ = (
        "ctype", "min_val", "max_val", "values", "mask", "expected",
        "str_min", "str_max", "bool_val", "non_null", "sub_constraints",
    )

    def __init__(self, ctype=ConstraintType.UNCONSTRAINED, **kwargs):
        self.ctype = ctype
        self.min_val = kwargs.get("min_val")
        self.max_val = kwargs.get("max_val")
        self.values = kwargs.get("values")         # frozenset for SET
        self.mask = kwargs.get("mask")
        self.expected = kwargs.get("expected")
        self.str_min = kwargs.get("str_min")
        self.str_max = kwargs.get("str_max")
        self.bool_val = kwargs.get("bool_val")
        self.non_null = kwargs.get("non_null")
        self.sub_constraints = kwargs.get("sub_constraints")  # list[Constraint]

    # -- Factory helpers --------------------------------------------------

    @staticmethod
    def unconstrained():
        return Constraint(ConstraintType.UNCONSTRAINED)

    @staticmethod
    def range_constraint(lo, hi):
        return Constraint(ConstraintType.RANGE, min_val=lo, max_val=hi)

    @staticmethod
    def set_constraint(vals):
        return Constraint(ConstraintType.SET, values=frozenset(vals))

    @staticmethod
    def bitmask_constraint(mask, expected):
        return Constraint(ConstraintType.BITMASK, mask=mask, expected=expected)

    @staticmethod
    def string_length_constraint(lo, hi):
        return Constraint(ConstraintType.STRING_LENGTH, str_min=lo, str_max=hi)

    @staticmethod
    def boolean_constraint(val=None):
        return Constraint(ConstraintType.BOOLEAN, bool_val=val)

    @staticmethod
    def null_check_constraint(non_null=True):
        return Constraint(ConstraintType.NULL_CHECK, non_null=non_null)

    @staticmethod
    def composite(constraints):
        """Intersection of multiple non-trivial constraints."""
        real = [c for c in constraints
                if c.ctype != ConstraintType.UNCONSTRAINED]
        if not real:
            return Constraint.unconstrained()
        if len(real) == 1:
            return real[0]
        return Constraint(ConstraintType.COMPOSITE, sub_constraints=real)

    # -- Narrowing / combination ------------------------------------------

    def intersect(self, other):
        """Narrow *self* by *other*.  Returns a new Constraint."""
        if other.ctype == ConstraintType.UNCONSTRAINED:
            return self
        if self.ctype == ConstraintType.UNCONSTRAINED:
            return other

        # Same type: refine
        if self.ctype == ConstraintType.RANGE and other.ctype == ConstraintType.RANGE:
            lo = max(self.min_val, other.min_val)
            hi = min(self.max_val, other.max_val)
            if lo > hi:
                return Constraint.set_constraint(set())  # empty — impossible
            return Constraint.range_constraint(lo, hi)

        if self.ctype == ConstraintType.SET and other.ctype == ConstraintType.SET:
            common = self.values & other.values
            return Constraint.set_constraint(common)

        if self.ctype == ConstraintType.RANGE and other.ctype == ConstraintType.SET:
            filtered = frozenset(v for v in other.values
                                 if self.min_val <= v <= self.max_val)
            return Constraint.set_constraint(filtered)

        if self.ctype == ConstraintType.SET and other.ctype == ConstraintType.RANGE:
            filtered = frozenset(v for v in self.values
                                 if other.min_val <= v <= other.max_val)
            return Constraint.set_constraint(filtered)

        # Different types that can combine into composite
        return Constraint.composite([self, other])

    def union(self, other):
        """Widen (merge point after if/else).  Returns a new Constraint."""
        if self.ctype == ConstraintType.UNCONSTRAINED or \
           other.ctype == ConstraintType.UNCONSTRAINED:
            return Constraint.unconstrained()

        if self.ctype == ConstraintType.RANGE and other.ctype == ConstraintType.RANGE:
            lo = min(self.min_val, other.min_val)
            hi = max(self.max_val, other.max_val)
            return Constraint.range_constraint(lo, hi)

        if self.ctype == ConstraintType.SET and other.ctype == ConstraintType.SET:
            return Constraint.set_constraint(self.values | other.values)

        if self.ctype == ConstraintType.SET and other.ctype == ConstraintType.RANGE:
            lo = min(other.min_val, min(self.values) if self.values else other.min_val)
            hi = max(other.max_val, max(self.values) if self.values else other.max_val)
            return Constraint.range_constraint(lo, hi)

        if self.ctype == ConstraintType.RANGE and other.ctype == ConstraintType.SET:
            return other.union(self)

        # Fall back to unconstrained for unrelated types
        return Constraint.unconstrained()

    # -- Serialisation ----------------------------------------------------

    def to_dict(self):
        """JSON-serialisable dict."""
        d = {"constraint_type": self.ctype}
        if self.ctype == ConstraintType.RANGE:
            d["min"] = self.min_val
            d["max"] = self.max_val
        elif self.ctype == ConstraintType.SET:
            d["values"] = sorted(self.values) if self.values else []
        elif self.ctype == ConstraintType.BITMASK:
            d["mask"] = self.mask
            d["expected"] = self.expected
        elif self.ctype == ConstraintType.STRING_LENGTH:
            d["str_min"] = self.str_min
            d["str_max"] = self.str_max
        elif self.ctype == ConstraintType.BOOLEAN:
            d["bool_val"] = self.bool_val
        elif self.ctype == ConstraintType.NULL_CHECK:
            d["non_null"] = self.non_null
        elif self.ctype == ConstraintType.COMPOSITE:
            d["sub_constraints"] = [c.to_dict() for c in (self.sub_constraints or [])]
        return d

    def human_readable(self):
        """Return a concise human-readable string."""
        if self.ctype == ConstraintType.UNCONSTRAINED:
            return "UNCONSTRAINED"
        if self.ctype == ConstraintType.RANGE:
            return f"[{self.min_val}, {self.max_val}]"
        if self.ctype == ConstraintType.SET:
            if self.values and len(self.values) <= 20:
                return "{" + ", ".join(str(v) for v in sorted(self.values)) + "}"
            count = len(self.values) if self.values else 0
            return f"{{...{count} values...}}"
        if self.ctype == ConstraintType.BITMASK:
            return f"(val & 0x{self.mask:X}) == 0x{self.expected:X}"
        if self.ctype == ConstraintType.STRING_LENGTH:
            return f"strlen in [{self.str_min}, {self.str_max}]"
        if self.ctype == ConstraintType.BOOLEAN:
            if self.bool_val is None:
                return "bool"
            return "true" if self.bool_val else "false"
        if self.ctype == ConstraintType.NULL_CHECK:
            return "non-null" if self.non_null else "nullable"
        if self.ctype == ConstraintType.COMPOSITE:
            parts = [c.human_readable() for c in (self.sub_constraints or [])]
            return " AND ".join(parts)
        return "?"

    def __repr__(self):
        return f"Constraint({self.human_readable()})"


# ======================================================================
# Type-based initial constraint ranges
# ======================================================================

_TYPE_RANGES = {
    "uint8":    (0, 0xFF),
    "int8":     (-128, 127),
    "uint16":   (0, 0xFFFF),
    "int16":    (-32768, 32767),
    "uint32":   (0, 0xFFFFFFFF),
    "int32":    (-2147483648, 2147483647),
    "uint64":   (0, 0xFFFFFFFFFFFFFFFF),
    "int64":    (-9223372036854775808, 9223372036854775807),
    "float":    (-3.4e38, 3.4e38),
    "double":   (-1.7e308, 1.7e308),
    "bool":     (0, 1),
    "bit":      (0, 1),
    "__int8":   (-128, 127),
    "__int16":  (-32768, 32767),
    "__int32":  (-2147483648, 2147483647),
    "__int64":  (-9223372036854775808, 9223372036854775807),
    "unsigned __int8":  (0, 0xFF),
    "unsigned __int16": (0, 0xFFFF),
    "unsigned __int32": (0, 0xFFFFFFFF),
    "unsigned __int64": (0, 0xFFFFFFFFFFFFFFFF),
    "char":     (0, 0xFF),
    "BYTE":     (0, 0xFF),
    "WORD":     (0, 0xFFFF),
    "DWORD":    (0, 0xFFFFFFFF),
    "QWORD":    (0, 0xFFFFFFFFFFFFFFFF),
}


def _initial_constraint_for_type(type_str):
    """Return the initial Constraint for a given C type string."""
    normalized = type_str.strip().lower()

    # Direct lookup
    for k, (lo, hi) in _TYPE_RANGES.items():
        if normalized == k.lower():
            if k == "bool" or k == "bit":
                return Constraint.boolean_constraint()
            return Constraint.range_constraint(lo, hi)

    # Bits(N) from ReadBits
    m = re.match(r'bits\((\d+)\)', normalized)
    if m:
        nbits = int(m.group(1))
        return Constraint.range_constraint(0, (1 << nbits) - 1)

    # ObjectGuid / PackedGuid — non-null check is the primary constraint
    if "guid" in normalized:
        return Constraint.null_check_constraint(non_null=True)

    # String
    if normalized == "string":
        return Constraint.string_length_constraint(0, 0xFFFF)

    # Stream-extracted or unknown — unconstrained
    return Constraint.unconstrained()


# ======================================================================
# Read-source identification (reuses patterns from taint_analysis)
# ======================================================================

_RE_READ_TEMPLATE = re.compile(
    r'(\w+)\s*=\s*.*?Read\s*<\s*(\w+)\s*>\s*\('
)
_RE_READ_BIT = re.compile(
    r'(\w+)\s*=\s*.*?ReadBit\s*\('
)
_RE_READ_BITS = re.compile(
    r'(\w+)\s*=\s*.*?ReadBits\s*\(\s*(\d+)\s*\)'
)
_RE_READ_PACKED_GUID = re.compile(
    r'(\w+)\s*=?\s*.*?ReadPackedGuid128\s*\('
)
_RE_READ_STRING = re.compile(
    r'(\w+)\s*=\s*.*?Read(?:C?String|String)\s*\('
)
_RE_READ_HELPER = re.compile(
    r'(\w+)\s*=\s*.*?(?:Read(?:Float|Double|UInt8|UInt16|UInt32|UInt64'
    r'|Int8|Int16|Int32|Int64))\s*\('
)
_RE_STREAM_EXTRACT = re.compile(
    r'operator>>\s*\(\s*\w+\s*,\s*&?\s*(\w+)\s*\)'
    r'|>>\s*\(\s*\w+\s*,\s*[&*]?\s*(\w+)\s*\)'
    r'|>>\s*(\w+)'
)
_RE_PARAM_DEREF = re.compile(
    r'(\w+)\s*=\s*\*\s*\(\s*(\w+)\s*\*?\s*\)\s*\(\s*(a[12])\s*\+\s*'
    r'(0x[0-9A-Fa-f]+|\d+)\s*\)'
)


def _identify_read_sources(pseudocode):
    """Find every Read*() call and return a list of source descriptors.

    Each descriptor: {variable, type, read_call, line}
    """
    sources = []
    lines = pseudocode.split("\n")

    for line_no, line in enumerate(lines):
        stripped = line.strip()

        m = _RE_READ_TEMPLATE.search(stripped)
        if m:
            sources.append({
                "variable": m.group(1), "type": m.group(2),
                "read_call": f"Read<{m.group(2)}>()", "line": line_no,
            })
            continue

        m = _RE_READ_BIT.search(stripped)
        if m:
            sources.append({
                "variable": m.group(1), "type": "bit",
                "read_call": "ReadBit()", "line": line_no,
            })
            continue

        m = _RE_READ_BITS.search(stripped)
        if m:
            sources.append({
                "variable": m.group(1), "type": f"bits({m.group(2)})",
                "read_call": f"ReadBits({m.group(2)})", "line": line_no,
            })
            continue

        m = _RE_READ_PACKED_GUID.search(stripped)
        if m:
            sources.append({
                "variable": m.group(1), "type": "ObjectGuid",
                "read_call": "ReadPackedGuid128()", "line": line_no,
            })
            continue

        m = _RE_READ_STRING.search(stripped)
        if m:
            sources.append({
                "variable": m.group(1), "type": "string",
                "read_call": "ReadString()", "line": line_no,
            })
            continue

        m = _RE_READ_HELPER.search(stripped)
        if m:
            helper_m = re.search(r'Read(\w+)\s*\(', stripped)
            rtype = _helper_to_type(helper_m.group(1)) if helper_m else "unknown"
            sources.append({
                "variable": m.group(1), "type": rtype,
                "read_call": f"Read{helper_m.group(1) if helper_m else '?'}()",
                "line": line_no,
            })
            continue

        m = _RE_STREAM_EXTRACT.search(stripped)
        if m:
            var = m.group(1) or m.group(2) or m.group(3)
            if var:
                sources.append({
                    "variable": var, "type": "stream_extracted",
                    "read_call": f"operator>>({var})", "line": line_no,
                })
                continue

        m = _RE_PARAM_DEREF.search(stripped)
        if m and m.group(3) in ("a1", "a2"):
            sources.append({
                "variable": m.group(1), "type": m.group(2),
                "read_call": f"*({m.group(2)}*)({m.group(3)}+{m.group(4)})",
                "line": line_no,
            })
            continue

    return sources


def _helper_to_type(helper_name):
    """Convert a ReadXxx helper name to a type string."""
    mapping = {
        "Float": "float", "Double": "double",
        "UInt8": "uint8", "UInt16": "uint16",
        "UInt32": "uint32", "UInt64": "uint64",
        "Int8": "int8", "Int16": "int16",
        "Int32": "int32", "Int64": "int64",
    }
    return mapping.get(helper_name, helper_name.lower())


# ======================================================================
# Branch-condition constraint extraction
# ======================================================================

# if (x < N)  /  if (x > N)  /  if (x <= N)  /  if (x >= N)  / if (x == N) / if (x != N)
_RE_CMP = re.compile(
    r'\b(\w+)\s*([<>=!]=?)\s*(0x[0-9A-Fa-f]+|-?\d+(?:\.\d+)?)[UuLlFf]*\b'
)
# Reverse comparison: constant OP var
_RE_CMP_REV = re.compile(
    r'(0x[0-9A-Fa-f]+|-?\d+(?:\.\d+)?)[UuLlFf]*\s*([<>=!]=?)\s*(\w+)'
)
# Compound: x >= A && x <= B   or   x < A || x > B
_RE_RANGE_AND = re.compile(
    r'\b(\w+)\s*>=?\s*(0x[0-9A-Fa-f]+|-?\d+)\s*&&\s*\1\s*<=?\s*(0x[0-9A-Fa-f]+|-?\d+)'
)
_RE_RANGE_OR_REJECT = re.compile(
    r'\b(\w+)\s*<\s*(0x[0-9A-Fa-f]+|-?\d+)\s*\|\|\s*\1\s*>\s*(0x[0-9A-Fa-f]+|-?\d+)'
)
# Switch / case
_RE_SWITCH = re.compile(r'switch\s*\(\s*(\w+)\s*\)')
_RE_CASE = re.compile(r'case\s+(0x[0-9A-Fa-f]+|-?\d+)\s*:')
# Bitmask: x & MASK
_RE_BITMASK_CHECK = re.compile(
    r'\b(\w+)\s*&\s*(0x[0-9A-Fa-f]+|\d+)'
)
# strlen check: strlen(x) > N  or  strlen(x) >= N  etc.
_RE_STRLEN = re.compile(
    r'strlen\s*\(\s*(\w+)\s*\)\s*([<>=!]=?)\s*(\d+)'
)
# Null check:  if (!ptr)  or  if (ptr == 0)  or  if (ptr == nullptr)
_RE_NULL_CHECK = re.compile(
    r'if\s*\(\s*!(\w+)\s*\)|if\s*\(\s*(\w+)\s*==\s*(?:0|nullptr|NULL)\s*\)'
)
# Bitwise AND in condition:  if (x & 0xFF)
_RE_BITMASK_COND = re.compile(
    r'if\s*\(\s*(\w+)\s*&\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
)
# Cast narrowing: (uint8)x or (unsigned __int8)x
_RE_CAST = re.compile(
    r'\(\s*(u?int(?:8|16|32|64)|unsigned\s+__int(?:8|16|32|64)|'
    r'BYTE|WORD|DWORD|char|bool)\s*\)\s*(\w+)'
)
# Array index: arr[x] where arr size may be known
_RE_ARRAY_INDEX = re.compile(
    r'(\w+)\s*\[\s*(\w+)\s*\]'
)


def _parse_int(s):
    """Parse an integer literal (hex or decimal)."""
    s = s.strip().rstrip("UuLlFf")
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        try:
            return int(float(s))
        except ValueError:
            return None


def _extract_condition_constraints(line, is_reject_branch):
    """Extract variable constraints from a single condition line.

    Args:
        line: stripped source line containing an if-condition
        is_reject_branch: True if this branch leads to return/error
                         (the constraint describes REJECTED values)

    Returns:
        list of (variable, Constraint) tuples for the TRUE branch.
        If is_reject_branch, the constraint is inverted so it represents
        the ACCEPTED domain.
    """
    results = []

    # Compound range check:  x >= A && x <= B
    m = _RE_RANGE_AND.search(line)
    if m:
        var = m.group(1)
        lo = _parse_int(m.group(2))
        hi = _parse_int(m.group(3))
        if lo is not None and hi is not None:
            if is_reject_branch:
                # Rejected values are in [lo, hi], accepted is outside
                # We can't express "not in range" as a single range easily,
                # so store the accepted as the complement heuristically
                pass
            else:
                results.append((var, Constraint.range_constraint(lo, hi)))
            return results

    # Reject-or pattern:  x < A || x > B   => accepted is [A, B]
    m = _RE_RANGE_OR_REJECT.search(line)
    if m:
        var = m.group(1)
        lo = _parse_int(m.group(2))
        hi = _parse_int(m.group(3))
        if lo is not None and hi is not None:
            if is_reject_branch:
                results.append((var, Constraint.range_constraint(lo, hi)))
            return results

    # strlen check
    m = _RE_STRLEN.search(line)
    if m:
        var = m.group(1)
        op = m.group(2)
        val = _parse_int(m.group(3))
        if val is not None:
            lo, hi = 0, 0xFFFF
            if is_reject_branch:
                lo, hi = _invert_cmp_for_strlen(op, val)
            else:
                lo, hi = _apply_cmp_for_strlen(op, val)
            results.append((var, Constraint.string_length_constraint(lo, hi)))
        return results

    # Null check
    m = _RE_NULL_CHECK.search(line)
    if m:
        var = m.group(1) or m.group(2)
        if var:
            if is_reject_branch:
                # if (!x) return; => accepted requires non-null
                results.append((var, Constraint.null_check_constraint(non_null=True)))
            else:
                results.append((var, Constraint.null_check_constraint(non_null=False)))
        return results

    # Bitmask condition:  if (x & MASK)
    m = _RE_BITMASK_COND.search(line)
    if m:
        var = m.group(1)
        mask = _parse_int(m.group(2))
        if mask is not None:
            if is_reject_branch:
                # if (x & mask) return; => accepted has (x & mask) == 0
                results.append((var, Constraint.bitmask_constraint(mask, 0)))
            else:
                # accepted requires at least one bit set in mask
                results.append((var, Constraint.bitmask_constraint(mask, mask)))
        return results

    # Simple comparison: var OP constant
    m = _RE_CMP.search(line)
    if m:
        var, op, val_s = m.group(1), m.group(2), m.group(3)
        val = _parse_int(val_s)
        if val is not None and _is_variable_name(var):
            c = _constraint_from_comparison(var, op, val, is_reject_branch)
            if c:
                results.append((var, c))
            return results

    # Reverse comparison: constant OP var
    m = _RE_CMP_REV.search(line)
    if m:
        val_s, op, var = m.group(1), m.group(2), m.group(3)
        val = _parse_int(val_s)
        if val is not None and _is_variable_name(var):
            flipped = _flip_operator(op)
            c = _constraint_from_comparison(var, flipped, val, is_reject_branch)
            if c:
                results.append((var, c))
            return results

    return results


def _constraint_from_comparison(var, op, val, is_reject_branch):
    """Build a range constraint from  `var OP val`.

    If is_reject_branch is True, the constraint represents the ACCEPTED
    domain (the complement of what triggers the reject).
    """
    # What the condition ASSERTS (true branch):
    #   x < val   =>  x in [-inf, val-1]
    #   x <= val  =>  x in [-inf, val]
    #   x > val   =>  x in [val+1, +inf]
    #   x >= val  =>  x in [val, +inf]
    #   x == val  =>  x in {val}
    #   x != val  =>  x in everything except {val}
    BIG = 0xFFFFFFFFFFFFFFFF  # upper sentinel

    if is_reject_branch:
        # The condition triggers a return/error, so ACCEPTED is the
        # complement of what the condition describes.
        if op == "<":
            return Constraint.range_constraint(val, BIG)          # accepted: x >= val
        if op == "<=":
            return Constraint.range_constraint(val + 1, BIG)      # accepted: x > val
        if op == ">":
            return Constraint.range_constraint(0, val)             # accepted: x <= val
        if op == ">=":
            return Constraint.range_constraint(0, val - 1)         # accepted: x < val
        if op == "==":
            return None  # hard to express "not equal to one value" as range
        if op == "!=":
            return Constraint.set_constraint({val})                # accepted: x == val
    else:
        # True branch is the accepted path
        if op == "<":
            return Constraint.range_constraint(0, val - 1)
        if op == "<=":
            return Constraint.range_constraint(0, val)
        if op == ">":
            return Constraint.range_constraint(val + 1, BIG)
        if op == ">=":
            return Constraint.range_constraint(val, BIG)
        if op == "==":
            return Constraint.set_constraint({val})
        if op == "!=":
            return None  # everything except one value
    return None


def _flip_operator(op):
    """Flip comparison operator for reverse comparisons (constant OP var)."""
    flips = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}
    return flips.get(op, op)


def _apply_cmp_for_strlen(op, val):
    """Return (lo, hi) representing the accepted strlen range for the TRUE branch."""
    if op == "<":
        return (0, val - 1)
    if op == "<=":
        return (0, val)
    if op == ">":
        return (val + 1, 0xFFFF)
    if op == ">=":
        return (val, 0xFFFF)
    if op == "==":
        return (val, val)
    if op == "!=":
        return (0, 0xFFFF)  # everything except val — approximate
    return (0, 0xFFFF)


def _invert_cmp_for_strlen(op, val):
    """Return (lo, hi) for accepted strlen when the condition triggers reject."""
    if op == ">":
        return (0, val)
    if op == ">=":
        return (0, val - 1)
    if op == "<":
        return (val, 0xFFFF)
    if op == "<=":
        return (val + 1, 0xFFFF)
    if op == "==":
        return (0, 0xFFFF)
    if op == "!=":
        return (val, val)
    return (0, 0xFFFF)


_REJECT_KEYWORDS = {"return", "break", "goto", "continue", "throw"}


def _is_variable_name(s):
    """Return True if s looks like a variable (not a keyword or constant)."""
    if not s or not re.match(r'^[a-zA-Z_]\w*$', s):
        return False
    if s in ("return", "if", "else", "for", "while", "do", "switch", "case",
             "break", "continue", "void", "int", "unsigned", "char", "float",
             "double", "true", "false", "nullptr", "NULL", "sizeof",
             "this", "const", "static", "struct", "class", "enum"):
        return False
    return True


# ======================================================================
# Switch-case extraction
# ======================================================================

def _extract_switch_cases(pseudocode):
    """Find switch(var) blocks and extract the set of case values.

    Returns: list of (variable, frozenset_of_case_values, has_default_return)
    """
    results = []
    lines = pseudocode.split("\n")

    i = 0
    while i < len(lines):
        m = _RE_SWITCH.search(lines[i])
        if m:
            var = m.group(1)
            case_vals = set()
            has_default_return = False
            brace_depth = lines[i].count("{") - lines[i].count("}")

            j = i + 1
            while j < len(lines) and j < i + 200:
                case_m = _RE_CASE.search(lines[j])
                if case_m:
                    v = _parse_int(case_m.group(1))
                    if v is not None:
                        case_vals.add(v)

                if "default:" in lines[j]:
                    # Check if the default leads to return
                    for k in range(j, min(j + 5, len(lines))):
                        if "return" in lines[k]:
                            has_default_return = True
                            break

                brace_depth += lines[j].count("{") - lines[j].count("}")
                if brace_depth <= 0:
                    break
                j += 1

            if case_vals:
                results.append((var, frozenset(case_vals), has_default_return))

        i += 1

    return results


# ======================================================================
# Constraint propagation through assignments and operations
# ======================================================================

_RE_ASSIGN = re.compile(r'^(\w+)\s*=\s*(.+?)\s*;$')
_RE_ARITH_ADD = re.compile(r'^(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|-?\d+)$')
_RE_ARITH_SUB = re.compile(r'^(\w+)\s*-\s*(0x[0-9A-Fa-f]+|-?\d+)$')
_RE_ARITH_MUL = re.compile(r'^(\w+)\s*\*\s*(0x[0-9A-Fa-f]+|-?\d+)$')
_RE_BITWISE_AND = re.compile(r'^(\w+)\s*&\s*(0x[0-9A-Fa-f]+|\d+)$')
_RE_BITWISE_OR = re.compile(r'^(\w+)\s*\|\s*(0x[0-9A-Fa-f]+|\d+)$')
_RE_MODULO = re.compile(r'^(\w+)\s*%\s*(0x[0-9A-Fa-f]+|\d+)$')


def _propagate_constraint_through_op(source_constraint, rhs_expr):
    """Given a constraint on a source variable, compute the constraint on
    the result of applying an operation to it.

    Args:
        source_constraint: Constraint on the source variable
        rhs_expr: the RHS expression string (e.g. "v12 + 1")

    Returns:
        A new Constraint for the destination variable, or None if
        the operation could not be interpreted.
    """
    if source_constraint.ctype == ConstraintType.UNCONSTRAINED:
        return Constraint.unconstrained()

    expr = rhs_expr.strip()

    # Cast narrowing
    cm = _RE_CAST.search(expr)
    if cm:
        cast_type = cm.group(1).strip()
        type_range = _TYPE_RANGES.get(cast_type)
        if not type_range:
            # Try normalised
            normalised = cast_type.lower().replace(" ", "")
            for k, v in _TYPE_RANGES.items():
                if k.lower().replace(" ", "") == normalised:
                    type_range = v
                    break
        if type_range:
            cast_constraint = Constraint.range_constraint(type_range[0], type_range[1])
            return source_constraint.intersect(cast_constraint)

    # Bitwise AND: x & MASK => [0, MASK]
    m = _RE_BITWISE_AND.match(expr)
    if m:
        mask = _parse_int(m.group(2))
        if mask is not None:
            mask_constraint = Constraint.range_constraint(0, mask)
            return source_constraint.intersect(mask_constraint)

    # Modulo: x % N => [0, N-1]
    m = _RE_MODULO.match(expr)
    if m:
        mod_val = _parse_int(m.group(2))
        if mod_val is not None and mod_val > 0:
            return Constraint.range_constraint(0, mod_val - 1)

    # Addition: x + C
    m = _RE_ARITH_ADD.match(expr)
    if m and source_constraint.ctype == ConstraintType.RANGE:
        c = _parse_int(m.group(2))
        if c is not None:
            return Constraint.range_constraint(
                source_constraint.min_val + c,
                source_constraint.max_val + c
            )

    # Subtraction: x - C
    m = _RE_ARITH_SUB.match(expr)
    if m and source_constraint.ctype == ConstraintType.RANGE:
        c = _parse_int(m.group(2))
        if c is not None:
            return Constraint.range_constraint(
                source_constraint.min_val - c,
                source_constraint.max_val - c
            )

    # Multiplication: x * C
    m = _RE_ARITH_MUL.match(expr)
    if m and source_constraint.ctype == ConstraintType.RANGE:
        c = _parse_int(m.group(2))
        if c is not None and c != 0:
            if c > 0:
                return Constraint.range_constraint(
                    source_constraint.min_val * c,
                    source_constraint.max_val * c
                )
            else:
                return Constraint.range_constraint(
                    source_constraint.max_val * c,
                    source_constraint.min_val * c
                )

    # Bitwise OR: x | C — lower bound at least C
    m = _RE_BITWISE_OR.match(expr)
    if m and source_constraint.ctype == ConstraintType.RANGE:
        c = _parse_int(m.group(2))
        if c is not None:
            return Constraint.range_constraint(
                max(source_constraint.min_val, c),
                source_constraint.max_val | c
            )

    return None


# ======================================================================
# Path-sensitive analysis engine
# ======================================================================

class ConstraintState:
    """Tracks variable constraints at a specific point in execution."""

    def __init__(self):
        self.constraints = {}   # var_name -> Constraint

    def clone(self):
        new = ConstraintState()
        new.constraints = {k: copy.copy(v) for k, v in self.constraints.items()}
        return new

    def set_constraint(self, var, constraint):
        if var in self.constraints:
            self.constraints[var] = self.constraints[var].intersect(constraint)
        else:
            self.constraints[var] = constraint

    def get_constraint(self, var):
        return self.constraints.get(var, Constraint.unconstrained())

    def merge(self, other):
        """Union merge at a join point (after if-else)."""
        merged = ConstraintState()
        all_vars = set(self.constraints.keys()) | set(other.constraints.keys())
        for var in all_vars:
            c1 = self.constraints.get(var, Constraint.unconstrained())
            c2 = other.constraints.get(var, Constraint.unconstrained())
            merged.constraints[var] = c1.union(c2)
        return merged


def _analyze_handler_constraints(pseudocode, sources):
    """Perform path-sensitive constraint analysis on one handler.

    Args:
        pseudocode: decompiled text
        sources: list of read source descriptors from _identify_read_sources

    Returns:
        dict mapping variable name to final Constraint, plus metadata about
        which checks contributed to the constraint.
    """
    lines = pseudocode.split("\n")
    state = ConstraintState()
    check_records = collections.defaultdict(list)  # var -> list of check info

    # Seed initial constraints from type ranges
    for src in sources:
        initial = _initial_constraint_for_type(src["type"])
        state.set_constraint(src["variable"], initial)

    # Extract switch-case constraints (global analysis)
    switch_cases = _extract_switch_cases(pseudocode)
    for var, case_vals, has_default_return in switch_cases:
        if has_default_return and case_vals:
            # switch with default:return acts as a whitelist
            sc = Constraint.set_constraint(case_vals)
            state.set_constraint(var, sc)
            check_records[var].append({
                "condition": f"switch({var}) with default:return",
                "line": _find_line_containing(lines, f"switch", var),
                "branch": "switch_whitelist",
            })

    # Walk through lines looking for if-conditions, assignments, casts
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()

        # -- If-condition with reject (return/break) in the body ----------
        if stripped.startswith("if") and "(" in stripped:
            # Determine if this is a reject branch
            block = _get_if_block_text(lines, i)
            is_reject = _block_has_reject(block, i, lines)

            condition_line = stripped
            conds = _extract_condition_constraints(condition_line, is_reject)
            for var, constraint in conds:
                state.set_constraint(var, constraint)
                check_records[var].append({
                    "condition": condition_line[:200],
                    "line": i,
                    "branch": "reject" if is_reject else "accept",
                })

        # -- Assignment propagation ----------------------------------------
        m = _RE_ASSIGN.search(stripped)
        if m:
            lhs = m.group(1)
            rhs = m.group(2).strip()

            # Direct variable copy
            if _is_variable_name(rhs) and rhs in state.constraints:
                state.set_constraint(lhs, state.get_constraint(rhs))
                check_records[lhs].extend(check_records.get(rhs, []))
            elif _is_variable_name(lhs):
                # Try to propagate through operations
                rhs_tokens = re.findall(r'\b(\w+)\b', rhs)
                for token in rhs_tokens:
                    if token in state.constraints:
                        propagated = _propagate_constraint_through_op(
                            state.get_constraint(token), rhs
                        )
                        if propagated:
                            state.set_constraint(lhs, propagated)
                            check_records[lhs].extend(check_records.get(token, []))
                        break

        # -- Cast narrowing on its own line --------------------------------
        cm = _RE_CAST.search(stripped)
        if cm and cm.group(2) in state.constraints:
            cast_type = cm.group(1).strip()
            var = cm.group(2)
            type_range = None
            for k, v in _TYPE_RANGES.items():
                if k.lower().replace(" ", "") == cast_type.lower().replace(" ", ""):
                    type_range = v
                    break
            if type_range:
                cast_c = Constraint.range_constraint(type_range[0], type_range[1])
                state.set_constraint(var, cast_c)
                check_records[var].append({
                    "condition": f"cast to {cast_type}",
                    "line": i,
                    "branch": "cast",
                })

        # -- Array index implies constraint: x < array_size ----------------
        am = _RE_ARRAY_INDEX.search(stripped)
        if am:
            idx_var = am.group(2)
            arr_var = am.group(1)
            if _is_variable_name(idx_var) and idx_var in state.constraints:
                # Heuristic: if we can figure out array size from context
                arr_size = _guess_array_size(pseudocode, arr_var)
                if arr_size is not None:
                    arr_c = Constraint.range_constraint(0, arr_size - 1)
                    state.set_constraint(idx_var, arr_c)
                    check_records[idx_var].append({
                        "condition": f"{arr_var}[{idx_var}] implies index < {arr_size}",
                        "line": i,
                        "branch": "array_bound",
                    })

        i += 1

    return state, check_records


def _find_line_containing(lines, keyword, var):
    """Return the line number containing both keyword and var, or -1."""
    for i, line in enumerate(lines):
        if keyword in line and var in line:
            return i
    return -1


def _get_if_block_text(lines, start_idx):
    """Get text of the if-block starting at start_idx."""
    block_lines = [lines[start_idx]]
    brace_depth = lines[start_idx].count("{") - lines[start_idx].count("}")

    for j in range(start_idx + 1, min(start_idx + 20, len(lines))):
        block_lines.append(lines[j])
        brace_depth += lines[j].count("{") - lines[j].count("}")
        if brace_depth <= 0 and ("return" in lines[j] or "}" in lines[j]):
            break

    return "\n".join(block_lines)


def _block_has_reject(block_text, start_idx, lines):
    """Determine if an if-block contains a reject statement (return, etc.).

    A reject is: the if-body contains return/break and the block is SHORT
    (guard-style pattern), meaning the code AFTER the if continues with the
    accepted path.
    """
    block_lines = block_text.split("\n")
    # Short block (guard-style): if (...) { return ...; }
    if len(block_lines) <= 6:
        for bl in block_lines[1:]:
            stripped = bl.strip()
            for kw in _REJECT_KEYWORDS:
                if stripped.startswith(kw):
                    return True
    # Also check single-line: if (x > 10) return;
    first_line = block_lines[0].strip()
    for kw in _REJECT_KEYWORDS:
        if kw in first_line and "if" in first_line:
            # e.g. "if (x > 10) return 0;"
            # Check that the return is AFTER the condition close
            paren_close = first_line.rfind(")")
            if paren_close >= 0 and kw in first_line[paren_close:]:
                return True
    return False


def _guess_array_size(pseudocode, arr_name):
    """Try to guess the size of an array from the pseudocode context.

    Looks for patterns like:
      - TYPE arr[SIZE];
      - reserve(SIZE) or resize(SIZE) on arr
      - comparison: idx < SIZE  near the array access
    """
    # Array declaration: type arr[N];
    m = re.search(rf'\b{re.escape(arr_name)}\s*\[\s*(\d+)\s*\]', pseudocode)
    if m:
        return _parse_int(m.group(1))

    # Known game constants
    _KNOWN_ARRAYS = {
        "m_items": 150,          # player inventory slots
        "m_spells": 500000,
        "equipmentSlots": 19,
        "bagSlots": 5,
    }
    if arr_name in _KNOWN_ARRAYS:
        return _KNOWN_ARRAYS[arr_name]

    return None


# ======================================================================
# Concrete constant resolution
# ======================================================================

def _resolve_game_constants(session, constraints_dict, check_records):
    """Replace symbolic constant references with concrete values.

    Uses the "game_constants" kv store populated by constant_mining.
    """
    game_constants = session.db.kv_get("game_constants")
    if not game_constants:
        return constraints_dict, {}

    # Build a reverse map: value -> list of constant names
    if isinstance(game_constants, dict):
        const_map = game_constants
    else:
        const_map = {}

    resolved = {}
    for var, constraint in constraints_dict.items():
        if constraint.ctype == ConstraintType.RANGE:
            lo_name = _find_constant_name(const_map, constraint.min_val)
            hi_name = _find_constant_name(const_map, constraint.max_val)
            if lo_name or hi_name:
                resolved[var] = {
                    "min_name": lo_name,
                    "max_name": hi_name,
                    "human": f"{lo_name or constraint.min_val} .. "
                             f"{hi_name or constraint.max_val}"
                }
        elif constraint.ctype == ConstraintType.SET and constraint.values:
            val_names = []
            for v in sorted(constraint.values):
                name = _find_constant_name(const_map, v)
                val_names.append(name or str(v))
            resolved[var] = {
                "value_names": val_names,
                "human": "{" + ", ".join(val_names) + "}",
            }
        elif constraint.ctype == ConstraintType.BITMASK:
            mask_name = _find_constant_name(const_map, constraint.mask)
            if mask_name:
                resolved[var] = {
                    "mask_name": mask_name,
                    "human": f"({var} & {mask_name}) == 0x{constraint.expected:X}",
                }

    return constraints_dict, resolved


def _find_constant_name(const_map, value):
    """Look up a constant name for a given numeric value."""
    if not const_map or value is None:
        return None

    # Search through constant categories
    for category, entries in const_map.items():
        if isinstance(entries, dict):
            for name, val in entries.items():
                if isinstance(val, (int, float)) and val == value:
                    return name
        elif isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    if entry.get("value") == value:
                        return entry.get("name", str(value))
    return None


# ======================================================================
# TC Source Comparison
# ======================================================================

def _compare_with_tc(session, handler_name, param_constraints):
    """Compare binary constraints against TrinityCore handler source.

    Returns a list of comparison records.
    """
    import os

    tc_dir = session.cfg.tc_source_dir
    if not tc_dir:
        return []

    tc_source = _find_tc_handler_source(tc_dir, handler_name)
    if not tc_source:
        return []

    comparisons = []

    for param in param_constraints:
        var = param["name"]
        binary_c = param.get("final_constraint_obj")
        if not binary_c or binary_c.ctype == ConstraintType.UNCONSTRAINED:
            continue

        tc_constraint = _extract_tc_constraint_for_param(tc_source, var, param.get("type", ""))
        match_status = _compare_constraints(binary_c, tc_constraint)

        comparisons.append({
            "handler": handler_name,
            "param": var,
            "binary_constraint": binary_c.human_readable(),
            "tc_constraint": tc_constraint.human_readable() if tc_constraint else "NOT_FOUND",
            "match": match_status,
        })

    return comparisons


def _find_tc_handler_source(tc_dir, handler_name):
    """Locate and return TC handler function source code."""
    import os

    handlers_dir = os.path.join(tc_dir, "src", "server", "game", "Handlers")
    if not os.path.isdir(handlers_dir):
        return None

    func_name = None
    if handler_name.startswith("CMSG_") or handler_name.startswith("SMSG_"):
        parts = handler_name.split("_")[1:]
        func_name = "Handle" + "".join(p.capitalize() for p in parts)
    else:
        func_name = handler_name

    for fname in os.listdir(handlers_dir):
        if not fname.endswith(".cpp"):
            continue
        filepath = os.path.join(handlers_dir, fname)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if func_name and func_name in content:
                start = content.index(func_name)
                brace_pos = content.index("{", start)
                depth = 1
                pos = brace_pos + 1
                while depth > 0 and pos < len(content):
                    if content[pos] == "{":
                        depth += 1
                    elif content[pos] == "}":
                        depth -= 1
                    pos += 1
                return content[start:pos]
        except (ValueError, IOError):
            continue
    return None


def _extract_tc_constraint_for_param(tc_source, param_name, param_type):
    """Attempt to extract constraint info from TC source for a given parameter.

    Searches for comparison patterns involving similar names/offsets.
    """
    if not tc_source:
        return None

    constraints_found = []

    # Search for range checks
    for m in re.finditer(
        r'if\s*\(\s*\w[\w.>\-]*\s*([<>=!]=?)\s*(0x[0-9A-Fa-f]+|\d+)',
        tc_source
    ):
        op = m.group(1)
        val = _parse_int(m.group(2))
        if val is None:
            continue

        # Check if there's a return after this check (reject pattern)
        after = tc_source[m.end():m.end() + 200]
        if "return" in after.split("\n")[0] if "\n" in after else "return" in after:
            c = _constraint_from_comparison("x", op, val, is_reject_branch=True)
            if c:
                constraints_found.append(c)

    # Search for switch statements
    switch_m = re.search(r'switch\s*\(\s*\w+\s*\)', tc_source)
    if switch_m:
        case_vals = set()
        for cm in re.finditer(r'case\s+(0x[0-9A-Fa-f]+|\d+)\s*:', tc_source):
            v = _parse_int(cm.group(1))
            if v is not None:
                case_vals.add(v)
        if case_vals and "default:" in tc_source:
            constraints_found.append(Constraint.set_constraint(case_vals))

    if not constraints_found:
        return None

    # Combine all found constraints
    result = constraints_found[0]
    for c in constraints_found[1:]:
        result = result.intersect(c)
    return result


def _compare_constraints(binary_c, tc_c):
    """Compare binary and TC constraints, returning a match status string.

    Returns one of:
        "match" — same or equivalent constraints
        "tc_wider" — TC allows more values (potential exploit)
        "tc_stricter" — TC rejects valid binary inputs
        "different" — constraints are of different types
        "tc_missing" — no TC constraint found
    """
    if tc_c is None:
        return "tc_missing"

    if binary_c.ctype != tc_c.ctype:
        return "different"

    if binary_c.ctype == ConstraintType.RANGE and tc_c.ctype == ConstraintType.RANGE:
        if binary_c.min_val == tc_c.min_val and binary_c.max_val == tc_c.max_val:
            return "match"
        if tc_c.min_val <= binary_c.min_val and tc_c.max_val >= binary_c.max_val:
            if tc_c.min_val < binary_c.min_val or tc_c.max_val > binary_c.max_val:
                return "tc_wider"
            return "match"
        if tc_c.min_val >= binary_c.min_val and tc_c.max_val <= binary_c.max_val:
            return "tc_stricter"
        return "different"

    if binary_c.ctype == ConstraintType.SET and tc_c.ctype == ConstraintType.SET:
        if binary_c.values == tc_c.values:
            return "match"
        if binary_c.values and tc_c.values:
            if tc_c.values > binary_c.values:
                return "tc_wider"
            if tc_c.values < binary_c.values:
                return "tc_stricter"
        return "different"

    return "different"


# ======================================================================
# Risk assessment for unconstrained parameters
# ======================================================================

_HIGH_RISK_TYPES = {"uint32", "int32", "uint64", "int64", "float", "double",
                    "string", "stream_extracted", "unknown"}
_MEDIUM_RISK_TYPES = {"uint16", "int16"}
_LOW_RISK_TYPES = {"uint8", "int8", "bit", "bool", "ObjectGuid"}


def _assess_unconstrained_risk(param_type):
    """Return risk level for an unconstrained parameter of the given type."""
    normalized = param_type.lower().strip()
    if normalized in _HIGH_RISK_TYPES or "32" in normalized or "64" in normalized:
        return "high"
    if normalized in _MEDIUM_RISK_TYPES or "16" in normalized:
        return "medium"
    if normalized in _LOW_RISK_TYPES or "8" in normalized or normalized in ("bit", "bool"):
        return "low"
    if "guid" in normalized:
        return "low"
    if "string" in normalized:
        return "high"
    return "medium"


# ======================================================================
# Export: C++ constexpr validation header
# ======================================================================

def export_constraints_header(session):
    """Generate a C++ header with constexpr validation functions for each
    handler's parameters.

    Returns the header as a string.
    """
    data = session.db.kv_get("symbolic_constraints")
    if not data:
        msg_warn("No symbolic constraints data — run propagate_constraints() first")
        return ""

    lines = [
        "// Auto-generated by TC WoW Analyzer — symbolic_constraints module",
        "// Validation functions derived from binary constraint analysis",
        "#pragma once",
        "",
        "#include <cstdint>",
        "#include <cstring>",
        "",
        "namespace BinaryConstraints",
        "{",
        "",
    ]

    for handler_info in data.get("handler_constraints", []):
        handler = handler_info["handler"]
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', handler)
        params = handler_info.get("parameters", [])
        if not params:
            continue

        lines.append(f"    // {handler}")

        for param in params:
            ctype = param.get("constraint_type", "unconstrained")
            pname = re.sub(r'[^a-zA-Z0-9_]', '_', param.get("name", "unknown"))
            fc = param.get("final_constraint", {})

            if ctype == "range":
                lo = fc.get("min", 0)
                hi = fc.get("max", 0xFFFFFFFF)
                lines.append(
                    f"    constexpr bool Validate_{safe_name}_{pname}"
                    f"(uint64_t val) {{ return val >= {lo} && val <= {hi}; }}"
                )
            elif ctype == "set":
                vals = fc.get("values", [])
                if vals and len(vals) <= 30:
                    vals_str = ", ".join(str(v) for v in vals)
                    lines.append(
                        f"    constexpr bool Validate_{safe_name}_{pname}"
                        f"(uint64_t val) {{"
                    )
                    for v in vals:
                        lines.append(f"        if (val == {v}) return true;")
                    lines.append("        return false;")
                    lines.append("    }")
            elif ctype == "bitmask":
                mask = fc.get("mask", 0)
                expected = fc.get("expected", 0)
                lines.append(
                    f"    constexpr bool Validate_{safe_name}_{pname}"
                    f"(uint64_t val) {{ return (val & 0x{mask:X}) == 0x{expected:X}; }}"
                )
            elif ctype == "string_length":
                smin = fc.get("str_min", 0)
                smax = fc.get("str_max", 0xFFFF)
                lines.append(
                    f"    inline bool Validate_{safe_name}_{pname}"
                    f"(const char* s) {{ auto len = std::strlen(s); "
                    f"return len >= {smin} && len <= {smax}; }}"
                )

        lines.append("")

    lines.append("} // namespace BinaryConstraints")
    lines.append("")

    header_text = "\n".join(lines)

    session.db.kv_set("symbolic_constraints_header", header_text)
    session.db.commit()
    msg_info(f"Exported C++ constraints header ({len(lines)} lines)")
    return header_text


# ======================================================================
# Per-handler constraint retrieval
# ======================================================================

def get_handler_constraints(session, handler_name):
    """Retrieve the constraint set for a specific handler.

    Args:
        session: PluginSession
        handler_name: TC opcode name (e.g. "CMSG_HOUSING_DECOR_PLACE")

    Returns:
        dict with handler constraints, or None if not found.
    """
    data = session.db.kv_get("symbolic_constraints")
    if not data:
        return None

    for hc in data.get("handler_constraints", []):
        if hc.get("handler") == handler_name:
            return hc

    return None


# ======================================================================
# Main entry point
# ======================================================================

def propagate_constraints(session):
    """Analyse every CMSG handler for parameter constraints.

    Performs symbolic constraint propagation on each handler's decompiled
    pseudocode, tracking how Read*() parameters are validated through
    if/else branches, switch statements, casts, and arithmetic.

    Args:
        session: PluginSession with .db (KnowledgeDB)

    Returns:
        Count of total constraints found (constrained parameters).
    """
    db = session.db
    t_start = time.time()

    query = ("SELECT * FROM opcodes "
             "WHERE direction = 'CMSG' AND handler_ea IS NOT NULL")
    handlers = db.fetchall(query)

    msg_info(f"Symbolic constraint propagation: scanning {len(handlers)} CMSG handlers...")

    all_handler_constraints = []
    all_tc_comparisons = []
    total_params = 0
    total_constrained = 0
    total_unconstrained = 0
    handlers_processed = 0

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"handler_0x{ea:X}"
        opcode = handler.get("wire_opcode") or handler.get("internal_index", 0)

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        handlers_processed += 1

        # Step 1: Identify read sources
        sources = _identify_read_sources(pseudocode)
        if not sources:
            continue

        # Step 2: Analyse constraints
        state, check_records = _analyze_handler_constraints(pseudocode, sources)

        # Step 3: Resolve concrete constants
        constraints_dict, resolved_names = _resolve_game_constants(
            session, state.constraints, check_records
        )

        # Step 4: Build per-parameter results
        param_results = []
        unconstrained_params = []

        for src in sources:
            var = src["variable"]
            constraint = state.get_constraint(var)
            initial = _initial_constraint_for_type(src["type"])

            total_params += 1

            param_entry = {
                "name": var,
                "type": src["type"],
                "source_read_type": src["read_call"],
                "initial_range": initial.to_dict(),
                "final_constraint": constraint.to_dict(),
                "final_constraint_obj": constraint,  # temporary, stripped before JSON
                "constraint_type": constraint.ctype,
                "constraining_checks": check_records.get(var, []),
                "concrete_values": resolved_names.get(var),
            }

            if constraint.ctype != ConstraintType.UNCONSTRAINED:
                total_constrained += 1
            else:
                total_unconstrained += 1
                risk = _assess_unconstrained_risk(src["type"])
                unconstrained_params.append({
                    "name": var,
                    "type": src["type"],
                    "risk_level": risk,
                })

            param_results.append(param_entry)

        # Step 5: TC comparison
        tc_comps = _compare_with_tc(session, tc_name, param_results)
        all_tc_comparisons.extend(tc_comps)

        # Strip non-serialisable objects before storing
        for p in param_results:
            p.pop("final_constraint_obj", None)

        handler_entry = {
            "handler": tc_name,
            "opcode": opcode,
            "parameters": param_results,
            "unconstrained_params": unconstrained_params,
        }
        all_handler_constraints.append(handler_entry)

        if handlers_processed % 100 == 0:
            msg_info(f"  ... processed {handlers_processed} handlers, "
                     f"{total_constrained} constrained params so far")

    # Count TC mismatches
    tc_mismatches = sum(1 for c in all_tc_comparisons
                        if c["match"] not in ("match", "tc_missing"))

    # Build final report
    report = {
        "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": round(time.time() - t_start, 2),
        "handler_constraints": all_handler_constraints,
        "tc_comparison": all_tc_comparisons,
        "total_params_analyzed": total_params,
        "total_constrained": total_constrained,
        "total_unconstrained": total_unconstrained,
        "tc_mismatches": tc_mismatches,
        "handlers_processed": handlers_processed,
    }

    db.kv_set("symbolic_constraints", report)
    db.commit()

    msg_info(f"Symbolic constraint propagation complete:")
    msg_info(f"  Handlers processed: {handlers_processed}")
    msg_info(f"  Total parameters:   {total_params}")
    msg_info(f"  Constrained:        {total_constrained}")
    msg_info(f"  Unconstrained:      {total_unconstrained}")
    msg_info(f"  TC mismatches:      {tc_mismatches}")
    msg_info(f"  Duration:           {report['duration_seconds']}s")

    return total_constrained


# ======================================================================
# Report retrieval helper
# ======================================================================

def get_constraint_report(session):
    """Retrieve the stored symbolic constraints report.

    Returns the full report dict, or None if no analysis has been run.
    """
    return session.db.kv_get("symbolic_constraints")
