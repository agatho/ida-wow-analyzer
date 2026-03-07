"""
Shared Code Detection Analyzer
Identifies code in the WoW client binary that must be replicated identically
on the server side (TrinityCore).  This includes validation logic, math
calculations, serialization routines, and game mechanics that are shared
between client and server.

The fundamental insight: WoW is a client-server architecture where both sides
must agree on validation rules, formulas, serialization formats, enum values,
and protocol constants.  Any divergence causes desyncs, exploits, or crashes.
This analyzer finds those shared contract points in the client binary so
TrinityCore can replicate them faithfully.

Categories detected:
  1. Validation logic   -- range checks before CMSG sends
  2. Mathematical formulas -- damage, distance, rating conversions
  3. Serialization pairs   -- matching read/write routines
  4. Enum consistency      -- constants used in both send and receive
  5. Protocol constants    -- max lengths, buffer sizes, magic numbers
  6. Shared utilities      -- functions called by both senders and receivers
"""

import json
import re
import time
from collections import defaultdict

import ida_funcs
import ida_name
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Regex patterns for validation detection in pseudocode
# ---------------------------------------------------------------------------

# Range check before send: if (val < MIN || val > MAX) return;
_RE_RANGE_GUARD = re.compile(
    r'if\s*\(\s*'
    r'(\w[\w.\->\[\]]*)\s*([<>!=]=?)\s*'
    r'(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+)[UuLl]*)'
    r'\s*(?:\|\||&&)\s*'
    r'(\w[\w.\->\[\]]*)\s*([<>!=]=?)\s*'
    r'(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+)[UuLl]*)'
    r'\s*\)',
    re.DOTALL
)

# Simple guard: if (val > MAX) return;  or  if (val < 0) return;
_RE_SIMPLE_GUARD = re.compile(
    r'if\s*\(\s*'
    r'(\w[\w.\->\[\]]*)\s*([<>!=]=?)\s*'
    r'(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+)[UuLl]*)'
    r'\s*\)\s*(?:\{?\s*)?return',
    re.DOTALL
)

# String length check: if (strlen(x) > MAX || wcslen(x) > MAX)
_RE_STRLEN_CHECK = re.compile(
    r'(?:strlen|wcslen|lstrlen|strnlen)\s*\(\s*(\w+)\s*\)\s*'
    r'([<>!=]=?)\s*'
    r'(0x[0-9A-Fa-f]+|\d+)',
    re.IGNORECASE
)

# Clamp pattern: val = min(val, MAX);  or  val = max(val, MIN);
_RE_CLAMP = re.compile(
    r'(\w[\w.\->\[\]]*)\s*=\s*'
    r'(?:min|max|__min|__max|std::min|std::max|fminf?|fmaxf?)\s*\(\s*'
    r'[^,]+,\s*'
    r'(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+)[UuLl]*)\s*\)',
    re.IGNORECASE
)

# Permission/capability check: if (!HasFlag(...)) return;
_RE_PERMISSION = re.compile(
    r'if\s*\(\s*!?\s*'
    r'(Has\w+|Can\w+|Is\w+|Check\w+|Validate\w+)\s*\([^)]*\)\s*\)'
    r'.*?return',
    re.DOTALL
)

# Enum assignment/comparison in guard:  if (type != EXPECTED_TYPE) return;
_RE_ENUM_GUARD = re.compile(
    r'if\s*\(\s*'
    r'(\w[\w.\->\[\]]*)\s*([!=]=)\s*'
    r'(\d+|0x[0-9A-Fa-f]+)\s*\)\s*'
    r'(?:\{?\s*)?return',
    re.DOTALL
)

# SendPacket / Send call
_RE_SEND_CALL = re.compile(
    r'(?:SendPacket|Send|SendToServer|SendMessage|SendServerMessage|'
    r'WriteTo|Flush|QueuePacket|PostPacket|DispatchPacket)\s*\(',
    re.IGNORECASE
)

# CMSG reference in function name or string
_RE_CMSG_REF = re.compile(r'CMSG_\w+', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Mathematical formula patterns
# ---------------------------------------------------------------------------

# stat * coefficient + base  (floating point)
_RE_STAT_FORMULA = re.compile(
    r'(\w[\w.\->\[\]]*)\s*\*\s*'
    r'(-?\d+\.\d+[fF]?)\s*'
    r'([+\-])\s*'
    r'(-?\d+\.\d+[fF]?|\d+)',
)

# Division-based conversion: val * NUMERATOR / DENOMINATOR
_RE_RATIO_FORMULA = re.compile(
    r'(\w[\w.\->\[\]]*)\s*\*\s*'
    r'(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+))\s*'
    r'/\s*'
    r'(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+))',
)

# Polynomial: a*x*x + b*x + c  (quadratic formulas)
_RE_QUADRATIC = re.compile(
    r'(-?\d+\.\d+[fF]?)\s*\*\s*(\w+)\s*\*\s*\2\s*'
    r'([+\-])\s*(-?\d+\.\d+[fF]?)\s*\*\s*\2\s*'
    r'([+\-])\s*(-?\d+\.\d+[fF]?)',
)

# sqrt / sqrtf calls (distance calculations)
_RE_SQRT = re.compile(
    r'(?:sqrtf?|sqrt)\s*\(\s*'
    r'([^)]+)\s*\)',
    re.IGNORECASE
)

# pow / powf calls (exponential formulas)
_RE_POW = re.compile(
    r'(?:powf?|pow)\s*\(\s*'
    r'([^,]+)\s*,\s*([^)]+)\s*\)',
    re.IGNORECASE
)

# Floor/ceil/round (rounding in formulas)
_RE_ROUND = re.compile(
    r'(?:floorf?|ceilf?|roundf?|truncf?)\s*\(\s*',
    re.IGNORECASE
)

# exp/log (exponential scaling)
_RE_EXPLOG = re.compile(
    r'(?:expf?|logf?|log2f?|log10f?)\s*\(\s*',
    re.IGNORECASE
)

# Float multiply (general coefficient): var * 0.95f
_RE_FLOAT_MUL = re.compile(
    r'(\w[\w.\->\[\]]*)\s*\*\s*(-?\d+\.\d+[fF]?)'
)

# Float comparison (threshold checks in formulas)
_RE_FLOAT_CMP = re.compile(
    r'(\w[\w.\->\[\]]*)\s*([<>]=?)\s*(-?\d+\.\d+[fF]?)'
)

# ---------------------------------------------------------------------------
# Serialization patterns
# ---------------------------------------------------------------------------

# Read/Write function calls
_RE_READ_CALL = re.compile(
    r'(Read(?:UInt8|UInt16|UInt32|UInt64|Int8|Int16|Int32|Int64|Float|Double|'
    r'Bit|Bits|PackedGuid128|PackedGuid|String|CString|ObjectGuid|'
    r'ByteString|Packed))\s*\(',
    re.IGNORECASE
)

_RE_WRITE_CALL = re.compile(
    r'(Write(?:UInt8|UInt16|UInt32|UInt64|Int8|Int16|Int32|Int64|Float|Double|'
    r'Bit|Bits|PackedGuid128|PackedGuid|String|CString|ObjectGuid|'
    r'ByteString|Packed))\s*\(',
    re.IGNORECASE
)

# Template Read/Write: Read<uint32>(), Write<float>()
_RE_TEMPLATE_READ = re.compile(
    r'Read\s*<\s*(u?int(?:8|16|32|64)(?:_t)?|float|double)\s*>\s*\(',
    re.IGNORECASE
)

_RE_TEMPLATE_WRITE = re.compile(
    r'Write\s*<\s*(u?int(?:8|16|32|64)(?:_t)?|float|double)\s*>\s*\(',
    re.IGNORECASE
)

# Stream operators: stream >> var; or stream << var;
_RE_STREAM_READ = re.compile(r'>>\s+(\w+)\s*;')
_RE_STREAM_WRITE = re.compile(r'<<\s+(\w+)\s*;')

# FlushBits / ResetBitPos
_RE_FLUSH = re.compile(r'(?:FlushBits|ResetBitPos)\s*\(', re.IGNORECASE)

# ReadBits(N) — captures bit count
_RE_READBITS = re.compile(r'ReadBits\s*\(\s*(?:\w+\s*,\s*)?(\d+)\s*\)', re.IGNORECASE)
_RE_WRITEBITS = re.compile(r'WriteBits\s*\(\s*[^,]+,\s*(\d+)\s*\)', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Constant extraction patterns
# ---------------------------------------------------------------------------

# Hex constant in any context
_RE_HEX = re.compile(r'\b(0x[0-9A-Fa-f]+)[UuLl]*\b')

# Decimal constant (non-trivial)
_RE_DEC = re.compile(r'(?<![0-9A-Fa-fxX.])(-?\b[0-9]+)[UuLl]*\b(?![.xX0-9A-Fa-f])')

# Float constant
_RE_FLOAT_CONST = re.compile(
    r'(?<![0-9A-Fa-fxX])(-?\b\d+\.\d+(?:[eE][+-]?\d+)?)[fFdD]?\b'
)

# Buffer/array allocation: alloc(SIZE), new char[SIZE], malloc(SIZE)
_RE_ALLOC = re.compile(
    r'(?:alloc|malloc|calloc|new\s+\w+\[|operator\s+new\[?)\s*\(\s*'
    r'(0x[0-9A-Fa-f]+|\d+)\s*\)',
    re.IGNORECASE
)

# Array size declaration: type arr[SIZE]
_RE_ARRAY_SIZE = re.compile(
    r'\w+\s+\w+\s*\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\]'
)

# ---------------------------------------------------------------------------
# Semantic categorisation for game formulas
# ---------------------------------------------------------------------------

_FORMULA_KEYWORDS = {
    "damage": ["damage", "dmg", "attack", "hit", "dps", "weapon", "melee", "ranged"],
    "healing": ["heal", "health", "regen", "restore", "absorb"],
    "distance": ["dist", "distance", "range", "radius", "reach", "position"],
    "cooldown": ["cooldown", "cd", "timer", "delay", "duration", "gcd"],
    "experience": ["xp", "exp", "experience", "level", "levelup"],
    "rating": ["rating", "crit", "haste", "mastery", "versatility", "dodge",
               "parry", "block", "resilience", "armor", "mitigation"],
    "speed": ["speed", "velocity", "runspeed", "swimspeed", "flyspeed"],
    "resource": ["mana", "rage", "energy", "focus", "runic", "power", "chi",
                 "insanity", "maelstrom", "fury", "pain", "combo"],
    "scaling": ["scale", "scaling", "modifier", "multiplier", "coefficient"],
}

# Criticality levels for shared code items
CRITICALITY_CRITICAL = "critical"      # must match exactly or exploits/desyncs
CRITICALITY_HIGH = "high"              # should match or noticeable gameplay bugs
CRITICALITY_MEDIUM = "medium"          # desirable match but minor if off
CRITICALITY_LOW = "low"                # cosmetic or non-gameplay impact

# Trivial values to skip in constant extraction
_TRIVIAL_VALUES = {0, 1, -1, 2, 4, 8, 0xFF, 0xFFFF, 0xFFFFFFFF}


# ---------------------------------------------------------------------------
# Helper: classify a function as sender, handler, or both
# ---------------------------------------------------------------------------

def _classify_function_role(pseudocode, func_name):
    """Determine if a function is a CMSG sender, SMSG handler, or shared.

    Returns a set of roles: {'sender', 'handler', 'shared'}
    """
    roles = set()

    # Check for send calls
    if _RE_SEND_CALL.search(pseudocode):
        roles.add("sender")

    # Check for read calls (handler-side deserialization)
    read_count = len(_RE_READ_CALL.findall(pseudocode))
    read_count += len(_RE_TEMPLATE_READ.findall(pseudocode))
    read_count += len(_RE_STREAM_READ.findall(pseudocode))
    if read_count >= 2:
        roles.add("handler")

    # Check for write calls (sender-side serialization)
    write_count = len(_RE_WRITE_CALL.findall(pseudocode))
    write_count += len(_RE_TEMPLATE_WRITE.findall(pseudocode))
    write_count += len(_RE_STREAM_WRITE.findall(pseudocode))
    if write_count >= 2:
        roles.add("sender")

    # Check function name for CMSG/SMSG hints
    name_upper = func_name.upper() if func_name else ""
    if "CMSG" in name_upper or "SEND" in name_upper:
        roles.add("sender")
    if "SMSG" in name_upper or "HANDLE" in name_upper or "RECV" in name_upper:
        roles.add("handler")

    # If function is both sender and handler, it's shared code
    if "sender" in roles and "handler" in roles:
        roles.add("shared")

    return roles if roles else {"unknown"}


def _extract_if_block(lines, start_idx, max_lines=15):
    """Extract the full if-block starting at a given line index."""
    block = [lines[start_idx]]
    depth = lines[start_idx].count("{") - lines[start_idx].count("}")

    for j in range(start_idx + 1, min(start_idx + max_lines, len(lines))):
        block.append(lines[j])
        depth += lines[j].count("{") - lines[j].count("}")
        if depth <= 0 and ("return" in lines[j] or "}" in lines[j]):
            break

    return "\n".join(block)


def _parse_int(s):
    """Parse a string as an integer, handling hex and suffixes."""
    s = s.rstrip("UuLl")
    try:
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


def _parse_number(s):
    """Parse a string as int or float."""
    s = s.rstrip("UuLlFfDd")
    try:
        if "." in s or "e" in s.lower():
            return float(s)
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


def _classify_formula(pseudocode, func_name):
    """Classify a formula by its semantic purpose using keyword matching."""
    text = (pseudocode + " " + (func_name or "")).lower()
    scores = {}
    for category, keywords in _FORMULA_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scores[category] = score

    if not scores:
        return "unknown"
    return max(scores, key=scores.get)


def _count_float_ops(pseudocode):
    """Count floating-point operations in pseudocode as a heaviness metric."""
    count = 0
    count += len(_RE_FLOAT_MUL.findall(pseudocode))
    count += len(_RE_FLOAT_CMP.findall(pseudocode))
    count += len(_RE_SQRT.findall(pseudocode))
    count += len(_RE_POW.findall(pseudocode))
    count += len(_RE_ROUND.findall(pseudocode))
    count += len(_RE_EXPLOG.findall(pseudocode))
    count += len(_RE_FLOAT_CONST.findall(pseudocode))
    return count


def _extract_serialization_ops(pseudocode):
    """Extract an ordered list of serialization operations from pseudocode.

    Returns a list of dicts: [{op: 'ReadUInt32', type: 'uint32', bits: 32}, ...]
    """
    ops = []
    lines = pseudocode.split("\n")

    for line_num, line in enumerate(lines):
        stripped = line.strip()

        # Named read calls
        for m in _RE_READ_CALL.finditer(stripped):
            ops.append({
                "direction": "read",
                "op": m.group(1),
                "line": line_num,
                "raw": stripped[:200],
            })

        # Named write calls
        for m in _RE_WRITE_CALL.finditer(stripped):
            ops.append({
                "direction": "write",
                "op": m.group(1),
                "line": line_num,
                "raw": stripped[:200],
            })

        # Template reads
        for m in _RE_TEMPLATE_READ.finditer(stripped):
            ops.append({
                "direction": "read",
                "op": f"Read<{m.group(1)}>",
                "line": line_num,
                "raw": stripped[:200],
            })

        # Template writes
        for m in _RE_TEMPLATE_WRITE.finditer(stripped):
            ops.append({
                "direction": "write",
                "op": f"Write<{m.group(1)}>",
                "line": line_num,
                "raw": stripped[:200],
            })

        # ReadBits/WriteBits
        for m in _RE_READBITS.finditer(stripped):
            ops.append({
                "direction": "read",
                "op": f"ReadBits({m.group(1)})",
                "line": line_num,
                "raw": stripped[:200],
            })
        for m in _RE_WRITEBITS.finditer(stripped):
            ops.append({
                "direction": "write",
                "op": f"WriteBits({m.group(1)})",
                "line": line_num,
                "raw": stripped[:200],
            })

        # Stream operators
        for m in _RE_STREAM_READ.finditer(stripped):
            ops.append({
                "direction": "read",
                "op": "stream_read",
                "line": line_num,
                "raw": stripped[:200],
            })
        for m in _RE_STREAM_WRITE.finditer(stripped):
            ops.append({
                "direction": "write",
                "op": "stream_write",
                "line": line_num,
                "raw": stripped[:200],
            })

        # FlushBits
        if _RE_FLUSH.search(stripped):
            ops.append({
                "direction": "flush",
                "op": "FlushBits",
                "line": line_num,
                "raw": stripped[:200],
            })

    return ops


def _normalize_op(op_str):
    """Normalize a serialization op name for comparison.

    E.g. ReadUInt32 -> uint32, Write<float> -> float, ReadBits(3) -> bits3
    """
    op = op_str.lower()

    # ReadBits(N) / WriteBits(N)
    m = re.match(r'(?:read|write)bits\((\d+)\)', op)
    if m:
        return f"bits{m.group(1)}"

    # ReadXxx / WriteXxx -> strip prefix
    for prefix in ("read", "write"):
        if op.startswith(prefix):
            return op[len(prefix):]

    # Read<type> / Write<type>
    m = re.match(r'(?:read|write)<(\w+)>', op)
    if m:
        return m.group(1)

    if op in ("stream_read", "stream_write"):
        return "stream"
    if op == "flushbits":
        return "flush"

    return op


# ---------------------------------------------------------------------------
# Phase 1: Validation Logic Detection
# ---------------------------------------------------------------------------

def _detect_validations(session, cmsg_senders):
    """Find client-side validation logic before CMSG sends.

    Scans functions that contain SendPacket / similar calls and extracts
    validation checks (range, permission, string length, etc.) that appear
    before the send point.
    """
    db = session.db
    validations = []
    checked = 0

    msg_info(f"Phase 1: Scanning {len(cmsg_senders)} CMSG sender functions for validations...")

    for func_ea, func_name in cmsg_senders:
        pseudocode = get_decompiled_text(func_ea)
        if not pseudocode:
            continue

        checked += 1
        lines = pseudocode.split("\n")

        # Find the line where SendPacket is called — validations before it matter
        send_line = -1
        for i, line in enumerate(lines):
            if _RE_SEND_CALL.search(line):
                send_line = i
                break

        if send_line < 0:
            # No explicit send call found but function may still validate
            send_line = len(lines)

        # Extract validations from lines BEFORE the send call
        for i in range(min(send_line, len(lines))):
            stripped = lines[i].strip()
            if not stripped.startswith("if"):
                continue

            block = _extract_if_block(lines, i)

            # Range guard: if (val < 0 || val > MAX) return;
            m = _RE_RANGE_GUARD.search(block)
            if m:
                validations.append({
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "opcode": _find_cmsg_opcode(pseudocode, func_name),
                    "check_type": "range_check",
                    "condition": stripped[:300],
                    "values": {
                        "var1": m.group(1), "op1": m.group(2), "val1": m.group(3),
                        "var2": m.group(4), "op2": m.group(5), "val2": m.group(6),
                    },
                    "criticality": CRITICALITY_CRITICAL,
                    "line_index": i,
                    "block": block[:500],
                })
                continue

            # Simple guard: if (val > MAX) return;
            m = _RE_SIMPLE_GUARD.search(block)
            if m:
                val = _parse_number(m.group(3))
                if val is not None and val not in _TRIVIAL_VALUES:
                    validations.append({
                        "function_ea": func_ea,
                        "function_name": func_name,
                        "opcode": _find_cmsg_opcode(pseudocode, func_name),
                        "check_type": "boundary_check",
                        "condition": stripped[:300],
                        "values": {
                            "var": m.group(1), "op": m.group(2), "val": m.group(3),
                        },
                        "criticality": CRITICALITY_CRITICAL,
                        "line_index": i,
                        "block": block[:500],
                    })
                continue

            # String length check
            m = _RE_STRLEN_CHECK.search(block)
            if m:
                validations.append({
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "opcode": _find_cmsg_opcode(pseudocode, func_name),
                    "check_type": "string_length",
                    "condition": stripped[:300],
                    "values": {
                        "var": m.group(1), "op": m.group(2), "max_len": m.group(3),
                    },
                    "criticality": CRITICALITY_CRITICAL,
                    "line_index": i,
                    "block": block[:500],
                })
                continue

            # Permission check
            m = _RE_PERMISSION.search(block)
            if m:
                validations.append({
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "opcode": _find_cmsg_opcode(pseudocode, func_name),
                    "check_type": "permission_check",
                    "condition": stripped[:300],
                    "values": {"check_func": m.group(1)},
                    "criticality": CRITICALITY_HIGH,
                    "line_index": i,
                    "block": block[:500],
                })
                continue

            # Clamp patterns (not an if-block but handle inline)
            # These are handled below outside the if-block scan

        # Clamp checks (can appear anywhere before send)
        for i in range(min(send_line, len(lines))):
            m = _RE_CLAMP.search(lines[i])
            if m:
                validations.append({
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "opcode": _find_cmsg_opcode(pseudocode, func_name),
                    "check_type": "value_clamp",
                    "condition": lines[i].strip()[:300],
                    "values": {"var": m.group(1), "limit": m.group(2)},
                    "criticality": CRITICALITY_HIGH,
                    "line_index": i,
                    "block": lines[i].strip()[:500],
                })

        # Enum guard checks
        for i in range(min(send_line, len(lines))):
            stripped = lines[i].strip()
            if not stripped.startswith("if"):
                continue
            block = _extract_if_block(lines, i)
            m = _RE_ENUM_GUARD.search(block)
            if m:
                val = _parse_int(m.group(3))
                if val is not None and val not in _TRIVIAL_VALUES:
                    # Avoid duplicating range/boundary checks already captured
                    already = any(
                        v["function_ea"] == func_ea and v["line_index"] == i
                        for v in validations
                    )
                    if not already:
                        validations.append({
                            "function_ea": func_ea,
                            "function_name": func_name,
                            "opcode": _find_cmsg_opcode(pseudocode, func_name),
                            "check_type": "enum_guard",
                            "condition": stripped[:300],
                            "values": {
                                "var": m.group(1), "op": m.group(2),
                                "expected": m.group(3),
                            },
                            "criticality": CRITICALITY_HIGH,
                            "line_index": i,
                            "block": block[:500],
                        })

        if checked % 100 == 0:
            msg_info(f"  Scanned {checked} senders, {len(validations)} validations found...")

    msg_info(f"Phase 1 complete: {len(validations)} validations from {checked} sender functions")
    return validations


def _find_cmsg_opcode(pseudocode, func_name):
    """Try to extract a CMSG opcode name from pseudocode or function name."""
    m = _RE_CMSG_REF.search(pseudocode)
    if m:
        return m.group(0)
    m = _RE_CMSG_REF.search(func_name or "")
    if m:
        return m.group(0)
    return None


# ---------------------------------------------------------------------------
# Phase 2: Mathematical Formula Extraction
# ---------------------------------------------------------------------------

def _detect_formulas(session, candidate_funcs):
    """Extract mathematical formulas from game logic functions.

    Targets functions with heavy floating-point usage that are likely
    implementing game mechanics calculations.
    """
    db = session.db
    formulas = []
    checked = 0

    msg_info(f"Phase 2: Scanning {len(candidate_funcs)} functions for mathematical formulas...")

    for func_ea, func_name in candidate_funcs:
        pseudocode = get_decompiled_text(func_ea)
        if not pseudocode:
            continue

        checked += 1
        float_ops = _count_float_ops(pseudocode)

        # Skip functions without meaningful float usage
        if float_ops < 3:
            continue

        formula_type = _classify_formula(pseudocode, func_name)
        constants_used = []

        # Extract float constants
        for m in _RE_FLOAT_CONST.finditer(pseudocode):
            val = _parse_number(m.group(1))
            if val is not None and val not in (0.0, 1.0, -1.0, 0.5, 2.0):
                constants_used.append({
                    "value": val,
                    "raw": m.group(0),
                    "type": "float",
                })

        # Look for stat*coeff+base pattern
        stat_formulas = _RE_STAT_FORMULA.findall(pseudocode)
        for sf in stat_formulas:
            formulas.append({
                "function_ea": func_ea,
                "function_name": func_name,
                "formula_type": formula_type,
                "pattern": "stat_coefficient",
                "pseudocode": f"{sf[0]} * {sf[1]} {sf[2]} {sf[3]}",
                "constants_used": constants_used[:20],
                "tc_equivalent": None,
                "float_op_count": float_ops,
            })

        # Look for ratio formulas: val * A / B
        ratio_formulas = _RE_RATIO_FORMULA.findall(pseudocode)
        for rf in ratio_formulas:
            denom = _parse_number(rf[2])
            if denom is not None and denom not in _TRIVIAL_VALUES:
                formulas.append({
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "formula_type": formula_type,
                    "pattern": "ratio_conversion",
                    "pseudocode": f"{rf[0]} * {rf[1]} / {rf[2]}",
                    "constants_used": constants_used[:20],
                    "tc_equivalent": None,
                    "float_op_count": float_ops,
                })

        # Look for quadratic formulas
        quad_formulas = _RE_QUADRATIC.findall(pseudocode)
        for qf in quad_formulas:
            formulas.append({
                "function_ea": func_ea,
                "function_name": func_name,
                "formula_type": formula_type,
                "pattern": "quadratic",
                "pseudocode": f"{qf[0]}*x^2 {qf[2]}{qf[3]}*x {qf[4]}{qf[5]}",
                "constants_used": constants_used[:20],
                "tc_equivalent": None,
                "float_op_count": float_ops,
            })

        # Look for sqrt (distance formula)
        sqrt_matches = _RE_SQRT.findall(pseudocode)
        if sqrt_matches:
            for sq in sqrt_matches:
                formulas.append({
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "formula_type": "distance" if "distance" in formula_type else formula_type,
                    "pattern": "sqrt_distance",
                    "pseudocode": f"sqrt({sq[:100]})",
                    "constants_used": constants_used[:20],
                    "tc_equivalent": None,
                    "float_op_count": float_ops,
                })

        # Look for pow (exponential scaling)
        pow_matches = _RE_POW.findall(pseudocode)
        for pm in pow_matches:
            formulas.append({
                "function_ea": func_ea,
                "function_name": func_name,
                "formula_type": formula_type,
                "pattern": "exponential",
                "pseudocode": f"pow({pm[0][:60]}, {pm[1][:60]})",
                "constants_used": constants_used[:20],
                "tc_equivalent": None,
                "float_op_count": float_ops,
            })

        # Generic high-float-count function with no specific pattern
        if not stat_formulas and not ratio_formulas and not quad_formulas \
                and not sqrt_matches and not pow_matches and float_ops >= 5:
            formulas.append({
                "function_ea": func_ea,
                "function_name": func_name,
                "formula_type": formula_type,
                "pattern": "complex_float_math",
                "pseudocode": _extract_formula_snippet(pseudocode, 500),
                "constants_used": constants_used[:20],
                "tc_equivalent": None,
                "float_op_count": float_ops,
            })

        if checked % 100 == 0:
            msg_info(f"  Scanned {checked} functions, {len(formulas)} formulas found...")

    msg_info(f"Phase 2 complete: {len(formulas)} formulas from {checked} functions")
    return formulas


def _extract_formula_snippet(pseudocode, max_len):
    """Extract the most formula-dense snippet from pseudocode."""
    lines = pseudocode.split("\n")
    best_start = 0
    best_score = 0
    window = 10

    for i in range(len(lines)):
        chunk = "\n".join(lines[i:i + window])
        score = _count_float_ops(chunk)
        if score > best_score:
            best_score = score
            best_start = i

    snippet = "\n".join(lines[best_start:best_start + window])
    return snippet[:max_len]


# ---------------------------------------------------------------------------
# Phase 3: Serialization Symmetry Detection
# ---------------------------------------------------------------------------

def _detect_serialization_pairs(session, all_funcs):
    """Find matching read/write function pairs and check symmetry.

    Serialization pairs are functions that serialize and deserialize the
    same data structure.  The field order and types must match exactly.
    """
    db = session.db
    pairs = []
    checked = 0

    # Collect all functions with serialization ops, grouped by direction
    readers = {}   # func_ea -> (func_name, ops_list)
    writers = {}   # func_ea -> (func_name, ops_list)

    msg_info(f"Phase 3: Scanning {len(all_funcs)} functions for serialization pairs...")

    for func_ea, func_name in all_funcs:
        pseudocode = get_decompiled_text(func_ea)
        if not pseudocode:
            continue

        checked += 1
        ops = _extract_serialization_ops(pseudocode)
        if len(ops) < 2:
            continue

        read_ops = [o for o in ops if o["direction"] == "read"]
        write_ops = [o for o in ops if o["direction"] == "write"]

        if len(read_ops) >= 2:
            readers[func_ea] = (func_name, read_ops)
        if len(write_ops) >= 2:
            writers[func_ea] = (func_name, write_ops)

        if checked % 200 == 0:
            msg_info(f"  Scanned {checked} functions, "
                     f"{len(readers)} readers, {len(writers)} writers...")

    msg_info(f"Found {len(readers)} reader functions and {len(writers)} writer functions")

    # Match reader-writer pairs by name similarity
    matched_readers = set()
    matched_writers = set()

    for r_ea, (r_name, r_ops) in readers.items():
        r_base = _strip_rw_prefix(r_name)
        if not r_base:
            continue

        best_writer = None
        best_score = 0

        for w_ea, (w_name, w_ops) in writers.items():
            w_base = _strip_rw_prefix(w_name)
            if not w_base:
                continue

            # Name similarity scoring
            score = 0
            if r_base == w_base:
                score = 100
            elif r_base.lower() == w_base.lower():
                score = 90
            elif r_base.lower() in w_base.lower() or w_base.lower() in r_base.lower():
                score = 60

            # Op count similarity bonus
            if score > 0 and abs(len(r_ops) - len(w_ops)) <= 2:
                score += 10

            if score > best_score:
                best_score = score
                best_writer = (w_ea, w_name, w_ops)

        if best_writer and best_score >= 60:
            w_ea, w_name, w_ops = best_writer

            # Check for asymmetries
            asymmetries = _find_serialization_asymmetries(r_ops, w_ops)

            pairs.append({
                "read_ea": r_ea,
                "read_name": r_name,
                "write_ea": w_ea,
                "write_name": w_name,
                "read_field_count": len(r_ops),
                "write_field_count": len(w_ops),
                "asymmetries": asymmetries,
                "match_score": best_score,
                "is_symmetric": len(asymmetries) == 0,
            })

            matched_readers.add(r_ea)
            matched_writers.add(w_ea)

    # Also try matching via xref analysis: find struct types that appear
    # in both a reader and a writer
    for r_ea, (r_name, r_ops) in readers.items():
        if r_ea in matched_readers:
            continue

        # Look for writers that share callers with this reader
        reader_callers = set()
        try:
            for xref in idautils.XrefsTo(r_ea, 0):
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    reader_callers.add(caller_func.start_ea)
        except Exception:
            continue

        for w_ea, (w_name, w_ops) in writers.items():
            if w_ea in matched_writers:
                continue

            writer_callers = set()
            try:
                for xref in idautils.XrefsTo(w_ea, 0):
                    caller_func = ida_funcs.get_func(xref.frm)
                    if caller_func:
                        writer_callers.add(caller_func.start_ea)
            except Exception:
                continue

            shared_callers = reader_callers & writer_callers
            if len(shared_callers) >= 1:
                asymmetries = _find_serialization_asymmetries(r_ops, w_ops)
                pairs.append({
                    "read_ea": r_ea,
                    "read_name": r_name,
                    "write_ea": w_ea,
                    "write_name": w_name,
                    "read_field_count": len(r_ops),
                    "write_field_count": len(w_ops),
                    "asymmetries": asymmetries,
                    "match_score": 50,
                    "is_symmetric": len(asymmetries) == 0,
                    "shared_callers": len(shared_callers),
                })
                matched_readers.add(r_ea)
                matched_writers.add(w_ea)

    msg_info(f"Phase 3 complete: {len(pairs)} serialization pairs found, "
             f"{sum(1 for p in pairs if not p['is_symmetric'])} asymmetric")
    return pairs


def _strip_rw_prefix(name):
    """Strip Read/Write/Serialize/Deserialize prefix for matching."""
    if not name:
        return None

    prefixes = [
        "Read", "Write", "Serialize", "Deserialize",
        "Pack", "Unpack", "Encode", "Decode",
        "Marshal", "Unmarshal", "Build", "Parse",
        "read_", "write_", "serialize_", "deserialize_",
    ]

    for prefix in prefixes:
        if name.startswith(prefix) and len(name) > len(prefix):
            return name[len(prefix):]

    # Also try removing common suffixes
    suffixes = ["_Read", "_Write", "Reader", "Writer"]
    for suffix in suffixes:
        if name.endswith(suffix):
            return name[:-len(suffix)]

    return name


def _find_serialization_asymmetries(read_ops, write_ops):
    """Compare read and write op sequences to find mismatches.

    Returns a list of asymmetry descriptions.
    """
    asymmetries = []

    # Normalize both sequences (skip flush markers for comparison)
    r_norm = [_normalize_op(o["op"]) for o in read_ops if o["direction"] == "read"]
    w_norm = [_normalize_op(o["op"]) for o in write_ops if o["direction"] == "write"]

    # Length mismatch
    if len(r_norm) != len(w_norm):
        asymmetries.append({
            "type": "field_count_mismatch",
            "read_count": len(r_norm),
            "write_count": len(w_norm),
            "detail": f"Reader has {len(r_norm)} fields, writer has {len(w_norm)}",
        })

    # Compare field-by-field up to the shorter list
    min_len = min(len(r_norm), len(w_norm))
    for idx in range(min_len):
        if r_norm[idx] != w_norm[idx]:
            asymmetries.append({
                "type": "type_mismatch",
                "field_index": idx,
                "read_type": r_norm[idx],
                "write_type": w_norm[idx],
                "detail": f"Field {idx}: reader={r_norm[idx]}, writer={w_norm[idx]}",
            })

    # Extra fields
    if len(r_norm) > len(w_norm):
        for idx in range(len(w_norm), len(r_norm)):
            asymmetries.append({
                "type": "extra_read_field",
                "field_index": idx,
                "read_type": r_norm[idx],
                "detail": f"Reader has extra field {idx}: {r_norm[idx]}",
            })
    elif len(w_norm) > len(r_norm):
        for idx in range(len(r_norm), len(w_norm)):
            asymmetries.append({
                "type": "extra_write_field",
                "field_index": idx,
                "write_type": w_norm[idx],
                "detail": f"Writer has extra field {idx}: {w_norm[idx]}",
            })

    return asymmetries


# ---------------------------------------------------------------------------
# Phase 4: Enum Value Consistency
# ---------------------------------------------------------------------------

def _detect_shared_constants(session, sender_funcs, handler_funcs):
    """Find constants used in BOTH CMSG senders and SMSG handlers.

    These enum values and magic numbers must be identical on the server.
    """
    db = session.db
    sender_constants = defaultdict(list)   # value -> list of (ea, name, context)
    handler_constants = defaultdict(list)  # value -> list of (ea, name, context)

    msg_info("Phase 4: Extracting constants from senders and handlers...")

    # Extract constants from senders
    for func_ea, func_name in sender_funcs:
        pseudocode = get_decompiled_text(func_ea)
        if not pseudocode:
            continue
        _collect_constants(pseudocode, func_ea, func_name, sender_constants)

    msg_info(f"  Extracted {len(sender_constants)} unique values from {len(sender_funcs)} senders")

    # Extract constants from handlers
    for func_ea, func_name in handler_funcs:
        pseudocode = get_decompiled_text(func_ea)
        if not pseudocode:
            continue
        _collect_constants(pseudocode, func_ea, func_name, handler_constants)

    msg_info(f"  Extracted {len(handler_constants)} unique values from {len(handler_funcs)} handlers")

    # Find intersection — values used in BOTH senders and handlers
    shared_values = set(sender_constants.keys()) & set(handler_constants.keys())
    shared_constants = []

    for val in sorted(shared_values):
        # Get representative usage from each side
        send_usage = sender_constants[val][:5]
        recv_usage = handler_constants[val][:5]

        # Determine if this looks like an enum value or a protocol constant
        is_enum = _looks_like_enum_value(val, send_usage, recv_usage)

        shared_constants.append({
            "name": _infer_constant_name(val, send_usage + recv_usage),
            "value": val,
            "hex_value": f"0x{val:X}" if isinstance(val, int) and val >= 0 else str(val),
            "used_in_send": True,
            "used_in_recv": True,
            "send_functions": [
                {"ea": u[0], "name": u[1], "context": u[2][:200]}
                for u in send_usage
            ],
            "recv_functions": [
                {"ea": u[0], "name": u[1], "context": u[2][:200]}
                for u in recv_usage
            ],
            "is_likely_enum": is_enum,
            "total_usage_count": len(sender_constants[val]) + len(handler_constants[val]),
        })

    msg_info(f"Phase 4 complete: {len(shared_constants)} shared constants found")
    return shared_constants


def _collect_constants(pseudocode, func_ea, func_name, target_dict):
    """Extract numeric constants from pseudocode into target_dict."""
    # Hex constants
    for m in _RE_HEX.finditer(pseudocode):
        val = _parse_int(m.group(1))
        if val is not None and val not in _TRIVIAL_VALUES and val < 0x100000000:
            context_start = max(0, m.start() - 40)
            context_end = min(len(pseudocode), m.end() + 40)
            context = pseudocode[context_start:context_end].strip()
            target_dict[val].append((func_ea, func_name, context))

    # Decimal constants (only non-trivial)
    for m in _RE_DEC.finditer(pseudocode):
        val = _parse_int(m.group(1))
        if val is not None and val not in _TRIVIAL_VALUES and abs(val) > 2 and abs(val) < 0x10000000:
            context_start = max(0, m.start() - 40)
            context_end = min(len(pseudocode), m.end() + 40)
            context = pseudocode[context_start:context_end].strip()
            target_dict[val].append((func_ea, func_name, context))


def _looks_like_enum_value(val, send_usage, recv_usage):
    """Heuristic: does this constant look like an enum member?

    Enum-like: small integers, used in comparisons (if x == 5),
    used in switch cases, clean powers of two.
    """
    if not isinstance(val, int):
        return False
    if val < 0 or val > 0xFFFF:
        return False
    # Check if it appears in comparison context
    for _, _, ctx in send_usage + recv_usage:
        if "==" in ctx or "!=" in ctx or "switch" in ctx or "case" in ctx:
            return True
    return False


def _infer_constant_name(val, usages):
    """Try to infer a meaningful name for a constant from its usage context."""
    # Look for uppercase identifiers near the constant
    for _, func_name, context in usages:
        # Find nearby UPPER_CASE identifiers
        m = re.search(r'([A-Z][A-Z_0-9]{3,})', context)
        if m:
            return m.group(1)

    # Fall back to function name or hex value
    if usages and usages[0][1]:
        return f"CONST_in_{usages[0][1]}"

    if isinstance(val, int):
        return f"CONST_0x{val:X}"
    return f"CONST_{val}"


# ---------------------------------------------------------------------------
# Phase 5: Protocol Constants
# ---------------------------------------------------------------------------

def _detect_protocol_constants(session, all_funcs):
    """Find protocol-level constants: max string lengths, buffer sizes,
    max array sizes, packet size limits, and version magic numbers.
    """
    db = session.db
    proto_constants = []

    msg_info(f"Phase 5: Scanning {len(all_funcs)} functions for protocol constants...")
    checked = 0

    for func_ea, func_name in all_funcs:
        pseudocode = get_decompiled_text(func_ea)
        if not pseudocode:
            continue

        checked += 1

        # String length limits (strlen checks)
        for m in _RE_STRLEN_CHECK.finditer(pseudocode):
            limit = _parse_int(m.group(3))
            if limit is not None and limit > 0:
                proto_constants.append({
                    "name": f"MAX_STRLEN_{m.group(1).upper()}",
                    "value": limit,
                    "type": "max_string_length",
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "context": m.group(0)[:200],
                })

        # Buffer allocation sizes
        for m in _RE_ALLOC.finditer(pseudocode):
            size = _parse_int(m.group(1))
            if size is not None and size > 16 and size < 0x100000:
                proto_constants.append({
                    "name": _infer_buffer_name(func_name, size),
                    "value": size,
                    "type": "buffer_size",
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "context": m.group(0)[:200],
                })

        # Array size declarations
        for m in _RE_ARRAY_SIZE.finditer(pseudocode):
            size = _parse_int(m.group(1))
            if size is not None and size > 2 and size < 0x10000:
                proto_constants.append({
                    "name": f"ARRAY_SIZE_{size}",
                    "value": size,
                    "type": "array_size",
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "context": m.group(0)[:200],
                })

        # ReadBits size (max array size in packet)
        for m in _RE_READBITS.finditer(pseudocode):
            bits = _parse_int(m.group(1))
            if bits is not None and bits > 1:
                max_val = (1 << bits) - 1
                proto_constants.append({
                    "name": f"MAX_BITS_{bits}",
                    "value": max_val,
                    "bits": bits,
                    "type": "bit_field_max",
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "context": m.group(0)[:200],
                })

        if checked % 200 == 0:
            msg_info(f"  Scanned {checked} functions, {len(proto_constants)} proto constants...")

    # Deduplicate by (type, value)
    seen = set()
    unique_constants = []
    for pc in proto_constants:
        key = (pc["type"], pc["value"])
        if key not in seen:
            seen.add(key)
            unique_constants.append(pc)

    msg_info(f"Phase 5 complete: {len(unique_constants)} protocol constants "
             f"(from {len(proto_constants)} raw)")
    return unique_constants


def _infer_buffer_name(func_name, size):
    """Infer a name for a buffer allocation constant."""
    if func_name:
        # Clean function name
        clean = re.sub(r'^sub_[0-9A-Fa-f]+$', 'UNKNOWN', func_name)
        if clean != "UNKNOWN":
            return f"BUFFER_{clean}_{size}"
    return f"BUFFER_SIZE_{size}"


# ---------------------------------------------------------------------------
# Phase 6: Shared Utility Functions
# ---------------------------------------------------------------------------

def _detect_shared_utilities(session, sender_eas, handler_eas):
    """Find functions called by BOTH CMSG senders and SMSG handlers.

    These shared callees implement logic that must be equivalent on the server:
    data conversion, validation, formatting, address calculation, etc.
    """
    db = session.db

    # Build caller sets
    sender_set = set(sender_eas)
    handler_set = set(handler_eas)
    all_callers = sender_set | handler_set

    msg_info(f"Phase 6: Analyzing callees of {len(sender_set)} senders "
             f"and {len(handler_set)} handlers...")

    # For each caller, collect its direct callees
    sender_callees = defaultdict(set)    # callee_ea -> set of sender_eas calling it
    handler_callees = defaultdict(set)   # callee_ea -> set of handler_eas calling it

    for caller_ea in sender_set:
        func = ida_funcs.get_func(caller_ea)
        if not func:
            continue
        try:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.type in (1, 17, 18, 19, 21):  # call types
                        target_func = ida_funcs.get_func(xref.to)
                        if target_func and target_func.start_ea != caller_ea:
                            sender_callees[target_func.start_ea].add(caller_ea)
        except Exception:
            continue

    for caller_ea in handler_set:
        func = ida_funcs.get_func(caller_ea)
        if not func:
            continue
        try:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.type in (1, 17, 18, 19, 21):  # call types
                        target_func = ida_funcs.get_func(xref.to)
                        if target_func and target_func.start_ea != caller_ea:
                            handler_callees[target_func.start_ea].add(caller_ea)
        except Exception:
            continue

    # Find callees used by BOTH senders and handlers
    shared_callee_eas = set(sender_callees.keys()) & set(handler_callees.keys())

    shared_utilities = []
    for callee_ea in sorted(shared_callee_eas):
        callee_name = ida_name.get_name(callee_ea) or ea_str(callee_ea)
        callee_func = ida_funcs.get_func(callee_ea)

        # Skip tiny wrappers (less than 16 bytes)
        if callee_func and callee_func.size() < 16:
            continue

        # Skip common runtime/library functions
        if _is_runtime_function(callee_name):
            continue

        sender_callers = sender_callees[callee_ea]
        handler_callers = handler_callees[callee_ea]

        # Categorize the shared utility
        category = _categorize_utility(callee_ea, callee_name)

        shared_utilities.append({
            "function_ea": callee_ea,
            "name": callee_name,
            "size": callee_func.size() if callee_func else 0,
            "category": category,
            "sender_caller_count": len(sender_callers),
            "handler_caller_count": len(handler_callers),
            "total_caller_count": len(sender_callers) + len(handler_callers),
            "caller_types": {
                "sender_callers": [ea_str(e) for e in list(sender_callers)[:5]],
                "handler_callers": [ea_str(e) for e in list(handler_callers)[:5]],
            },
        })

    # Sort by total caller count descending (most-used shared functions first)
    shared_utilities.sort(key=lambda x: x["total_caller_count"], reverse=True)

    msg_info(f"Phase 6 complete: {len(shared_utilities)} shared utility functions")
    return shared_utilities


def _is_runtime_function(name):
    """Check if a function name indicates a runtime/library function."""
    if not name:
        return False
    runtime_prefixes = [
        "sub_", "__", "_Thunk", "_Guard", "operator", "std::",
        "memcpy", "memmove", "memset", "memcmp",
        "strlen", "strcmp", "strcpy", "strcat",
        "printf", "sprintf", "snprintf", "fprintf",
        "malloc", "free", "realloc", "calloc",
        "new", "delete",
        "j_", "nullsub",
        "_CRT", "_RTC", "__GSHandler",
        "??0", "??1", "??_G", "??_E",  # MSVC manglings
    ]
    for prefix in runtime_prefixes:
        if name.startswith(prefix):
            return True

    runtime_contains = [
        "DebugBreak", "OutputDebugString", "GetLastError",
        "QueryPerformance", "GetTickCount", "InterlockedCompare",
        "EnterCriticalSection", "LeaveCriticalSection",
        "RaiseException", "UnhandledExceptionFilter",
    ]
    for keyword in runtime_contains:
        if keyword in name:
            return True

    return False


def _categorize_utility(func_ea, func_name):
    """Categorize a shared utility function by its likely purpose."""
    name_lower = (func_name or "").lower()

    categories = {
        "serialization": ["serialize", "deserialize", "pack", "unpack",
                          "encode", "decode", "marshal", "unmarshal",
                          "read", "write", "bytebuffer"],
        "validation": ["validate", "check", "verify", "isvalid",
                       "canuse", "hasflag", "ispermitted"],
        "conversion": ["convert", "transform", "translate", "tofloat",
                       "toint", "tostring", "parse", "format"],
        "math": ["calc", "compute", "distance", "sqrt", "lerp",
                 "interpolate", "clamp", "normalize", "scale"],
        "lookup": ["get", "find", "lookup", "resolve", "fetch",
                   "query", "search"],
        "guid": ["guid", "objectguid", "packedguid"],
        "hash": ["hash", "crc", "checksum", "digest"],
        "compression": ["compress", "decompress", "inflate", "deflate", "zlib"],
    }

    for category, keywords in categories.items():
        for kw in keywords:
            if kw in name_lower:
                return category

    # Try to classify by decompiled content
    pseudocode = get_decompiled_text(func_ea)
    if pseudocode:
        pcode_lower = pseudocode.lower()
        if _count_float_ops(pseudocode) >= 3:
            return "math"
        if "readbit" in pcode_lower or "writebit" in pcode_lower:
            return "serialization"
        if "return" in pcode_lower and ("==" in pcode_lower or "!=" in pcode_lower):
            return "validation"

    return "unknown"


# ---------------------------------------------------------------------------
# Phase 7: Classification and Scoring
# ---------------------------------------------------------------------------

def _classify_and_score(validations, formulas, serial_pairs, shared_consts,
                        proto_consts, shared_utils):
    """Assign criticality scores and attempt TC equivalence matching.

    Returns summary statistics.
    """
    critical_count = 0

    # Score validations
    for v in validations:
        if v["check_type"] in ("range_check", "string_length"):
            v["criticality"] = CRITICALITY_CRITICAL
            critical_count += 1
        elif v["check_type"] in ("boundary_check", "enum_guard"):
            v["criticality"] = CRITICALITY_CRITICAL
            critical_count += 1
        elif v["check_type"] == "permission_check":
            v["criticality"] = CRITICALITY_HIGH
        elif v["check_type"] == "value_clamp":
            v["criticality"] = CRITICALITY_HIGH
        v["tc_has_equivalent"] = False  # will be filled by conformance checks

    # Score formulas
    for f in formulas:
        if f["formula_type"] in ("damage", "healing", "rating"):
            f["criticality"] = CRITICALITY_CRITICAL
            critical_count += 1
        elif f["formula_type"] in ("distance", "speed", "cooldown"):
            f["criticality"] = CRITICALITY_HIGH
        elif f["formula_type"] in ("experience", "scaling"):
            f["criticality"] = CRITICALITY_HIGH
        else:
            f["criticality"] = CRITICALITY_MEDIUM
        f["tc_has_equivalent"] = False

    # Score serialization pairs
    for p in serial_pairs:
        if not p["is_symmetric"]:
            p["criticality"] = CRITICALITY_CRITICAL
            critical_count += 1
        else:
            p["criticality"] = CRITICALITY_HIGH
        p["tc_has_equivalent"] = False

    # Score shared constants
    for c in shared_consts:
        if c["is_likely_enum"]:
            c["criticality"] = CRITICALITY_CRITICAL
            critical_count += 1
        elif c["total_usage_count"] >= 5:
            c["criticality"] = CRITICALITY_HIGH
        else:
            c["criticality"] = CRITICALITY_MEDIUM
        c["tc_has_equivalent"] = False

    # Score protocol constants
    for pc in proto_consts:
        if pc["type"] in ("max_string_length", "bit_field_max"):
            pc["criticality"] = CRITICALITY_CRITICAL
            critical_count += 1
        elif pc["type"] == "buffer_size":
            pc["criticality"] = CRITICALITY_HIGH
        else:
            pc["criticality"] = CRITICALITY_MEDIUM
        pc["tc_has_equivalent"] = False

    # Score shared utilities
    for u in shared_utils:
        if u["category"] in ("serialization", "validation", "guid"):
            u["criticality"] = CRITICALITY_CRITICAL
            critical_count += 1
        elif u["category"] in ("math", "conversion", "hash"):
            u["criticality"] = CRITICALITY_HIGH
        else:
            u["criticality"] = CRITICALITY_MEDIUM
        u["tc_has_equivalent"] = False

    total = (len(validations) + len(formulas) + len(serial_pairs) +
             len(shared_consts) + len(proto_consts) + len(shared_utils))

    return total, critical_count


# ---------------------------------------------------------------------------
# Candidate function collection helpers
# ---------------------------------------------------------------------------

def _collect_cmsg_senders(session):
    """Collect CMSG sender functions from the database and binary analysis.

    A CMSG sender is a function that constructs and sends a client-to-server message.
    """
    db = session.db
    senders = []
    seen_eas = set()

    # 1. Functions from opcodes table marked as CMSG
    rows = db.fetchall(
        "SELECT handler_ea, tc_name FROM opcodes "
        "WHERE direction = 'CMSG' AND handler_ea IS NOT NULL"
    )
    for row in rows:
        ea = row["handler_ea"]
        name = row["tc_name"] or ea_str(ea)
        if ea not in seen_eas:
            senders.append((ea, name))
            seen_eas.add(ea)

    # 2. Functions classified as senders in functions table
    rows = db.fetchall(
        "SELECT ea, name FROM functions WHERE system IN ('networking', 'protocol') "
        "AND name LIKE '%Send%'"
    )
    for row in rows:
        ea = row["ea"]
        if ea not in seen_eas:
            name = row["name"] or ea_str(ea)
            senders.append((ea, name))
            seen_eas.add(ea)

    # 3. Functions with CMSG in their name
    rows = db.fetchall(
        "SELECT ea, name FROM functions WHERE name LIKE '%CMSG%'"
    )
    for row in rows:
        ea = row["ea"]
        if ea not in seen_eas:
            name = row["name"] or ea_str(ea)
            senders.append((ea, name))
            seen_eas.add(ea)

    msg_info(f"Collected {len(senders)} CMSG sender functions")
    return senders


def _collect_smsg_handlers(session):
    """Collect SMSG handler functions from the database."""
    db = session.db
    handlers = []
    seen_eas = set()

    # From opcodes table
    rows = db.fetchall(
        "SELECT handler_ea, tc_name FROM opcodes "
        "WHERE direction = 'SMSG' AND handler_ea IS NOT NULL"
    )
    for row in rows:
        ea = row["handler_ea"]
        name = row["tc_name"] or ea_str(ea)
        if ea not in seen_eas:
            handlers.append((ea, name))
            seen_eas.add(ea)

    # Functions with SMSG or Handle in their name
    rows = db.fetchall(
        "SELECT ea, name FROM functions WHERE name LIKE '%SMSG%' "
        "OR name LIKE '%Handle%'"
    )
    for row in rows:
        ea = row["ea"]
        if ea not in seen_eas:
            name = row["name"] or ea_str(ea)
            handlers.append((ea, name))
            seen_eas.add(ea)

    msg_info(f"Collected {len(handlers)} SMSG handler functions")
    return handlers


def _collect_math_candidates(session):
    """Collect functions likely to contain game math formulas.

    Prioritizes functions in combat, rating, experience, and movement systems.
    """
    db = session.db
    candidates = []
    seen_eas = set()

    # From classified functions in formula-heavy systems
    math_systems = [
        "combat", "rating", "experience", "movement", "scaling",
        "stat", "damage", "healing", "spell",
    ]
    for sys in math_systems:
        rows = db.fetchall(
            "SELECT ea, name FROM functions WHERE system = ?", (sys,)
        )
        for row in rows:
            ea = row["ea"]
            if ea not in seen_eas:
                candidates.append((ea, row["name"] or ea_str(ea)))
                seen_eas.add(ea)

    # Also include ALL handler functions (they often contain inline formulas)
    rows = db.fetchall(
        "SELECT handler_ea, tc_name FROM opcodes WHERE handler_ea IS NOT NULL"
    )
    for row in rows:
        ea = row["handler_ea"]
        if ea not in seen_eas:
            candidates.append((ea, row["tc_name"] or ea_str(ea)))
            seen_eas.add(ea)

    # Also scan named game functions
    rows = db.fetchall(
        "SELECT ea, name FROM functions WHERE name IS NOT NULL AND name != '' "
        "AND system IS NOT NULL LIMIT 5000"
    )
    for row in rows:
        ea = row["ea"]
        if ea not in seen_eas:
            candidates.append((ea, row["name"]))
            seen_eas.add(ea)

    msg_info(f"Collected {len(candidates)} math formula candidate functions")
    return candidates


def _collect_all_classified_funcs(session):
    """Collect all classified functions for serialization and protocol scanning."""
    db = session.db
    funcs = []
    seen = set()

    # All handler functions
    rows = db.fetchall(
        "SELECT handler_ea, tc_name FROM opcodes WHERE handler_ea IS NOT NULL"
    )
    for row in rows:
        ea = row["handler_ea"]
        if ea not in seen:
            funcs.append((ea, row["tc_name"] or ea_str(ea)))
            seen.add(ea)

    # All named/classified functions
    rows = db.fetchall(
        "SELECT ea, name FROM functions WHERE name IS NOT NULL AND name != '' "
        "ORDER BY ea LIMIT 10000"
    )
    for row in rows:
        ea = row["ea"]
        if ea not in seen:
            funcs.append((ea, row["name"]))
            seen.add(ea)

    # JAM serializer/deserializer functions
    rows = db.fetchall(
        "SELECT serializer_ea, deserializer_ea, name FROM jam_types "
        "WHERE serializer_ea IS NOT NULL OR deserializer_ea IS NOT NULL"
    )
    for row in rows:
        for col in ("serializer_ea", "deserializer_ea"):
            ea = row[col]
            if ea and ea not in seen:
                funcs.append((ea, f"JAM_{row['name']}_{col.split('_')[0]}"))
                seen.add(ea)

    msg_info(f"Collected {len(funcs)} total classified functions")
    return funcs


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def detect_shared_code(session):
    """Detect code in the WoW client binary that must be replicated on the
    server side (TrinityCore).

    Runs all six detection phases:
      1. Validation logic in CMSG senders
      2. Mathematical formulas in game logic
      3. Serialization read/write symmetry
      4. Enum value consistency (send vs recv)
      5. Protocol constants (limits, sizes)
      6. Shared utility functions (callees of both senders and handlers)

    Results stored in session.db.kv_set("shared_code", {...}).

    Returns:
        int: Total number of shared code items detected.
    """
    db = session.db
    t_start = time.time()

    msg("=" * 72)
    msg("Shared Code Detection — Finding client/server contract points")
    msg("=" * 72)

    # ── Collect candidate function sets ────────────────────────────────
    cmsg_senders = _collect_cmsg_senders(session)
    smsg_handlers = _collect_smsg_handlers(session)
    math_candidates = _collect_math_candidates(session)
    all_funcs = _collect_all_classified_funcs(session)

    if not cmsg_senders and not smsg_handlers:
        msg_warn("No CMSG senders or SMSG handlers found in database. "
                 "Run opcode_dispatcher and jam_recovery first.")
        return 0

    # ── Phase 1: Validation detection ─────────────────────────────────
    validations = _detect_validations(session, cmsg_senders)

    # ── Phase 2: Formula extraction ───────────────────────────────────
    formulas = _detect_formulas(session, math_candidates)

    # ── Phase 3: Serialization symmetry ───────────────────────────────
    serial_pairs = _detect_serialization_pairs(session, all_funcs)

    # ── Phase 4: Enum / constant consistency ──────────────────────────
    shared_consts = _detect_shared_constants(session, cmsg_senders, smsg_handlers)

    # ── Phase 5: Protocol constants ───────────────────────────────────
    proto_consts = _detect_protocol_constants(session, all_funcs)

    # ── Phase 6: Shared utilities ─────────────────────────────────────
    sender_eas = [ea for ea, _ in cmsg_senders]
    handler_eas = [ea for ea, _ in smsg_handlers]
    shared_utils = _detect_shared_utilities(session, sender_eas, handler_eas)

    # ── Phase 7: Classification & scoring ─────────────────────────────
    total_items, critical_items = _classify_and_score(
        validations, formulas, serial_pairs,
        shared_consts, proto_consts, shared_utils
    )

    # ── Store results ─────────────────────────────────────────────────
    elapsed = time.time() - t_start

    # Serialise ea values as hex strings for JSON compatibility
    def _ea_safe(obj):
        """Convert any integer ea fields to hex strings for JSON."""
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if k.endswith("_ea") and isinstance(v, int):
                    result[k] = ea_str(v)
                elif isinstance(v, (dict, list)):
                    result[k] = _ea_safe(v)
                else:
                    result[k] = v
            return result
        elif isinstance(obj, list):
            return [_ea_safe(item) for item in obj]
        return obj

    results = {
        "validations": _ea_safe(validations),
        "formulas": _ea_safe(formulas),
        "serialization_pairs": _ea_safe(serial_pairs),
        "shared_constants": _ea_safe(shared_consts),
        "protocol_constants": _ea_safe(proto_consts),
        "shared_utilities": _ea_safe(shared_utils),
        "total_shared_items": total_items,
        "critical_items": critical_items,
        "summary": {
            "validation_count": len(validations),
            "formula_count": len(formulas),
            "serial_pair_count": len(serial_pairs),
            "shared_constant_count": len(shared_consts),
            "protocol_constant_count": len(proto_consts),
            "shared_utility_count": len(shared_utils),
            "cmsg_senders_scanned": len(cmsg_senders),
            "smsg_handlers_scanned": len(smsg_handlers),
            "total_funcs_scanned": len(all_funcs),
        },
        "elapsed_seconds": round(elapsed, 2),
        "timestamp": time.time(),
    }

    db.kv_set("shared_code", results)
    db.commit()

    # ── Report ────────────────────────────────────────────────────────
    msg("")
    msg("=" * 72)
    msg("Shared Code Detection Results")
    msg("=" * 72)
    msg(f"  Validations:           {len(validations):>6}")
    msg(f"  Mathematical formulas: {len(formulas):>6}")
    msg(f"  Serialization pairs:   {len(serial_pairs):>6}")
    msg(f"    (asymmetric):        {sum(1 for p in serial_pairs if not p.get('is_symmetric')):>6}")
    msg(f"  Shared constants:      {len(shared_consts):>6}")
    msg(f"  Protocol constants:    {len(proto_consts):>6}")
    msg(f"  Shared utilities:      {len(shared_utils):>6}")
    msg(f"  ---")
    msg(f"  Total shared items:    {total_items:>6}")
    msg(f"  Critical items:        {critical_items:>6}")
    msg(f"  Elapsed:               {elapsed:>6.1f}s")
    msg("=" * 72)

    # Store per-phase results for drill-down
    if validations:
        db.kv_set("shared_code:validations", _ea_safe(validations))
    if formulas:
        db.kv_set("shared_code:formulas", _ea_safe(formulas))
    if serial_pairs:
        db.kv_set("shared_code:serialization_pairs", _ea_safe(serial_pairs))
    if shared_consts:
        db.kv_set("shared_code:shared_constants", _ea_safe(shared_consts))
    if proto_consts:
        db.kv_set("shared_code:protocol_constants", _ea_safe(proto_consts))
    if shared_utils:
        db.kv_set("shared_code:shared_utilities", _ea_safe(shared_utils))
    db.commit()

    return total_items


# ---------------------------------------------------------------------------
# Report accessor
# ---------------------------------------------------------------------------

def get_shared_code_report(session):
    """Retrieve stored shared code detection results.

    Returns:
        dict or None: The full results dict, or None if not yet run.
    """
    if not session.db:
        msg_error("No database loaded")
        return None

    data = session.db.kv_get("shared_code")
    if data is None:
        msg_warn("No shared code results found. Run detect_shared_code() first.")
        return None

    return data
