"""
Object Layout Recovery
Recovers C++ class layouts from Hex-Rays decompiled pseudocode by analyzing
member access patterns across thousands of functions.

Every `*(type*)(this + 0x1A8)` in decompiled output is a class member access.
By aggregating these across all handler functions and vtable-associated methods,
we reconstruct complete class field maps: offset, size, type, name, and usage.

Detects inheritance by comparing field overlap between classes, identifies
arrays via consecutive same-type fields at regular intervals, and maps vtable
slots for virtual function dispatch.
"""

import json
import re
from collections import defaultdict

import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# IDA type name -> canonical type mapping
# ---------------------------------------------------------------------------
_IDA_TYPE_MAP = {
    "_DWORD":   ("uint32",  4),
    "_QWORD":   ("uint64",  8),
    "_WORD":    ("uint16",  2),
    "_BYTE":    ("uint8",   1),
    "_OWORD":   ("uint128", 16),
    "__int64":  ("int64",   8),
    "__int32":  ("int32",   4),
    "__int16":  ("int16",   2),
    "__int8":   ("int8",    1),
    "int64":    ("int64",   8),
    "int32":    ("int32",   4),
    "int16":    ("int16",   2),
    "int8":     ("int8",    1),
    "uint64":   ("uint64",  8),
    "uint32":   ("uint32",  4),
    "uint16":   ("uint16",  2),
    "uint8":    ("uint8",   1),
    "unsigned __int64":  ("uint64",  8),
    "unsigned __int32":  ("uint32",  4),
    "unsigned __int16":  ("uint16",  2),
    "unsigned __int8":   ("uint8",   1),
    "unsigned int":      ("uint32",  4),
    "unsigned short":    ("uint16",  2),
    "unsigned char":     ("uint8",   1),
    "int":      ("int32",   4),
    "short":    ("int16",   2),
    "char":     ("int8",    1),
    "float":    ("float",   4),
    "double":   ("double",  8),
    "bool":     ("bool",    1),
    "BOOL":     ("int32",   4),
    "void":     ("pointer", 8),   # void* on x64
    "GUID":     ("uint128", 16),
}

# Known TC class offset signatures for identification
# Maps frozenset of characteristic offsets to class name
_KNOWN_CLASS_SIGNATURES = {
    # WorldSession: typically has accountId, player pointer, security level
    # Player: has known Unit offsets plus player-specific
    # These are heuristic — populated dynamically from vtable data
}

# Handler parameter heuristics: first param of CMSG handlers is WorldSession*
_CMSG_PARAM_TYPES = {
    "a1": "WorldSession*",
    "this": "WorldSession*",
}


# ---------------------------------------------------------------------------
# Regex patterns for Hex-Rays pseudocode member access extraction
# ---------------------------------------------------------------------------

# Pattern 1: *(type *)(base + 0xOFFSET)
# Matches: *(uint32 *)(a1 + 0x1A8), *(_DWORD *)(this + 0x48), *(float *)(a1 + 0x2C)
# Also handles multi-word types: *(unsigned __int64 *)(a1 + 0x10)
_RE_TYPED_DEREF = re.compile(
    r'\*\s*\(\s*'                                    # *( with optional spaces
    r'([\w ]+?)'                                     # type name (capture group 1)
    r'\s*\*\s*\)\s*\(\s*'                            # *)(
    r'(\w+)'                                         # base pointer name (capture group 2)
    r'\s*\+\s*'                                      # +
    r'(0x[0-9A-Fa-f]+|\d+)'                          # offset (capture group 3)
    r'\s*\)'                                          # closing )
)

# Pattern 2: *(base + offset) — pointer deref without explicit cast
_RE_UNTYPED_DEREF = re.compile(
    r'(?<!\w)\*\s*\(\s*'                             # *( but not part of larger token
    r'(\w+)'                                         # base pointer (group 1)
    r'\s*\+\s*'                                      # +
    r'(0x[0-9A-Fa-f]+|\d+)'                          # offset (group 2)
    r'\s*\)'                                          # )
)

# Pattern 3: base[offset] — array-style access
_RE_ARRAY_ACCESS = re.compile(
    r'(\w+)'                                         # base pointer (group 1)
    r'\s*\[\s*'                                      # [
    r'(0x[0-9A-Fa-f]+|\d+)'                          # index (group 2)
    r'\s*\]'                                          # ]
)

# Pattern 4: LOBYTE/HIBYTE/LOWORD/HIWORD/LOBYTE extraction macros
_RE_BYTE_EXTRACT = re.compile(
    r'(LOBYTE|HIBYTE|LOWORD|HIWORD|BYTE\d|WORD\d)'  # macro name (group 1)
    r'\s*\(\s*\*?\s*\(?\s*'                          # (  with optional * and (
    r'(?:[\w ]+\s*\*\s*\))?\s*\(?\s*'                # optional type cast
    r'(\w+)'                                         # base pointer (group 2)
    r'\s*\+\s*'                                      # +
    r'(0x[0-9A-Fa-f]+|\d+)'                          # offset (group 3)
    r'\s*\)?\s*\)'                                   # closing parens
)

# Pattern 5: vtable call — (*(void (__fastcall **)(...))(*(base) + 0xSLOT))(base, ...)
# or simpler: (*(*base + 0xSLOT))(base, ...)
_RE_VTABLE_CALL = re.compile(
    r'\(\s*\*\s*\(\s*'                               # (*(
    r'(?:void\s*\(\s*__fastcall\s*\*\*\s*\)'         # void (__fastcall **)
    r'(?:\s*\([^)]*\))?'                             # optional parameter list
    r'\s*\)\s*\(\s*)?'                               # ) (
    r'\*?\s*\(?\s*'                                  # optional * and (
    r'(\w+)'                                         # base pointer (group 1)
    r'\s*\)?\s*\+\s*'                                # ) +
    r'(0x[0-9A-Fa-f]+|\d+)'                          # vtable offset / slot (group 2)
    r'\s*\)\s*\)\s*\(\s*'                            # )) (
    r'(\w+)'                                         # first arg = this (group 3)
)

# Pattern 5b: Simpler vtable dispatch: (*(qword *)(*(qword *)base + OFFSET))(base, ...)
_RE_VTABLE_CALL_SIMPLE = re.compile(
    r'\(\s*\*\s*\('                                  # (*(
    r'[^)]*\*\s*\)\s*\('                             # type*)(
    r'\s*\*\s*\('                                    # *(
    r'[^)]*\*\s*\)\s*'                               # type*)
    r'(\w+)'                                         # base pointer (group 1)
    r'\s*\+?\s*'                                     # optional +
    r'(0x[0-9A-Fa-f]+|\d+)?'                         # optional vtable ptr offset (group 2)
    r'\s*\)\s*\+\s*'                                 # ) +
    r'(0x[0-9A-Fa-f]+|\d+)'                          # function slot offset (group 3)
    r'\s*\)\s*\)\s*\(\s*'                            # ))(
    r'(\w+)'                                         # first arg = this (group 4)
)

# Pattern 6: base->field_name — struct member access (Hex-Rays applied struct)
_RE_STRUCT_MEMBER = re.compile(
    r'(\w+)'                                         # base pointer (group 1)
    r'\s*->\s*'                                      # ->
    r'(\w+)'                                         # field name (group 2)
)

# Pattern for detecting writes: lhs = rhs (assignment to a member)
_RE_ASSIGNMENT_LHS = re.compile(
    r'\*\s*\(\s*[\w ]+?\s*\*\s*\)\s*\(\s*\w+\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\)\s*='
)


def _parse_offset(offset_str):
    """Parse an offset string (hex or decimal) into an integer."""
    if offset_str is None:
        return 0
    try:
        return int(offset_str, 0)
    except (ValueError, TypeError):
        return 0


def _resolve_type(type_str):
    """Resolve a Hex-Rays type string to (canonical_name, size_bytes)."""
    type_str = type_str.strip()
    if type_str in _IDA_TYPE_MAP:
        return _IDA_TYPE_MAP[type_str]

    # Check for pointer types
    if type_str.endswith("*") or type_str == "void *":
        return ("pointer", 8)

    # Check case-insensitive
    for key, val in _IDA_TYPE_MAP.items():
        if key.lower() == type_str.lower():
            return val

    # Unknown type — guess from common patterns
    if "64" in type_str:
        return (type_str, 8)
    if "16" in type_str or "short" in type_str.lower():
        return (type_str, 2)
    if "8" in type_str or "byte" in type_str.lower() or "char" in type_str.lower():
        return (type_str, 1)

    # Default: assume 4-byte (most common in game code)
    return (type_str, 4)


def _determine_access_type(line, match_start, match_end):
    """Determine if a member access is a read, write, or both.

    Checks if the matched access pattern appears on the left side of an
    assignment operator.
    """
    # Check the text before the match on this line for assignment context
    prefix = line[:match_start].rstrip()

    # Check if there's an '=' after the match (this is being assigned TO)
    suffix = line[match_end:].lstrip()
    if suffix.startswith("=") and not suffix.startswith("=="):
        return "write"

    # Check if part of an assignment target (the whole expression is LHS)
    if _RE_ASSIGNMENT_LHS.search(line):
        # Check if our match IS the assignment target
        lhs_match = _RE_ASSIGNMENT_LHS.search(line)
        if lhs_match and lhs_match.start() <= match_start and lhs_match.end() > match_start:
            return "write"

    return "read"


def _is_base_pointer(name, pseudocode_lines):
    """Check if a variable name is likely a base object pointer (parameter).

    We look for: function parameters (a1, a2, ..., this), or variables assigned
    from parameters.
    """
    if name in ("this", "a1", "a2", "a3", "a4", "a5", "a6"):
        return True
    if name.startswith("v") and name[1:].isdigit():
        # Local variable — check if it's assigned from a parameter
        # e.g., v5 = a1;  or  v5 = *(a1 + 8);
        for line in pseudocode_lines[:30]:  # check early lines only
            if re.search(rf'{name}\s*=\s*(?:a[1-6]|this)\s*;', line):
                return True
            # Also: v5 = *(_QWORD *)(a1 + 0x...); — object fetched from param
            if re.search(rf'{name}\s*=\s*\*\s*\(.*\)\s*\(\s*(?:a[1-6]|this)\s*\+', line):
                return True
    return False


# ---------------------------------------------------------------------------
# Core extraction: parse one function's pseudocode
# ---------------------------------------------------------------------------

def _extract_member_accesses(pseudocode, func_ea, func_name):
    """Parse member access patterns from one function's decompiled pseudocode.

    Detects all Hex-Rays member access patterns:
      - *(type *)(base + offset)        — typed dereference
      - *(base + offset)                — untyped dereference
      - base[index]                     — array-style
      - LOBYTE/HIBYTE/etc macros        — byte extraction
      - vtable dispatch calls           — virtual function calls
      - base->field_name                — struct member (if typed)

    Returns a list of access records.
    """
    accesses = []
    lines = pseudocode.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # --- Pattern 1: Typed dereference *(type*)(base + offset) ---
        for m in _RE_TYPED_DEREF.finditer(line):
            type_str = m.group(1).strip()
            base = m.group(2)
            offset = _parse_offset(m.group(3))

            if not _is_base_pointer(base, lines):
                continue

            canonical_type, size = _resolve_type(type_str)
            access_type = _determine_access_type(line, m.start(), m.end())

            accesses.append({
                "base_param": base,
                "offset": offset,
                "access_type": access_type,
                "field_type": canonical_type,
                "field_size": size,
                "context": stripped[:120],
                "function": func_name,
                "function_ea": func_ea,
                "line_number": line_num,
            })

        # --- Pattern 4: Byte extraction macros (before untyped to avoid overlap) ---
        for m in _RE_BYTE_EXTRACT.finditer(line):
            macro = m.group(1)
            base = m.group(2)
            offset = _parse_offset(m.group(3))

            if not _is_base_pointer(base, lines):
                continue

            # Macro determines the sub-access size and the underlying field size
            if macro in ("LOBYTE", "HIBYTE") or macro.startswith("BYTE"):
                sub_type = "uint8"
                sub_size = 1
            elif macro in ("LOWORD", "HIWORD") or macro.startswith("WORD"):
                sub_type = "uint16"
                sub_size = 2
            else:
                sub_type = "uint8"
                sub_size = 1

            access_type = _determine_access_type(line, m.start(), m.end())

            accesses.append({
                "base_param": base,
                "offset": offset,
                "access_type": access_type,
                "field_type": sub_type,
                "field_size": sub_size,
                "context": stripped[:120],
                "function": func_name,
                "function_ea": func_ea,
                "line_number": line_num,
                "byte_extract_macro": macro,
            })

        # --- Pattern 5: Vtable call dispatch ---
        for m in _RE_VTABLE_CALL.finditer(line):
            base = m.group(1)
            slot_offset = _parse_offset(m.group(2))
            this_arg = m.group(3)

            if not _is_base_pointer(base, lines):
                continue

            # The vtable pointer is at offset 0 of the object
            # The function slot is at slot_offset within the vtable
            accesses.append({
                "base_param": base,
                "offset": 0,
                "access_type": "call",
                "field_type": "vtable_ptr",
                "field_size": 8,
                "context": stripped[:120],
                "function": func_name,
                "function_ea": func_ea,
                "line_number": line_num,
                "vtable_slot_offset": slot_offset,
            })

        for m in _RE_VTABLE_CALL_SIMPLE.finditer(line):
            base = m.group(1)
            vtable_ptr_offset = _parse_offset(m.group(2))
            slot_offset = _parse_offset(m.group(3))
            this_arg = m.group(4)

            if not _is_base_pointer(base, lines):
                continue

            accesses.append({
                "base_param": base,
                "offset": vtable_ptr_offset,
                "access_type": "call",
                "field_type": "vtable_ptr",
                "field_size": 8,
                "context": stripped[:120],
                "function": func_name,
                "function_ea": func_ea,
                "line_number": line_num,
                "vtable_slot_offset": slot_offset,
            })

        # --- Pattern 6: Struct member access base->field ---
        for m in _RE_STRUCT_MEMBER.finditer(line):
            base = m.group(1)
            field_name = m.group(2)

            if not _is_base_pointer(base, lines):
                continue

            # Skip common non-object dereferences
            if field_name in ("next", "prev", "size", "data", "begin", "end",
                              "first", "second", "m_size", "m_data"):
                continue

            access_type = _determine_access_type(line, m.start(), m.end())

            accesses.append({
                "base_param": base,
                "offset": -1,  # unknown offset for named fields
                "access_type": access_type,
                "field_type": "unknown",
                "field_size": 0,
                "context": stripped[:120],
                "function": func_name,
                "function_ea": func_ea,
                "line_number": line_num,
                "named_field": field_name,
            })

        # --- Pattern 2: Untyped dereference *(base + offset) ---
        # Only match if not already caught by typed pattern
        for m in _RE_UNTYPED_DEREF.finditer(line):
            base = m.group(1)
            offset = _parse_offset(m.group(2))

            if not _is_base_pointer(base, lines):
                continue

            # Check this wasn't already captured by typed dereference
            already_captured = False
            for existing in accesses:
                if (existing["base_param"] == base
                        and existing["offset"] == offset
                        and existing["function_ea"] == func_ea
                        and existing["line_number"] == line_num):
                    already_captured = True
                    break
            if already_captured:
                continue

            access_type = _determine_access_type(line, m.start(), m.end())

            # Infer type from context: if compared to int, likely uint32
            inferred_type = "pointer"
            inferred_size = 8
            # If compared or used with small constants, likely uint32
            if re.search(rf'\*\s*\(\s*{re.escape(base)}\s*\+\s*{re.escape(m.group(2))}\s*\)'
                         r'\s*[<>=!]+\s*\d', line):
                inferred_type = "uint32"
                inferred_size = 4

            accesses.append({
                "base_param": base,
                "offset": offset,
                "access_type": access_type,
                "field_type": inferred_type,
                "field_size": inferred_size,
                "context": stripped[:120],
                "function": func_name,
                "function_ea": func_ea,
                "line_number": line_num,
            })

        # --- Pattern 3: Array-style access base[offset] ---
        for m in _RE_ARRAY_ACCESS.finditer(line):
            base = m.group(1)
            index = _parse_offset(m.group(2))

            if not _is_base_pointer(base, lines):
                continue

            # Array index is element index, not byte offset
            # For pointer-sized elements (most common in decompiler output), multiply by 8
            byte_offset = index * 8

            # Check this wasn't already captured
            already_captured = False
            for existing in accesses:
                if (existing["base_param"] == base
                        and existing["offset"] == byte_offset
                        and existing["function_ea"] == func_ea
                        and existing["line_number"] == line_num):
                    already_captured = True
                    break
            if already_captured:
                continue

            access_type = _determine_access_type(line, m.start(), m.end())

            accesses.append({
                "base_param": base,
                "offset": byte_offset,
                "access_type": access_type,
                "field_type": "pointer",
                "field_size": 8,
                "context": stripped[:120],
                "function": func_name,
                "function_ea": func_ea,
                "line_number": line_num,
                "array_index": index,
            })

    return accesses


# ---------------------------------------------------------------------------
# Class identification
# ---------------------------------------------------------------------------

def _identify_classes(all_accesses, db):
    """Group member accesses into distinct class buckets.

    Uses:
      - Vtable associations from the database
      - Function parameter types (Hex-Rays typing)
      - CMSG handler first-param heuristic (a1 = WorldSession*)
      - Offset pattern matching against known TC classes

    Returns {class_key: [accesses]} where class_key is an identifier string.
    """
    classes = defaultdict(list)

    # Build vtable EA -> class name mapping from DB
    vtable_class_map = {}
    try:
        vtables = db.fetchall("SELECT ea, class_name FROM vtables WHERE class_name IS NOT NULL")
        for vt in vtables:
            vtable_class_map[vt["ea"]] = vt["class_name"]
    except Exception:
        pass

    # Build handler EA -> opcode info mapping
    handler_info = {}
    try:
        opcodes = db.fetchall("SELECT handler_ea, tc_name, direction FROM opcodes "
                              "WHERE handler_ea IS NOT NULL")
        for op in opcodes:
            handler_info[op["handler_ea"]] = {
                "tc_name": op["tc_name"],
                "direction": op["direction"],
            }
    except Exception:
        pass

    # Build function EA -> vtable class mapping (which vtable methods reference which class)
    func_to_vtable_class = {}
    try:
        vt_entries = db.fetchall(
            "SELECT ve.func_ea, v.class_name FROM vtable_entries ve "
            "JOIN vtables v ON ve.vtable_ea = v.ea "
            "WHERE v.class_name IS NOT NULL"
        )
        for entry in vt_entries:
            func_to_vtable_class[entry["func_ea"]] = entry["class_name"]
    except Exception:
        pass

    for access in all_accesses:
        func_ea = access["function_ea"]
        base_param = access["base_param"]

        class_key = None

        # Strategy 1: If function is a vtable entry, the 'this' param is that class
        if base_param in ("this", "a1") and func_ea in func_to_vtable_class:
            class_key = func_to_vtable_class[func_ea]

        # Strategy 2: If function is a CMSG handler, a1 is typically WorldSession*
        if class_key is None and func_ea in handler_info:
            info = handler_info[func_ea]
            if info["direction"] == "CMSG" and base_param in ("a1", "this"):
                class_key = "WorldSession"

        # Strategy 3: Check if the function name hints at a class
        if class_key is None:
            func_name = access["function"]
            # Patterns like ClassName::MethodName or ClassName_MethodName
            class_match = re.match(r'([A-Z]\w+?)(?:::|\s*_\s*)(\w+)', func_name)
            if class_match:
                potential_class = class_match.group(1)
                if base_param in ("this", "a1"):
                    class_key = potential_class

        # Strategy 4: Fallback — group by base_param + function cluster
        if class_key is None:
            # Group by the base parameter within function groups
            class_key = f"Unknown_{base_param}_{func_ea:X}"

        classes[class_key].append(access)

    return dict(classes)


# ---------------------------------------------------------------------------
# Field merging
# ---------------------------------------------------------------------------

def _merge_field_info(accesses_by_class):
    """Merge per-access observations into unified class layouts.

    For each class:
      - Group accesses by offset
      - Resolve type conflicts (majority vote, prefer more specific types)
      - Detect arrays (consecutive same-type fields at regular intervals)
      - Compute total object size

    Returns {class_key: layout_dict}
    """
    layouts = {}

    for class_key, accesses in accesses_by_class.items():
        # Group by offset
        by_offset = defaultdict(list)
        all_functions = set()

        for acc in accesses:
            offset = acc["offset"]
            if offset < 0:
                continue  # skip named-but-unknown-offset fields
            by_offset[offset].append(acc)
            all_functions.add(acc["function"])

        if not by_offset:
            continue

        # Build field list
        fields = []
        for offset in sorted(by_offset.keys()):
            offset_accesses = by_offset[offset]

            # Resolve type: majority vote with priority for more specific types
            type_votes = defaultdict(int)
            size_votes = defaultdict(int)
            accessors = set()
            read_count = 0
            write_count = 0
            call_count = 0
            contexts = []
            vtable_slots = set()
            has_named_field = None

            for acc in offset_accesses:
                ftype = acc["field_type"]
                fsize = acc["field_size"]
                type_votes[ftype] += 1
                size_votes[fsize] += 1
                accessors.add(acc["function"])
                if acc["access_type"] == "read":
                    read_count += 1
                elif acc["access_type"] == "write":
                    write_count += 1
                elif acc["access_type"] == "call":
                    call_count += 1
                if len(contexts) < 5:
                    contexts.append(acc["context"])
                if "vtable_slot_offset" in acc:
                    vtable_slots.add(acc["vtable_slot_offset"])
                if "named_field" in acc:
                    has_named_field = acc["named_field"]

            # Select best type: prefer specific over generic
            resolved_type = _resolve_type_conflict(type_votes)
            resolved_size = _resolve_size_conflict(size_votes, resolved_type)

            # Infer field name
            field_name = _infer_field_name(
                offset, resolved_type, accessors, contexts,
                has_named_field, class_key
            )

            field = {
                "offset": offset,
                "type": resolved_type,
                "size": resolved_size,
                "name": field_name,
                "access_count": len(offset_accesses),
                "read_count": read_count,
                "write_count": write_count,
                "call_count": call_count,
                "accessors": sorted(accessors)[:20],  # cap at 20 for storage
                "contexts": contexts[:5],
            }

            if vtable_slots:
                field["vtable_slots"] = sorted(vtable_slots)
                field["has_vtable"] = True

            if has_named_field:
                field["hex_rays_name"] = has_named_field

            fields.append(field)

        # Detect arrays within the field list
        fields = _detect_arrays(fields)

        # Compute total object size
        if fields:
            last_field = max(fields, key=lambda f: f["offset"])
            total_size = last_field["offset"] + last_field["size"]
            # Align to 8 bytes
            total_size = (total_size + 7) & ~7
        else:
            total_size = 0

        # Check for enum associations (from state_machines in kv_store)
        _annotate_enum_fields(fields, class_key)

        layouts[class_key] = {
            "key": class_key,
            "class_name": class_key,
            "total_size": total_size,
            "vtable_ea": None,
            "field_count": len(fields),
            "fields": fields,
            "inheritance": [],
            "source_function_count": len(all_functions),
        }

    return layouts


def _resolve_type_conflict(type_votes):
    """Resolve conflicting type observations for a field.

    Priority:
      1. Named/specific types (float, double, uint128) always win
      2. Signed vs unsigned: check comparison context
      3. Most votes wins among same-priority types
      4. Specific > generic (uint32 > pointer > unknown)
    """
    if not type_votes:
        return "unknown"

    # Priority classes
    HIGH_PRIORITY = {"float", "double", "uint128", "vtable_ptr", "bool"}
    MED_PRIORITY = {"uint64", "int64", "uint32", "int32", "uint16", "int16", "uint8", "int8"}
    LOW_PRIORITY = {"pointer", "unknown"}

    # Check for high-priority type
    for t in HIGH_PRIORITY:
        if t in type_votes:
            return t

    # Among medium priority, pick the most voted
    med_candidates = {t: v for t, v in type_votes.items() if t in MED_PRIORITY}
    if med_candidates:
        return max(med_candidates, key=med_candidates.get)

    # Fallback
    return max(type_votes, key=type_votes.get)


def _resolve_size_conflict(size_votes, resolved_type):
    """Resolve conflicting size observations."""
    # If we know the type, use its canonical size
    for _, (canonical, size) in _IDA_TYPE_MAP.items():
        if canonical == resolved_type:
            return size

    if not size_votes:
        return 4  # default

    # Pick the most common size
    return max(size_votes, key=size_votes.get)


def _infer_field_name(offset, field_type, accessors, contexts, named_field, class_key):
    """Infer a meaningful field name from context.

    Uses:
      - Hex-Rays applied name if available
      - Context string analysis (comparison values, function names)
      - Type-based defaults
    """
    if named_field:
        return named_field

    # Try to extract from accessor function names
    # e.g., "HandleHousingInit" accessing offset 0x1A8 → "housingState" or "field_1A8"
    for accessor in accessors:
        # Look for Get/Set/Is patterns
        m = re.match(r'(?:Get|Set|Is|Has|Update|Handle)(\w+)', accessor)
        if m:
            candidate = m.group(1)
            # camelCase the candidate
            if len(candidate) > 2:
                return candidate[0].lower() + candidate[1:]

    # Check contexts for hints
    for ctx in contexts:
        # If compared against string-like values, might be a string field
        if '"' in ctx:
            pass  # no good inference from string comparison alone

        # If used in switch with many cases, likely a state/enum
        if "switch" in ctx:
            return f"state_{offset:X}"

        # If compared against boolean-like values (0, 1)
        if field_type == "bool" or (field_type in ("uint8", "int8")
                                     and re.search(r'[!=]=\s*[01]\s*[;)]', ctx)):
            return f"flag_{offset:X}"

    # Type-based naming
    if field_type == "vtable_ptr":
        return "vtable"
    if field_type == "uint128":
        return f"guid_{offset:X}"
    if field_type == "float":
        return f"float_{offset:X}"

    return f"field_{offset:X}"


def _detect_arrays(fields):
    """Detect array patterns in field list.

    If consecutive fields have the same type and are at regular intervals,
    mark them as array elements.
    """
    if len(fields) < 3:
        return fields

    # Sort by offset
    fields.sort(key=lambda f: f["offset"])

    i = 0
    while i < len(fields) - 2:
        f1 = fields[i]
        f2 = fields[i + 1]
        f3 = fields[i + 2]

        # Check for regular spacing with same type
        if (f1["type"] == f2["type"] == f3["type"]
                and f1["size"] == f2["size"] == f3["size"]
                and f1["size"] > 0):
            stride = f2["offset"] - f1["offset"]
            if stride == f1["size"] and f3["offset"] - f2["offset"] == stride:
                # Found start of an array — count how far it extends
                array_len = 3
                j = i + 3
                while j < len(fields):
                    fn = fields[j]
                    expected_offset = f1["offset"] + array_len * stride
                    if (fn["type"] == f1["type"]
                            and fn["size"] == f1["size"]
                            and fn["offset"] == expected_offset):
                        array_len += 1
                        j += 1
                    else:
                        break

                # Mark the first field as an array
                fields[i]["is_array"] = True
                fields[i]["array_count"] = array_len
                fields[i]["array_stride"] = stride
                fields[i]["name"] = re.sub(r'_[0-9A-Fa-f]+$', '', f1["name"]) + "_array"

                # Remove the subsequent array element fields
                del fields[i + 1:i + array_len]
                # Adjust total size
                fields[i]["size"] = stride * array_len
                continue

        i += 1

    return fields


def _annotate_enum_fields(fields, class_key):
    """Mark fields that have associated enum recovery data."""
    for field in fields:
        # Check if any context mentions switch or multiple comparisons
        switch_count = sum(1 for ctx in field.get("contexts", []) if "switch" in ctx)
        compare_count = sum(1 for ctx in field.get("contexts", [])
                           if re.search(r'[!=]=\s*(?:0x[0-9A-Fa-f]+|\d+)', ctx or ""))

        if switch_count > 0 or compare_count >= 3:
            field["has_enum"] = True
            field["enum_key"] = f"{class_key}+0x{field['offset']:X}"
        else:
            field["has_enum"] = False
            field["enum_key"] = None


# ---------------------------------------------------------------------------
# Inheritance detection
# ---------------------------------------------------------------------------

def _detect_inheritance(layouts):
    """Detect inheritance relationships between recovered classes.

    Heuristics:
      1. If ClassB's fields at offsets 0..N exactly match ClassA's fields, B inherits A
      2. If ClassB has a vtable at offset 0 and ClassA has the same vtable, they share hierarchy
      3. Larger class likely inherits from smaller class (the smaller is the base)
    """
    class_keys = list(layouts.keys())

    # Build offset-type fingerprints for each class
    fingerprints = {}
    for key, layout in layouts.items():
        fp = []
        for field in layout["fields"]:
            fp.append((field["offset"], field["type"], field["size"]))
        fingerprints[key] = sorted(fp)

    # Compare all pairs
    for i, key_a in enumerate(class_keys):
        fp_a = set((o, t) for o, t, _ in fingerprints[key_a])
        size_a = layouts[key_a]["total_size"]

        for key_b in class_keys[i + 1:]:
            fp_b = set((o, t) for o, t, _ in fingerprints[key_b])
            size_b = layouts[key_b]["total_size"]

            if not fp_a or not fp_b:
                continue

            # Check if A's fields are a subset of B's (A is base, B is derived)
            if fp_a.issubset(fp_b) and size_a < size_b:
                overlap = len(fp_a)
                total_b = len(fp_b)
                # Require significant overlap (at least 60% of A's fields)
                if overlap >= max(3, len(fp_a) * 0.6):
                    if key_a not in layouts[key_b]["inheritance"]:
                        layouts[key_b]["inheritance"].append(key_a)

            elif fp_b.issubset(fp_a) and size_b < size_a:
                overlap = len(fp_b)
                if overlap >= max(3, len(fp_b) * 0.6):
                    if key_b not in layouts[key_a]["inheritance"]:
                        layouts[key_a]["inheritance"].append(key_b)

    # Also check vtable cross-references
    for key, layout in layouts.items():
        vtable_ea = layout.get("vtable_ea")
        if not vtable_ea:
            continue
        for other_key, other_layout in layouts.items():
            if other_key == key:
                continue
            if other_layout.get("vtable_ea") == vtable_ea:
                # Same vtable — likely same class or direct inheritance
                pass  # handled by field overlap above

    return layouts


# ---------------------------------------------------------------------------
# TC comparison
# ---------------------------------------------------------------------------

def compare_layouts_with_tc(session):
    """Compare recovered layouts against TrinityCore header files.

    Parses TC source headers for class member declarations and compares
    offsets, types, and sizes with our recovered layouts.

    Returns a comparison report dict.
    """
    db = session.db
    tc_source = session.cfg.tc_source_dir
    layouts = db.kv_get("object_layouts")

    if not layouts:
        msg_warn("No recovered layouts found. Run recover_object_layouts first.")
        return {"error": "no_layouts", "comparisons": []}

    if not tc_source:
        msg_warn("TrinityCore source directory not configured. "
                 "Set tc_source_dir in settings.")
        return {"error": "no_tc_source", "comparisons": []}

    import os
    comparisons = []

    # Parse TC headers for known classes
    tc_classes = _parse_tc_headers(tc_source)

    for layout in layouts:
        class_name = layout.get("class_name", "")
        if class_name.startswith("Unknown_"):
            continue

        tc_class = tc_classes.get(class_name)
        if not tc_class:
            comparisons.append({
                "class": class_name,
                "status": "not_found_in_tc",
                "recovered_fields": layout["field_count"],
            })
            continue

        # Compare fields
        matched = 0
        mismatched = []
        missing_in_binary = []
        extra_in_binary = []

        tc_offsets = {f["offset"]: f for f in tc_class.get("fields", []) if f.get("offset") is not None}
        bin_offsets = {f["offset"]: f for f in layout.get("fields", [])}

        for offset, tc_field in tc_offsets.items():
            if offset in bin_offsets:
                bin_field = bin_offsets[offset]
                # Compare types
                if _types_compatible(tc_field.get("type", ""), bin_field.get("type", "")):
                    matched += 1
                else:
                    mismatched.append({
                        "offset": offset,
                        "tc_type": tc_field.get("type"),
                        "bin_type": bin_field.get("type"),
                        "tc_name": tc_field.get("name"),
                        "bin_name": bin_field.get("name"),
                    })
            else:
                missing_in_binary.append({
                    "offset": offset,
                    "tc_type": tc_field.get("type"),
                    "tc_name": tc_field.get("name"),
                })

        for offset, bin_field in bin_offsets.items():
            if offset not in tc_offsets:
                extra_in_binary.append({
                    "offset": offset,
                    "bin_type": bin_field.get("type"),
                    "bin_name": bin_field.get("name"),
                })

        total_checked = matched + len(mismatched) + len(missing_in_binary)
        accuracy = (matched / total_checked * 100) if total_checked > 0 else 0.0

        comparisons.append({
            "class": class_name,
            "status": "compared",
            "matched": matched,
            "mismatched": mismatched,
            "missing_in_binary": missing_in_binary,
            "extra_in_binary": extra_in_binary,
            "accuracy": round(accuracy, 1),
        })

    report = {
        "total_classes_compared": len(comparisons),
        "comparisons": comparisons,
    }

    db.kv_set("object_layout_tc_comparison", report)
    db.commit()

    compared_count = sum(1 for c in comparisons if c["status"] == "compared")
    msg_info(f"Compared {compared_count} classes against TC source")
    for c in comparisons:
        if c["status"] == "compared":
            msg_info(f"  {c['class']}: {c['accuracy']}% match "
                     f"({c['matched']} matched, {len(c['mismatched'])} mismatched, "
                     f"{len(c['missing_in_binary'])} missing, "
                     f"{len(c['extra_in_binary'])} extra)")

    return report


def _parse_tc_headers(tc_source_dir):
    """Parse TrinityCore C++ headers for class member declarations.

    Looks for patterns like:
      uint32 _accountId;     // or with offset comment
      float  _speed[MAX_SPEED];
      ObjectGuid _guid;

    Returns {class_name: {"fields": [{offset, type, name, size}]}}
    """
    import os
    import glob

    classes = {}

    # Key header files to parse
    header_patterns = [
        "src/server/game/Entities/Player/Player.h",
        "src/server/game/Entities/Unit/Unit.h",
        "src/server/game/Entities/Object/Object.h",
        "src/server/game/Server/WorldSession.h",
        "src/server/game/Entities/Creature/Creature.h",
        "src/server/game/Entities/GameObject/GameObject.h",
        "src/server/game/Entities/Item/Item.h",
    ]

    for pattern in header_patterns:
        full_path = os.path.join(tc_source_dir, pattern)
        if not os.path.isfile(full_path):
            continue

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            continue

        # Extract class name from filename
        basename = os.path.splitext(os.path.basename(full_path))[0]

        # Find class declarations
        class_pattern = re.compile(
            r'class\s+(?:TC_\w+\s+)?(\w+)\s*(?::\s*(?:public|protected|private)\s+'
            r'(\w+)(?:\s*,\s*(?:public|protected|private)\s+\w+)*)?\s*\{',
            re.MULTILINE
        )

        for cm in class_pattern.finditer(content):
            class_name = cm.group(1)
            parent_class = cm.group(2)

            # Extract member declarations
            # Find the class body (approximate — look for next class or end of file)
            class_start = cm.end()
            brace_depth = 1
            pos = class_start
            while pos < len(content) and brace_depth > 0:
                if content[pos] == '{':
                    brace_depth += 1
                elif content[pos] == '}':
                    brace_depth -= 1
                pos += 1
            class_body = content[class_start:pos]

            fields = _extract_tc_members(class_body)
            classes[class_name] = {
                "fields": fields,
                "parent": parent_class,
                "header": full_path,
            }

    return classes


def _extract_tc_members(class_body):
    """Extract member variable declarations from a C++ class body."""
    fields = []

    # Match member declarations: type name; or type name = value;
    member_re = re.compile(
        r'^\s*'
        r'((?:const\s+)?(?:std::)?[\w:]+(?:<[^>]+>)?(?:\s*\*)?)'  # type
        r'\s+'
        r'(_?\w+)'                                                  # name
        r'(?:\s*\[([^\]]+)\])?'                                     # optional array
        r'(?:\s*=\s*[^;]+)?'                                        # optional initializer
        r'\s*;'                                                      # semicolon
        r'(?:\s*//\s*(?:offset\s*)?(?:0x)?([0-9A-Fa-f]+))?',        # optional offset comment
        re.MULTILINE
    )

    for m in member_re.finditer(class_body):
        type_str = m.group(1).strip()
        name = m.group(2)
        array_size = m.group(3)
        offset_comment = m.group(4)

        # Skip function declarations, typedefs, etc.
        if type_str in ("return", "if", "else", "while", "for", "switch",
                        "case", "break", "continue", "typedef", "using",
                        "static", "virtual", "friend", "class", "struct",
                        "enum", "template", "public", "private", "protected"):
            continue

        field = {
            "type": type_str,
            "name": name,
            "size": _estimate_tc_type_size(type_str),
        }

        if offset_comment:
            try:
                field["offset"] = int(offset_comment, 16)
            except ValueError:
                field["offset"] = None
        else:
            field["offset"] = None

        if array_size:
            field["array_size"] = array_size

        fields.append(field)

    return fields


def _estimate_tc_type_size(type_str):
    """Estimate the byte size of a TrinityCore C++ type."""
    type_str = type_str.strip().rstrip("*").strip()

    size_map = {
        "uint8": 1, "int8": 1, "bool": 1, "char": 1,
        "uint16": 2, "int16": 2, "short": 2,
        "uint32": 4, "int32": 4, "int": 4, "float": 4,
        "uint64": 8, "int64": 8, "double": 8, "time_t": 8,
        "ObjectGuid": 16, "GUID": 16,
    }

    for key, size in size_map.items():
        if type_str == key or type_str.endswith("::" + key):
            return size

    # Pointer types
    if "*" in type_str or type_str.endswith("Ptr"):
        return 8

    # std:: types
    if "string" in type_str:
        return 32  # std::string SSO
    if "vector" in type_str or "map" in type_str or "set" in type_str:
        return 24  # typical container

    return 8  # default for unknown types on x64


def _types_compatible(tc_type, bin_type):
    """Check if a TrinityCore type and binary-recovered type are compatible."""
    tc = tc_type.strip().lower()
    bn = bin_type.strip().lower()

    # Exact match
    if tc == bn:
        return True

    # Type equivalences
    equivalences = {
        ("uint32", "int32"), ("uint32", "_dword"), ("uint32", "unsigned int"),
        ("uint64", "int64"), ("uint64", "_qword"), ("uint64", "unsigned __int64"),
        ("uint16", "int16"), ("uint16", "_word"), ("uint16", "unsigned short"),
        ("uint8", "int8"), ("uint8", "_byte"), ("uint8", "unsigned char"), ("uint8", "bool"),
        ("objectguid", "uint128"), ("guid", "uint128"),
        ("float", "float"), ("double", "double"),
    }

    pair = (tc, bn)
    rev_pair = (bn, tc)
    for eq in equivalences:
        if pair == eq or rev_pair == eq:
            return True

    # Pointer types
    if ("*" in tc_type or "pointer" in tc) and ("pointer" in bn or bn == "uint64"):
        return True

    return False


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------

def generate_struct_header(session, class_key):
    """Generate a C++ struct/class definition for a recovered class layout.

    Output format:
      // Recovered from binary analysis (47 functions, 156 accesses)
      struct RecoveredWorldSession  // Total size: 0x2A0 (672 bytes)
      {
          /* 0x000 */ void* vtable;
          /* 0x008 */ uint64 field_8;        // Read in HandleLogin, HandleLogout
          ...
      };
    """
    db = session.db
    layouts = db.kv_get("object_layouts")
    if not layouts:
        return f"// No recovered layouts found\n"

    target = None
    for layout in layouts:
        if layout["key"] == class_key or layout["class_name"] == class_key:
            target = layout
            break

    if not target:
        return f"// Layout '{class_key}' not found\n"

    return _format_struct(target)


def _format_struct(layout):
    """Format a single layout as a C++ struct definition."""
    class_name = layout["class_name"]
    safe_name = re.sub(r'[^A-Za-z0-9_]', '_', class_name)
    total_size = layout["total_size"]
    func_count = layout["source_function_count"]
    field_count = layout["field_count"]
    total_accesses = sum(f.get("access_count", 0) for f in layout.get("fields", []))

    lines = []
    lines.append(f"// Recovered from binary analysis "
                 f"({func_count} functions, {total_accesses} accesses)")

    if layout.get("inheritance"):
        parents = ", ".join(layout["inheritance"])
        lines.append(f"// Inherits from: {parents}")

    lines.append(f"struct Recovered{safe_name}  "
                 f"// Total size: 0x{total_size:X} ({total_size} bytes)")
    lines.append("{")

    prev_offset_end = 0
    for field in sorted(layout.get("fields", []), key=lambda f: f["offset"]):
        offset = field["offset"]
        ftype = field["type"]
        fsize = field["size"]
        fname = field["name"]

        # Insert padding if there's a gap
        if offset > prev_offset_end:
            gap = offset - prev_offset_end
            lines.append(f"    /* 0x{prev_offset_end:03X} */ "
                         f"uint8 _padding_{prev_offset_end:X}[{gap}];")

        # Build the type string for C++
        cpp_type = _to_cpp_type(ftype, fsize)

        # Build comment with accessor info
        accessors = field.get("accessors", [])
        access_count = field.get("access_count", 0)
        read_count = field.get("read_count", 0)
        write_count = field.get("write_count", 0)

        comment_parts = []
        if read_count > 0 or write_count > 0:
            rw = []
            if read_count > 0:
                rw.append(f"R:{read_count}")
            if write_count > 0:
                rw.append(f"W:{write_count}")
            comment_parts.append("/".join(rw))

        if accessors:
            short_accessors = accessors[:3]
            comment_parts.append("in " + ", ".join(short_accessors))
            if len(accessors) > 3:
                comment_parts.append(f"+{len(accessors) - 3} more")

        if field.get("has_enum"):
            comment_parts.append("(enum)")

        if field.get("is_array"):
            arr_count = field.get("array_count", 0)
            arr_stride = field.get("array_stride", fsize)
            cpp_type_base = _to_cpp_type(ftype, arr_stride)
            line = (f"    /* 0x{offset:03X} */ "
                    f"{cpp_type_base} {fname}[{arr_count}];")
        elif field.get("has_vtable"):
            slots = field.get("vtable_slots", [])
            slot_str = ", ".join(f"0x{s:X}" for s in slots[:5])
            comment_parts.append(f"vtable slots: {slot_str}")
            line = f"    /* 0x{offset:03X} */ {cpp_type} {fname};"
        else:
            line = f"    /* 0x{offset:03X} */ {cpp_type} {fname};"

        if comment_parts:
            # Pad to align comments
            line = line.ljust(55)
            line += "// " + " | ".join(comment_parts)

        lines.append(line)
        prev_offset_end = offset + fsize

    lines.append("};")
    lines.append("")

    return "\n".join(lines)


def _to_cpp_type(type_name, size):
    """Convert a canonical type name to a C++ type string."""
    cpp_map = {
        "uint8": "uint8",
        "int8": "int8",
        "bool": "bool",
        "uint16": "uint16",
        "int16": "int16",
        "uint32": "uint32",
        "int32": "int32",
        "uint64": "uint64",
        "int64": "int64",
        "uint128": "ObjectGuid",
        "float": "float",
        "double": "double",
        "pointer": "void*",
        "vtable_ptr": "void*",
        "unknown": f"uint8[{size}]" if size > 0 else "uint8",
    }
    return cpp_map.get(type_name, type_name)


def apply_layouts_to_idb(session):
    """Apply recovered layouts as IDA struct types using __fixed/__at syntax.

    IDA 9.3+ supports __fixed(size) to specify exact struct size, and
    __at(offset) to pin fields at specific offsets — perfect for
    recovered class layouts where we know exact field positions.

    Falls back to standard struct definitions for older IDA versions.

    Returns:
        Number of struct types created or updated.
    """
    db = session.db
    layouts = db.kv_get("object_layouts")
    if not layouts:
        msg_info("No recovered layouts to apply")
        return 0

    try:
        import ida_typeinf
        tif = ida_typeinf.tinfo_t()
    except ImportError:
        msg_warn("ida_typeinf not available — cannot create struct types")
        return 0

    # Check for __fixed/__at support (IDA 9.3+)
    has_fixed_at = _check_fixed_at_support()

    count = 0
    for layout in layouts:
        class_name = layout["class_name"]
        safe_name = "Recovered" + re.sub(r'[^A-Za-z0-9_]', '_', class_name)
        total_size = layout.get("total_size", 0)
        fields = sorted(layout.get("fields", []), key=lambda f: f["offset"])

        if not fields or total_size <= 0:
            continue

        if has_fixed_at:
            # Use __fixed(size) and __at(offset) for exact layout
            decl = _build_fixed_at_struct(safe_name, total_size, fields)
        else:
            # Standard struct declaration with padding
            decl = _build_standard_struct(safe_name, total_size, fields)

        # Parse and apply the type declaration
        try:
            til = ida_typeinf.get_idati()
            errcode = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_TYP)
            if errcode is not None:
                # Save the type to the local type library
                tif.set_named_type(til, safe_name, ida_typeinf.NTF_REPLACE)
                count += 1
        except Exception as exc:
            msg_warn(f"Failed to create type '{safe_name}': {exc}")

    if count:
        msg_info(f"Applied {count} struct types to IDB" +
                 (" (using __fixed/__at)" if has_fixed_at else ""))
    return count


def _check_fixed_at_support():
    """Check if IDA supports __fixed(size) and __at(offset) type syntax."""
    try:
        import ida_typeinf
        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        # Try parsing a minimal __fixed struct
        test_decl = "struct __fixed(8) _test_fixed_at { __at(0) int x; };"
        result = ida_typeinf.parse_decl(tif, til, test_decl, ida_typeinf.PT_TYP)
        # Clean up test type
        if result is not None:
            ida_typeinf.del_named_type(til, "_test_fixed_at", ida_typeinf.NTF_TYPE)
            return True
    except Exception:
        pass
    return False


def _build_fixed_at_struct(name, total_size, fields):
    """Build a struct declaration using __fixed(size) and __at(offset)."""
    lines = [f"struct __fixed({total_size}) {name} {{"]
    for field in fields:
        offset = field["offset"]
        ftype = field["type"]
        fsize = field["size"]
        fname = field["name"]
        cpp_type = _to_cpp_type(ftype, fsize)

        if field.get("is_array"):
            arr_count = field.get("array_count", 1)
            arr_stride = field.get("array_stride", fsize)
            cpp_type_base = _to_cpp_type(ftype, arr_stride)
            lines.append(f"  __at({offset}) {cpp_type_base} {fname}[{arr_count}];")
        else:
            lines.append(f"  __at({offset}) {cpp_type} {fname};")
    lines.append("};")
    return "\n".join(lines)


def _build_standard_struct(name, total_size, fields):
    """Build a standard struct declaration with explicit padding."""
    lines = [f"struct {name} {{"]
    prev_end = 0
    for field in fields:
        offset = field["offset"]
        ftype = field["type"]
        fsize = field["size"]
        fname = field["name"]
        cpp_type = _to_cpp_type(ftype, fsize)

        if offset > prev_end:
            gap = offset - prev_end
            lines.append(f"  unsigned char _pad_{prev_end:X}[{gap}];")

        if field.get("is_array"):
            arr_count = field.get("array_count", 1)
            arr_stride = field.get("array_stride", fsize)
            cpp_type_base = _to_cpp_type(ftype, arr_stride)
            lines.append(f"  {cpp_type_base} {fname}[{arr_count}];")
            prev_end = offset + arr_stride * arr_count
        else:
            lines.append(f"  {cpp_type} {fname};")
            prev_end = offset + fsize

    if prev_end < total_size:
        lines.append(f"  unsigned char _pad_tail[{total_size - prev_end}];")
    lines.append("};")
    return "\n".join(lines)


def generate_all_layouts(session):
    """Generate C++ struct definitions for all recovered classes.

    Returns the full header text with all struct definitions.
    """
    db = session.db
    layouts = db.kv_get("object_layouts")
    if not layouts:
        return "// No recovered layouts found\n"

    lines = [
        "// ============================================================",
        "// Auto-generated C++ struct definitions from binary analysis",
        f"// Total classes recovered: {len(layouts)}",
        "// ============================================================",
        "",
        "#pragma once",
        "#include <cstdint>",
        "",
        "using uint8 = uint8_t;",
        "using int8 = int8_t;",
        "using uint16 = uint16_t;",
        "using int16 = int16_t;",
        "using uint32 = uint32_t;",
        "using int32 = int32_t;",
        "using uint64 = uint64_t;",
        "using int64 = int64_t;",
        "",
        "struct ObjectGuid { uint64 low; uint64 high; };",
        "",
    ]

    # Sort: known classes first, then unknowns
    known = [l for l in layouts if not l["class_name"].startswith("Unknown_")]
    unknown = [l for l in layouts if l["class_name"].startswith("Unknown_")]

    # Sort each group by size (largest first — more useful)
    known.sort(key=lambda l: -l.get("total_size", 0))
    unknown.sort(key=lambda l: -l.get("total_size", 0))

    for layout in known:
        lines.append(_format_struct(layout))

    if unknown:
        lines.append("// ============================================================")
        lines.append("// Unknown classes (grouped by access patterns)")
        lines.append("// ============================================================")
        lines.append("")
        # Only include unknowns with significant field counts
        for layout in unknown:
            if layout.get("field_count", 0) >= 3:
                lines.append(_format_struct(layout))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Retrieval functions
# ---------------------------------------------------------------------------

def get_object_layouts(session):
    """Retrieve all stored object layouts."""
    return session.db.kv_get("object_layouts") or []


def get_layout_for_class(session, class_name_or_key):
    """Get the layout for a specific class by name or key.

    Searches both class_name and key fields for a match.
    Returns the layout dict or None.
    """
    layouts = session.db.kv_get("object_layouts") or []
    for layout in layouts:
        if (layout.get("class_name") == class_name_or_key
                or layout.get("key") == class_name_or_key):
            return layout

    # Fuzzy match: substring
    class_lower = class_name_or_key.lower()
    for layout in layouts:
        if (class_lower in layout.get("class_name", "").lower()
                or class_lower in layout.get("key", "").lower()):
            return layout

    return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def recover_object_layouts(session, system_filter=None):
    """Recover C++ object layouts from decompiled pseudocode.

    Scans all handler functions and vtable-associated functions,
    extracts member access patterns, groups them by class, merges
    field information, detects inheritance, and stores results.

    Args:
        session: PluginSession with db and cfg
        system_filter: Optional string to filter by system name
                       (e.g., "housing", "combat")

    Returns:
        Number of classes recovered.
    """
    db = session.db

    msg_info("Starting object layout recovery...")

    # ---------------------------------------------------------------
    # Step 1: Gather candidate functions to analyze
    # ---------------------------------------------------------------

    # Source A: Opcode handler functions
    handler_query = "SELECT handler_ea, tc_name, direction FROM opcodes WHERE handler_ea IS NOT NULL"
    if system_filter:
        handler_query += (f" AND (tc_name LIKE '%{system_filter}%' "
                          f"OR jam_type LIKE '%{system_filter}%')")
    handlers = db.fetchall(handler_query)
    msg_info(f"  Found {len(handlers)} opcode handlers to analyze")

    # Source B: Vtable member functions
    vtable_func_query = (
        "SELECT ve.func_ea, ve.func_name, v.class_name "
        "FROM vtable_entries ve "
        "JOIN vtables v ON ve.vtable_ea = v.ea "
        "WHERE ve.func_ea IS NOT NULL"
    )
    if system_filter:
        vtable_func_query += f" AND v.class_name LIKE '%{system_filter}%'"
    vtable_funcs = db.fetchall(vtable_func_query)
    msg_info(f"  Found {len(vtable_funcs)} vtable functions to analyze")

    # Source C: Named functions in the functions table
    named_func_query = "SELECT ea, name FROM functions WHERE name IS NOT NULL"
    if system_filter:
        named_func_query += f" AND (system = '{system_filter}' OR name LIKE '%{system_filter}%')"
    named_funcs = db.fetchall(named_func_query)
    msg_info(f"  Found {len(named_funcs)} named functions to analyze")

    # Build unique function set: {ea: name}
    func_set = {}
    for h in handlers:
        ea = h["handler_ea"]
        name = h["tc_name"] or f"handler_{ea:X}"
        func_set[ea] = name

    for vf in vtable_funcs:
        ea = vf["func_ea"]
        if ea not in func_set:
            name = vf["func_name"] or vf["class_name"] or f"vtable_func_{ea:X}"
            func_set[ea] = name

    for nf in named_funcs:
        ea = nf["ea"]
        if ea not in func_set:
            func_set[ea] = nf["name"]

    total_funcs = len(func_set)
    msg_info(f"  Total unique functions to analyze: {total_funcs}")

    if total_funcs == 0:
        msg_warn("No functions to analyze. Run opcode dispatcher or vtable "
                 "analyzer first.")
        return 0

    # ---------------------------------------------------------------
    # Step 2: Decompile and extract member accesses from each function
    # ---------------------------------------------------------------

    all_accesses = []
    decompiled_count = 0
    failed_count = 0
    progress_interval = max(1, total_funcs // 20)  # 5% progress steps

    for idx, (ea, func_name) in enumerate(func_set.items()):
        if idx > 0 and idx % progress_interval == 0:
            pct = idx * 100 // total_funcs
            msg(f"  Progress: {pct}% ({idx}/{total_funcs}) — "
                f"{len(all_accesses)} accesses found so far")

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            failed_count += 1
            continue

        decompiled_count += 1
        accesses = _extract_member_accesses(pseudocode, ea, func_name)
        all_accesses.extend(accesses)

    msg_info(f"  Decompiled {decompiled_count}/{total_funcs} functions "
             f"({failed_count} failed)")
    msg_info(f"  Extracted {len(all_accesses)} total member accesses")

    if not all_accesses:
        msg_warn("No member accesses found in any function.")
        return 0

    # ---------------------------------------------------------------
    # Step 3: Identify classes (group accesses)
    # ---------------------------------------------------------------

    accesses_by_class = _identify_classes(all_accesses, db)
    msg_info(f"  Identified {len(accesses_by_class)} potential classes")

    # ---------------------------------------------------------------
    # Step 4: Merge field information per class
    # ---------------------------------------------------------------

    layouts = _merge_field_info(accesses_by_class)
    msg_info(f"  Merged into {len(layouts)} class layouts")

    # ---------------------------------------------------------------
    # Step 5: Detect inheritance
    # ---------------------------------------------------------------

    layouts = _detect_inheritance(layouts)
    inheritance_count = sum(1 for l in layouts.values() if l.get("inheritance"))
    msg_info(f"  Detected {inheritance_count} inheritance relationships")

    # ---------------------------------------------------------------
    # Step 6: Associate vtable addresses
    # ---------------------------------------------------------------

    try:
        vtables = db.fetchall("SELECT ea, class_name FROM vtables WHERE class_name IS NOT NULL")
        vtable_by_class = {}
        for vt in vtables:
            vtable_by_class[vt["class_name"]] = vt["ea"]

        for key, layout in layouts.items():
            if key in vtable_by_class:
                layout["vtable_ea"] = vtable_by_class[key]
    except Exception:
        pass

    # ---------------------------------------------------------------
    # Step 7: Consolidate Unknown classes with few fields
    # ---------------------------------------------------------------

    # Merge Unknown_ classes that share the same base_param patterns
    # and have overlapping offsets (likely the same class seen from different functions)
    layouts = _consolidate_unknowns(layouts)
    msg_info(f"  After consolidation: {len(layouts)} class layouts")

    # ---------------------------------------------------------------
    # Step 8: Store results
    # ---------------------------------------------------------------

    # Convert to list for JSON storage
    layout_list = sorted(layouts.values(), key=lambda l: -l.get("field_count", 0))
    db.kv_set("object_layouts", layout_list)
    db.commit()

    # ---------------------------------------------------------------
    # Report
    # ---------------------------------------------------------------

    msg_info(f"Object layout recovery complete:")
    msg_info(f"  Classes recovered: {len(layout_list)}")
    msg_info(f"  Total fields: {sum(l['field_count'] for l in layout_list)}")
    msg_info(f"  Functions analyzed: {decompiled_count}")

    # Print top classes by field count
    for layout in layout_list[:15]:
        name = layout["class_name"]
        fields = layout["field_count"]
        size = layout["total_size"]
        funcs = layout["source_function_count"]
        parents = layout.get("inheritance", [])
        parent_str = f" (inherits {', '.join(parents)})" if parents else ""
        msg_info(f"    {name}: {fields} fields, 0x{size:X} bytes, "
                 f"{funcs} functions{parent_str}")

    return len(layout_list)


def _consolidate_unknowns(layouts):
    """Merge Unknown_ classes that likely represent the same object.

    If two Unknown_ classes share many of the same offsets with compatible
    types, merge them into one.
    """
    unknown_keys = [k for k in layouts if k.startswith("Unknown_")]
    known_keys = [k for k in layouts if not k.startswith("Unknown_")]

    if len(unknown_keys) < 2:
        return layouts

    # Build offset fingerprints for unknowns
    fingerprints = {}
    for key in unknown_keys:
        layout = layouts[key]
        offsets = frozenset(f["offset"] for f in layout.get("fields", []))
        fingerprints[key] = offsets

    # Find merge candidates
    merged = set()
    merge_map = {}  # key -> merge_target

    for i, key_a in enumerate(unknown_keys):
        if key_a in merged:
            continue
        fp_a = fingerprints[key_a]
        if not fp_a:
            continue

        for key_b in unknown_keys[i + 1:]:
            if key_b in merged:
                continue
            fp_b = fingerprints[key_b]
            if not fp_b:
                continue

            # Compute overlap
            intersection = fp_a & fp_b
            union = fp_a | fp_b
            if len(union) == 0:
                continue

            jaccard = len(intersection) / len(union)

            # Merge if significant overlap (>50% Jaccard similarity)
            if jaccard > 0.5 and len(intersection) >= 3:
                merge_map[key_b] = key_a
                merged.add(key_b)

    # Execute merges
    for source, target in merge_map.items():
        if target in layouts and source in layouts:
            # Merge fields from source into target
            target_offsets = {f["offset"] for f in layouts[target]["fields"]}
            for field in layouts[source]["fields"]:
                if field["offset"] not in target_offsets:
                    layouts[target]["fields"].append(field)
                    target_offsets.add(field["offset"])
                else:
                    # Merge accessor lists
                    for tf in layouts[target]["fields"]:
                        if tf["offset"] == field["offset"]:
                            existing_accessors = set(tf.get("accessors", []))
                            new_accessors = field.get("accessors", [])
                            for acc in new_accessors:
                                if acc not in existing_accessors:
                                    tf["accessors"].append(acc)
                                    tf["access_count"] = tf.get("access_count", 0) + 1
                            break

            # Update counts
            layouts[target]["field_count"] = len(layouts[target]["fields"])
            layouts[target]["source_function_count"] = (
                layouts[target].get("source_function_count", 0)
                + layouts[source].get("source_function_count", 0)
            )

            # Recompute total size
            if layouts[target]["fields"]:
                last_field = max(layouts[target]["fields"], key=lambda f: f["offset"])
                total_size = last_field["offset"] + last_field["size"]
                layouts[target]["total_size"] = (total_size + 7) & ~7

            # Remove source
            del layouts[source]

    return layouts
