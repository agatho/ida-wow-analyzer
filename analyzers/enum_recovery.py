"""
Enum Universe Recovery
Recovers complete enum definitions by aggregating ALL comparisons against
a particular struct offset across ALL functions in the binary.

The key insight: switch statements and if-chains across the ENTIRE binary
use the same enum values. By merging comparisons from every function that
touches a given (struct_base + offset), we recover the full enum -- not
just the 3 states one handler checks, but ALL values used anywhere.

Produces:
  - Recovered enum definitions with inferred names and value labels
  - C++ enum class declarations for direct use in TrinityCore
  - Flags vs sequential vs sparse classification
"""

import json
import math
import re
import time
from collections import defaultdict

import ida_bytes
import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ── Regex patterns for comparison/assignment extraction ──────────────

# switch ( *(type *)(ptr + offset) )
# Captures: group(1)=var, group(2)=offset (may be None)
_SWITCH_PATTERN = re.compile(
    r'switch\s*\(\s*'
    r'(?:\*\s*\(\s*(?:unsigned\s+)?(?:_?[A-Z]+\s*\*|char\s*\*|int\s*\*|__int\d+\s*\*)\s*\)\s*)?'
    r'\(?\s*(\w+)\s*'
    r'(?:\+\s*(0x[0-9A-Fa-f]+|\d+))?\s*\)?\s*\)',
    re.MULTILINE
)

# case VALUE:
_CASE_PATTERN = re.compile(r'case\s+(0x[0-9A-Fa-f]+|-?\d+)\s*:')

# if ( *(type*)(ptr + offset) OP value )
_IF_STRUCT_PATTERN = re.compile(
    r'if\s*\(\s*'
    r'\*?\s*\(\s*(?:unsigned\s+)?(?:_?[A-Z]+\s*\*?|char\s*\*?|int\s*\*?|__int\d+\s*\*?)\s*\)\s*'
    r'\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*'
    r'([!=<>]=?)\s*'
    r'(0x[0-9A-Fa-f]+|-?\d+)\s*\)'
)

# if ( *(ptr + offset) OP value )  -- without explicit cast
_IF_DEREF_PATTERN = re.compile(
    r'if\s*\(\s*'
    r'\*\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*'
    r'([!=<>]=?)\s*'
    r'(0x[0-9A-Fa-f]+|-?\d+)\s*\)'
)

# if ( local_var OP value ) where local_var was loaded from struct
# We handle this by matching plain variable comparisons
_IF_VAR_PATTERN = re.compile(
    r'if\s*\(\s*'
    r'(\w+)\s+'
    r'([!=<>]=?)\s*'
    r'(0x[0-9A-Fa-f]+|-?\d+)\s*\)'
)

# Direct assignment: *(type*)(ptr + offset) = value
_ASSIGN_STRUCT_PATTERN = re.compile(
    r'\*\s*\(\s*(?:unsigned\s+)?(?:_?[A-Z]+\s*\*?|char\s*\*?|int\s*\*?|__int\d+\s*\*?)\s*\)\s*'
    r'\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*'
    r'=\s*(0x[0-9A-Fa-f]+|-?\d+)\s*;'
)

# Direct assignment without cast: *(ptr + offset) = value
_ASSIGN_DEREF_PATTERN = re.compile(
    r'\*\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*'
    r'=\s*(0x[0-9A-Fa-f]+|-?\d+)\s*;'
)

# Return value comparison: if ( SomeFunction() == value )
_RETVAL_CMP_PATTERN = re.compile(
    r'if\s*\(\s*'
    r'(\w+)\s*\([^)]*\)\s*'
    r'([!=<>]=?)\s*'
    r'(0x[0-9A-Fa-f]+|-?\d+)\s*\)'
)

# Cast width detection in pseudocode
_CAST_WIDTH_PATTERN = re.compile(
    r'\*\s*\(\s*(unsigned\s+)?(_?BYTE|_?WORD|_?DWORD|_?QWORD|char|__int8|__int16|__int32|__int64)\s*\*\s*\)\s*'
    r'\(?\s*\w+\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?'
)

# Map IDA pseudocode type names to C++ underlying types
_TYPE_WIDTH_MAP = {
    '_BYTE': ('uint8', 1), 'BYTE': ('uint8', 1), 'char': ('int8', 1),
    '__int8': ('int8', 1), 'unsigned __int8': ('uint8', 1),
    '_WORD': ('uint16', 2), 'WORD': ('uint16', 2),
    '__int16': ('int16', 2), 'unsigned __int16': ('uint16', 2),
    '_DWORD': ('uint32', 4), 'DWORD': ('uint32', 4),
    '__int32': ('int32', 4), 'unsigned __int32': ('uint32', 4),
    'int': ('int32', 4), 'unsigned int': ('uint32', 4),
    '_QWORD': ('uint64', 8), 'QWORD': ('uint64', 8),
    '__int64': ('int64', 8), 'unsigned __int64': ('uint64', 8),
}


def recover_enums(session, system_filter=None):
    """Main entry point: recover enum definitions from the binary.

    Scans all handler functions (and optionally named functions) for
    comparison patterns, groups them by (struct_base_type + offset),
    merges values from every function, classifies the enum, and
    attempts to infer value names from context.

    Args:
        session: PluginSession with .db access
        system_filter: Optional system name to restrict analysis scope

    Returns:
        Number of enums recovered.
    """
    db = session.db

    # Gather candidate functions: all opcode handlers
    query = "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL"
    if system_filter:
        query += f" AND (tc_name LIKE '%{system_filter}%' OR jam_type LIKE '%{system_filter}%')"
    handlers = db.fetchall(query)

    msg_info(f"Enum recovery: scanning {len(handlers)} handler functions...")

    # Master accumulator: offset_key -> list of ComparisonInfo dicts
    all_comparisons = defaultdict(list)

    scanned = 0
    failed = 0

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or handler["jam_type"] or f"handler_0x{ea:X}"

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            failed += 1
            continue

        comparisons = _scan_function_for_enums(pseudocode, ea, tc_name)
        for offset_key, comp_list in comparisons.items():
            all_comparisons[offset_key].extend(comp_list)

        scanned += 1
        if scanned % 100 == 0:
            msg_info(f"  Scanned {scanned}/{len(handlers)} handlers, "
                     f"{len(all_comparisons)} candidate enums so far...")

    # Also scan named functions from the functions table if available
    named_query = "SELECT ea, name FROM functions WHERE name IS NOT NULL"
    if system_filter:
        named_query += f" AND system = '{system_filter}'"
    named_query += " LIMIT 5000"
    named_funcs = db.fetchall(named_query)

    # Avoid re-scanning handler EAs
    handler_eas = {h["handler_ea"] for h in handlers}

    for nf in named_funcs:
        nf_ea = nf["ea"]
        if nf_ea in handler_eas:
            continue

        pseudocode = get_decompiled_text(nf_ea)
        if not pseudocode:
            continue

        nf_name = nf["name"] or f"func_0x{nf_ea:X}"
        comparisons = _scan_function_for_enums(pseudocode, nf_ea, nf_name)
        for offset_key, comp_list in comparisons.items():
            all_comparisons[offset_key].extend(comp_list)

        scanned += 1

    msg_info(f"  Total scanned: {scanned} functions ({failed} decompilation failures)")
    msg_info(f"  Raw candidate offset keys: {len(all_comparisons)}")

    # Filter: only keep offset keys with at least 2 distinct values
    # (a single value isn't an enum)
    filtered = {}
    for offset_key, comp_list in all_comparisons.items():
        distinct_values = set()
        for comp in comp_list:
            if comp["value"] is not None:
                distinct_values.add(comp["value"])
        if len(distinct_values) >= 2:
            filtered[offset_key] = comp_list

    msg_info(f"  After filtering (>=2 values): {len(filtered)} candidate enums")

    # Build enum definitions
    recovered_enums = []

    for offset_key, comp_list in sorted(filtered.items()):
        enum_info = _classify_enum(offset_key, comp_list)
        if enum_info is None:
            continue

        # Try to infer value names
        _infer_value_names(enum_info)

        recovered_enums.append(enum_info)

    # Store results
    db.kv_set("recovered_enums", recovered_enums)
    db.commit()

    msg_info(f"Recovered {len(recovered_enums)} enums:")
    for enum in recovered_enums[:20]:
        msg_info(f"  {enum['suggested_name']}: {enum['value_count']} values "
                 f"({'flags' if enum['is_flags'] else 'sequential'}) "
                 f"from {enum['source_function_count']} functions")

    if len(recovered_enums) > 20:
        msg_info(f"  ... and {len(recovered_enums) - 20} more")

    return len(recovered_enums)


def _scan_function_for_enums(pseudocode, func_ea, func_name):
    """Scan one decompiled function for enum comparison/assignment patterns.

    Returns:
        dict: offset_key -> list of comparison info dicts
    """
    results = defaultdict(list)
    lines = pseudocode.split('\n')

    # 1. Find switch statements and their case values
    for switch_match in _SWITCH_PATTERN.finditer(pseudocode):
        var = switch_match.group(1)
        offset = switch_match.group(2) or "0"
        offset_key = f"{var}+{offset}"

        # Detect cast width near the switch
        underlying = _detect_cast_width(pseudocode, var, offset)

        # Scan for case values after this switch
        switch_pos = switch_match.end()
        # Scan forward until the next switch or end of function (up to 5000 chars)
        block_end = len(pseudocode)
        next_switch = _SWITCH_PATTERN.search(pseudocode, switch_pos)
        if next_switch:
            block_end = next_switch.start()
        block = pseudocode[switch_pos:min(switch_pos + 5000, block_end)]

        for case_match in _CASE_PATTERN.finditer(block):
            try:
                value = int(case_match.group(1), 0)
            except ValueError:
                continue

            # Find the line number for context
            case_abs_pos = switch_pos + case_match.start()
            line_no = pseudocode[:case_abs_pos].count('\n')

            results[offset_key].append({
                "value": value,
                "operator": "==",
                "context_function": func_name,
                "func_ea": func_ea,
                "line": line_no,
                "source": "switch_case",
                "underlying_type": underlying,
            })

    # 2. Find if-comparisons against struct offsets (with cast)
    for m in _IF_STRUCT_PATTERN.finditer(pseudocode):
        var = m.group(1)
        offset = m.group(2)
        operator = m.group(3)
        value_str = m.group(4)
        offset_key = f"{var}+{offset}"
        underlying = _detect_cast_width(pseudocode, var, offset)

        try:
            value = int(value_str, 0)
        except ValueError:
            continue

        line_no = pseudocode[:m.start()].count('\n')
        results[offset_key].append({
            "value": value,
            "operator": operator,
            "context_function": func_name,
            "func_ea": func_ea,
            "line": line_no,
            "source": "if_struct",
            "underlying_type": underlying,
        })

    # 3. Find if-comparisons against struct offsets (without cast)
    for m in _IF_DEREF_PATTERN.finditer(pseudocode):
        var = m.group(1)
        offset = m.group(2)
        operator = m.group(3)
        value_str = m.group(4)
        offset_key = f"{var}+{offset}"
        underlying = _detect_cast_width(pseudocode, var, offset)

        try:
            value = int(value_str, 0)
        except ValueError:
            continue

        line_no = pseudocode[:m.start()].count('\n')
        results[offset_key].append({
            "value": value,
            "operator": operator,
            "context_function": func_name,
            "func_ea": func_ea,
            "line": line_no,
            "source": "if_deref",
            "underlying_type": underlying,
        })

    # 4. Find direct assignments: *(ptr + offset) = value
    for m in _ASSIGN_STRUCT_PATTERN.finditer(pseudocode):
        var = m.group(1)
        offset = m.group(2)
        value_str = m.group(3)
        offset_key = f"{var}+{offset}"
        underlying = _detect_cast_width(pseudocode, var, offset)

        try:
            value = int(value_str, 0)
        except ValueError:
            continue

        line_no = pseudocode[:m.start()].count('\n')
        results[offset_key].append({
            "value": value,
            "operator": "=",
            "context_function": func_name,
            "func_ea": func_ea,
            "line": line_no,
            "source": "assignment",
            "underlying_type": underlying,
        })

    for m in _ASSIGN_DEREF_PATTERN.finditer(pseudocode):
        var = m.group(1)
        offset = m.group(2)
        value_str = m.group(3)
        offset_key = f"{var}+{offset}"
        underlying = _detect_cast_width(pseudocode, var, offset)

        try:
            value = int(value_str, 0)
        except ValueError:
            continue

        line_no = pseudocode[:m.start()].count('\n')
        results[offset_key].append({
            "value": value,
            "operator": "=",
            "context_function": func_name,
            "func_ea": func_ea,
            "line": line_no,
            "source": "assignment",
            "underlying_type": underlying,
        })

    # 5. Find return-value comparisons: if ( SomeFunction() == value )
    for m in _RETVAL_CMP_PATTERN.finditer(pseudocode):
        callee_name = m.group(1)
        operator = m.group(2)
        value_str = m.group(3)

        # Skip common false positives (standard library, very short names)
        if callee_name in ('if', 'for', 'while', 'return', 'sizeof', 'offsetof'):
            continue
        if len(callee_name) < 3:
            continue

        offset_key = f"retval:{callee_name}"

        try:
            value = int(value_str, 0)
        except ValueError:
            continue

        line_no = pseudocode[:m.start()].count('\n')
        results[offset_key].append({
            "value": value,
            "operator": operator,
            "context_function": func_name,
            "func_ea": func_ea,
            "line": line_no,
            "source": "retval_cmp",
            "underlying_type": None,
        })

    return dict(results)


def _detect_cast_width(pseudocode, var, offset):
    """Detect the underlying integer type from cast expressions near a var+offset."""
    # Look for *(TYPE *)(var + offset) patterns
    pattern = re.compile(
        r'\*\s*\(\s*(unsigned\s+)?'
        r'(_?BYTE|_?WORD|_?DWORD|_?QWORD|char|__int8|__int16|__int32|__int64)'
        r'\s*\*\s*\)\s*\(?\s*' + re.escape(var) + r'\s*\+\s*' + re.escape(offset)
    )
    m = pattern.search(pseudocode)
    if m:
        unsigned_prefix = m.group(1) or ''
        base_type = m.group(2)
        full_type = (unsigned_prefix + base_type).strip()
        if full_type in _TYPE_WIDTH_MAP:
            return _TYPE_WIDTH_MAP[full_type][0]
        if base_type in _TYPE_WIDTH_MAP:
            t, _ = _TYPE_WIDTH_MAP[base_type]
            if unsigned_prefix.strip() == 'unsigned' and t.startswith('int'):
                return 'u' + t
            return t
    return None


def _classify_enum(offset_key, comparisons):
    """Classify a set of comparisons into an enum definition.

    Analyzes the value distribution to determine:
      - Sequential from 0 (state/type enum)
      - Powers of 2 (flags/bitmask)
      - Sparse large values (error codes or IDs)
      - Mixed

    Args:
        offset_key: The struct base+offset identifier (e.g., "a1+0x48")
        comparisons: List of comparison info dicts

    Returns:
        Enum info dict, or None if not a valid enum
    """
    # Collect distinct values and per-value metadata
    value_map = defaultdict(lambda: {"used_by": set(), "frequency": 0, "operators": set()})

    all_functions = set()
    underlying_types = set()
    has_signed_compare = False
    has_unsigned_compare = False

    for comp in comparisons:
        val = comp["value"]
        if val is None:
            continue

        info = value_map[val]
        info["used_by"].add(comp["context_function"])
        info["frequency"] += 1
        info["operators"].add(comp["operator"])

        all_functions.add(comp["context_function"])

        if comp["underlying_type"]:
            underlying_types.add(comp["underlying_type"])

        # Track signedness from comparison operators
        op = comp["operator"]
        if op in ('<', '<=', '>','>='):
            if val < 0:
                has_signed_compare = True

    if not value_map:
        return None

    values = sorted(value_map.keys())
    min_val = min(values)
    max_val = max(values)
    count = len(values)

    # Determine underlying type
    underlying_type = _pick_underlying_type(underlying_types, min_val, max_val)

    # Determine if signed
    is_signed = has_signed_compare or min_val < 0

    # Classify the enum pattern
    is_flags = _is_power_of_two_pattern(values)
    is_sequential = _is_sequential_pattern(values)
    is_sparse = (not is_flags and not is_sequential and count >= 2)

    # Generate suggested name
    suggested_name = _suggest_enum_name(offset_key, all_functions, is_flags)

    # Build value entries
    value_entries = []
    for val in values:
        info = value_map[val]
        value_entries.append({
            "value": val,
            "name": None,  # filled by _infer_value_names later
            "used_by": sorted(info["used_by"]),
            "frequency": info["frequency"],
        })

    return {
        "key": offset_key,
        "suggested_name": suggested_name,
        "underlying_type": underlying_type,
        "is_flags": is_flags,
        "is_signed": is_signed,
        "values": value_entries,
        "min_value": min_val,
        "max_value": max_val,
        "value_count": count,
        "source_functions": sorted(all_functions),
        "source_function_count": len(all_functions),
    }


def _is_power_of_two_pattern(values):
    """Check if values follow a bitmask / flags pattern (powers of 2)."""
    if not values:
        return False

    # Allow 0 as the "none" flag
    nonzero = [v for v in values if v > 0]
    if len(nonzero) < 2:
        return False

    power_of_two_count = sum(1 for v in nonzero if (v & (v - 1)) == 0)
    # If at least 60% of non-zero values are powers of 2, it's a flags enum
    return power_of_two_count / len(nonzero) >= 0.6


def _is_sequential_pattern(values):
    """Check if values are (mostly) sequential starting near 0."""
    if not values:
        return False

    min_val = min(values)
    max_val = max(values)
    count = len(values)

    # Sequential if the range roughly matches the count and starts near 0
    if min_val < 0:
        return False
    if min_val > 5:
        return False
    expected_range = max_val - min_val + 1
    # Allow up to 30% gaps (some enum values might not be observed)
    return count >= expected_range * 0.5


def _pick_underlying_type(detected_types, min_val, max_val):
    """Choose the most likely underlying integer type."""
    # If we detected explicit types from casts, prefer the most common
    if detected_types:
        # Prefer unsigned types, wider types
        priority = ['uint32', 'int32', 'uint16', 'int16', 'uint8', 'int8',
                     'uint64', 'int64']
        for p in priority:
            if p in detected_types:
                return p
        return next(iter(detected_types))

    # Infer from value range
    if min_val < 0:
        if min_val >= -128 and max_val <= 127:
            return 'int8'
        if min_val >= -32768 and max_val <= 32767:
            return 'int16'
        return 'int32'
    else:
        if max_val <= 0xFF:
            return 'uint8'
        if max_val <= 0xFFFF:
            return 'uint16'
        if max_val <= 0xFFFFFFFF:
            return 'uint32'
        return 'uint64'


def _suggest_enum_name(offset_key, functions, is_flags):
    """Generate a suggested enum name from context."""
    suffix = "Flags" if is_flags else "Type"

    # For return-value enums, use the function name
    if offset_key.startswith("retval:"):
        callee = offset_key.split(":", 1)[1]
        # PascalCase the function name
        parts = re.split(r'[_\s]+', callee)
        name = "".join(p.capitalize() for p in parts if p)
        return f"{name}Result"

    # Try to extract a meaningful name from the most common function name
    # Look for system keywords in function names
    system_keywords = [
        "Housing", "Quest", "Spell", "Aura", "Combat", "Guild", "Chat",
        "Mail", "Party", "Group", "Raid", "Item", "Inventory", "Equip",
        "Loot", "Auction", "Craft", "Achievement", "Pet", "Talent",
        "Character", "Player", "Map", "Zone", "Vehicle", "Garrison",
        "Calendar", "Transmog", "Collection", "Mount", "Toy",
        "Neighborhood", "Interior", "Decor", "Plot", "Steward",
        "Battleground", "Arena", "PvP",
    ]

    detected_system = None
    for func in functions:
        for kw in system_keywords:
            if kw.lower() in func.lower():
                detected_system = kw
                break
        if detected_system:
            break

    # Parse the offset from the key
    parts = offset_key.split('+')
    offset_part = parts[1] if len(parts) > 1 else parts[0]

    if detected_system:
        return f"{detected_system}_{offset_part}_{suffix}"

    # Fallback: use the offset key cleaned up
    clean_key = offset_key.replace('+', '_off_').replace('0x', '')
    clean_key = re.sub(r'[^a-zA-Z0-9_]', '_', clean_key)
    return f"Enum_{clean_key}_{suffix}"


def _infer_value_names(enum_info):
    """Try to name individual enum values from context.

    Uses:
      - Function names that only handle one specific value
      - Power-of-2 naming for flags
      - Sequential naming for state enums
      - TC opcode/error naming conventions
    """
    values = enum_info["values"]
    is_flags = enum_info["is_flags"]
    key = enum_info["key"]

    # Try to load state machine data for cross-reference
    # (State machine analyzer may have named some states already)
    state_names = {}

    for entry in values:
        val = entry["value"]
        used_by = entry["used_by"]

        # Strategy 1: If only one function uses this value, derive name from it
        if len(used_by) == 1:
            func_name = used_by[0]
            # Extract the most specific part of the function name
            # e.g., "HandleHousingPlotBrowse" -> "PlotBrowse"
            clean = _extract_specific_name_part(func_name)
            if clean:
                entry["name"] = clean
                continue

        # Strategy 2: For flags enums, name by bit position
        if is_flags and val > 0 and (val & (val - 1)) == 0:
            bit = int(math.log2(val))
            entry["name"] = f"FLAG_BIT_{bit}"
            continue

        # Strategy 3: For flags, 0 is typically "None"
        if is_flags and val == 0:
            entry["name"] = "NONE"
            continue

        # Strategy 4: For sequential enums starting at 0
        if not is_flags:
            if val == 0:
                entry["name"] = "NONE"
                continue
            if val == -1 or (val == 0xFFFFFFFF and not enum_info["is_signed"]):
                entry["name"] = "INVALID"
                continue

        # Strategy 5: Try to find patterns in function names that use this value
        common_prefix = _find_common_name_element(used_by)
        if common_prefix:
            entry["name"] = f"{common_prefix}_{val}"
            continue

        # Fallback: descriptive name
        if is_flags:
            entry["name"] = f"FLAG_0x{val:X}" if val >= 10 else f"FLAG_{val}"
        else:
            entry["name"] = f"VALUE_{val}" if val < 0x100 else f"VALUE_0x{val:X}"


def _extract_specific_name_part(func_name):
    """Extract the most descriptive part of a function name.

    "HandleHousingDecorPlace" -> "DecorPlace"
    "sub_7FF725A3B160" -> None
    """
    if func_name.startswith("sub_") or func_name.startswith("handler_0x"):
        return None

    # Remove common prefixes
    name = func_name
    for prefix in ("Handle", "Process", "On", "Do", "Send", "Recv",
                    "CMSG_", "SMSG_", "Update", "Set", "Get", "Is", "Has",
                    "Check", "Validate"):
        if name.startswith(prefix) and len(name) > len(prefix):
            name = name[len(prefix):]
            break

    # Remove common suffixes
    for suffix in ("Handler", "Callback", "Response", "Request", "Packet"):
        if name.endswith(suffix) and len(name) > len(suffix):
            name = name[:-len(suffix)]
            break

    # Convert to UPPER_CASE for enum style
    # Split CamelCase
    parts = re.findall(r'[A-Z][a-z0-9]*|[a-z0-9]+|[A-Z]+(?=[A-Z]|$)', name)
    if parts:
        result = '_'.join(p.upper() for p in parts)
        if len(result) >= 2:
            return result

    return None


def _find_common_name_element(func_names):
    """Find a common meaningful word across multiple function names."""
    if not func_names:
        return None

    # Split all names into words
    word_counts = defaultdict(int)
    skip_words = {
        'HANDLE', 'PROCESS', 'ON', 'DO', 'SEND', 'RECV', 'UPDATE',
        'SET', 'GET', 'IS', 'HAS', 'CHECK', 'VALIDATE', 'THE', 'AND',
        'FOR', 'SUB', 'HANDLER', 'CALLBACK', 'A1', 'A2', 'A3', 'V1',
    }

    for name in func_names:
        words = set(re.findall(r'[A-Z][a-z0-9]*|[A-Z]+(?=[A-Z]|$)', name))
        for w in words:
            w_upper = w.upper()
            if w_upper not in skip_words and len(w_upper) >= 3:
                word_counts[w_upper] += 1

    if not word_counts:
        return None

    # Return the most common word that appears in at least half the functions
    threshold = max(2, len(func_names) // 2)
    best = max(word_counts.items(), key=lambda x: x[1])
    if best[1] >= threshold:
        return best[0]

    # If nothing meets threshold, just return the most common word
    if best[1] >= 2:
        return best[0]

    return None


def _collect_string_refs_in_function(func_ea):
    """Collect string literals referenced within a function.

    Returns a list of (address_of_string, string_value) tuples.
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []

    strings = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head, 0):
            target = xref.to
            # Check if the target is a string
            str_val = _get_string_at(target)
            if str_val and len(str_val) >= 2:
                strings.append((target, str_val))

    return strings


def _get_string_at(ea):
    """Try to read a C string at address ea."""
    try:
        stype = ida_bytes.get_str_type(ea)
        if stype is not None and stype >= 0:
            s = ida_bytes.get_strlit_contents(ea, -1, stype)
            if s:
                return s.decode('utf-8', errors='replace')
    except Exception:
        pass
    return None


def generate_enum_cpp(session, enum_key):
    """Generate a C++ enum class definition for a recovered enum.

    Args:
        session: PluginSession
        enum_key: The offset key of the enum (e.g., "a1+0x48")

    Returns:
        C++ enum definition as a string.
    """
    enums = get_recovered_enums(session)

    target = None
    for e in enums:
        if e["key"] == enum_key or e["suggested_name"] == enum_key:
            target = e
            break

    if not target:
        return f"// Enum '{enum_key}' not found in recovered enums\n"

    name = target["suggested_name"]
    underlying = target["underlying_type"]
    is_flags = target["is_flags"]

    lines = []
    lines.append(f"// Recovered from {target['source_function_count']} functions")
    lines.append(f"// Source offset: {target['key']}")
    lines.append(f"// Values: {target['min_value']}..{target['max_value']} "
                 f"({target['value_count']} distinct)")
    lines.append(f"enum class {name} : {underlying}")
    lines.append("{")

    max_name_len = max(
        (len(v["name"]) for v in target["values"] if v["name"]),
        default=10
    )

    for v in target["values"]:
        val = v["value"]
        vname = v["name"] or f"VALUE_{val}"
        used_by = v["used_by"]

        # Format value as hex for flags, decimal for sequential
        if is_flags and val > 0:
            val_str = f"0x{val:X}"
        else:
            val_str = str(val)

        # Comment showing which functions use this value
        comment = ""
        if used_by:
            func_list = ", ".join(used_by[:3])
            if len(used_by) > 3:
                func_list += f", ... (+{len(used_by) - 3})"
            comment = f"  // used by: {func_list}"

        lines.append(f"    {vname:<{max_name_len}} = {val_str},{comment}")

    lines.append("};")

    # For flags enums, add bitwise operator overloads
    if is_flags:
        lines.append("")
        lines.append(f"// Bitwise operators for {name}")
        lines.append(f"inline {name} operator|({name} a, {name} b) "
                     f"{{ return static_cast<{name}>"
                     f"(static_cast<{underlying}>(a) | "
                     f"static_cast<{underlying}>(b)); }}")
        lines.append(f"inline {name} operator&({name} a, {name} b) "
                     f"{{ return static_cast<{name}>"
                     f"(static_cast<{underlying}>(a) & "
                     f"static_cast<{underlying}>(b)); }}")
        lines.append(f"inline {name} operator~({name} a) "
                     f"{{ return static_cast<{name}>"
                     f"(~static_cast<{underlying}>(a)); }}")
        lines.append(f"inline bool HasFlag({name} flags, {name} flag) "
                     f"{{ return (flags & flag) == flag; }}")

    return "\n".join(lines) + "\n"


def generate_all_enums_header(session):
    """Generate a complete C++ header file with all recovered enums.

    Returns:
        Complete header file content as a string.
    """
    enums = get_recovered_enums(session)
    if not enums:
        return "// No recovered enums found. Run recover_enums() first.\n"

    lines = []
    lines.append("/**")
    lines.append(" * Auto-generated enum definitions recovered from WoW binary analysis.")
    lines.append(f" * Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f" * Total enums: {len(enums)}")
    lines.append(f" * Total values: {sum(e['value_count'] for e in enums)}")
    lines.append(" */")
    lines.append("")
    lines.append("#ifndef _RECOVERED_ENUMS_H_")
    lines.append("#define _RECOVERED_ENUMS_H_")
    lines.append("")
    lines.append("#include <cstdint>")
    lines.append("")

    # Sort enums: flags first, then by name
    sorted_enums = sorted(enums, key=lambda e: (not e["is_flags"], e["suggested_name"]))

    # Group by classification
    flags_enums = [e for e in sorted_enums if e["is_flags"]]
    state_enums = [e for e in sorted_enums if not e["is_flags"]]

    if flags_enums:
        lines.append("// ====== Flag Enums (bitmask patterns) ======")
        lines.append("")
        for e in flags_enums:
            lines.append(generate_enum_cpp(session, e["key"]))
            lines.append("")

    if state_enums:
        lines.append("// ====== State/Type Enums (sequential patterns) ======")
        lines.append("")
        for e in state_enums:
            lines.append(generate_enum_cpp(session, e["key"]))
            lines.append("")

    lines.append("#endif // _RECOVERED_ENUMS_H_")
    return "\n".join(lines) + "\n"


def get_recovered_enums(session):
    """Retrieve stored enum data from the knowledge DB.

    Returns:
        List of recovered enum info dicts, or empty list.
    """
    return session.db.kv_get("recovered_enums") or []


def find_enum_for_offset(session, base_type, offset):
    """Look up a recovered enum by struct base type and offset.

    Args:
        session: PluginSession
        base_type: The variable/parameter name (e.g., "a1", "this")
        offset: The struct offset (e.g., "0x48", "72", 0x48)

    Returns:
        Enum info dict if found, None otherwise.
    """
    enums = get_recovered_enums(session)

    # Normalize offset to string for comparison
    if isinstance(offset, int):
        offset_strs = [f"0x{offset:X}", f"0x{offset:x}", str(offset)]
    else:
        offset_str = str(offset)
        offset_strs = [offset_str]
        # Also try converting hex string to int and back
        try:
            val = int(offset_str, 0)
            offset_strs.extend([f"0x{val:X}", f"0x{val:x}", str(val)])
        except ValueError:
            pass

    for e in enums:
        key = e["key"]
        for offset_str in offset_strs:
            candidate_key = f"{base_type}+{offset_str}"
            if key == candidate_key:
                return e
            # Also try case-insensitive match
            if key.lower() == candidate_key.lower():
                return e

    # Broader search: match just the offset part regardless of base variable
    # (different functions may use different parameter names for the same struct)
    for e in enums:
        key = e["key"]
        key_offset = key.split('+', 1)[1] if '+' in key else key
        for offset_str in offset_strs:
            try:
                key_val = int(key_offset, 0)
                search_val = int(offset_str, 0)
                if key_val == search_val:
                    return e
            except ValueError:
                if key_offset == offset_str:
                    return e

    return None
