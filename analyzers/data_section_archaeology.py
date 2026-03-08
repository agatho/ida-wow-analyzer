"""
Data Section Archaeology
Systematically mines the .rdata and .data sections for structured data:
lookup tables, jump tables, function pointer arrays, const struct arrays,
initialized data, string tables, and global variables.

By scanning data sections for regular patterns -- pointer arrays pointing
into .text, repeating struct-sized blocks, pointer-to-string sequences --
we recover a wealth of structured information that enriches every other
analyzer's output.

Produces:
  - Function pointer tables (vtables, dispatch tables, callback arrays)
  - Jump tables from switch statements with enum cardinality
  - Const data arrays (integer/float/struct lookup tables)
  - String tables (enum-to-string mappings)
  - Initialized struct instances with field type heuristics
  - Global variable classification (config, state, singleton, pool)
"""

import json
import re
import time
import struct
import collections

import ida_funcs
import ida_name
import ida_bytes
import ida_segment
import ida_xref
import idautils
import idaapi
import idc

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum consecutive code pointers to qualify as a function pointer table
_MIN_FPTR_TABLE_ENTRIES = 3

# Maximum gap allowed between consecutive code pointers (bytes of non-pointer
# data interspersed) -- 0 means strictly contiguous qwords
_MAX_FPTR_GAP = 0

# Minimum entries for a jump table
_MIN_JUMP_TABLE_ENTRIES = 3

# Maximum entries for a single jump table (sanity cap)
_MAX_JUMP_TABLE_ENTRIES = 4096

# Minimum elements for a const data array
_MIN_CONST_ARRAY_ELEMENTS = 4

# Maximum element size to consider for const array heuristic (bytes)
_MAX_CONST_ELEMENT_SIZE = 256

# Minimum string pointers for a string table
_MIN_STRING_TABLE_ENTRIES = 3

# Maximum string length to accept (sanity cap)
_MAX_STRING_LENGTH = 4096

# Minimum fields for an initialized struct
_MIN_STRUCT_FIELDS = 2

# Pointer size for x64
_PTR_SIZE = 8

# System keyword mapping for classifying globals by name/context
_SYSTEM_KEYWORDS = {
    "HOUSING": "Housing", "HOUSE": "Housing", "DECOR": "Housing",
    "NEIGHBORHOOD": "Housing", "INTERIOR": "Housing",
    "QUEST": "Quest", "SPELL": "Combat", "AURA": "Combat",
    "DAMAGE": "Combat", "HEAL": "Combat", "ATTACK": "Combat",
    "GUILD": "Social", "CHAT": "Social", "MAIL": "Social",
    "FRIEND": "Social", "PARTY": "Social", "GROUP": "Social",
    "BATTLEGROUND": "PvP", "ARENA": "PvP", "DUEL": "PvP",
    "AUCTION": "Auction", "TRADE": "Crafting", "RECIPE": "Crafting",
    "TALENT": "Talent", "PET": "Pet", "MOUNT": "Mount",
    "ACHIEVEMENT": "Achievement", "LOOT": "Loot",
    "MOVEMENT": "Movement", "MOVE": "Movement",
    "ITEM": "Item", "INVENTORY": "Item", "BAG": "Item", "EQUIP": "Item",
    "CHARACTER": "Character", "PLAYER": "Character",
    "GARRISON": "Garrison", "DELVE": "Delves",
    "MYTHIC": "MythicPlus", "KEYSTONE": "MythicPlus",
    "VEHICLE": "Vehicle", "TAXI": "Movement",
    "CURRENCY": "Currency", "TOKEN": "Currency",
    "BANK": "Item", "VOID_STORAGE": "Item",
    "TRANSMOG": "Transmog", "WARDROBE": "Transmog",
    "CALENDAR": "Calendar", "EVENT": "Calendar",
    "DB2": "DB2", "DBC": "DB2", "LUA": "Lua", "SCRIPT": "Lua",
    "NETWORK": "Network", "PACKET": "Network", "OPCODE": "Network",
    "MAP": "Map", "ZONE": "Map", "AREA": "Map", "TERRAIN": "Map",
}


# ---------------------------------------------------------------------------
# Segment utilities
# ---------------------------------------------------------------------------

def _get_text_segment():
    """Return the .text segment, or None."""
    seg = ida_segment.get_segm_by_name(".text")
    if seg:
        return seg
    # Fallback: find first executable segment
    for s in _iter_segments():
        if s.perm & ida_segment.SFL_CODE:
            return s
    return None


def _iter_segments():
    """Iterate all segments as ida_segment.segment_t objects."""
    n = ida_segment.get_segm_qty()
    for i in range(n):
        seg = ida_segment.getnseg(i)
        if seg:
            yield seg


def _get_data_segments():
    """Return a list of (segment_t, name) tuples for .rdata, .data, and
    any other readable non-executable segments."""
    result = []
    seen = set()

    # Named segments first
    for name in (".rdata", ".data"):
        seg = ida_segment.get_segm_by_name(name)
        if seg and seg.start_ea not in seen:
            result.append((seg, name))
            seen.add(seg.start_ea)

    # Also scan any readable, non-executable segments we haven't already found
    for seg in _iter_segments():
        if seg.start_ea in seen:
            continue
        seg_name = ida_segment.get_segm_name(seg) or ""
        # Skip .text, .pdata, .rsrc, .reloc
        if seg_name in (".text", ".pdata", ".rsrc", ".reloc", ".idata", ".tls"):
            continue
        # Must be readable, not executable
        if (seg.perm & 4) and not (seg.perm & 1):
            result.append((seg, seg_name))
            seen.add(seg.start_ea)

    return result


def _is_code_address(ea, text_seg):
    """Check if an address falls within the .text segment."""
    if text_seg is None:
        return False
    return text_seg.start_ea <= ea < text_seg.end_ea


def _is_in_data_segments(ea, data_segments):
    """Check if an address falls within any of the data segments."""
    for seg, _ in data_segments:
        if seg.start_ea <= ea < seg.end_ea:
            return True
    return False


def _read_qword_safe(ea):
    """Read a 64-bit value at ea, returning None on failure."""
    val = ida_bytes.get_qword(ea)
    if val == 0xFFFFFFFFFFFFFFFF:
        # Could be a valid value or read failure; check if bytes are defined
        flags = ida_bytes.get_flags(ea)
        if not ida_bytes.is_loaded(ea):
            return None
    return val


def _read_dword_safe(ea):
    """Read a 32-bit value at ea, returning None on failure."""
    if not ida_bytes.is_loaded(ea):
        return None
    return ida_bytes.get_dword(ea)


def _read_float_safe(ea):
    """Read a 32-bit float at ea, returning None on failure."""
    if not ida_bytes.is_loaded(ea):
        return None
    raw = ida_bytes.get_dword(ea)
    try:
        val = struct.unpack('<f', struct.pack('<I', raw))[0]
        import math
        if math.isnan(val) or math.isinf(val):
            return None
        return val
    except Exception:
        return None


def _get_string_at(ea, max_len=_MAX_STRING_LENGTH):
    """Try to read a null-terminated string at ea. Returns None on failure."""
    if not ida_bytes.is_loaded(ea):
        return None
    s = idc.get_strlit_contents(ea, max_len, idc.STRTYPE_C)
    if s:
        try:
            return s.decode('utf-8', errors='replace')
        except Exception:
            return None
    return None


def _get_xrefs_to(ea):
    """Get all code cross-references TO an address."""
    refs = []
    for xref in idautils.XrefsTo(ea, 0):
        if xref.frm != idaapi.BADADDR:
            refs.append(xref.frm)
    return refs


def _get_func_name_at(ea):
    """Get a meaningful function name at ea."""
    name = ida_name.get_name(ea)
    if name and not name.startswith("sub_") and not name.startswith("j_"):
        return name
    func = ida_funcs.get_func(ea)
    if func:
        fname = ida_name.get_name(func.start_ea)
        if fname and not fname.startswith("sub_"):
            return fname
    return None


def _classify_system(name):
    """Classify a name string into a game system category."""
    if not name:
        return "Unknown"
    upper = name.upper()
    for keyword, system in _SYSTEM_KEYWORDS.items():
        if keyword in upper:
            return system
    return "Unknown"


def _get_existing_vtable_eas(session):
    """Get a set of known vtable addresses from the session database."""
    vtable_eas = set()
    try:
        rows = session.db.fetchall("SELECT ea FROM vtables")
        for row in rows:
            vtable_eas.add(row["ea"])
    except Exception:
        pass
    return vtable_eas


# ---------------------------------------------------------------------------
# Phase 1: Function Pointer Table Detection
# ---------------------------------------------------------------------------

def _scan_function_pointer_tables(data_segments, text_seg, vtable_eas):
    """Scan data segments for arrays of consecutive code pointers.

    Returns a list of dicts describing each function pointer table found.
    """
    tables = []
    processed_ranges = set()  # Track (start_ea, end_ea) to avoid overlaps

    for seg, seg_name in data_segments:
        ea = seg.start_ea
        end = seg.end_ea
        msg_info(f"Scanning {seg_name} ({ea_str(ea)}-{ea_str(end)}) "
                 f"for function pointer tables...")

        while ea + _PTR_SIZE <= end:
            # Skip if already part of a discovered table
            if any(s <= ea < e for s, e in processed_ranges):
                ea += _PTR_SIZE
                continue

            val = _read_qword_safe(ea)
            if val is None or not _is_code_address(val, text_seg):
                ea += _PTR_SIZE
                continue

            # Potential start of a function pointer table
            table_start = ea
            targets = []
            scan_ea = ea

            while scan_ea + _PTR_SIZE <= end:
                ptr_val = _read_qword_safe(scan_ea)
                if ptr_val is None or not _is_code_address(ptr_val, text_seg):
                    break

                func = ida_funcs.get_func(ptr_val)
                if func is None:
                    # Pointer into .text but not a known function start -- could
                    # be a thunk or mid-function pointer.  Allow if it is the
                    # start of defined code bytes.
                    flags = ida_bytes.get_flags(ptr_val)
                    if not ida_bytes.is_code(flags):
                        break

                target_name = _get_func_name_at(ptr_val) or ea_str(ptr_val)
                targets.append({
                    "ea": ptr_val,
                    "name": target_name,
                })
                scan_ea += _PTR_SIZE

            entry_count = len(targets)
            if entry_count < _MIN_FPTR_TABLE_ENTRIES:
                ea += _PTR_SIZE
                continue

            table_end = table_start + entry_count * _PTR_SIZE
            processed_ranges.add((table_start, table_end))

            # Classify the table
            table_type = _classify_fptr_table(table_start, entry_count,
                                              targets, vtable_eas)

            # Find referencing code
            ref_funcs = _get_referencing_functions(table_start)

            tables.append({
                "ea": table_start,
                "entry_count": entry_count,
                "targets": targets,
                "referencing_functions": ref_funcs,
                "table_type": table_type,
                "segment": seg_name,
            })

            ea = table_end

    return tables


def _classify_fptr_table(ea, entry_count, targets, vtable_eas):
    """Classify a function pointer table as vtable, dispatch, callback, etc."""
    # Already known vtable?
    if ea in vtable_eas:
        return "vtable"

    # Check naming patterns
    name = ida_name.get_name(ea) or ""
    name_lower = name.lower()

    if "vtbl" in name_lower or "vftable" in name_lower or "??_7" in name:
        return "vtable"

    # Check if referenced by a switch/jump pattern
    refs = _get_xrefs_to(ea)
    for ref_ea in refs:
        # Look for indirect jump/call pattern
        insn_bytes = ida_bytes.get_bytes(ref_ea, 16)
        if insn_bytes:
            # jmp qword [reg + reg*8] or call qword [reg + reg*8]
            # These indicate switch dispatch
            if b'\xff' in insn_bytes[:2]:
                return "dispatch_table"

    # Heuristic: if many targets share a name prefix, likely dispatch
    prefixes = collections.Counter()
    for t in targets:
        tname = t["name"]
        if tname and not tname.startswith("0x"):
            parts = tname.split("_", 1)
            if len(parts) > 1:
                prefixes[parts[0]] += 1

    if prefixes:
        most_common_prefix, count = prefixes.most_common(1)[0]
        if count > entry_count * 0.5:
            return "dispatch_table"

    # Large tables with no clear pattern are likely vtables
    if entry_count >= 10:
        return "vtable_candidate"

    # Heuristic: if all targets are within a small code range, likely
    # event handler or callback array
    if targets:
        min_ea = min(t["ea"] for t in targets)
        max_ea = max(t["ea"] for t in targets)
        spread = max_ea - min_ea
        if spread < 0x10000:
            return "callback_array"

    return "function_pointer_array"


def _get_referencing_functions(ea):
    """Get list of functions that reference the given address."""
    ref_funcs = []
    seen = set()
    for xref_ea in _get_xrefs_to(ea):
        func = ida_funcs.get_func(xref_ea)
        if func and func.start_ea not in seen:
            seen.add(func.start_ea)
            fname = _get_func_name_at(func.start_ea) or ea_str(func.start_ea)
            ref_funcs.append({
                "ea": func.start_ea,
                "name": fname,
            })
    return ref_funcs


# ---------------------------------------------------------------------------
# Phase 2: Jump Table Recovery
# ---------------------------------------------------------------------------

def _scan_jump_tables(data_segments, text_seg):
    """Find switch statement jump tables in data segments.

    A jump table is an array of code addresses referenced by an indirect
    jump instruction (jmp [base + reg*8]).

    Returns a list of jump table descriptors.
    """
    jump_tables = []
    discovered_eas = set()

    # Strategy 1: Find jump tables by scanning for indirect jump xrefs
    # IDA marks switch info on functions; we can also scan data for
    # arrays of code pointers that are referenced by jmp instructions.
    for seg, seg_name in data_segments:
        ea = seg.start_ea
        end = seg.end_ea

        while ea + _PTR_SIZE <= end:
            val = _read_qword_safe(ea)
            if val is None or not _is_code_address(val, text_seg):
                ea += _PTR_SIZE
                continue

            # Check if this address is referenced by an indirect jump
            refs = _get_xrefs_to(ea)
            is_jump_target = False
            switch_func_ea = None

            for ref_ea in refs:
                func = ida_funcs.get_func(ref_ea)
                if func is None:
                    continue

                # Read the instruction at the reference site
                mnem = idc.print_insn_mnem(ref_ea)
                if mnem and mnem.lower() in ("jmp", "call"):
                    # Check if it is an indirect reference (table-based)
                    op_type = idc.get_operand_type(ref_ea, 0)
                    # o_mem (2) = direct memory ref, o_displ (4) = displacement
                    if op_type in (idc.o_mem, idc.o_displ, idc.o_phrase):
                        is_jump_target = True
                        switch_func_ea = func.start_ea
                        break

            if not is_jump_target:
                ea += _PTR_SIZE
                continue

            if ea in discovered_eas:
                ea += _PTR_SIZE
                continue

            # Count consecutive code pointer entries
            table_start = ea
            entry_count = 0
            scan_ea = ea

            while (scan_ea + _PTR_SIZE <= end and
                   entry_count < _MAX_JUMP_TABLE_ENTRIES):
                ptr_val = _read_qword_safe(scan_ea)
                if ptr_val is None or not _is_code_address(ptr_val, text_seg):
                    break
                entry_count += 1
                scan_ea += _PTR_SIZE

            if entry_count < _MIN_JUMP_TABLE_ENTRIES:
                ea += _PTR_SIZE
                continue

            discovered_eas.add(table_start)

            # Determine switch function
            switch_func_name = None
            if switch_func_ea:
                switch_func_name = _get_func_name_at(switch_func_ea)

            # Suggest an enum name based on entry count and context
            enum_suggestion = _suggest_enum_name(
                table_start, entry_count, switch_func_name
            )

            jump_tables.append({
                "ea": table_start,
                "entry_count": entry_count,
                "switch_function_ea": switch_func_ea,
                "switch_function_name": switch_func_name,
                "enum_name_suggestion": enum_suggestion,
                "segment": seg_name if seg_name else "data",
            })

            ea = table_start + entry_count * _PTR_SIZE

    # Strategy 2: Use IDA's switch info database
    _scan_ida_switch_info(jump_tables, discovered_eas, text_seg)

    return jump_tables


def _scan_ida_switch_info(jump_tables, discovered_eas, text_seg):
    """Supplement jump table discovery using IDA's built-in switch analysis."""
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if func is None:
            continue

        # Walk instructions in the function looking for switch info
        for head in idautils.Heads(func.start_ea, func.end_ea):
            si = idaapi.get_switch_info(head)
            if si is None:
                continue

            jump_table_ea = si.jumps
            if jump_table_ea in discovered_eas:
                continue
            if jump_table_ea == idaapi.BADADDR:
                continue

            discovered_eas.add(jump_table_ea)

            entry_count = si.get_jtable_size()
            if entry_count < _MIN_JUMP_TABLE_ENTRIES:
                continue

            switch_func_name = _get_func_name_at(func_ea)
            enum_suggestion = _suggest_enum_name(
                jump_table_ea, entry_count, switch_func_name
            )

            jump_tables.append({
                "ea": jump_table_ea,
                "entry_count": entry_count,
                "switch_function_ea": func_ea,
                "switch_function_name": switch_func_name,
                "enum_name_suggestion": enum_suggestion,
                "segment": "switch_info",
            })


def _suggest_enum_name(table_ea, entry_count, func_name):
    """Generate a suggested enum name from context."""
    if func_name:
        # Strip common prefixes
        clean = func_name
        for prefix in ("?", "sub_", "j_", "nullsub_"):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]

        # Extract meaningful parts
        # "HandleFoo" -> "FooType"
        if clean.startswith("Handle"):
            return clean[6:] + "Type"
        # "ProcessBarEvent" -> "BarEventType"
        if clean.startswith("Process"):
            return clean[7:] + "Type"
        # "OnBaz" -> "BazType"
        if clean.startswith("On"):
            return clean[2:] + "Type"

        return clean + f"_SwitchEnum_{entry_count}"

    return f"Enum_{ea_str(table_ea)}_{entry_count}"


# ---------------------------------------------------------------------------
# Phase 3: Const Data Array Detection
# ---------------------------------------------------------------------------

def _scan_const_arrays(data_segments, text_seg, fptr_table_ranges,
                       jump_table_ranges):
    """Detect arrays of non-pointer constant data in data segments.

    Looks for repeating patterns of consistent size -- arrays of integers,
    floats, pairs, triplets, or small structs.

    Returns a list of const array descriptors.
    """
    arrays = []

    for seg, seg_name in data_segments:
        # Only scan .rdata for const arrays (writable .data has globals)
        if seg_name not in (".rdata",):
            continue

        ea = seg.start_ea
        end = seg.end_ea
        msg_info(f"Scanning {seg_name} for const data arrays...")

        skip_ranges = set()
        for s, e in fptr_table_ranges:
            for addr in range(s, e, _PTR_SIZE):
                skip_ranges.add(addr)
        for s, e in jump_table_ranges:
            for addr in range(s, e, _PTR_SIZE):
                skip_ranges.add(addr)

        scan_ea = ea
        while scan_ea + 16 <= end:
            if scan_ea in skip_ranges:
                scan_ea += _PTR_SIZE
                continue

            # Try to detect a repeating pattern starting here
            result = _detect_repeating_pattern(scan_ea, end, text_seg,
                                               skip_ranges)
            if result:
                element_size, element_count, element_type, preview = result
                total_size = element_size * element_count

                arrays.append({
                    "ea": scan_ea,
                    "element_size": element_size,
                    "element_count": element_count,
                    "element_type": element_type,
                    "data_preview": preview,
                    "segment": seg_name,
                })

                scan_ea += total_size
            else:
                scan_ea += 4  # Advance by dword alignment

    return arrays


def _detect_repeating_pattern(ea, seg_end, text_seg, skip_ranges):
    """Try to detect a repeating data pattern starting at ea.

    Tests element sizes from 4 to _MAX_CONST_ELEMENT_SIZE.
    Returns (element_size, element_count, element_type, preview) or None.
    """
    # Quick reject: if this looks like a pointer, skip
    val = _read_qword_safe(ea)
    if val is not None and _is_code_address(val, text_seg):
        return None

    best = None

    for element_size in (4, 8, 12, 16, 20, 24, 32, 48, 64, 128):
        if ea + element_size * _MIN_CONST_ARRAY_ELEMENTS > seg_end:
            continue

        # Read the first element as a byte pattern
        first_bytes = ida_bytes.get_bytes(ea, element_size)
        if first_bytes is None:
            continue

        # Check if there is a repeating structural pattern
        count = _count_structurally_similar_elements(
            ea, element_size, seg_end, text_seg, skip_ranges
        )

        if count >= _MIN_CONST_ARRAY_ELEMENTS:
            element_type = _classify_element(ea, element_size, text_seg)

            # Generate a small preview of the first few elements
            preview = _generate_element_preview(ea, element_size, count,
                                                element_type)

            if best is None or count > best[1]:
                best = (element_size, count, element_type, preview)

    return best


def _count_structurally_similar_elements(ea, element_size, seg_end, text_seg,
                                         skip_ranges):
    """Count how many consecutive elements of element_size share a
    structural similarity (same pattern of pointer vs non-pointer fields,
    similar magnitude ranges)."""
    if element_size < 4:
        return 0

    # Build a "field type signature" for the first element
    first_sig = _element_field_signature(ea, element_size, text_seg)
    if first_sig is None:
        return 0

    count = 1
    scan_ea = ea + element_size
    max_elements = min((_MAX_JUMP_TABLE_ENTRIES,
                        (seg_end - ea) // element_size))

    while count < max_elements and scan_ea + element_size <= seg_end:
        if scan_ea in skip_ranges:
            break

        sig = _element_field_signature(scan_ea, element_size, text_seg)
        if sig != first_sig:
            break

        count += 1
        scan_ea += element_size

    return count


def _element_field_signature(ea, element_size, text_seg):
    """Create a structural signature for an element: a string describing
    the type of each aligned field (P=pointer, I=integer, F=float, Z=zero)."""
    sig_parts = []
    offset = 0

    while offset < element_size:
        remaining = element_size - offset

        if remaining >= 8:
            val = _read_qword_safe(ea + offset)
            if val is None:
                return None

            if val == 0:
                sig_parts.append('Z8')
            elif _is_code_address(val, text_seg):
                sig_parts.append('P')
            elif val > 0x10000000000:
                sig_parts.append('Q')  # Large qword, possibly data pointer
            else:
                sig_parts.append('Q')
            offset += 8
        elif remaining >= 4:
            val = _read_dword_safe(ea + offset)
            if val is None:
                return None

            fval = _read_float_safe(ea + offset)
            if (fval is not None and
                    abs(fval) > 1e-10 and abs(fval) < 1e10 and
                    val != 0):
                sig_parts.append('F')
            elif val == 0:
                sig_parts.append('Z4')
            else:
                sig_parts.append('I')
            offset += 4
        else:
            offset += remaining
            sig_parts.append('B')

    return '|'.join(sig_parts)


def _classify_element(ea, element_size, text_seg):
    """Classify the type of a const array element."""
    if element_size == 4:
        fval = _read_float_safe(ea)
        ival = _read_dword_safe(ea)
        if (fval is not None and ival is not None and
                ival != 0 and abs(fval) > 1e-10 and abs(fval) < 1e10):
            # Check if all elements look like valid floats
            return "float"
        return "int32"

    if element_size == 8:
        val = _read_qword_safe(ea)
        if val is not None and _is_code_address(val, text_seg):
            return "code_pointer"
        return "int64"

    if element_size == 12:
        # Could be a float triple (vector3) or int triple
        f1 = _read_float_safe(ea)
        f2 = _read_float_safe(ea + 4)
        f3 = _read_float_safe(ea + 8)
        if (f1 is not None and f2 is not None and f3 is not None and
                all(abs(f) < 1e6 for f in (f1, f2, f3) if f != 0)):
            return "float3"
        return "struct12"

    if element_size == 16:
        f1 = _read_float_safe(ea)
        f2 = _read_float_safe(ea + 4)
        f3 = _read_float_safe(ea + 8)
        f4 = _read_float_safe(ea + 12)
        if (f1 is not None and f2 is not None and
                f3 is not None and f4 is not None and
                all(abs(f) < 1e6 for f in (f1, f2, f3, f4) if f != 0)):
            return "float4"
        return "struct16"

    return f"struct{element_size}"


def _generate_element_preview(ea, element_size, count, element_type):
    """Generate a human-readable preview of the first few elements."""
    preview = []
    max_preview = min(count, 5)

    for i in range(max_preview):
        elem_ea = ea + i * element_size

        if element_type == "float":
            val = _read_float_safe(elem_ea)
            preview.append(f"[{i}] {val:.6f}" if val is not None else f"[{i}] ???")

        elif element_type == "int32":
            val = _read_dword_safe(elem_ea)
            if val is not None:
                preview.append(f"[{i}] {val} (0x{val:X})")
            else:
                preview.append(f"[{i}] ???")

        elif element_type == "int64":
            val = _read_qword_safe(elem_ea)
            if val is not None:
                preview.append(f"[{i}] {val} (0x{val:X})")
            else:
                preview.append(f"[{i}] ???")

        elif element_type == "float3":
            f1 = _read_float_safe(elem_ea)
            f2 = _read_float_safe(elem_ea + 4)
            f3 = _read_float_safe(elem_ea + 8)
            preview.append(f"[{i}] ({f1:.3f}, {f2:.3f}, {f3:.3f})")

        elif element_type == "float4":
            f1 = _read_float_safe(elem_ea)
            f2 = _read_float_safe(elem_ea + 4)
            f3 = _read_float_safe(elem_ea + 8)
            f4 = _read_float_safe(elem_ea + 12)
            preview.append(f"[{i}] ({f1:.3f}, {f2:.3f}, {f3:.3f}, {f4:.3f})")

        else:
            # Generic struct preview: show raw bytes
            raw = ida_bytes.get_bytes(elem_ea, min(element_size, 32))
            if raw:
                hex_str = raw.hex()
                preview.append(f"[{i}] {hex_str}")
            else:
                preview.append(f"[{i}] ???")

    if count > max_preview:
        preview.append(f"... ({count - max_preview} more)")

    return preview


# ---------------------------------------------------------------------------
# Phase 4: String Table Detection
# ---------------------------------------------------------------------------

def _scan_string_tables(data_segments, text_seg):
    """Find arrays of pointers that all point to string data.

    These are typically enum-to-string mappings or debug name tables.

    Returns a list of string table descriptors.
    """
    string_tables = []
    discovered_eas = set()

    for seg, seg_name in data_segments:
        ea = seg.start_ea
        end = seg.end_ea
        msg_info(f"Scanning {seg_name} for string tables...")

        while ea + _PTR_SIZE <= end:
            if ea in discovered_eas:
                ea += _PTR_SIZE
                continue

            val = _read_qword_safe(ea)
            if val is None:
                ea += _PTR_SIZE
                continue

            # Check if this pointer targets a string
            s = _get_string_at(val)
            if s is None or len(s) < 1:
                ea += _PTR_SIZE
                continue

            # Found one string pointer; scan for consecutive string pointers
            table_start = ea
            strings = []
            scan_ea = ea

            while scan_ea + _PTR_SIZE <= end:
                ptr_val = _read_qword_safe(scan_ea)
                if ptr_val is None:
                    break

                # Allow NULL pointers in string tables (represent gaps)
                if ptr_val == 0:
                    strings.append({
                        "index": len(strings),
                        "value": None,
                        "ea": 0,
                    })
                    scan_ea += _PTR_SIZE
                    continue

                str_val = _get_string_at(ptr_val)
                if str_val is None:
                    break

                strings.append({
                    "index": len(strings),
                    "value": str_val,
                    "ea": ptr_val,
                })
                scan_ea += _PTR_SIZE

            if len(strings) < _MIN_STRING_TABLE_ENTRIES:
                ea += _PTR_SIZE
                continue

            # Filter: at least 60% must be non-null strings
            non_null = sum(1 for s in strings if s["value"] is not None)
            if non_null < len(strings) * 0.6:
                ea += _PTR_SIZE
                continue

            table_end = table_start + len(strings) * _PTR_SIZE
            for addr in range(table_start, table_end, _PTR_SIZE):
                discovered_eas.add(addr)

            # Generate enum suggestion from string patterns
            enum_suggestion = _suggest_string_enum(table_start, strings)

            # Find referencing code
            ref_funcs = _get_referencing_functions(table_start)

            # Truncate strings list for storage (keep first 100 and
            # strip very long string values)
            stored_strings = []
            for entry in strings[:200]:
                stored = dict(entry)
                if stored["value"] and len(stored["value"]) > 200:
                    stored["value"] = stored["value"][:200] + "..."
                stored_strings.append(stored)

            string_tables.append({
                "ea": table_start,
                "string_count": len(strings),
                "strings": stored_strings,
                "enum_suggestion": enum_suggestion,
                "referencing_functions": ref_funcs,
                "segment": seg_name,
            })

            ea = table_end

    return string_tables


def _suggest_string_enum(table_ea, strings):
    """Suggest an enum name based on the string content patterns."""
    # Check for common prefix among non-null strings
    non_null = [s["value"] for s in strings if s["value"]]
    if not non_null:
        return f"StringTable_{ea_str(table_ea)}"

    # Find longest common prefix
    prefix = non_null[0]
    for s in non_null[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                break
        if not prefix:
            break

    if len(prefix) >= 3:
        # Clean up prefix: remove trailing underscore/space/separator
        prefix = prefix.rstrip("_- .")
        if prefix:
            return f"{prefix}Enum"

    # Check for a naming pattern from the table's own name
    table_name = ida_name.get_name(table_ea) or ""
    if table_name and not table_name.startswith("off_"):
        return table_name + "_Enum"

    # Fallback: check referencing function names
    refs = _get_xrefs_to(table_ea)
    for ref_ea in refs:
        func = ida_funcs.get_func(ref_ea)
        if func:
            fname = _get_func_name_at(func.start_ea)
            if fname:
                return fname + "_StringEnum"

    return f"StringTable_{ea_str(table_ea)}"


# ---------------------------------------------------------------------------
# Phase 5: Initialized Struct Detection
# ---------------------------------------------------------------------------

def _scan_initialized_structs(data_segments, text_seg, fptr_table_ranges,
                              jump_table_ranges, string_table_ranges):
    """Find initialized struct instances in .rdata: regions with mixed
    types (pointers + integers + floats) that represent default object
    state or configuration records.

    Returns a list of initialized struct descriptors.
    """
    structs = []
    exclusion_ranges = set()

    # Build exclusion set from already-classified regions
    for s, e in fptr_table_ranges:
        for addr in range(s, e, _PTR_SIZE):
            exclusion_ranges.add(addr)
    for s, e in jump_table_ranges:
        for addr in range(s, e, _PTR_SIZE):
            exclusion_ranges.add(addr)
    for s, e in string_table_ranges:
        for addr in range(s, e, _PTR_SIZE):
            exclusion_ranges.add(addr)

    for seg, seg_name in data_segments:
        if seg_name not in (".rdata",):
            continue

        ea = seg.start_ea
        end = seg.end_ea
        msg_info(f"Scanning {seg_name} for initialized structs...")

        while ea + 16 <= end:
            if ea in exclusion_ranges:
                ea += _PTR_SIZE
                continue

            # Try to identify a struct-like region with mixed types
            result = _detect_initialized_struct(ea, end, text_seg,
                                                exclusion_ranges)
            if result:
                size, field_types, matching_layout = result

                structs.append({
                    "ea": ea,
                    "size": size,
                    "field_types": field_types,
                    "matching_layout": matching_layout,
                    "segment": seg_name,
                })

                ea += size
            else:
                ea += _PTR_SIZE

    return structs


def _detect_initialized_struct(ea, seg_end, text_seg, exclusion_ranges):
    """Attempt to detect an initialized struct at ea.

    Looks for a region with mixed field types: at least two different
    type categories among {pointer, integer, float, zero}.

    Returns (size, field_types, matching_layout) or None.
    """
    fields = []
    offset = 0
    max_size = min(512, seg_end - ea)
    type_categories = set()

    while offset < max_size:
        field_ea = ea + offset

        if field_ea in exclusion_ranges:
            break

        if not ida_bytes.is_loaded(field_ea):
            break

        remaining = max_size - offset

        # Try to identify field type at current offset
        if remaining >= 8:
            qval = _read_qword_safe(field_ea)
            if qval is not None:
                if _is_code_address(qval, text_seg):
                    fields.append({
                        "offset": offset,
                        "size": 8,
                        "type": "code_pointer",
                        "value": ea_str(qval),
                    })
                    type_categories.add("pointer")
                    offset += 8
                    continue

                # Check if it looks like a data pointer (high bits set,
                # typical VA range)
                if qval > 0x100000 and qval < 0x7FFFFFFFFFFF:
                    s = _get_string_at(qval)
                    if s:
                        fields.append({
                            "offset": offset,
                            "size": 8,
                            "type": "string_pointer",
                            "value": s[:80],
                        })
                        type_categories.add("pointer")
                        offset += 8
                        continue

                    fields.append({
                        "offset": offset,
                        "size": 8,
                        "type": "data_pointer",
                        "value": ea_str(qval),
                    })
                    type_categories.add("pointer")
                    offset += 8
                    continue

        # Try as dword
        if remaining >= 4:
            dval = _read_dword_safe(field_ea)
            if dval is not None:
                fval = _read_float_safe(field_ea)
                if (fval is not None and dval != 0 and
                        abs(fval) > 1e-10 and abs(fval) < 1e10 and
                        # Reject values that look like reasonable integers
                        # but happen to parse as floats
                        not (dval < 0x10000 and dval == int(dval))):
                    fields.append({
                        "offset": offset,
                        "size": 4,
                        "type": "float",
                        "value": f"{fval:.6f}",
                    })
                    type_categories.add("float")
                    offset += 4
                    continue

                if dval == 0:
                    fields.append({
                        "offset": offset,
                        "size": 4,
                        "type": "zero",
                        "value": "0",
                    })
                    type_categories.add("zero")
                    offset += 4
                    continue

                fields.append({
                    "offset": offset,
                    "size": 4,
                    "type": "int32",
                    "value": f"{dval} (0x{dval:X})",
                })
                type_categories.add("integer")
                offset += 4
                continue

        # Remaining bytes
        offset += 1

    if len(fields) < _MIN_STRUCT_FIELDS:
        return None

    # Require at least 2 different type categories for it to be "interesting"
    # (pure int arrays are caught by const array detection)
    meaningful_types = type_categories - {"zero"}
    if len(meaningful_types) < 2:
        return None

    total_size = offset
    if total_size < 16:
        return None

    # Align to 8 bytes
    total_size = (total_size + 7) & ~7

    # Try to match against a known layout name from cross-references
    matching_layout = _match_struct_layout(ea, fields)

    field_type_list = [f["type"] for f in fields]

    return (total_size, field_type_list, matching_layout)


def _match_struct_layout(ea, fields):
    """Try to match a struct's field layout against known object layouts.
    Returns a suggested layout name or None."""
    # Check for xrefs that might indicate the struct's type
    refs = _get_xrefs_to(ea)
    for ref_ea in refs:
        func = ida_funcs.get_func(ref_ea)
        if func:
            fname = _get_func_name_at(func.start_ea)
            if fname:
                # Common patterns: "CClassName::Init" referencing default data
                match = re.match(r'(C[A-Z]\w+)::(\w+)', fname)
                if match:
                    return match.group(1)

    # Check the data label itself
    name = ida_name.get_name(ea) or ""
    if name and not name.startswith("unk_") and not name.startswith("stru_"):
        return name

    return None


# ---------------------------------------------------------------------------
# Phase 6: Global Variable Classification
# ---------------------------------------------------------------------------

def _scan_global_variables(data_segments, text_seg):
    """Classify global variables in the .data section.

    For each defined data item in .data, determines:
      - Access pattern: read-only (config), read-write (state),
        write-once (init)
      - Accessor functions
      - Whether it is a singleton pointer
      - System classification

    Returns a list of global variable descriptors.
    """
    globals_list = []
    _MAX_GLOBALS = 50000  # Safety cap to prevent OOM on huge .data sections

    for seg, seg_name in data_segments:
        if seg_name != ".data":
            continue

        ea = seg.start_ea
        end = seg.end_ea
        msg_info(f"Scanning {seg_name} for global variables...")

        processed = set()

        while ea < end:
            if len(globals_list) >= _MAX_GLOBALS:
                msg_warn(f"  Global variable scan capped at {_MAX_GLOBALS}")
                break

            if ea in processed:
                ea += _PTR_SIZE
                continue

            # Skip undefined/uninitialized regions
            flags = ida_bytes.get_flags(ea)
            if not ida_bytes.is_loaded(ea):
                ea += 1
                continue

            # Determine the size of this data item
            item_size = ida_bytes.get_item_size(ea)
            if item_size <= 0:
                item_size = _PTR_SIZE

            # Get all xrefs to this global
            all_refs = _get_xrefs_to(ea)
            if not all_refs:
                # No references -- skip uninteresting globals
                ea += max(item_size, _PTR_SIZE)
                continue

            processed.add(ea)

            # Classify the access pattern
            access_type, accessor_functions = _classify_global_access(
                ea, all_refs
            )

            # Determine if it is a singleton (pointer to object)
            is_singleton = False
            val = _read_qword_safe(ea)
            if (item_size == _PTR_SIZE and val is not None and
                    val > 0x10000 and val < 0x7FFFFFFFFFFF):
                is_singleton = True

            # Get variable name and classify system
            var_name = ida_name.get_name(ea) or ea_str(ea)
            system = _classify_system(var_name)

            globals_list.append({
                "ea": ea,
                "size": item_size,
                "access_type": access_type,
                "accessor_count": len(all_refs),
                "accessor_functions": accessor_functions[:10],  # Cap at 10
                "is_singleton": is_singleton,
                "name": var_name,
                "system": system,
            })

            ea += max(item_size, _PTR_SIZE)

    return globals_list


def _classify_global_access(ea, refs):
    """Classify how a global variable is accessed.

    Examines the instructions at each reference site to determine if
    the reference is a read (mov reg, [global]) or write (mov [global], reg).

    Returns (access_type, accessor_functions) where access_type is one of:
      "read_only", "write_once", "read_write", "unknown"
    """
    reads = 0
    writes = 0
    accessor_functions = []
    seen_funcs = set()

    for ref_ea in refs:
        func = ida_funcs.get_func(ref_ea)
        if func and func.start_ea not in seen_funcs:
            seen_funcs.add(func.start_ea)
            fname = _get_func_name_at(func.start_ea) or ea_str(func.start_ea)
            accessor_functions.append({
                "ea": func.start_ea,
                "name": fname,
            })

        # Analyze the instruction at the reference site
        mnem = idc.print_insn_mnem(ref_ea)
        if not mnem:
            continue

        mnem_lower = mnem.lower()

        if mnem_lower in ("mov", "movzx", "movsx", "movsxd", "movsd",
                          "movss", "movaps", "movups", "movdqa"):
            # Check if the global is the destination (write) or source (read)
            op0_type = idc.get_operand_type(ref_ea, 0)
            op1_type = idc.get_operand_type(ref_ea, 1)

            # If operand 0 is a memory reference to our global, it is a write
            if op0_type == idc.o_mem:
                op0_addr = idc.get_operand_value(ref_ea, 0)
                if op0_addr == ea:
                    writes += 1
                    continue

            # If operand 1 is a memory reference to our global, it is a read
            if op1_type == idc.o_mem:
                op1_addr = idc.get_operand_value(ref_ea, 1)
                if op1_addr == ea:
                    reads += 1
                    continue

        elif mnem_lower in ("lea",):
            reads += 1  # LEA takes address, treat as read
        elif mnem_lower in ("cmp", "test"):
            reads += 1
        elif mnem_lower in ("add", "sub", "inc", "dec", "or", "and", "xor",
                            "xadd", "xchg", "lock"):
            writes += 1
            reads += 1  # Read-modify-write

    # Classify
    if writes == 0 and reads > 0:
        access_type = "read_only"
    elif writes == 1 and reads >= 0:
        access_type = "write_once"
    elif writes > 0 and reads > 0:
        access_type = "read_write"
    elif writes > 0 and reads == 0:
        access_type = "write_only"
    else:
        access_type = "unknown"

    return access_type, accessor_functions


# ---------------------------------------------------------------------------
# Phase 7: Cross-Reference Enrichment
# ---------------------------------------------------------------------------

def _enrich_cross_references(fptr_tables, jump_tables, const_arrays,
                             string_tables, initialized_structs, globals_list):
    """For each discovered table/structure, analyze how it is indexed
    and generate additional metadata.

    Modifies the input lists in-place to add enrichment fields.
    """
    msg_info("Enriching cross-references...")

    # Enrich function pointer tables
    for table in fptr_tables:
        table_ea = table["ea"]
        entry_count = table["entry_count"]

        # Determine indexing pattern
        indexing = _determine_indexing_pattern(table_ea, entry_count)
        table["indexing_pattern"] = indexing

        # Suggest enum from entry count
        if entry_count >= 3 and entry_count <= 512:
            table["enum_size_suggestion"] = entry_count

    # Enrich jump tables with case value ranges
    for jt in jump_tables:
        jt_ea = jt["ea"]
        entry_count = jt["entry_count"]
        jt["indexing_pattern"] = "direct_index"
        jt["enum_size_suggestion"] = entry_count

    # Enrich const arrays
    for arr in const_arrays:
        arr_ea = arr["ea"]
        ref_funcs = _get_referencing_functions(arr_ea)
        arr["referencing_functions"] = ref_funcs

        indexing = _determine_indexing_pattern(arr_ea, arr["element_count"])
        arr["indexing_pattern"] = indexing

    # Enrich string tables
    for st in string_tables:
        st_ea = st["ea"]
        entry_count = st["string_count"]

        indexing = _determine_indexing_pattern(st_ea, entry_count)
        st["indexing_pattern"] = indexing

        if entry_count >= 3 and entry_count <= 512:
            st["enum_size_suggestion"] = entry_count

    # Enrich initialized structs
    for s in initialized_structs:
        ref_funcs = _get_referencing_functions(s["ea"])
        s["referencing_functions"] = ref_funcs

    # Enrich globals with system classification from accessor names
    for g in globals_list:
        if g["system"] == "Unknown" and g.get("accessor_functions"):
            for acc in g["accessor_functions"]:
                sys = _classify_system(acc["name"])
                if sys != "Unknown":
                    g["system"] = sys
                    break


def _determine_indexing_pattern(table_ea, entry_count):
    """Determine how a table is indexed by examining referencing code.

    Returns one of: "direct_index", "hash_lookup", "linear_search",
    "unknown".
    """
    refs = _get_xrefs_to(table_ea)

    for ref_ea in refs:
        # Look at the instruction
        mnem = idc.print_insn_mnem(ref_ea)
        if not mnem:
            continue

        mnem_lower = mnem.lower()

        # Direct index: mov reg, [table + reg*8]
        if mnem_lower in ("mov", "lea", "call", "jmp"):
            # Check for scaled index operand
            op_str = idc.print_operand(ref_ea, 0) + " " + idc.print_operand(ref_ea, 1)
            if "*8" in op_str or "*4" in op_str:
                return "direct_index"

        # Indirect jump through table
        if mnem_lower == "jmp":
            return "direct_index"

    # Check for loop patterns around the reference (linear search)
    for ref_ea in refs:
        func = ida_funcs.get_func(ref_ea)
        if func is None:
            continue

        # Look for a compare-and-branch pattern near the reference
        for head in range(max(ref_ea - 32, func.start_ea),
                          min(ref_ea + 32, func.end_ea)):
            mnem = idc.print_insn_mnem(head)
            if mnem and mnem.lower() in ("cmp", "test"):
                # Found a comparison near the table access
                # Check for a loop back
                for h2 in range(head, min(head + 20, func.end_ea)):
                    m2 = idc.print_insn_mnem(h2)
                    if m2 and m2.lower() in ("jl", "jle", "jb", "jbe",
                                             "jnz", "jne", "loop"):
                        return "linear_search"

    return "unknown"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def mine_data_sections(session):
    """Systematically mine .rdata and .data sections for structured data.

    Discovers function pointer tables, jump tables, const data arrays,
    string tables, initialized structs, and global variables.

    Args:
        session: PluginSession with db and cfg attributes.

    Returns:
        Total count of tables and structures found.
    """
    start_time = time.time()
    msg("=" * 70)
    msg("Data Section Archaeology -- Mining structured data")
    msg("=" * 70)

    # Get segment information
    text_seg = _get_text_segment()
    if text_seg is None:
        msg_error("Cannot find .text segment -- aborting")
        return 0

    data_segments = _get_data_segments()
    if not data_segments:
        msg_error("Cannot find any data segments -- aborting")
        return 0

    msg_info(f"Text segment: {ea_str(text_seg.start_ea)} - "
             f"{ea_str(text_seg.end_ea)}")
    for seg, name in data_segments:
        size_kb = (seg.end_ea - seg.start_ea) / 1024
        msg_info(f"Data segment: {name} @ {ea_str(seg.start_ea)} - "
                 f"{ea_str(seg.end_ea)} ({size_kb:.0f} KB)")

    # Get known vtable addresses to avoid re-classifying them
    vtable_eas = _get_existing_vtable_eas(session)
    msg_info(f"Known vtables: {len(vtable_eas)}")

    # ── Phase 1: Function pointer tables ──────────────────────────────
    msg("")
    msg("Phase 1: Scanning for function pointer tables...")
    fptr_tables = _scan_function_pointer_tables(data_segments, text_seg,
                                                vtable_eas)
    msg_info(f"Found {len(fptr_tables)} function pointer tables")

    fptr_ranges = []
    for t in fptr_tables:
        fptr_ranges.append(
            (t["ea"], t["ea"] + t["entry_count"] * _PTR_SIZE)
        )

    # ── Phase 2: Jump tables ──────────────────────────────────────────
    msg("")
    msg("Phase 2: Recovering jump tables...")
    jump_tables = _scan_jump_tables(data_segments, text_seg)
    msg_info(f"Found {len(jump_tables)} jump tables")

    jt_ranges = []
    for jt in jump_tables:
        jt_ranges.append(
            (jt["ea"], jt["ea"] + jt["entry_count"] * _PTR_SIZE)
        )

    # ── Phase 3: Const data arrays ────────────────────────────────────
    msg("")
    msg("Phase 3: Detecting const data arrays...")
    const_arrays = _scan_const_arrays(data_segments, text_seg,
                                      fptr_ranges, jt_ranges)
    msg_info(f"Found {len(const_arrays)} const data arrays")

    # ── Phase 4: String tables ────────────────────────────────────────
    msg("")
    msg("Phase 4: Scanning for string tables...")
    string_tables = _scan_string_tables(data_segments, text_seg)
    msg_info(f"Found {len(string_tables)} string tables")

    st_ranges = []
    for st in string_tables:
        st_ranges.append(
            (st["ea"], st["ea"] + st["string_count"] * _PTR_SIZE)
        )

    # ── Phase 5: Initialized structs ──────────────────────────────────
    msg("")
    msg("Phase 5: Detecting initialized struct instances...")
    initialized_structs = _scan_initialized_structs(
        data_segments, text_seg, fptr_ranges, jt_ranges, st_ranges
    )
    msg_info(f"Found {len(initialized_structs)} initialized struct instances")

    # ── Phase 6: Global variables ─────────────────────────────────────
    msg("")
    msg("Phase 6: Classifying global variables...")
    globals_list = _scan_global_variables(data_segments, text_seg)
    msg_info(f"Classified {len(globals_list)} global variables")

    # ── Phase 7: Cross-reference enrichment ───────────────────────────
    msg("")
    msg("Phase 7: Enriching cross-references...")
    _enrich_cross_references(fptr_tables, jump_tables, const_arrays,
                             string_tables, initialized_structs, globals_list)

    # ── Summarize and store ───────────────────────────────────────────
    total_tables = (len(fptr_tables) + len(jump_tables) +
                    len(const_arrays) + len(string_tables) +
                    len(initialized_structs))
    total_globals = len(globals_list)

    # Print summary statistics
    msg("")
    msg("=" * 70)
    msg("Data Section Archaeology Results")
    msg("=" * 70)
    msg(f"  Function pointer tables: {len(fptr_tables)}")
    _print_fptr_table_summary(fptr_tables)
    msg(f"  Jump tables:             {len(jump_tables)}")
    _print_jump_table_summary(jump_tables)
    msg(f"  Const data arrays:       {len(const_arrays)}")
    _print_const_array_summary(const_arrays)
    msg(f"  String tables:           {len(string_tables)}")
    _print_string_table_summary(string_tables)
    msg(f"  Initialized structs:     {len(initialized_structs)}")
    msg(f"  Global variables:        {len(globals_list)}")
    _print_global_summary(globals_list)
    msg(f"  ---")
    msg(f"  Total tables/structs:    {total_tables}")
    msg(f"  Total globals:           {total_globals}")

    elapsed = time.time() - start_time
    msg(f"  Elapsed time:            {elapsed:.1f}s")

    # Convert addresses to strings for JSON serialization
    serializable_fptr = _serialize_fptr_tables(fptr_tables)
    serializable_jt = _serialize_jump_tables(jump_tables)
    serializable_ca = _serialize_const_arrays(const_arrays)
    serializable_st = _serialize_string_tables(string_tables)
    serializable_is = _serialize_initialized_structs(initialized_structs)
    serializable_gl = _serialize_globals(globals_list)

    result = {
        "function_pointer_tables": serializable_fptr,
        "jump_tables": serializable_jt,
        "const_arrays": serializable_ca,
        "string_tables": serializable_st,
        "initialized_structs": serializable_is,
        "global_variables": serializable_gl,
        "total_tables": total_tables,
        "total_globals": total_globals,
        "elapsed_seconds": round(elapsed, 1),
    }

    session.db.kv_set("data_archaeology", result)
    session.db.commit()
    msg_info("Results stored in kv_store key 'data_archaeology'")

    return total_tables


# ---------------------------------------------------------------------------
# Summary printers
# ---------------------------------------------------------------------------

def _print_fptr_table_summary(tables):
    """Print a summary breakdown of function pointer table types."""
    type_counts = collections.Counter(t["table_type"] for t in tables)
    for ttype, count in type_counts.most_common():
        msg(f"    {ttype}: {count}")

    # Show the top 5 largest tables
    by_size = sorted(tables, key=lambda t: t["entry_count"], reverse=True)
    for t in by_size[:5]:
        name = ida_name.get_name(t["ea"]) or ea_str(t["ea"])
        msg(f"    Top: {name} ({t['entry_count']} entries, "
            f"{t['table_type']})")


def _print_jump_table_summary(tables):
    """Print a summary of jump tables."""
    if not tables:
        return
    sizes = [t["entry_count"] for t in tables]
    msg(f"    Entry counts: min={min(sizes)}, max={max(sizes)}, "
        f"avg={sum(sizes)/len(sizes):.0f}")
    # Top 5 with function names
    by_size = sorted(tables, key=lambda t: t["entry_count"], reverse=True)
    for t in by_size[:5]:
        fname = t.get("switch_function_name") or ea_str(t.get("switch_function_ea", 0))
        msg(f"    Top: {fname} ({t['entry_count']} cases)")


def _print_const_array_summary(arrays):
    """Print a summary of const data arrays."""
    if not arrays:
        return
    type_counts = collections.Counter(a["element_type"] for a in arrays)
    for etype, count in type_counts.most_common():
        msg(f"    {etype}: {count}")


def _print_string_table_summary(tables):
    """Print a summary of string tables."""
    if not tables:
        return
    for t in tables[:5]:
        name = ida_name.get_name(t["ea"]) or ea_str(t["ea"])
        non_null = sum(1 for s in t.get("strings", [])
                       if s.get("value") is not None)
        msg(f"    {name}: {t['string_count']} entries "
            f"({non_null} non-null)")
        # Show first 3 strings
        for s in t.get("strings", [])[:3]:
            if s.get("value"):
                val = s["value"][:60]
                msg(f"      [{s['index']}] \"{val}\"")


def _print_global_summary(globals_list):
    """Print a summary of global variables."""
    if not globals_list:
        return
    access_counts = collections.Counter(g["access_type"] for g in globals_list)
    for atype, count in access_counts.most_common():
        msg(f"    {atype}: {count}")

    system_counts = collections.Counter(g["system"] for g in globals_list)
    interesting_systems = [(s, c) for s, c in system_counts.most_common()
                           if s != "Unknown"]
    if interesting_systems:
        msg(f"    Systems with classified globals:")
        for sys, count in interesting_systems[:10]:
            msg(f"      {sys}: {count}")

    singletons = [g for g in globals_list if g.get("is_singleton")]
    if singletons:
        msg(f"    Singleton pointers: {len(singletons)}")
        for g in singletons[:5]:
            msg(f"      {g['name']}")


# ---------------------------------------------------------------------------
# Serialization helpers (convert addresses to hex strings for JSON)
# ---------------------------------------------------------------------------

def _serialize_fptr_tables(tables):
    """Serialize function pointer tables for JSON storage."""
    result = []
    for t in tables:
        entry = {
            "ea": ea_str(t["ea"]),
            "entry_count": t["entry_count"],
            "targets": [
                {"ea": ea_str(tgt["ea"]), "name": tgt["name"]}
                for tgt in t["targets"][:50]  # Cap stored targets
            ],
            "referencing_functions": [
                {"ea": ea_str(rf["ea"]), "name": rf["name"]}
                for rf in t.get("referencing_functions", [])
            ],
            "table_type": t["table_type"],
            "segment": t.get("segment", ""),
            "indexing_pattern": t.get("indexing_pattern", "unknown"),
        }
        if "enum_size_suggestion" in t:
            entry["enum_size_suggestion"] = t["enum_size_suggestion"]
        result.append(entry)
    return result


def _serialize_jump_tables(tables):
    """Serialize jump tables for JSON storage."""
    result = []
    for t in tables:
        entry = {
            "ea": ea_str(t["ea"]),
            "entry_count": t["entry_count"],
            "switch_function_ea": ea_str(t["switch_function_ea"])
                if t.get("switch_function_ea") else None,
            "switch_function_name": t.get("switch_function_name"),
            "enum_name_suggestion": t.get("enum_name_suggestion"),
            "segment": t.get("segment", ""),
            "indexing_pattern": t.get("indexing_pattern", "unknown"),
        }
        if "enum_size_suggestion" in t:
            entry["enum_size_suggestion"] = t["enum_size_suggestion"]
        result.append(entry)
    return result


def _serialize_const_arrays(arrays):
    """Serialize const data arrays for JSON storage."""
    result = []
    for a in arrays:
        entry = {
            "ea": ea_str(a["ea"]),
            "element_size": a["element_size"],
            "element_count": a["element_count"],
            "element_type": a["element_type"],
            "data_preview": a.get("data_preview", []),
            "segment": a.get("segment", ""),
            "indexing_pattern": a.get("indexing_pattern", "unknown"),
            "referencing_functions": [
                {"ea": ea_str(rf["ea"]), "name": rf["name"]}
                for rf in a.get("referencing_functions", [])
            ],
        }
        result.append(entry)
    return result


def _serialize_string_tables(tables):
    """Serialize string tables for JSON storage."""
    result = []
    for t in tables:
        entry = {
            "ea": ea_str(t["ea"]),
            "string_count": t["string_count"],
            "strings": [
                {
                    "index": s["index"],
                    "value": s["value"],
                }
                for s in t.get("strings", [])[:200]
            ],
            "enum_suggestion": t.get("enum_suggestion"),
            "referencing_functions": [
                {"ea": ea_str(rf["ea"]), "name": rf["name"]}
                for rf in t.get("referencing_functions", [])
            ],
            "segment": t.get("segment", ""),
            "indexing_pattern": t.get("indexing_pattern", "unknown"),
        }
        if "enum_size_suggestion" in t:
            entry["enum_size_suggestion"] = t["enum_size_suggestion"]
        result.append(entry)
    return result


def _serialize_initialized_structs(structs):
    """Serialize initialized struct instances for JSON storage."""
    result = []
    for s in structs:
        entry = {
            "ea": ea_str(s["ea"]),
            "size": s["size"],
            "field_types": s["field_types"],
            "matching_layout": s.get("matching_layout"),
            "segment": s.get("segment", ""),
            "referencing_functions": [
                {"ea": ea_str(rf["ea"]), "name": rf["name"]}
                for rf in s.get("referencing_functions", [])
            ],
        }
        result.append(entry)
    return result


def _serialize_globals(globals_list):
    """Serialize global variables for JSON storage."""
    result = []
    for g in globals_list:
        entry = {
            "ea": ea_str(g["ea"]),
            "size": g["size"],
            "access_type": g["access_type"],
            "accessor_count": g["accessor_count"],
            "name": g.get("name", ""),
            "system": g.get("system", "Unknown"),
            "is_singleton": g.get("is_singleton", False),
        }
        result.append(entry)
    return result


# ---------------------------------------------------------------------------
# Public helper: retrieve stored results
# ---------------------------------------------------------------------------

def get_data_archaeology(session):
    """Retrieve previously stored data archaeology results.

    Args:
        session: PluginSession with db attribute.

    Returns:
        dict with all archaeology results, or None if not yet run.
    """
    return session.db.kv_get("data_archaeology")
