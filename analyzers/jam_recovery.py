"""
JAM Message Structure Recovery
Decompiles serializer/deserializer functions to extract field layouts
for JAM wire format types (JamCliHouse, JamCliNeighborhood, etc.).
"""

import json
import re

import ida_bytes
import ida_funcs
import ida_name
import ida_xref
import idc
import idaapi
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# Known serializer call patterns to identify field types
WRITE_PATTERNS = {
    "WriteUInt8": {"type": "uint8", "size": 1},
    "WriteUInt16": {"type": "uint16", "size": 2},
    "WriteUInt32": {"type": "uint32", "size": 4},
    "WriteUInt64": {"type": "uint64", "size": 8},
    "WriteInt8": {"type": "int8", "size": 1},
    "WriteInt16": {"type": "int16", "size": 2},
    "WriteInt32": {"type": "int32", "size": 4},
    "WriteInt64": {"type": "int64", "size": 8},
    "WriteFloat": {"type": "float", "size": 4},
    "WriteObjectGuid": {"type": "ObjectGuid", "size": 16},
    "WritePackedGuid": {"type": "PackedGuid", "size": 18},
    "WriteBits": {"type": "bits", "size": 0},
    "FlushBits": {"type": "flush", "size": 0},
    "WriteCString": {"type": "string", "size": 0},
}

READ_PATTERNS = {
    "ReadUInt8": {"type": "uint8", "size": 1},
    "ReadUInt16": {"type": "uint16", "size": 2},
    "ReadUInt32": {"type": "uint32", "size": 4},
    "ReadUInt64": {"type": "uint64", "size": 8},
    "ReadInt8": {"type": "int8", "size": 1},
    "ReadInt16": {"type": "int16", "size": 2},
    "ReadInt32": {"type": "int32", "size": 4},
    "ReadInt64": {"type": "int64", "size": 8},
    "ReadFloat": {"type": "float", "size": 4},
    "ReadObjectGuid": {"type": "ObjectGuid", "size": 16},
    "ReadPackedGuid": {"type": "PackedGuid", "size": 18},
    "ReadBits": {"type": "bits", "size": 0},
    "ReadCString": {"type": "string", "size": 0},
}


def analyze_jam_types(session):
    """Discover JAM types by scanning for serializer/deserializer patterns.

    Strategy:
      1. Find functions that call known Write*/Read* serializer functions
      2. Group them by the JAM type they operate on (from function name or caller)
      3. Decompile each serializer to extract field order and types
    """
    db = session.db
    cfg = session.cfg

    # First, import existing JAM type data if available
    import os
    extraction_dir = cfg.get("builds", str(cfg.build_number), "extraction_dir")
    if extraction_dir:
        jam_file = os.path.join(extraction_dir,
                                f"wow_jam_messages_{cfg.build_number}.json")
        if os.path.isfile(jam_file):
            return _import_jam_types_json(session, jam_file)

    msg_warn("No existing JAM extraction found — scanning binary")
    return _scan_for_jam_patterns(session)


def _import_jam_types_json(session, jam_file):
    """Import JAM types from the existing extraction JSON."""
    db = session.db
    cfg = session.cfg

    msg_info(f"Importing JAM types from {jam_file}")
    with open(jam_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    count = 0

    for category in ("client_messages", "server_messages", "shared_types"):
        messages = data.get(category, [])
        for m in messages:
            name = m.get("name", "")
            if not name:
                continue

            serializer_rva = m.get("function_rva") or m.get("code_rva")
            serializer_ea = None
            if serializer_rva:
                if isinstance(serializer_rva, str):
                    serializer_rva = int(serializer_rva, 16)
                serializer_ea = cfg.rva_to_ea(serializer_rva)

            handler_rva = m.get("handler_rva")
            deserializer_ea = None
            if handler_rva:
                if isinstance(handler_rva, str):
                    handler_rva = int(handler_rva, 16)
                deserializer_ea = cfg.rva_to_ea(handler_rva)

            db.upsert_jam_type(
                name=name,
                serializer_ea=serializer_ea,
                deserializer_ea=deserializer_ea,
                status="discovered",
            )
            count += 1

    db.commit()
    msg_info(f"Imported {count} JAM type definitions")
    return count


def _scan_for_jam_patterns(session):
    """Scan the binary for JAM serialization patterns.

    Discovers JAM serializer/deserializer functions by:
      1. Finding all functions named Write*/Read* from WRITE_PATTERNS/READ_PATTERNS
      2. Walking xrefs to find callers that invoke 3+ different Write/Read methods
      3. Extracting JAM type names from function names, string refs, and RTTI
      4. Classifying as serializer (Write*) or deserializer (Read*)
      5. Storing results via db.upsert_jam_type()
    """
    db = session.db

    # ── Step 1: Find all Write*/Read* target functions by scanning names ──
    write_targets = {}   # pattern_name -> list of ea
    read_targets = {}    # pattern_name -> list of ea
    all_pattern_names = set(WRITE_PATTERNS.keys()) | set(READ_PATTERNS.keys())

    msg_info("JAM scan: locating Write*/Read* functions...")
    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if not name:
            continue
        for pattern in WRITE_PATTERNS:
            if pattern in name:
                write_targets.setdefault(pattern, []).append(ea)
        for pattern in READ_PATTERNS:
            if pattern in name:
                read_targets.setdefault(pattern, []).append(ea)

    total_write = sum(len(v) for v in write_targets.values())
    total_read = sum(len(v) for v in read_targets.values())
    msg_info(f"JAM scan: found {total_write} Write functions across "
             f"{len(write_targets)} patterns, {total_read} Read functions "
             f"across {len(read_targets)} patterns")

    if total_write == 0 and total_read == 0:
        msg_warn("JAM scan: no Write*/Read* functions found in binary")
        return 0

    # ── Step 2: For each Write/Read function, find callers via xrefs ──
    # Track which Write/Read patterns each caller uses
    serializer_calls = {}    # caller_ea -> set of write pattern names
    deserializer_calls = {}  # caller_ea -> set of read pattern names

    msg_info("JAM scan: collecting xrefs to Write*/Read* functions...")
    exclude_eas = _all_target_eas(write_targets, read_targets)

    for pattern_name, ea_list in write_targets.items():
        for target_ea in ea_list:
            for xref in idautils.XrefsTo(target_ea, 0):
                caller = ida_funcs.get_func(xref.frm)
                if not caller:
                    continue
                caller_ea = caller.start_ea
                # Skip self-references (the Write/Read function itself)
                if caller_ea in exclude_eas:
                    continue
                serializer_calls.setdefault(caller_ea, set()).add(pattern_name)

    for pattern_name, ea_list in read_targets.items():
        for target_ea in ea_list:
            for xref in idautils.XrefsTo(target_ea, 0):
                caller = ida_funcs.get_func(xref.frm)
                if not caller:
                    continue
                caller_ea = caller.start_ea
                if caller_ea in exclude_eas:
                    continue
                deserializer_calls.setdefault(caller_ea, set()).add(pattern_name)

    msg_info(f"JAM scan: {len(serializer_calls)} potential serializer callers, "
             f"{len(deserializer_calls)} potential deserializer callers")

    # ── Step 3: Filter to functions calling 3+ distinct Write/Read methods ──
    MIN_DISTINCT_CALLS = 3

    serializer_candidates = {
        ea: patterns for ea, patterns in serializer_calls.items()
        if len(patterns) >= MIN_DISTINCT_CALLS
    }
    deserializer_candidates = {
        ea: patterns for ea, patterns in deserializer_calls.items()
        if len(patterns) >= MIN_DISTINCT_CALLS
    }

    msg_info(f"JAM scan: {len(serializer_candidates)} serializers and "
             f"{len(deserializer_candidates)} deserializers pass "
             f"{MIN_DISTINCT_CALLS}+ distinct call threshold")

    # ── Step 4: Identify JAM type names and store results ──
    # Merge serializers and deserializers, keyed by inferred JAM type name
    jam_types_found = {}  # name -> {serializer_ea, deserializer_ea}

    for ea, patterns in serializer_candidates.items():
        jam_name = _infer_jam_name(ea)
        if not jam_name:
            jam_name = f"UnknownJam_{ea:X}"
        entry = jam_types_found.setdefault(jam_name, {
            "serializer_ea": None,
            "deserializer_ea": None,
            "write_patterns": set(),
            "read_patterns": set(),
        })
        entry["serializer_ea"] = ea
        entry["write_patterns"] |= patterns

    for ea, patterns in deserializer_candidates.items():
        jam_name = _infer_jam_name(ea)
        if not jam_name:
            jam_name = f"UnknownJam_{ea:X}"
        entry = jam_types_found.setdefault(jam_name, {
            "serializer_ea": None,
            "deserializer_ea": None,
            "write_patterns": set(),
            "read_patterns": set(),
        })
        entry["deserializer_ea"] = ea
        entry["read_patterns"] |= patterns

    # ── Step 5: Store in database ──
    count = 0
    for jam_name, info in jam_types_found.items():
        db.upsert_jam_type(
            name=jam_name,
            serializer_ea=info["serializer_ea"],
            deserializer_ea=info["deserializer_ea"],
            field_count=len(info["write_patterns"]) + len(info["read_patterns"]),
            status="discovered",
        )
        count += 1

    db.commit()
    msg_info(f"JAM scan complete: discovered {count} JAM types "
             f"({len(serializer_candidates)} serializers, "
             f"{len(deserializer_candidates)} deserializers)")
    return count


def _all_target_eas(write_targets, read_targets):
    """Return set of all Write*/Read* function EAs to exclude from callers."""
    result = set()
    for ea_list in write_targets.values():
        result.update(ea_list)
    for ea_list in read_targets.values():
        result.update(ea_list)
    return result


def _infer_jam_name(func_ea):
    """Try to infer the JAM type name for a serializer/deserializer function.

    Strategies (in priority order):
      1. Function name contains a JAM prefix (JamCli*, JamSvr*, Jam*)
      2. Function name is meaningful (not sub_XXX) — derive from it
      3. String references in the function body contain JAM type names
      4. RTTI class name from vtable references in the function
    """
    # Strategy 1 & 2: Check function name
    func_name = ida_name.get_name(func_ea)
    if func_name and not func_name.startswith("sub_"):
        jam_name = _extract_jam_name_from_symbol(func_name)
        if jam_name:
            return jam_name

    # Strategy 3: Scan string references within the function body
    jam_name = _find_jam_name_in_strings(func_ea)
    if jam_name:
        return jam_name

    # Strategy 4: Check RTTI via vtable references
    jam_name = _find_jam_name_from_rtti(func_ea)
    if jam_name:
        return jam_name

    return None


# Regex to match JAM-prefixed identifiers in symbol names
_JAM_NAME_RE = re.compile(
    r'(Jam(?:Cli|Svr|Client|Server)?[A-Z][A-Za-z0-9_]+)'
)

# Regex to extract a type name from common serializer naming conventions
# e.g., "Serialize_HouseInfo", "Write_NeighborhoodData", "Read_JamCliHouse"
_SERIALIZE_FUNC_RE = re.compile(
    r'(?:Serialize|Deserialize|Write|Read|Pack|Unpack)'
    r'[_]?([A-Z][A-Za-z0-9_]+)'
)


def _extract_jam_name_from_symbol(func_name):
    """Extract a JAM type name from a function symbol.

    Handles patterns like:
      JamCliHouse::Serialize       -> JamCliHouse
      Serialize_JamCliNeighborhood -> JamCliNeighborhood
      JamSvrHouseResult::Read      -> JamSvrHouseResult
      HouseData::Write             -> HouseData
    """
    # Demangle if needed (C++ mangled names)
    demangled = ida_name.demangle_name(func_name, 0)
    name = demangled if demangled else func_name

    # Try to find JamXxx pattern first (highest confidence)
    m = _JAM_NAME_RE.search(name)
    if m:
        return m.group(1)

    # Try class::method pattern — extract the class name
    if "::" in name:
        class_part = name.split("::")[0]
        # Strip namespaces, take last component
        class_name = class_part.rsplit("::", 1)[-1].strip()
        if class_name and not class_name.startswith("sub_"):
            return class_name

    # Try Serialize_TypeName or Write_TypeName patterns
    m = _SERIALIZE_FUNC_RE.search(name)
    if m:
        return m.group(1)

    return None


def _find_jam_name_in_strings(func_ea):
    """Scan string references within a function for JAM type names.

    Looks at data references from each instruction head in the function,
    checking if any referenced string contains a Jam* prefix or common
    JAM error/assert patterns.
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    # Limit scan to avoid spending too long on huge functions
    max_heads = 500
    head_count = 0

    for head in idautils.Heads(func.start_ea, func.end_ea):
        head_count += 1
        if head_count > max_heads:
            break

        # Check data references from this instruction
        for xref in idautils.XrefsFrom(head, 0):
            # Only follow data references (not code)
            if xref.type not in (ida_xref.dr_O, ida_xref.dr_R, ida_xref.dr_W,
                                  ida_xref.dr_T, ida_xref.dr_I):
                # Also try any xref that points to a string
                pass

            str_val = _get_string_at(xref.to)
            if not str_val:
                continue

            # Look for JamXxx patterns in the string
            m = _JAM_NAME_RE.search(str_val)
            if m:
                return m.group(1)

    return None


def _get_string_at(ea):
    """Try to read a C string at the given address. Returns str or None."""
    try:
        s = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
        if s:
            return s.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _find_jam_name_from_rtti(func_ea):
    """Check if the function references a vtable with RTTI containing a JAM name.

    Looks for LEA instructions that load vtable pointers, then reads RTTI
    from the vtable's COL (Complete Object Locator) at vtable_ea - 8.
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    image_base = idaapi.get_imagebase()
    max_heads = 300
    head_count = 0

    for head in idautils.Heads(func.start_ea, func.end_ea):
        head_count += 1
        if head_count > max_heads:
            break

        for xref in idautils.XrefsFrom(head, 0):
            if xref.type not in (ida_xref.dr_O,):
                continue

            # Check if this is a vtable (has a COL pointer at ea - 8)
            rtti_name = _read_rtti_class_name(xref.to, image_base)
            if not rtti_name:
                continue

            m = _JAM_NAME_RE.search(rtti_name)
            if m:
                return m.group(1)

            # Even non-Jam RTTI names can be useful for naming
            if rtti_name and not rtti_name.startswith("sub_"):
                return rtti_name

    return None


def _read_rtti_class_name(vtable_ea, image_base):
    """Read MSVC RTTI class name from a vtable address.

    On x64 MSVC, the COL pointer is at vtable_ea - 8.
    Returns the demangled class name or None.
    """
    try:
        col_ptr = ida_bytes.get_qword(vtable_ea - 8)
        if col_ptr == 0 or col_ptr == idaapi.BADADDR:
            return None

        sig = ida_bytes.get_dword(col_ptr)
        if sig not in (0, 1):
            return None

        if sig == 1:  # x64 RVA-based
            td_rva = ida_bytes.get_dword(col_ptr + 12)
            td_ea = image_base + td_rva
            name_ea = td_ea + 16
        else:  # 32-bit absolute
            td_ptr = ida_bytes.get_qword(col_ptr + 16)
            if not td_ptr or td_ptr == idaapi.BADADDR:
                return None
            name_ea = td_ptr + 16

        raw = idc.get_strlit_contents(name_ea, -1, idc.STRTYPE_C)
        if not raw:
            return None

        raw_name = raw.decode("utf-8", errors="replace")
        return _demangle_rtti(raw_name)
    except Exception:
        return None


def _demangle_rtti(raw_name):
    """Demangle MSVC RTTI name like '.?AVJamCliHouse@@' -> 'JamCliHouse'."""
    if not raw_name:
        return None
    name = raw_name.lstrip(".?")
    if name[:2] in ("AV", "AU", "AT"):
        name = name[2:]
    # Remove trailing @@ and handle namespaces
    parts = name.split("@")
    parts = [p for p in parts if p]
    if not parts:
        return None
    # MSVC RTTI stores innermost name first, then outer namespaces
    # For JAM types we want the full qualified name
    if len(parts) == 1:
        return parts[0]
    # Reverse to get Namespace::ClassName order, join with ::
    return "::".join(reversed(parts))


def recover_jam_fields(session, jam_name):
    """Recover field layout for a specific JAM type by decompiling its serializer.

    Returns a list of field dicts: [{name, type, size, offset, is_optional}]
    """
    db = session.db
    row = db.fetchone("SELECT * FROM jam_types WHERE name = ?", (jam_name,))
    if not row:
        msg_error(f"JAM type '{jam_name}' not found in database")
        return []

    # Try serializer first, then deserializer
    target_ea = row["serializer_ea"] or row["deserializer_ea"]
    if not target_ea:
        msg_warn(f"No serializer/deserializer address for {jam_name}")
        return []

    msg_info(f"Decompiling {jam_name} serializer at {ea_str(target_ea)}...")
    pseudocode = get_decompiled_text(target_ea)
    if not pseudocode:
        msg_error(f"Decompilation failed for {ea_str(target_ea)}")
        return []

    # Parse the pseudocode for Write*/Read* calls to determine field layout
    fields = _parse_serializer_pseudocode(pseudocode)

    if fields:
        db.upsert_jam_type(
            name=jam_name,
            field_count=len(fields),
            fields_json=json.dumps(fields),
            status="fields_extracted",
        )
        db.commit()
        msg_info(f"Recovered {len(fields)} fields for {jam_name}")

    return fields


def _parse_serializer_pseudocode(pseudocode):
    """Parse decompiled pseudocode to extract field write/read operations.

    Looks for patterns like:
      WriteUInt32(stream, *(a1 + 0x48))
      WriteObjectGuid(stream, a1 + 8)
      WriteBits(stream, *(a1 + 0x24), 3)
    """
    fields = []
    offset = 0
    all_patterns = {}
    all_patterns.update(WRITE_PATTERNS)
    all_patterns.update(READ_PATTERNS)

    # Build regex: match function calls like WriteUInt32(..., offset_expr)
    pattern_names = "|".join(re.escape(p) for p in all_patterns)
    regex = re.compile(
        rf'({pattern_names})\s*\([^)]*\)',
        re.IGNORECASE
    )

    for match in regex.finditer(pseudocode):
        func_name = match.group(1)
        # Find the matching pattern
        for pat_name, pat_info in all_patterns.items():
            if func_name.lower() == pat_name.lower():
                if pat_info["type"] in ("flush",):
                    continue  # skip FlushBits, not a real field
                fields.append({
                    "index": len(fields),
                    "type": pat_info["type"],
                    "size": pat_info["size"],
                    "wire_offset": offset,
                    "name": f"field_{len(fields)}",
                    "is_optional": False,
                })
                offset += pat_info["size"]
                break

    return fields
