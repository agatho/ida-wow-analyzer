"""
JAM Message Structure Recovery
Decompiles serializer/deserializer functions to extract field layouts
for JAM wire format types (JamCliHouse, JamCliNeighborhood, etc.).
"""

import json
import re

import ida_funcs
import ida_name
import ida_xref
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
    """Scan the binary for JAM serialization patterns."""
    # This will be fully implemented in Phase B
    msg_warn("JAM pattern scanning not yet implemented")
    return 0


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
