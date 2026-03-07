"""
DB2 Metadata Deep Analyzer
Parses DB2Meta structures from the WoW binary to extract complete
field type information for TrinityCore LoadInfo generation.
"""

import json
import struct

import ida_bytes
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# DB2Meta field type constants (from WoW binary)
DB2_FIELD_TYPE_INT8 = 0
DB2_FIELD_TYPE_INT16 = 1
DB2_FIELD_TYPE_INT32 = 2
DB2_FIELD_TYPE_INT64 = 3
DB2_FIELD_TYPE_FLOAT = 4
DB2_FIELD_TYPE_STRING = 5

FIELD_TYPE_NAMES = {
    DB2_FIELD_TYPE_INT8: "int8",
    DB2_FIELD_TYPE_INT16: "int16",
    DB2_FIELD_TYPE_INT32: "int32",
    DB2_FIELD_TYPE_INT64: "int64",
    DB2_FIELD_TYPE_FLOAT: "float",
    DB2_FIELD_TYPE_STRING: "string",
}

# TrinityCore FMeta type chars
TC_TYPE_CHARS = {
    DB2_FIELD_TYPE_INT8: "b",
    DB2_FIELD_TYPE_INT16: "h",
    DB2_FIELD_TYPE_INT32: "i",
    DB2_FIELD_TYPE_INT64: "l",
    DB2_FIELD_TYPE_FLOAT: "f",
    DB2_FIELD_TYPE_STRING: "s",
}


def analyze_db2_metadata(session):
    """Scan for DB2Meta structures in the binary and extract field metadata.

    DB2Meta structures are typically referenced by string names in .rdata.
    We locate them by finding functions that load DB2 tables and extracting
    the metadata pointer from the initialization calls.
    """
    db = session.db
    cfg = session.cfg

    # Strategy: Find all named DB2 metadata addresses from existing extractions
    extraction_dir = cfg.get("builds", str(cfg.build_number), "extraction_dir")
    if not extraction_dir:
        msg_warn("No extraction directory configured for current build")
        return _scan_for_db2_meta_patterns(session)

    import os
    meta_file = os.path.join(extraction_dir,
                             f"wow_db2_metadata_{cfg.build_number}.json")
    if not os.path.isfile(meta_file):
        msg_warn(f"DB2 metadata file not found: {meta_file}")
        return _scan_for_db2_meta_patterns(session)

    return _import_db2_metadata_json(session, meta_file)


def _import_db2_metadata_json(session, meta_file):
    """Import DB2 metadata from the existing extraction JSON."""
    db = session.db
    cfg = session.cfg

    msg_info(f"Importing DB2 metadata from {meta_file}")
    with open(meta_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    tables = data.get("tables", [])
    count = 0

    for table in tables:
        name = table.get("name", "")
        if not name:
            continue

        meta_rva = table.get("meta_rva")
        meta_ea = None
        if meta_rva:
            if isinstance(meta_rva, str):
                meta_rva = int(meta_rva, 16)
            meta_ea = cfg.rva_to_ea(meta_rva)

        db.upsert_db2_table(
            name=name,
            file_data_id=table.get("file_data_id"),
            layout_hash=table.get("layout_hash", 0),
            meta_rva=meta_rva,
            meta_ea=meta_ea,
            field_count=table.get("field_count", 0),
            record_size=table.get("record_size", 0),
            index_field=table.get("index_field", -1),
        )
        count += 1

    db.commit()
    msg_info(f"Imported {count} DB2 table definitions")
    return count


def _scan_for_db2_meta_patterns(session):
    """Scan the binary for DB2Meta structures using pattern matching.
    Fallback when no existing extraction is available."""
    msg_warn("DB2Meta pattern scanning not yet implemented")
    return 0


def parse_db2meta_at(ea, cfg):
    """Parse a DB2Meta structure at the given address.

    DB2Meta layout (approximate, may vary by build):
        uint32 fieldCount
        uint32 recordSize
        uint32 hotfixFieldCount
        uint32 indexField
        uint32 parentIndexField
        uint32 fieldOffsetsOffs  (relative pointer to field offsets array)
        uint32 fieldTypesOffs    (relative pointer to field types array)
        uint32 arraySizesOffs    (relative pointer to array sizes)
        uint32 flagsOffs         (relative pointer to signed flags)
    """
    fields = []

    try:
        field_count = ida_bytes.get_dword(ea)
        if field_count == 0 or field_count > 500:
            return None

        record_size = ida_bytes.get_dword(ea + 4)
        index_field = ida_bytes.get_dword(ea + 16)

        # This is a simplified parser — the exact offsets depend on the build
        # For a full implementation, we need to reverse the DB2Meta struct layout
        # for the specific build being analyzed

        return {
            "field_count": field_count,
            "record_size": record_size,
            "index_field": index_field,
            "fields": fields,
        }
    except Exception:
        return None


def generate_loadinfo(table_name, fields):
    """Generate TrinityCore LoadInfo C++ code for a DB2 table.

    Example output:
        static char const* const types = "iisfi";
        static uint8 const arraySizes[5] = {1, 1, 1, 1, 1};
    """
    if not fields:
        return f"// {table_name}: no field data available"

    type_chars = []
    array_sizes = []
    for f in fields:
        ftype = f.get("type", DB2_FIELD_TYPE_INT32)
        type_chars.append(TC_TYPE_CHARS.get(ftype, "i"))
        array_sizes.append(str(f.get("array_size", 1)))

    types_str = "".join(type_chars)
    arrays_str = ", ".join(array_sizes)

    return (
        f'// LoadInfo for {table_name}\n'
        f'static char const* const types = "{types_str}";\n'
        f'static uint8 const arraySizes[{len(fields)}] = {{{arrays_str}}};\n'
    )
