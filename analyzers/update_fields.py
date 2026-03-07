"""
Update Field Analyzer
Identifies WoW client object update field descriptor tables and extracts
field names, offsets, types, and sizes for TrinityCore UpdateFields generation.

Supports importing from existing wow_updatefields JSON extraction
and binary scanning for descriptor table pointers.
"""

import json
import os

import ida_bytes
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# Known WoW object types and their update field class names
OBJECT_TYPE_CLASSES = {
    "CGObject_C": "OBJECT",
    "CGItem_C": "ITEM",
    "CGContainer_C": "CONTAINER",
    "CGAzeriteEmpoweredItem_C": "AZERITE_EMPOWERED_ITEM",
    "CGAzeriteItem_C": "AZERITE_ITEM",
    "CGUnit_C": "UNIT",
    "CGPlayer_C": "PLAYER",
    "CGActivePlayer_C": "ACTIVE_PLAYER",
    "CGGameObject_C": "GAMEOBJECT",
    "CGDynamicObject_C": "DYNAMICOBJECT",
    "CGCorpse_C": "CORPSE",
    "CGAreaTrigger_C": "AREATRIGGER",
    "CGSceneObject_C": "SCENEOBJECT",
    "CGConversation_C": "CONVERSATION",
}

# TrinityCore update field type names
TC_UF_TYPES = {
    "int8": "UF_TYPE_INT",
    "int16": "UF_TYPE_INT",
    "int32": "UF_TYPE_INT",
    "int64": "UF_TYPE_TWO_SHORT",
    "uint8": "UF_TYPE_INT",
    "uint16": "UF_TYPE_INT",
    "uint32": "UF_TYPE_INT",
    "uint64": "UF_TYPE_TWO_SHORT",
    "float": "UF_TYPE_FLOAT",
    "guid": "UF_TYPE_GUID",
    "bytes": "UF_TYPE_BYTES",
}


def analyze_update_fields(session):
    """Discover update field descriptors from the binary.

    Strategy:
      1. Import from existing wow_updatefields JSON if available
      2. Try wow_object_layouts JSON as fallback
      3. Otherwise, scan for descriptor table patterns in .rdata
    """
    db = session.db
    cfg = session.cfg

    ext_dir = cfg.extraction_dir
    if ext_dir:
        for filename in [f"wow_updatefields_{cfg.build_number}.json", "wow_updatefields.json"]:
            filepath = os.path.join(ext_dir, filename)
            if os.path.isfile(filepath):
                return _import_update_fields_json(session, filepath)
        for filename in [f"wow_object_layouts_{cfg.build_number}.json", "wow_object_layouts.json"]:
            filepath = os.path.join(ext_dir, filename)
            if os.path.isfile(filepath):
                return _import_object_layouts_json(session, filepath)

    msg_warn("No update field data found — configure extraction_dir in settings")
    return _scan_for_descriptor_tables(session)


def _import_update_fields_json(session, uf_file):
    """Import update field data from existing extraction."""
    db = session.db
    cfg = session.cfg

    msg_info(f"Importing update fields from {uf_file}")
    with open(uf_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    classes = data.get("classes", [])
    count = 0

    for cls in classes:
        name = cls.get("name", "")
        if not name:
            continue

        obj_type = OBJECT_TYPE_CLASSES.get(name, name)
        fields = cls.get("fields", [])

        for field in fields:
            fname = field.get("name", f"field_{count}")
            ftype = field.get("type", "int32")
            foffset = field.get("offset", 0)
            fsize = field.get("size", 4)
            fflags = field.get("flags", "PUBLIC")
            array_count = field.get("array_size", field.get("array_count", 1))
            is_dynamic = 1 if field.get("is_dynamic") or "dynamic" in ftype else 0

            db.execute(
                """INSERT OR REPLACE INTO update_fields
                   (object_type, field_name, field_offset, field_size,
                    field_type, field_flags, array_count, is_dynamic)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (obj_type, fname, foffset, fsize, ftype, fflags,
                 array_count, is_dynamic),
            )
            count += 1

    db.commit()
    msg_info(f"Imported {count} update fields from {len(classes)} classes")
    return count


def _import_object_layouts_json(session, layout_file):
    """Import from wow_object_layouts JSON (alternative format)."""
    db = session.db

    msg_info(f"Importing object layouts from {layout_file}")
    with open(layout_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    layouts = data if isinstance(data, list) else data.get("layouts", [])
    count = 0

    for layout in layouts:
        name = layout.get("name", layout.get("class_name", ""))
        if not name:
            continue

        obj_type = OBJECT_TYPE_CLASSES.get(name, name)
        fields = layout.get("fields", layout.get("members", []))

        for field in fields:
            fname = field.get("name", f"field_{count}")
            ftype = field.get("type", "int32")
            foffset = field.get("offset", 0)
            fsize = field.get("size", 4)
            fflags = field.get("flags", "PUBLIC")

            db.execute(
                """INSERT OR REPLACE INTO update_fields
                   (object_type, field_name, field_offset, field_size,
                    field_type, field_flags, array_count, is_dynamic)
                   VALUES (?, ?, ?, ?, ?, ?, 1, 0)""",
                (obj_type, fname, foffset, fsize, ftype, fflags),
            )
            count += 1

    db.commit()
    msg_info(f"Imported {count} fields from object layouts")
    return count


def _scan_for_descriptor_tables(session):
    """Scan the binary for update field descriptor table patterns.

    Descriptor tables are arrays of {name_ptr, type, offset, size} structs
    in .rdata, typically referenced from CGObject_C::InitDescriptorFields
    and similar initialization functions.
    """
    msg_warn("Update field descriptor scanning not yet implemented")
    return 0


def generate_update_fields_header(session, object_type):
    """Generate TrinityCore-style UpdateFields.h entries for an object type.

    Example output:
        struct ObjectData : public HasChangesMask<4>
        {
            UpdateField<int32, 0, 1> EntryID;
            UpdateField<int32, 0, 2> DynamicFlags;
            ...
        };
    """
    db = session.db
    rows = db.fetchall(
        """SELECT * FROM update_fields
           WHERE object_type = ?
           ORDER BY field_offset""",
        (object_type,),
    )

    if not rows:
        return f"// {object_type}: no field data available\n"

    mask_bits = max(1, len(rows) // 32 + 1)
    lines = [
        f"struct {object_type}Data : public HasChangesMask<{mask_bits}>",
        "{",
    ]

    for i, row in enumerate(rows):
        tc_type = TC_UF_TYPES.get(row["field_type"], "UF_TYPE_INT")
        fname = row["field_name"]

        if row["array_count"] and row["array_count"] > 1:
            lines.append(f"    UpdateFieldArray<{tc_type}, {i}, "
                         f"{row['array_count']}> {fname};")
        elif row["is_dynamic"]:
            lines.append(f"    DynamicUpdateField<{tc_type}, 0, {i}> {fname};")
        else:
            lines.append(f"    UpdateField<{tc_type}, 0, {i}> {fname};")

    lines.append("};")
    return "\n".join(lines) + "\n"
