"""
UpdateFields Code Generator
Generates TrinityCore UpdateFields.h/cpp code from the knowledge DB.
"""

from tc_wow_analyzer.core.utils import msg_info


# TC update field type mapping
UF_TYPE_MAP = {
    "int8": ("int32", "UF_TYPE_INT"),
    "int16": ("int32", "UF_TYPE_INT"),
    "int32": ("int32", "UF_TYPE_INT"),
    "int64": ("int64", "UF_TYPE_TWO_SHORT"),
    "uint8": ("uint32", "UF_TYPE_INT"),
    "uint16": ("uint32", "UF_TYPE_INT"),
    "uint32": ("uint32", "UF_TYPE_INT"),
    "uint64": ("uint64", "UF_TYPE_TWO_SHORT"),
    "float": ("float", "UF_TYPE_FLOAT"),
    "guid": ("ObjectGuid", "UF_TYPE_GUID"),
    "bytes": ("uint32", "UF_TYPE_BYTES"),
}


def generate_update_fields_h(session, object_type):
    """Generate UpdateFields.h struct definition for an object type."""
    db = session.db
    rows = db.fetchall(
        "SELECT * FROM update_fields WHERE object_type = ? "
        "ORDER BY field_offset",
        (object_type,))

    if not rows:
        return f"// No update fields for {object_type}\n"

    mask_size = max(1, (len(rows) + 31) // 32)
    struct_name = f"{object_type}Data"

    lines = [
        f"struct {struct_name} : public HasChangesMask<{mask_size}>",
        "{",
    ]

    for i, row in enumerate(rows):
        fname = row["field_name"]
        ftype = row["field_type"]
        is_dynamic = row["is_dynamic"]
        array_count = row["array_count"] or 1

        cpp_type, _ = UF_TYPE_MAP.get(ftype, ("int32", "UF_TYPE_INT"))

        if is_dynamic:
            lines.append(
                f"    DynamicUpdateField<{cpp_type}, 0, {i}> {fname};")
        elif array_count > 1:
            lines.append(
                f"    UpdateFieldArray<{cpp_type}, {i}, "
                f"{array_count}> {fname};")
        else:
            lines.append(
                f"    UpdateField<{cpp_type}, 0, {i}> {fname};")

    lines.append("};")
    return "\n".join(lines) + "\n"


def generate_all_update_fields(session):
    """Generate UpdateFields code for all known object types."""
    db = session.db
    types = db.fetchall(
        "SELECT DISTINCT object_type FROM update_fields ORDER BY object_type")

    sections = []
    for row in types:
        obj_type = row["object_type"]
        code = generate_update_fields_h(session, obj_type)
        sections.append(code)

    return "\n\n".join(sections)
