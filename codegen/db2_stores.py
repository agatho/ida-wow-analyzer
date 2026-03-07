"""
DB2 Store Code Generator
Generates TrinityCore C++ code for DB2 data stores based on
DB2Meta structure analysis from the knowledge DB.

Generates:
  - LoadInfo definitions (DB2LoadInfo.h)
  - Entry struct definitions (DB2Structure.h)
  - Store declarations and hotfix statements
"""

import json

from tc_wow_analyzer.core.utils import msg, msg_info


# DB2 field type → C++ type
DB2_TO_CPP_TYPE = {
    "int8": "int8",
    "int16": "int16",
    "int32": "int32",
    "int64": "int64",
    "float": "float",
    "string": "char const*",
}

# DB2 field type → LoadInfo type char
DB2_TO_LOADINFO_CHAR = {
    "int8": "b",
    "int16": "h",
    "int32": "i",
    "int64": "l",
    "float": "f",
    "string": "s",
}


def generate_loadinfo(session, table_name):
    """Generate TC LoadInfo struct for a DB2 table.

    Example:
        struct HouseDecorItemLoadInfo
        {
            static constexpr DB2MetaField Fields[5] =
            {
                { false, FT_INT, "ID" },
                { false, FT_INT, "DecorType" },
                { false, FT_INT, "FileDataID" },
                { true, FT_SHORT, "Flags" },
                { false, FT_STRING, "Name" },
            };
            ...
        };
    """
    db = session.db
    row = db.fetchone("SELECT * FROM db2_tables WHERE name = ?",
                      (table_name,))
    if not row:
        return f"// DB2 table '{table_name}' not found\n"

    fields_json = row.get("fields_json")
    if not fields_json:
        # Generate skeleton from field_count
        return _generate_skeleton_loadinfo(table_name, row)

    fields = json.loads(fields_json)
    return _generate_full_loadinfo(table_name, row, fields)


def _generate_skeleton_loadinfo(table_name, row):
    """Generate a skeleton LoadInfo when field types are unknown."""
    field_count = row["field_count"] or 0
    index_field = row["index_field"] if row["index_field"] is not None else -1
    layout_hash = row["layout_hash"] or 0

    lines = [
        f"// Skeleton LoadInfo for {table_name}",
        f"// layout_hash = 0x{layout_hash:08X}",
        f"// field_count = {field_count}",
        f"// record_size = {row['record_size'] or 0}",
        f"// index_field = {index_field}",
        f"//",
        f"// TODO: Fill in actual field types from DB2Meta analysis",
        f"",
    ]

    type_chars = "i" * field_count
    array_sizes = ", ".join(["1"] * field_count)

    lines.append(f'static char const* const types = "{type_chars}";')
    if field_count > 0:
        lines.append(f'static uint8 const arraySizes[{field_count}] = '
                     f'{{{array_sizes}}};')

    return "\n".join(lines) + "\n"


def _generate_full_loadinfo(table_name, row, fields):
    """Generate full LoadInfo with known field types."""
    index_field = row["index_field"] if row["index_field"] is not None else -1
    layout_hash = row["layout_hash"] or 0

    lines = [
        f"struct {table_name}LoadInfo",
        "{",
        f"    static constexpr DB2MetaField Fields[{len(fields)}] =",
        "    {",
    ]

    type_chars = []
    array_sizes = []

    for field in fields:
        ftype = field.get("type", "int32")
        is_signed = field.get("is_signed", False)
        fname = field.get("name", f"field_{field.get('index', 0)}")
        array_size = field.get("array_size", 1)

        ft_name = _type_to_ft(ftype)
        signed_str = "true" if is_signed else "false"
        lines.append(f'        {{ {signed_str}, {ft_name}, "{fname}" }},')

        type_chars.append(DB2_TO_LOADINFO_CHAR.get(ftype, "i"))
        array_sizes.append(str(array_size))

    lines.append("    };")
    lines.append("")

    types_str = "".join(type_chars)
    arrays_str = ", ".join(array_sizes)
    lines.append(f'    static constexpr char const* Types = "{types_str}";')
    lines.append(f'    static constexpr uint8 ArraySizes[{len(fields)}] = '
                 f'{{{arrays_str}}};')
    lines.append(f'    static constexpr uint32 LayoutHash = 0x{layout_hash:08X};')

    if index_field >= 0:
        lines.append(f'    static constexpr int32 IndexField = {index_field};')

    lines.append("};")
    return "\n".join(lines) + "\n"


def generate_entry_struct(session, table_name):
    """Generate TrinityCore Entry struct for a DB2 table.

    Example:
        struct HouseDecorItemEntry
        {
            uint32 ID;
            uint32 DecorType;
            uint32 FileDataID;
            int16 Flags;
            char const* Name;
        };
    """
    db = session.db
    row = db.fetchone("SELECT * FROM db2_tables WHERE name = ?",
                      (table_name,))
    if not row:
        return f"// DB2 table '{table_name}' not found\n"

    fields_json = row.get("fields_json")
    if not fields_json:
        return _generate_skeleton_entry(table_name, row)

    fields = json.loads(fields_json)
    index_field = row["index_field"] if row["index_field"] is not None else -1

    lines = [f"struct {table_name}Entry", "{"]

    # ID field is always first in C++ struct
    lines.append("    uint32 ID;")

    for i, field in enumerate(fields):
        if index_field >= 0 and i == index_field:
            continue  # ID already added

        ftype = field.get("type", "int32")
        fname = field.get("name", f"Field{i}")
        is_signed = field.get("is_signed", False)
        array_size = field.get("array_size", 1)

        cpp_type = _get_cpp_type(ftype, is_signed)

        if array_size > 1:
            lines.append(f"    {cpp_type} {fname}[{array_size}];")
        else:
            lines.append(f"    {cpp_type} {fname};")

    lines.append("};")
    return "\n".join(lines) + "\n"


def _generate_skeleton_entry(table_name, row):
    """Generate skeleton entry when fields are unknown."""
    field_count = row["field_count"] or 0
    lines = [
        f"// Skeleton entry for {table_name} ({field_count} fields)",
        f"struct {table_name}Entry",
        "{",
        "    uint32 ID;",
    ]
    for i in range(1, field_count):
        lines.append(f"    uint32 Field{i};  // TODO: determine actual type")
    lines.append("};")
    return "\n".join(lines) + "\n"


def generate_store_declaration(table_name):
    """Generate DB2Storage declaration line."""
    return f"TC_GAME_API extern DB2Storage<{table_name}Entry> s{table_name}Store;\n"


def generate_hotfix_statements(table_name, field_count):
    """Generate hotfix SELECT prepared statement."""
    fields = ", ".join([f"Field{i}" for i in range(field_count)])
    return (
        f'// Hotfix SELECT for {table_name}\n'
        f'PrepareStatement(HOTFIX_SEL_{table_name.upper()}, '
        f'"SELECT ID, {fields} FROM {table_name.lower()}", '
        f'CONNECTION_SYNCH);\n'
    )


# ─── Helpers ───────────────────────────────────────────────────────

def _type_to_ft(ftype):
    """Convert type string to TrinityCore FT_ constant name."""
    mapping = {
        "int8": "FT_BYTE",
        "int16": "FT_SHORT",
        "int32": "FT_INT",
        "int64": "FT_LONG",
        "float": "FT_FLOAT",
        "string": "FT_STRING",
    }
    return mapping.get(ftype, "FT_INT")


def _get_cpp_type(ftype, is_signed=False):
    """Get C++ type for a DB2 field type."""
    if ftype == "string":
        return "char const*"
    if ftype == "float":
        return "float"

    size_map = {
        "int8": ("int8", "uint8"),
        "int16": ("int16", "uint16"),
        "int32": ("int32", "uint32"),
        "int64": ("int64", "uint64"),
    }
    pair = size_map.get(ftype, ("int32", "uint32"))
    return pair[0] if is_signed else pair[1]
