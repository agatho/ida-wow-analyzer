"""
Packet Handler Scaffolding Generator
Generates TrinityCore C++ code for packet handlers based on
JAM wire format analysis from the knowledge DB.

Generates:
  - Packet struct definitions (WorldPackets.h)
  - Handler function stubs (Handlers/*.cpp)
  - Opcode enum entries (Opcodes.cpp)
"""

import json
import os
import time

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn


# JAM field type → TrinityCore C++ type mapping
JAM_TO_CPP_TYPE = {
    "uint8": "uint8",
    "uint16": "uint16",
    "uint32": "uint32",
    "uint64": "uint64",
    "int8": "int8",
    "int16": "int16",
    "int32": "int32",
    "int64": "int64",
    "float": "float",
    "ObjectGuid": "ObjectGuid",
    "PackedGuid": "ObjectGuid",
    "string": "std::string",
    "bits": "uint32",  # bit field
}

# JAM field type → ByteBuffer read method
JAM_TO_READ_METHOD = {
    "uint8": ">> {field}",
    "uint16": ">> {field}",
    "uint32": ">> {field}",
    "uint64": ">> {field}",
    "int8": ">> {field}",
    "int16": ">> {field}",
    "int32": ">> {field}",
    "int64": ">> {field}",
    "float": ">> {field}",
    "ObjectGuid": ">> {field}",
    "PackedGuid": ".ReadPackedGuid({field})",
    "string": ">> {field}",
    "bits": ".ReadBits({field}, {bit_count})",
}

# JAM field type → ByteBuffer write method
JAM_TO_WRITE_METHOD = {
    "uint8": "<< {field}",
    "uint16": "<< {field}",
    "uint32": "<< {field}",
    "uint64": "<< {field}",
    "int8": "<< {field}",
    "int16": "<< {field}",
    "int32": "<< {field}",
    "int64": "<< {field}",
    "float": "<< {field}",
    "ObjectGuid": "<< {field}",
    "PackedGuid": ".WritePackedGuid({field})",
    "string": "<< {field}",
    "bits": ".WriteBits({field}, {bit_count})",
}


def generate_packet_struct(session, jam_name, direction="CMSG"):
    """Generate a TrinityCore packet struct definition.

    Example output:
        class HouseDecorAction final : public ClientPacket
        {
        public:
            HouseDecorAction(WorldPacket&& packet) : ClientPacket(CMSG_HOUSE_DECOR_ACTION, std::move(packet)) { }

            void Read() override;

            ObjectGuid HouseGuid;
            uint32 DecorEntryId = 0;
            uint32 Action = 0;
        };
    """
    db = session.db
    row = db.fetchone("SELECT * FROM jam_types WHERE name = ?", (jam_name,))
    if not row:
        return f"// JAM type '{jam_name}' not found in knowledge DB\n"

    fields = []
    if row["fields_json"]:
        fields = json.loads(row["fields_json"])

    # Derive class name from JAM name
    class_name = _jam_to_class_name(jam_name)
    opcode_name = _jam_to_opcode_name(jam_name, direction)
    base_class = "ClientPacket" if direction == "CMSG" else "ServerPacket"

    lines = []
    lines.append(f"class {class_name} final : public {base_class}")
    lines.append("{")
    lines.append("public:")

    if direction == "CMSG":
        lines.append(f"    {class_name}(WorldPacket&& packet) : "
                     f"{base_class}({opcode_name}, std::move(packet)) {{ }}")
        lines.append("")
        lines.append("    void Read() override;")
    else:
        lines.append(f"    {class_name}() : {base_class}({opcode_name}) {{ }}")
        lines.append("")
        lines.append("    WorldPacket const* Write() override;")

    if fields:
        lines.append("")
        for field in fields:
            cpp_type = JAM_TO_CPP_TYPE.get(field["type"], "uint32")
            fname = field.get("name", f"Field{field.get('index', 0)}")
            default = _get_default(cpp_type)
            lines.append(f"    {cpp_type} {fname}{default};")

    lines.append("};")
    return "\n".join(lines) + "\n"


def generate_read_method(session, jam_name):
    """Generate the Read() method for a CMSG packet."""
    db = session.db
    row = db.fetchone("SELECT * FROM jam_types WHERE name = ?", (jam_name,))
    if not row or not row["fields_json"]:
        return f"// No field data for {jam_name}\n"

    fields = json.loads(row["fields_json"])
    class_name = _jam_to_class_name(jam_name)

    lines = [f"void {class_name}::Read()"]
    lines.append("{")

    for field in fields:
        ftype = field["type"]
        fname = field.get("name", f"Field{field.get('index', 0)}")

        if ftype == "bits":
            bit_count = field.get("bit_count", 1)
            lines.append(f"    _worldPacket.ReadBits({fname}, {bit_count});")
        elif ftype == "PackedGuid":
            lines.append(f"    _worldPacket.ReadPackedGuid({fname});")
        elif ftype == "flush":
            lines.append(f"    _worldPacket.ResetBitPos();")
        else:
            lines.append(f"    _worldPacket >> {fname};")

    lines.append("}")
    return "\n".join(lines) + "\n"


def generate_write_method(session, jam_name):
    """Generate the Write() method for an SMSG packet."""
    db = session.db
    row = db.fetchone("SELECT * FROM jam_types WHERE name = ?", (jam_name,))
    if not row or not row["fields_json"]:
        return f"// No field data for {jam_name}\n"

    fields = json.loads(row["fields_json"])
    class_name = _jam_to_class_name(jam_name)

    lines = [f"WorldPacket const* {class_name}::Write()"]
    lines.append("{")

    for field in fields:
        ftype = field["type"]
        fname = field.get("name", f"Field{field.get('index', 0)}")

        if ftype == "bits":
            bit_count = field.get("bit_count", 1)
            lines.append(f"    _worldPacket.WriteBits({fname}, {bit_count});")
        elif ftype == "PackedGuid":
            lines.append(f"    _worldPacket.WritePackedGuid({fname});")
        elif ftype == "flush":
            lines.append(f"    _worldPacket.FlushBits();")
        else:
            lines.append(f"    _worldPacket << {fname};")

    lines.append("")
    lines.append("    return &_worldPacket;")
    lines.append("}")
    return "\n".join(lines) + "\n"


def generate_handler_stub(session, jam_name, direction="CMSG"):
    """Generate a handler function stub."""
    class_name = _jam_to_class_name(jam_name)

    if direction == "CMSG":
        return (
            f"void WorldSession::Handle{class_name}"
            f"(WorldPackets::{class_name}& packet)\n"
            f"{{\n"
            f"    // TODO: Implement {class_name} handler\n"
            f"    TC_LOG_DEBUG(\"network\", \"WORLD: Received {class_name}\");\n"
            f"}}\n"
        )
    return f"// SMSG handlers are typically send-only\n"


def generate_all_for_jam(session, jam_name, direction="CMSG"):
    """Generate all code artifacts for a single JAM type."""
    parts = {
        "packet_struct": generate_packet_struct(session, jam_name, direction),
        "read_method": generate_read_method(session, jam_name) if direction == "CMSG" else None,
        "write_method": generate_write_method(session, jam_name) if direction == "SMSG" else None,
        "handler_stub": generate_handler_stub(session, jam_name, direction),
    }
    return {k: v for k, v in parts.items() if v is not None}


# ─── Helpers ───────────────────────────────────────────────────────

def _jam_to_class_name(jam_name):
    """Convert JAM name to TrinityCore class name.

    JamCliHouseDecorAction → HouseDecorAction
    JamSvcsNeighborhoodReservePlot → NeighborhoodReservePlot
    """
    for prefix in ("JamCli", "JamSvcs", "JamSrv", "Jam"):
        if jam_name.startswith(prefix):
            return jam_name[len(prefix):]
    return jam_name


def _jam_to_opcode_name(jam_name, direction):
    """Convert JAM name to TrinityCore opcode enum name.

    JamCliHouseDecorAction + CMSG → CMSG_HOUSE_DECOR_ACTION
    """
    class_name = _jam_to_class_name(jam_name)
    # CamelCase to UPPER_SNAKE_CASE
    import re
    snake = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', class_name).upper()
    return f"{direction}_{snake}"


def _get_default(cpp_type):
    """Get default initializer for a C++ type."""
    if cpp_type in ("float",):
        return " = 0.0f"
    if cpp_type in ("std::string",):
        return ""
    if cpp_type in ("ObjectGuid",):
        return ""
    if cpp_type.startswith("int") or cpp_type.startswith("uint"):
        return " = 0"
    return ""
