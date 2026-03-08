"""
TrinityCore Source Knowledge Importer
Scans TrinityCore C++ source to extract known opcode names, packet structs,
handler function names, and DB2 store declarations. This creates the
"ground truth" side of the binary↔source mapping.

Imports:
  - Opcodes.h: CMSG_*/SMSG_* enum values
  - Opcodes.cpp: Opcode → handler function mapping
  - WorldSession.h: Handler declarations
  - DB2Structure.h: Entry struct names
  - Packet headers: WorldPackets/*

After import, cross_reference_opcodes() merges TC source knowledge with
binary-imported opcodes so downstream tasks can query by tc_name.
"""

import json
import os
import re
import time

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


def import_tc_source(session, tc_source_dir=None):
    """Import TrinityCore source knowledge into the DB.

    Args:
        session: PluginSession
        tc_source_dir: Path to TrinityCore source root
    """
    db = session.db
    cfg = session.cfg

    if not tc_source_dir:
        tc_source_dir = cfg.tc_source_dir
    if not tc_source_dir or not os.path.isdir(tc_source_dir):
        msg_error("TrinityCore source directory not configured. Set tc_source_dir in Settings.")
        return 0

    msg_info(f"Importing TC source knowledge from {tc_source_dir}")
    total = 0

    # Import opcodes from Opcodes.h
    opcodes_h = _find_file(tc_source_dir,
                           "src/server/game/Server/Protocol/Opcodes.h")
    if opcodes_h:
        total += _import_opcodes_h(db, opcodes_h)

    # Import opcode→handler mapping from Opcodes.cpp
    opcodes_cpp = _find_file(tc_source_dir,
                             "src/server/game/Server/Protocol/Opcodes.cpp")
    if opcodes_cpp:
        total += _import_opcodes_cpp(db, opcodes_cpp)

    # Import handler declarations from WorldSession.h
    ws_h = _find_file(tc_source_dir,
                      "src/server/game/Server/WorldSession.h")
    if ws_h:
        total += _import_worldsession_h(db, ws_h)

    # Import DB2 structure names
    db2_h = _find_file(tc_source_dir,
                       "src/server/game/DataStores/DB2Structure.h")
    if db2_h:
        total += _import_db2_structure_h(db, db2_h)

    # Import packet class definitions from WorldPackets/
    packets_dir = _find_dir(tc_source_dir,
                            "src/server/game/Server/Packets")
    if packets_dir:
        total += _import_packet_classes(db, packets_dir)

    db.commit()

    # Cross-reference TC opcodes with binary-imported opcodes
    xref_count = cross_reference_opcodes(session)
    total += xref_count

    msg_info(f"Imported {total} items from TrinityCore source")
    return total


def _import_opcodes_h(db, filepath):
    """Parse Opcodes.h to extract CMSG_*/SMSG_* enum values."""
    msg_info(f"  Parsing {filepath}")
    count = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Match patterns like: CMSG_FOO_BAR = 0x420127,
    pattern = re.compile(
        r'(CMSG_\w+|SMSG_\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)',
        re.MULTILINE)

    for m in pattern.finditer(content):
        name = m.group(1)
        value = int(m.group(2), 0)
        direction = "CMSG" if name.startswith("CMSG_") else "SMSG"

        db.upsert_opcode(
            direction=direction,
            internal_index=value,
            tc_name=name,
            status="tc_source",
        )
        count += 1

    msg_info(f"    {count} opcode definitions")
    return count


def _import_opcodes_cpp(db, filepath):
    """Parse Opcodes.cpp to extract opcode→handler function mappings.

    Stores:
      kv_store: tc_opcode_handler:{CMSG_FOO} → HandleFoo
      kv_store: tc_handler_opcode:{HandleFoo} → CMSG_FOO
    """
    msg_info(f"  Parsing {filepath}")
    count = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # DEFINE_HANDLER(CMSG_FOO, STATUS_LOGGEDIN, PROCESS_THREADUNSAFE, &WorldSession::HandleFoo);
    pattern = re.compile(
        r'DEFINE_HANDLER\(\s*(CMSG_\w+|SMSG_\w+)\s*,'
        r'\s*(\w+)\s*,'     # status
        r'\s*(\w+)\s*,'     # processing
        r'\s*&WorldSession::(\w+)\s*\)',
        re.MULTILINE)

    now = time.time()
    for m in pattern.finditer(content):
        opcode_name = m.group(1)
        tc_status = m.group(2)     # STATUS_LOGGEDIN etc
        handler_name = m.group(4)  # HandleFoo

        # Store bidirectional mapping
        db.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) "
            "VALUES (?, ?, ?)",
            (f"tc_opcode_handler:{opcode_name}",
             json.dumps({"handler": handler_name, "status": tc_status}),
             now))

        db.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) "
            "VALUES (?, ?, ?)",
            (f"tc_handler_opcode:{handler_name}",
             opcode_name,
             now))
        count += 1

    msg_info(f"    {count} opcode→handler mappings")
    return count


def _import_worldsession_h(db, filepath):
    """Parse WorldSession.h to extract handler declarations."""
    msg_info(f"  Parsing {filepath}")
    count = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Match: void HandleFooBar(WorldPackets::SomePacket& packet);
    pattern = re.compile(
        r'void\s+(Handle\w+)\s*\(\s*WorldPackets::'
        r'(\w+)::(\w+)\s*[&*]\s*\w+\s*\)',
        re.MULTILINE)

    now = time.time()
    for m in pattern.finditer(content):
        handler_name = m.group(1)
        packet_ns = m.group(2)
        packet_class = m.group(3)

        db.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) "
            "VALUES (?, ?, ?)",
            (f"tc_handler:{handler_name}",
             f"{packet_ns}::{packet_class}",
             now))
        count += 1

    msg_info(f"    {count} handler declarations")
    return count


def _import_db2_structure_h(db, filepath):
    """Parse DB2Structure.h to extract Entry struct names."""
    msg_info(f"  Parsing {filepath}")
    count = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Match: struct FooBarEntry
    pattern = re.compile(r'struct\s+(\w+Entry)\s*\{', re.MULTILINE)

    now = time.time()
    for m in pattern.finditer(content):
        struct_name = m.group(1)
        table_name = struct_name.replace("Entry", "")

        db.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) "
            "VALUES (?, ?, ?)",
            (f"tc_db2_struct:{table_name}",
             struct_name,
             now))
        count += 1

    msg_info(f"    {count} DB2 struct definitions")
    return count


def _import_packet_classes(db, packets_dir):
    """Scan WorldPackets/ headers to extract packet class → JAM message links.

    Looks for patterns like:
      class FooBar final : public ClientPacket
      class FooBar final : public ServerPacket
    And links them to their Read/Write methods.
    """
    count = 0
    now = time.time()

    for root, dirs, files in os.walk(packets_dir):
        for fname in files:
            if not fname.endswith(".h"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            # class FooBar final : public ClientPacket
            for m in re.finditer(
                r'class\s+(\w+)\s+final\s*:\s*public\s+(Client|Server)Packet',
                content):
                packet_class = m.group(1)
                packet_dir = "CMSG" if m.group(2) == "Client" else "SMSG"

                db.execute(
                    "INSERT OR REPLACE INTO kv_store (key, value, updated_at) "
                    "VALUES (?, ?, ?)",
                    (f"tc_packet_class:{packet_class}",
                     json.dumps({"direction": packet_dir, "file": fname}),
                     now))
                count += 1

    if count:
        msg_info(f"    {count} packet class definitions")
    return count


def cross_reference_opcodes(session):
    """Cross-reference TC source opcodes with binary-imported opcodes.

    Strategy:
      1. For each binary-imported opcode that has a jam_type, look for a
         matching JAM message name in the TC handler→packet mapping.
      2. Use the TC opcode→handler mapping to find the tc_name.
      3. Update the binary-imported opcode row with tc_name.

    Also works in reverse: if we have tc_name from TC source but the
    binary dispatch doesn't have one, try to match by JAM name patterns.
    """
    db = session.db

    # Build lookup tables from kv_store
    # tc_opcode_handler:{CMSG_FOO} → {"handler": "HandleFoo", "status": "..."}
    opcode_to_handler = {}
    handler_to_opcode = {}

    rows = db.fetchall(
        "SELECT key, value FROM kv_store WHERE key LIKE 'tc_opcode_handler:%'")
    for row in rows:
        opcode_name = row["key"].replace("tc_opcode_handler:", "")
        try:
            data = json.loads(row["value"])
            handler_name = data.get("handler", "")
            opcode_to_handler[opcode_name] = handler_name
            if handler_name and handler_name != "Handle_NULL":
                handler_to_opcode[handler_name] = opcode_name
        except (json.JSONDecodeError, AttributeError):
            pass

    if not opcode_to_handler:
        msg_warn("  No opcode→handler mappings found for cross-referencing")
        return 0

    # Build JAM name → TC opcode mapping
    # TC handler declarations tell us: HandleFoo → PacketNS::PacketClass
    # We need to find which JAM message corresponds to which packet class
    handler_to_packet = {}
    rows = db.fetchall(
        "SELECT key, value FROM kv_store WHERE key LIKE 'tc_handler:%' "
        "AND key NOT LIKE 'tc_handler_opcode:%'")
    for row in rows:
        handler_name = row["key"].replace("tc_handler:", "")
        handler_to_packet[handler_name] = row["value"]

    # Get all binary-imported opcodes with jam_type
    binary_opcodes = db.fetchall(
        "SELECT * FROM opcodes WHERE status = 'imported' AND jam_type IS NOT NULL")

    # Also get TC source opcodes for the reverse lookup
    tc_opcodes = db.fetchall(
        "SELECT * FROM opcodes WHERE status = 'tc_source'")
    tc_by_name = {row["tc_name"]: row for row in tc_opcodes}

    matched = 0

    # Strategy 1: Match by JAM name similarity
    # Binary jam_type might be truncated (e.g. "arrisonCompleteTalentType")
    # TC opcode names follow patterns like CMSG_GARRISON_COMPLETE_TALENT
    for row in binary_opcodes:
        jam_type = row["jam_type"]
        if not jam_type:
            continue

        # Try to find matching TC opcode by converting JAM name to opcode pattern
        tc_name = _match_jam_to_tc_opcode(jam_type, tc_by_name, opcode_to_handler)
        if tc_name:
            direction = row["direction"]
            idx = row["internal_index"]
            db.execute(
                "UPDATE opcodes SET tc_name = ?, status = 'matched' "
                "WHERE direction = ? AND internal_index = ?",
                (tc_name, direction, idx))
            matched += 1

    db.commit()

    if matched:
        msg_info(f"  Cross-referenced {matched} opcodes (binary↔TC source)")

    # Strategy 2: Build a name-based index for IDA function lookup
    # Store the handler function names so IDA-based analysis can match
    # binary handler_ea → function name → TC handler name → TC opcode name
    handler_index = {}
    for opcode_name, handler_name in opcode_to_handler.items():
        if handler_name and handler_name != "Handle_NULL":
            handler_index[handler_name] = opcode_name

    if handler_index:
        db.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) "
            "VALUES (?, ?, ?)",
            ("tc_handler_index",
             json.dumps(handler_index),
             time.time()))
        db.commit()
        msg_info(f"  Stored {len(handler_index)} handler→opcode mappings for IDA lookup")

    return matched


def _match_jam_to_tc_opcode(jam_name, tc_by_name, opcode_to_handler):
    """Try to match a binary JAM name to a TC opcode name.

    The binary jam_name is often a truncated or mangled version of the
    full JAM message name. We try several matching strategies:

    1. Direct packet class name match (e.g. "ChatMessage" → CMSG_CHAT_MESSAGE_*)
    2. Substring match against TC opcode names
    3. CamelCase → UPPER_SNAKE conversion and prefix match
    """
    if not jam_name:
        return None

    # Clean up common prefix/suffix patterns
    clean = jam_name.strip()

    # Convert CamelCase JAM name to UPPER_SNAKE for matching
    # e.g. "GarrisonCompleteTalentType" → "GARRISON_COMPLETE_TALENT_TYPE"
    snake = _camel_to_upper_snake(clean)

    # Try CMSG_ and SMSG_ prefixes
    for prefix in ("CMSG_", "SMSG_"):
        candidate = prefix + snake
        if candidate in tc_by_name:
            return candidate

        # Try partial match (JAM name might be truncated at the start)
        for tc_name in tc_by_name:
            if tc_name.startswith(prefix) and snake in tc_name:
                return tc_name

    return None


def _camel_to_upper_snake(name):
    """Convert CamelCase to UPPER_SNAKE_CASE."""
    # Insert underscore before uppercase letters preceded by lowercase
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name)
    # Insert underscore between consecutive uppercase and following lower
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', s)
    return s.upper()


def _find_file(base_dir, relative_path):
    """Find a file relative to the TC source root."""
    full_path = os.path.join(base_dir, relative_path)
    if os.path.isfile(full_path):
        return full_path

    # Try with forward slashes
    full_path = os.path.join(base_dir, relative_path.replace("/", os.sep))
    if os.path.isfile(full_path):
        return full_path

    msg_warn(f"  File not found: {relative_path}")
    return None


def _find_dir(base_dir, relative_path):
    """Find a directory relative to the TC source root."""
    full_path = os.path.join(base_dir, relative_path)
    if os.path.isdir(full_path):
        return full_path

    full_path = os.path.join(base_dir, relative_path.replace("/", os.sep))
    if os.path.isdir(full_path):
        return full_path

    return None
