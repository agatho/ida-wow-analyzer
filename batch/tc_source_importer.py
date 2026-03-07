"""
TrinityCore Source Knowledge Importer
Scans TrinityCore C++ source to extract known opcode names, packet structs,
handler function names, and DB2 store declarations. This creates the
"ground truth" side of the binary↔source mapping.

Imports:
  - Opcodes.h: CMSG_*/SMSG_* enum values
  - WorldSession.h: Handler declarations
  - DB2Structure.h: Entry struct names
  - DB2Stores.h: Store declarations
  - Packet headers: WorldPackets/*
"""

import os
import re

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
        tc_source_dir = cfg.get("tc_source_dir", "")
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

    db.commit()
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

    for m in pattern.finditer(content):
        handler_name = m.group(1)
        packet_ns = m.group(2)
        packet_class = m.group(3)

        # Store as annotation
        db.execute(
            """INSERT OR REPLACE INTO kv_store (key, value, updated_at)
               VALUES (?, ?, ?)""",
            (f"tc_handler:{handler_name}",
             f"{packet_ns}::{packet_class}",
             __import__("time").time()))
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

    for m in pattern.finditer(content):
        struct_name = m.group(1)
        table_name = struct_name.replace("Entry", "")

        db.execute(
            """INSERT OR REPLACE INTO kv_store (key, value, updated_at)
               VALUES (?, ?, ?)""",
            (f"tc_db2_struct:{table_name}",
             struct_name,
             __import__("time").time()))
        count += 1

    msg_info(f"    {count} DB2 struct definitions")
    return count


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
