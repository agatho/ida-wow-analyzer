"""
Opcode Enum Code Generator
Generates TrinityCore Opcodes.h enum entries and OpcodeTable registrations
from the knowledge DB opcode data.
"""

import re

from tc_wow_analyzer.core.utils import msg_info


def generate_opcode_enum(session, direction="CMSG"):
    """Generate opcode enum entries for a direction.

    Example output:
        CMSG_HOUSE_DECOR_ACTION              = 0x420127,
        CMSG_NEIGHBORHOOD_RESERVE_PLOT       = 0x420128,
    """
    db = session.db
    rows = db.fetchall(
        "SELECT * FROM opcodes WHERE direction = ? AND tc_name IS NOT NULL "
        "ORDER BY internal_index",
        (direction,))

    if not rows:
        return f"// No {direction} opcodes found\n"

    lines = [f"// {direction} opcodes ({len(rows)} entries)"]

    max_name_len = max((len(r["tc_name"]) for r in rows), default=40)

    for row in rows:
        name = row["tc_name"]
        idx = row["internal_index"]
        padding = " " * (max_name_len - len(name) + 1)
        lines.append(f"    {name}{padding}= 0x{idx:06X},")

    return "\n".join(lines) + "\n"


def generate_opcode_table_entries(session, direction="CMSG"):
    """Generate OpcodeTable registration entries.

    Example output:
        DEFINE_HANDLER(CMSG_HOUSE_DECOR_ACTION, STATUS_LOGGEDIN,
            PROCESS_THREADUNSAFE, &WorldSession::HandleHouseDecorAction);
    """
    db = session.db
    rows = db.fetchall(
        "SELECT * FROM opcodes WHERE direction = ? AND tc_name IS NOT NULL "
        "ORDER BY internal_index",
        (direction,))

    if not rows:
        return f"// No {direction} opcode handlers\n"

    lines = [f"// {direction} opcode table entries ({len(rows)} entries)"]

    for row in rows:
        name = row["tc_name"]
        handler_name = _opcode_to_handler_name(name, direction)
        status = "STATUS_LOGGEDIN"
        processing = "PROCESS_THREADUNSAFE"

        lines.append(
            f"    DEFINE_HANDLER({name}, {status}, "
            f"{processing}, &WorldSession::{handler_name});")

    return "\n".join(lines) + "\n"


def generate_opcode_names_table(session, direction="CMSG"):
    """Generate opcode name lookup table entries.

    Example:
        { CMSG_HOUSE_DECOR_ACTION, "CMSG_HOUSE_DECOR_ACTION" },
    """
    db = session.db
    rows = db.fetchall(
        "SELECT * FROM opcodes WHERE direction = ? AND tc_name IS NOT NULL "
        "ORDER BY internal_index",
        (direction,))

    lines = []
    for row in rows:
        name = row["tc_name"]
        lines.append(f'    {{ {name}, "{name}" }},')

    return "\n".join(lines) + "\n"


def find_new_opcodes(session):
    """Find opcodes that exist in the binary but not in TrinityCore.

    Returns list of opcodes with status='unknown' that have handler addresses.
    """
    db = session.db
    rows = db.fetchall(
        "SELECT * FROM opcodes WHERE status = 'unknown' "
        "AND handler_ea IS NOT NULL ORDER BY internal_index")

    return [dict(r) for r in rows]


def find_changed_opcodes(session):
    """Find opcodes where the handler address differs from previous build.

    Requires diffing data to be populated.
    """
    db = session.db
    rows = db.fetchall(
        """SELECT o.*, d.old_ea, d.match_type, d.confidence
           FROM opcodes o
           JOIN diffing d ON o.handler_ea = d.new_ea
           WHERE d.confidence < 1.0
           ORDER BY d.confidence""")

    return [dict(r) for r in rows]


# ─── Helpers ───────────────────────────────────────────────────────

def _opcode_to_handler_name(opcode_name, direction):
    """Convert opcode name to handler method name.

    CMSG_HOUSE_DECOR_ACTION → HandleHouseDecorAction
    """
    prefix = f"{direction}_"
    if opcode_name.startswith(prefix):
        base = opcode_name[len(prefix):]
    else:
        base = opcode_name

    # UPPER_SNAKE to PascalCase
    parts = base.split("_")
    pascal = "".join(p.capitalize() for p in parts)
    return f"Handle{pascal}"
