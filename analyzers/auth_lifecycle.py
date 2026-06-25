"""
Connection / Auth / World-State Lifecycle FSM Recovery

Recovers the global protocol state machine:
  - Which CMSG/SMSG opcodes belong to which protocol phase
    (handshake, realm-list, char-select, world, in-world, logout)
  - Phase transitions and their triggering opcodes
  - Per-phase opcode allow-lists (security boundary enforcement)

Why this exists: TC's connection FSM is hand-coded. When Blizzard adds a step
to the handshake or moves an opcode between phases, TC catches up by hand. This
analyzer extracts the canonical phase->opcode mapping from the binary so a
diff against the prior build surfaces protocol-shape changes immediately.

Output:
  kv_store["auth_lifecycle"] = {
      "version": 1,
      "phases": {
          "handshake":   {"opcodes": [...], "transitions_to": [...]},
          "realm_list":  {...},
          "char_select": {...},
          "world":       {...},
          "in_world":    {...},
          "logout":      {...},
      },
      "phase_of_opcode": {opcode_name: phase_name},
      "transition_handlers": [{"from": "...", "to": "...", "via_opcode": "..."}],
  }
"""

import time
from collections import defaultdict

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn

# Canonical phase definitions: ordered list of (phase_id, opcode_keyword_patterns).
# An opcode whose name contains one of the patterns is bucketed into that phase.
# Ordering matters: earlier patterns win on conflict.
PHASE_PATTERNS = [
    ("handshake", [
        "AUTH_CHALLENGE", "AUTH_SESSION", "AUTH_RESPONSE", "AUTH_LOGON",
        "AUTH_RECONNECT", "REDIRECT", "CONNECT_TO", "TRANSFER_INITIATE",
        "TRANSFER_ABORT", "PING", "PONG",
    ]),
    ("realm_list", [
        "REALM_LIST", "REALM_QUERY", "REALM_SPLIT", "REALM_CHARACTER",
    ]),
    ("char_select", [
        "CHAR_ENUM", "CHAR_CREATE", "CHAR_DELETE", "CHAR_RENAME",
        "CHAR_CUSTOMIZE", "CHAR_RACE_CHANGE", "CHAR_FACTION_CHANGE",
        "CHAR_LOGIN", "CHARACTER_LOGIN", "PLAYER_LOGIN",
        "ENUM_CHARACTERS", "RANDOMIZE_CHAR_NAME",
    ]),
    ("world_load", [
        "PLAYER_LOGOUT", "LOGIN_VERIFY_WORLD", "READY_FOR_ACCOUNT_DATA_TIMES",
        "LOAD_PLAYER", "LOGIN_SET_TIME_SPEED", "TUTORIAL_FLAGS",
        "INITIAL_SPELLS", "SEND_KNOWN_SPELLS", "SEND_FACTIONLIST",
    ]),
    ("logout", [
        "LOGOUT_REQUEST", "LOGOUT_RESPONSE", "LOGOUT_COMPLETE",
        "LOGOUT_CANCEL", "LOGOUT_CANCEL_ACK",
    ]),
    # in_world is the catch-all for any opcode not matched above
]

PHASE_ORDER = [p[0] for p in PHASE_PATTERNS] + ["in_world"]


def _phase_for_opcode(opcode_name: str) -> str:
    if not opcode_name:
        return "unknown"
    upper = opcode_name.upper()
    for phase_id, patterns in PHASE_PATTERNS:
        for pat in patterns:
            if pat in upper:
                return phase_id
    return "in_world"


def analyze_auth_lifecycle(session):
    """Main entry point. Builds the phase FSM from opcodes + JAM types."""
    db = session.db
    if db is None:
        msg_warn("Auth Lifecycle: no DB")
        return 0

    t0 = time.time()
    msg_info("Auth Lifecycle: recovering protocol phase FSM...")

    # ── Pull all opcodes (the DB column is `tc_name`, not `name`) ──
    try:
        opcodes = db.fetchall(
            "SELECT tc_name, direction, internal_index, handler_ea "
            "FROM opcodes WHERE tc_name IS NOT NULL"
        )
    except Exception as e:
        msg_warn(f"Auth Lifecycle: opcode query failed: {e}")
        return 0

    msg_info(f"  Bucketing {len(opcodes)} opcodes by phase")

    phase_to_opcodes = defaultdict(list)
    phase_of_opcode = {}

    for op in opcodes:
        name = op["tc_name"]
        phase = _phase_for_opcode(name)
        phase_of_opcode[name] = phase
        phase_to_opcodes[phase].append({
            "name": name,
            "direction": op["direction"],
            "internal_index": op["internal_index"],
            "handler_ea": op["handler_ea"],
        })

    # ── Identify phase transitions ──
    # A transition is: handler in phase X sends/receives an opcode that's
    # canonically in phase Y. We use protocol_sequencing data if available.
    transitions = []
    seen_transitions = set()
    try:
        seq = db.kv_get("protocol_sequences")
        if seq and isinstance(seq, dict):
            deps = seq.get("dependencies") or seq.get("ordering_constraints") or []
            for dep in deps:
                if not isinstance(dep, dict):
                    continue
                from_op = dep.get("predecessor") or dep.get("before") or dep.get("from")
                to_op = dep.get("successor") or dep.get("after") or dep.get("to")
                if not from_op or not to_op:
                    continue
                from_phase = phase_of_opcode.get(from_op, "in_world")
                to_phase = phase_of_opcode.get(to_op, "in_world")
                if from_phase == to_phase:
                    continue
                key = (from_phase, to_phase, to_op)
                if key in seen_transitions:
                    continue
                seen_transitions.add(key)
                transitions.append({
                    "from": from_phase,
                    "to": to_phase,
                    "via_opcode": to_op,
                    "from_opcode": from_op,
                })
    except Exception:
        pass

    # ── Build per-phase summary ──
    phases = {}
    for phase_id in PHASE_ORDER:
        ops_in_phase = phase_to_opcodes.get(phase_id, [])
        cmsg = sum(1 for o in ops_in_phase if (o["direction"] or "").upper() == "CMSG")
        smsg = sum(1 for o in ops_in_phase if (o["direction"] or "").upper() == "SMSG")
        transitions_to = sorted({
            t["to"] for t in transitions if t["from"] == phase_id
        })
        # Sort opcodes within phase: CMSG first, then by name
        ops_in_phase.sort(
            key=lambda o: (0 if (o["direction"] or "").upper() == "CMSG" else 1,
                          o["name"] or "")
        )
        phases[phase_id] = {
            "opcode_count": len(ops_in_phase),
            "cmsg_count": cmsg,
            "smsg_count": smsg,
            "opcodes": [o["name"] for o in ops_in_phase[:200]],
            "transitions_to": transitions_to,
        }

    # ── Persist ──
    result = {
        "version": 1,
        "phases": phases,
        "phase_of_opcode": phase_of_opcode,
        "transition_handlers": transitions,
        "phase_order": PHASE_ORDER,
        "elapsed_sec": round(time.time() - t0, 2),
        "generated_at": time.time(),
    }
    db.kv_set("auth_lifecycle", result)
    db.commit()

    msg_info(
        f"Auth Lifecycle: bucketed {len(opcodes)} opcodes into "
        f"{sum(1 for p in phases.values() if p['opcode_count'])} active phases, "
        f"{len(transitions)} transitions in {result['elapsed_sec']}s"
    )
    for phase_id in PHASE_ORDER:
        p = phases[phase_id]
        if p["opcode_count"] == 0:
            continue
        msg(f"  {phase_id:14s}  CMSG={p['cmsg_count']:>4} SMSG={p['smsg_count']:>4}  "
            f"transitions_to={p['transitions_to']}")

    return len(opcodes)


def get_auth_lifecycle(session):
    return session.db.kv_get("auth_lifecycle")


def get_phase_for_opcode(session, opcode_name):
    data = get_auth_lifecycle(session)
    if not data:
        return None
    return data.get("phase_of_opcode", {}).get(opcode_name)
