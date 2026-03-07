"""
Cross-System Dependency Mapper
Maps how game systems (Housing, Combat, Quest, etc.) interact with each
other by tracing shared function calls, data structures, and opcode
cross-references.

Produces a dependency graph showing which systems call into which others,
enabling developers to understand blast radius of changes and identify
tightly-coupled subsystems.
"""

import json
import re
from collections import defaultdict

import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# System classification patterns (opcode name / function name → system)
SYSTEM_PATTERNS = {
    "Housing":      ["HOUSING", "HOUSE", "DECOR", "NEIGHBORHOOD", "INTERIOR",
                     "PLOT", "STEWARD"],
    "Quest":        ["QUEST", "QUESTGIVER", "QUEST_COMPLETE"],
    "Combat":       ["SPELL", "AURA", "ATTACK", "DAMAGE", "HEAL", "CAST",
                     "COMBAT"],
    "Movement":     ["MOVE", "MOVEMENT", "TELEPORT", "TRANSPORT", "FLIGHT"],
    "Social":       ["GUILD", "CHAT", "MAIL", "FRIEND", "PARTY", "GROUP",
                     "RAID", "WHO", "CHANNEL"],
    "Item":         ["ITEM", "INVENTORY", "EQUIP", "BAG", "LOOT"],
    "PvP":          ["BATTLEGROUND", "ARENA", "PVP", "HONOR", "CONQUEST"],
    "Auction":      ["AUCTION"],
    "Crafting":     ["TRADE", "PROFESSION", "CRAFT", "RECIPE", "REAGENT"],
    "Achievement":  ["ACHIEVEMENT", "CRITERIA"],
    "Pet":          ["PET", "BATTLE_PET", "COMPANION"],
    "Talent":       ["TALENT", "SPEC", "GLYPH"],
    "Character":    ["CHARACTER", "PLAYER", "LOGIN", "LOGOUT", "CREATE_CHAR"],
    "NPC":          ["CREATURE", "GOSSIP", "TRAINER", "VENDOR", "NPC"],
    "Map":          ["MAP", "ZONE", "AREA", "INSTANCE", "SCENARIO", "PHASE"],
    "Vehicle":      ["VEHICLE", "SEAT"],
    "Garrison":     ["GARRISON", "FOLLOWER", "MISSION", "SHIPMENT"],
    "Calendar":     ["CALENDAR", "EVENT"],
    "Transmog":     ["TRANSMOG", "APPEARANCE", "WARDROBE"],
    "Collection":   ["COLLECTION", "MOUNT", "TOY", "HEIRLOOM"],
}


def analyze_dependencies(session, system_filter=None):
    """Build a cross-system dependency map.

    Strategy:
      1. Classify all known handlers/functions by system
      2. For each handler, trace callees and check if they belong
         to a different system
      3. Build a directed edge list: System A → System B
      4. Count shared data structures (DB2 tables, JAM types)

    Returns number of cross-system dependencies found.
    """
    db = session.db

    # Step 1: Classify handlers by system
    query = "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL"
    if system_filter:
        query += f" AND (tc_name LIKE '%{system_filter}%' OR jam_type LIKE '%{system_filter}%')"
    handlers = db.fetchall(query)

    handler_system = {}  # ea → system name
    system_handlers = defaultdict(list)  # system → [handler info]

    for h in handlers:
        ea = h["handler_ea"]
        name = h["tc_name"] or h["jam_type"] or f"handler_0x{ea:X}"
        system = _classify_system(name)
        handler_system[ea] = system
        system_handlers[system].append({
            "ea": ea,
            "name": name,
            "direction": h["direction"],
        })

    msg_info(f"Classified {len(handlers)} handlers across "
             f"{len(system_handlers)} systems")

    # Step 2: Trace callees across system boundaries
    edges = defaultdict(lambda: {"count": 0, "shared_funcs": [], "handlers": []})

    for h in handlers:
        ea = h["handler_ea"]
        src_system = handler_system.get(ea, "Other")

        if system_filter and src_system != system_filter:
            continue

        callee_systems = _trace_handler_callees(ea, handler_system)
        handler_name = h["tc_name"] or f"0x{ea:X}"

        for dst_system, callee_names in callee_systems.items():
            if dst_system == src_system:
                continue  # skip self-references

            key = (src_system, dst_system)
            edges[key]["count"] += len(callee_names)
            edges[key]["shared_funcs"].extend(callee_names[:3])
            edges[key]["handlers"].append(handler_name)

    # Step 3: Check for shared DB2 tables
    db2_systems = _classify_db2_by_system(db)
    db2_shared = _find_shared_db2(db2_systems)

    # Step 4: Check for shared JAM types
    jam_systems = _classify_jam_by_system(db)
    jam_shared = _find_shared_jam(jam_systems)

    # Build final dependency graph
    dep_graph = {
        "systems": {},
        "edges": [],
        "shared_db2": db2_shared,
        "shared_jam": jam_shared,
    }

    for system, handler_list in system_handlers.items():
        dep_graph["systems"][system] = {
            "handler_count": len(handler_list),
            "cmsg_count": sum(1 for h in handler_list if h["direction"] == "CMSG"),
            "smsg_count": sum(1 for h in handler_list if h["direction"] == "SMSG"),
        }

    for (src, dst), data in sorted(edges.items(), key=lambda x: -x[1]["count"]):
        dep_graph["edges"].append({
            "from": src,
            "to": dst,
            "weight": data["count"],
            "shared_functions": list(set(data["shared_funcs"]))[:5],
            "handler_count": len(set(data["handlers"])),
        })

    # Store
    db.kv_set("dependency_map", dep_graph)
    db.commit()

    edge_count = len(dep_graph["edges"])
    msg_info(f"Dependency map: {len(dep_graph['systems'])} systems, "
             f"{edge_count} cross-system edges")
    for edge in dep_graph["edges"][:10]:
        msg_info(f"  {edge['from']} -> {edge['to']}: "
                 f"weight={edge['weight']} ({edge['handler_count']} handlers)")

    return edge_count


def _classify_system(name):
    """Classify a handler/function name into a game system."""
    name_upper = name.upper()
    for system, keywords in SYSTEM_PATTERNS.items():
        for kw in keywords:
            if kw in name_upper:
                return system
    return "Other"


def _trace_handler_callees(handler_ea, handler_system_map):
    """Trace callees of a handler and classify them by system.

    Returns {system: [callee_names]} for systems different from the handler's.
    """
    func = ida_funcs.get_func(handler_ea)
    if not func:
        return {}

    result = defaultdict(list)

    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN):
                continue

            target_func = ida_funcs.get_func(xref.to)
            if not target_func or target_func.start_ea == func.start_ea:
                continue

            callee_name = ida_name.get_name(target_func.start_ea)
            if not callee_name or callee_name.startswith("sub_"):
                continue

            # Check if the callee itself is a known handler
            if target_func.start_ea in handler_system_map:
                callee_system = handler_system_map[target_func.start_ea]
                result[callee_system].append(callee_name)
            else:
                # Classify by function name
                callee_system = _classify_system(callee_name)
                if callee_system != "Other":
                    result[callee_system].append(callee_name)

    return dict(result)


def _classify_db2_by_system(db):
    """Classify DB2 tables by game system based on name patterns."""
    result = defaultdict(list)
    for row in db.fetchall("SELECT name FROM db2_tables"):
        name = row["name"]
        system = _classify_system(name)
        result[system].append(name)
    return dict(result)


def _classify_jam_by_system(db):
    """Classify JAM types by game system."""
    result = defaultdict(list)
    for row in db.fetchall("SELECT name FROM jam_types"):
        name = row["name"]
        system = _classify_system(name)
        result[system].append(name)
    return dict(result)


def _find_shared_db2(db2_systems):
    """Find DB2 tables that appear relevant to multiple systems."""
    shared = []
    all_tables = set()
    for tables in db2_systems.values():
        all_tables.update(tables)

    for table in sorted(all_tables):
        systems = []
        table_upper = table.upper()
        for system, keywords in SYSTEM_PATTERNS.items():
            for kw in keywords:
                if kw in table_upper:
                    systems.append(system)
                    break
        if len(systems) > 1:
            shared.append({"table": table, "systems": systems})

    return shared


def _find_shared_jam(jam_systems):
    """Find JAM types that bridge multiple systems."""
    shared = []
    all_jams = set()
    for jams in jam_systems.values():
        all_jams.update(jams)

    for jam in sorted(all_jams):
        systems = []
        jam_upper = jam.upper()
        for system, keywords in SYSTEM_PATTERNS.items():
            for kw in keywords:
                if kw in jam_upper:
                    systems.append(system)
                    break
        if len(systems) > 1:
            shared.append({"jam_type": jam, "systems": systems})

    return shared


def get_dependency_map(session):
    """Retrieve stored dependency map data."""
    return session.db.kv_get("dependency_map") or {}


def get_system_coupling_score(session, system_name):
    """Compute coupling score for a system (higher = more coupled).

    Coupling = (outgoing edges + incoming edges) / total_edges
    """
    dep_map = get_dependency_map(session)
    if not dep_map or "edges" not in dep_map:
        return 0.0

    edges = dep_map["edges"]
    total = len(edges) or 1

    relevant = sum(1 for e in edges
                   if e["from"] == system_name or e["to"] == system_name)
    return round(relevant / total * 100, 1)
