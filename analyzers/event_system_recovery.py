"""
Event System Recovery — Event/Callback Topology Analyzer

Recovers WoW's internal event and callback system topology from the binary:
  - Event registration (Subscribe/Register/AddListener/Bind/Connect patterns)
  - Event emission (Fire/Emit/Trigger/Notify/Dispatch/Broadcast patterns)
  - Timer and scheduled callbacks (CreateTimerQueueTimer, periodic Update loops)
  - Observer patterns (virtual OnXXX methods, subject/observer class hierarchies)
  - Signal/slot wiring (UI signal emission, connect/disconnect patterns)

Builds a complete event flow graph showing emitter -> event -> handler chains,
detects circular event dependencies and event storms, and maps events to
TrinityCore game systems for integration guidance.

Results are stored in the knowledge DB kv_store under key "event_system".
"""

import json
import re
import time
from collections import defaultdict

import ida_funcs
import ida_name
import ida_bytes
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Name patterns for event system function detection
# ---------------------------------------------------------------------------

# Registration patterns — functions that subscribe/register handlers
_REGISTER_PATTERNS = [
    re.compile(r'\bRegister(?:Event|Handler|Callback|Listener|Observer|Hook|Notification)\b', re.IGNORECASE),
    re.compile(r'\bSubscribe(?:To|Event|Handler)?\b', re.IGNORECASE),
    re.compile(r'\bAddListener\b', re.IGNORECASE),
    re.compile(r'\bAddCallback\b', re.IGNORECASE),
    re.compile(r'\bAddObserver\b', re.IGNORECASE),
    re.compile(r'\bAddHandler\b', re.IGNORECASE),
    re.compile(r'\bBind(?:Event|Handler|Callback)?\b', re.IGNORECASE),
    re.compile(r'\bConnect(?:Signal|Slot|Event|Handler)?\b', re.IGNORECASE),
    re.compile(r'\bAttach(?:Handler|Listener|Observer|Callback)\b', re.IGNORECASE),
    re.compile(r'\bInstall(?:Hook|Handler|Callback)\b', re.IGNORECASE),
    re.compile(r'\bSetCallback\b', re.IGNORECASE),
    re.compile(r'\bSet(?:Event|Notification)Handler\b', re.IGNORECASE),
    re.compile(r'\bOn[A-Z]\w{2,}$'),  # OnLoad, OnUpdate, OnDeath etc.
]

# Emission patterns — functions that fire/trigger events
_EMIT_PATTERNS = [
    re.compile(r'\bFire(?:Event|Callback|Handler|Notification)?\b', re.IGNORECASE),
    re.compile(r'\bEmit(?:Event|Signal)?\b', re.IGNORECASE),
    re.compile(r'\bTrigger(?:Event|Callback|Handler|Notification)?\b', re.IGNORECASE),
    re.compile(r'\bNotify(?:Observers?|Listeners?|Handlers?|All)?\b', re.IGNORECASE),
    re.compile(r'\bDispatch(?:Event|Message|Notification)?\b', re.IGNORECASE),
    re.compile(r'\bBroadcast(?:Event|Message|Notification)?\b', re.IGNORECASE),
    re.compile(r'\bRaise(?:Event|Notification)?\b', re.IGNORECASE),
    re.compile(r'\bSend(?:Event|Notification|Signal)\b', re.IGNORECASE),
    re.compile(r'\bPost(?:Event|Message|Notification)\b', re.IGNORECASE),
    re.compile(r'\bInvoke(?:Callbacks?|Handlers?|Listeners?)?\b', re.IGNORECASE),
    re.compile(r'\bProcess(?:Event|Notification)s?\b', re.IGNORECASE),
]

# Timer patterns — functions related to scheduled/periodic callbacks
_TIMER_PATTERNS = [
    re.compile(r'\bCreateTimerQueueTimer\b'),
    re.compile(r'\bSetTimer\b'),
    re.compile(r'\bRegisterTimer\b', re.IGNORECASE),
    re.compile(r'\bScheduleTimer\b', re.IGNORECASE),
    re.compile(r'\bAddTimer\b', re.IGNORECASE),
    re.compile(r'\bStartTimer\b', re.IGNORECASE),
    re.compile(r'\bSchedule(?:Once|Repeated|Periodic|Delayed|At)?\b', re.IGNORECASE),
    re.compile(r'\bSetInterval\b', re.IGNORECASE),
    re.compile(r'\bSetTimeout\b', re.IGNORECASE),
]

# Unregistration patterns — cleanup/disconnect
_UNREGISTER_PATTERNS = [
    re.compile(r'\bUnregister(?:Event|Handler|Callback|Listener|Observer|Hook)?\b', re.IGNORECASE),
    re.compile(r'\bUnsubscribe(?:From|Event|Handler)?\b', re.IGNORECASE),
    re.compile(r'\bRemoveListener\b', re.IGNORECASE),
    re.compile(r'\bRemoveCallback\b', re.IGNORECASE),
    re.compile(r'\bRemoveObserver\b', re.IGNORECASE),
    re.compile(r'\bRemoveHandler\b', re.IGNORECASE),
    re.compile(r'\bDisconnect(?:Signal|Slot|Event|Handler)?\b', re.IGNORECASE),
    re.compile(r'\bDetach(?:Handler|Listener|Observer|Callback)\b', re.IGNORECASE),
]

# System classification (shared with dependency_mapper)
_SYSTEM_PATTERNS = {
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
    "UI":           ["FRAME", "WIDGET", "BUTTON", "SLIDER", "EDIT_BOX",
                     "FONT_STRING", "TEXTURE", "SCRIPT_OBJECT"],
    "Addon":        ["ADDON", "LUA", "SCRIPT"],
    "Network":      ["PACKET", "OPCODE", "CMSG", "SMSG", "WARDEN"],
    "World":        ["WORLD", "UPDATE", "TICK", "HEARTBEAT"],
}


# ---------------------------------------------------------------------------
# Pseudocode patterns for event mechanics
# ---------------------------------------------------------------------------

# Callback storage: push_back, emplace_back, insert into containers
_CALLBACK_STORE_RE = re.compile(
    r'(?:'
    r'(?:push_back|emplace_back|emplace|insert|append)\s*\(\s*(\w+)'  # container.push_back(callback)
    r'|'
    r'\*\s*\(\s*\w+\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*=\s*(\w+)'   # *(arr + offset) = handler
    r'|'
    r'(\w+)\s*\[\s*(0x[0-9A-Fa-f]+|\d+|\w+)\s*\]\s*=\s*(\w+)'       # map[id] = handler
    r')',
    re.MULTILINE
)

# Event ID extraction: constants passed as first/second arg to registration functions
_EVENT_ID_ARG_RE = re.compile(
    r'\(\s*(0x[0-9A-Fa-f]+|\d+)\s*[,)]',
    re.MULTILINE
)

# Iteration over callback list (emission pattern)
_CALLBACK_ITERATE_RE = re.compile(
    r'(?:'
    r'for\s*\([^)]*\)\s*\{[^}]*(?:callback|handler|listener|func|pfn|notify)\s*\('
    r'|'
    r'while\s*\([^)]*(?:iterator|iter|it|node|cur|next)[^)]*\)\s*\{[^}]*\('
    r'|'
    r'(?:begin|cbegin)\s*\([^)]*\).*?(?:end|cend)\s*\('
    r')',
    re.IGNORECASE | re.DOTALL
)

# Timer interval extraction
_TIMER_INTERVAL_RE = re.compile(
    r'(?:'
    r'(?:interval|period|timeout|delay|duration|ms|millisec\w*)\s*'
    r'(?:=|,)\s*(0x[0-9A-Fa-f]+|\d+)'
    r'|'
    r'(?:CreateTimerQueueTimer|SetTimer)\s*\([^,]*,[^,]*,\s*(\w+)\s*,'
    r'[^,]*,\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)'
    r')',
    re.IGNORECASE
)

# Elapsed time check patterns (periodic update detection)
_ELAPSED_CHECK_RE = re.compile(
    r'(?:'
    r'(?:elapsed|delta|dt|diff|time_since|time_diff)\s*'
    r'(?:>=?|>)\s*(0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)'
    r'|'
    r'(?:GetTickCount|GetTime|clock|steady_clock|time)\s*\(\s*\)\s*-\s*(\w+)\s*'
    r'(?:>=?|>)\s*(0x[0-9A-Fa-f]+|\d+)'
    r'|'
    r'(\w+)\s*(?:\+=|-=)\s*(?:elapsed|delta|dt|diff)'
    r')',
    re.IGNORECASE
)

# Virtual function call pattern: (*(vtable + slot))(this, ...)
_VIRTUAL_CALL_RE = re.compile(
    r'\(\s*\*\s*\(\s*\*\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*\)\s*\('
    r'|'
    r'\(\*\(\w+\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\)\)\s*\('
)

# Signal/slot connect pattern
_SIGNAL_CONNECT_RE = re.compile(
    r'(?:'
    r'(?:connect|Connect)\s*\(\s*(?:&?\s*)?(\w+(?:::\w+)?)\s*,'
    r'\s*(?:&?\s*)?(\w+(?:::\w+)?)\s*'
    r'|'
    r'(?:signal|Signal)\s*\.\s*(?:connect|Connect)\s*\(\s*(\w+)'
    r')',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def recover_event_system(session):
    """Recover the complete event/callback system topology from the binary.

    Analyzes named functions, decompiled pseudocode, vtable data, and xrefs
    to build a comprehensive map of event registrations, emissions, timers,
    observer patterns, signal/slot wiring, and event chain topology.

    Args:
        session: PluginSession with db, cfg attributes.

    Returns:
        Total count of event system elements recovered.
    """
    db = session.db
    t0 = time.time()

    msg_info("=" * 60)
    msg_info("Event System Recovery — starting analysis")
    msg_info("=" * 60)

    # Phase 1: Scan all named functions for event-related names
    msg_info("Phase 1: Scanning named functions for event patterns...")
    registration_funcs, emission_funcs, timer_funcs, unregister_funcs = \
        _scan_named_functions()

    msg_info(f"  Found {len(registration_funcs)} registration functions")
    msg_info(f"  Found {len(emission_funcs)} emission functions")
    msg_info(f"  Found {len(timer_funcs)} timer functions")
    msg_info(f"  Found {len(unregister_funcs)} unregistration functions")

    # Phase 2: Analyze registration functions for event IDs and handlers
    msg_info("Phase 2: Analyzing event registrations...")
    event_registrations = _analyze_registrations(
        registration_funcs, db
    )
    msg_info(f"  Recovered {len(event_registrations)} event registrations")

    # Phase 3: Analyze emission functions
    msg_info("Phase 3: Analyzing event emissions...")
    event_emissions = _analyze_emissions(emission_funcs, db)
    msg_info(f"  Recovered {len(event_emissions)} event emissions")

    # Phase 4: Analyze timer/scheduled callbacks
    msg_info("Phase 4: Analyzing timers and scheduled callbacks...")
    timers = _analyze_timers(timer_funcs, db)
    msg_info(f"  Recovered {len(timers)} timer callbacks")

    # Phase 5: Recover observer patterns from vtable data
    msg_info("Phase 5: Recovering observer patterns from vtables...")
    observer_patterns = _recover_observer_patterns(db)
    msg_info(f"  Recovered {len(observer_patterns)} observer patterns")

    # Phase 6: Detect signal/slot wiring
    msg_info("Phase 6: Detecting signal/slot patterns...")
    signal_slots = _detect_signal_slots(db)
    msg_info(f"  Recovered {len(signal_slots)} signal/slot connections")

    # Phase 7: Detect periodic update patterns (non-timer-API based)
    msg_info("Phase 7: Detecting periodic update patterns...")
    periodic_updates = _detect_periodic_updates(db)
    timers.extend(periodic_updates)
    msg_info(f"  Found {len(periodic_updates)} periodic update patterns "
             f"(total timers now: {len(timers)})")

    # Phase 8: Build event topology and detect chains / cycles
    msg_info("Phase 8: Building event topology...")
    event_chains, circular_deps = _build_event_topology(
        event_registrations, event_emissions
    )
    msg_info(f"  Found {len(event_chains)} event chains")
    msg_info(f"  Found {len(circular_deps)} circular dependencies")

    # Phase 9: Map events to game systems
    msg_info("Phase 9: Mapping events to game systems...")
    _assign_systems(event_registrations)
    _assign_systems(event_emissions)
    _assign_systems_timers(timers)
    _assign_systems_observers(observer_patterns)

    # Phase 10: Build cross-system event bridges
    msg_info("Phase 10: Identifying cross-system event bridges...")
    cross_system = _find_cross_system_events(
        event_registrations, event_emissions, observer_patterns
    )

    # Assemble final results
    results = {
        "event_registrations": event_registrations,
        "event_emissions": event_emissions,
        "timers": timers,
        "observer_patterns": observer_patterns,
        "signal_slots": signal_slots,
        "event_chains": event_chains,
        "circular_dependencies": circular_deps,
        "cross_system_events": cross_system,
        "unregistrations": [
            {
                "ea": ea,
                "name": name,
                "system": _classify_system(name),
            }
            for ea, name in unregister_funcs
        ],
        "total_events": len(event_registrations) + len(event_emissions),
        "total_timers": len(timers),
        "total_observers": len(observer_patterns),
        "total_signal_slots": len(signal_slots),
        "analysis_time_sec": round(time.time() - t0, 2),
    }

    db.kv_set("event_system", results)
    db.commit()

    total = (len(event_registrations) + len(event_emissions) +
             len(timers) + len(observer_patterns) + len(signal_slots))

    msg_info("=" * 60)
    msg_info(f"Event System Recovery complete in {results['analysis_time_sec']}s")
    msg_info(f"  Registrations:   {len(event_registrations)}")
    msg_info(f"  Emissions:       {len(event_emissions)}")
    msg_info(f"  Timers:          {len(timers)}")
    msg_info(f"  Observers:       {len(observer_patterns)}")
    msg_info(f"  Signal/Slots:    {len(signal_slots)}")
    msg_info(f"  Event chains:    {len(event_chains)}")
    msg_info(f"  Circular deps:   {len(circular_deps)}")
    msg_info(f"  Cross-system:    {len(cross_system)}")
    msg_info(f"  Total elements:  {total}")
    msg_info("=" * 60)

    return total


# ---------------------------------------------------------------------------
# Phase 1: Scan named functions
# ---------------------------------------------------------------------------

def _scan_named_functions():
    """Scan all named functions in the IDB for event-related patterns.

    Returns four lists of (ea, name) tuples:
      - registration functions
      - emission functions
      - timer functions
      - unregistration functions
    """
    registration_funcs = []
    emission_funcs = []
    timer_funcs = []
    unregister_funcs = []

    count = 0
    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if not name or name.startswith("sub_") or name.startswith("nullsub_"):
            continue

        count += 1

        # Check registration patterns
        for pat in _REGISTER_PATTERNS:
            if pat.search(name):
                registration_funcs.append((ea, name))
                break

        # Check emission patterns
        for pat in _EMIT_PATTERNS:
            if pat.search(name):
                emission_funcs.append((ea, name))
                break

        # Check timer patterns
        for pat in _TIMER_PATTERNS:
            if pat.search(name):
                timer_funcs.append((ea, name))
                break

        # Check unregistration patterns
        for pat in _UNREGISTER_PATTERNS:
            if pat.search(name):
                unregister_funcs.append((ea, name))
                break

    msg_info(f"  Scanned {count} named functions")
    return registration_funcs, emission_funcs, timer_funcs, unregister_funcs


# ---------------------------------------------------------------------------
# Phase 2: Analyze registrations
# ---------------------------------------------------------------------------

def _analyze_registrations(registration_funcs, db):
    """Analyze registration functions to extract event IDs and handler targets.

    For each registration function:
      1. Decompile it
      2. Look for event ID constants passed as arguments
      3. Look for function pointer storage patterns
      4. Find callers to understand who registers what
    """
    registrations = []
    seen_keys = set()

    for ea, name in registration_funcs:
        pseudocode = get_decompiled_text(ea)

        # Extract event IDs from the function body
        event_ids = _extract_event_ids_from_body(pseudocode, name)

        # Extract handler function pointers stored in the body
        handler_eas = _extract_handler_stores(pseudocode, ea)

        # Find who calls this registration function (the registrars)
        callers = _get_callers(ea)

        if event_ids:
            # We have specific event IDs being registered
            for eid in event_ids:
                for handler_ea, handler_name in handler_eas:
                    key = (eid, handler_ea)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)

                    registrations.append({
                        "event_id": eid,
                        "handler_ea": handler_ea,
                        "handler_name": handler_name,
                        "registrar_ea": ea,
                        "registrar_name": name,
                        "callers": callers[:5],
                        "system": "",
                    })

                # If no handler_eas found but we have event IDs,
                # the function itself is the registration mechanism
                if not handler_eas:
                    for caller_ea, caller_name in callers:
                        key = (eid, caller_ea)
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)

                        registrations.append({
                            "event_id": eid,
                            "handler_ea": caller_ea,
                            "handler_name": caller_name,
                            "registrar_ea": ea,
                            "registrar_name": name,
                            "callers": [],
                            "system": "",
                        })
        else:
            # No explicit event IDs — record the registration function itself
            # and try to extract event info from callers' context
            caller_registrations = _analyze_caller_registrations(
                ea, name, callers, seen_keys
            )
            registrations.extend(caller_registrations)

    return registrations


def _extract_event_ids_from_body(pseudocode, func_name):
    """Extract event ID constants from function body.

    Looks for:
      - Integer constants passed as first arguments
      - Switch/case values on event type parameters
      - Named constants that look like event IDs
    """
    event_ids = []
    if not pseudocode:
        return event_ids

    # Look for case statements (dispatch on event ID)
    case_re = re.compile(r'case\s+(0x[0-9A-Fa-f]+|\d+)\s*:', re.MULTILINE)
    for m in case_re.finditer(pseudocode):
        try:
            val = int(m.group(1), 0)
            if 0 < val < 0x10000:  # reasonable event ID range
                event_ids.append(val)
        except ValueError:
            pass

    # Look for comparisons against event type parameter (a2 == X, eventType == X)
    cmp_re = re.compile(
        r'(?:a[12]|event(?:Type|Id|ID|_type|_id)?)\s*==\s*(0x[0-9A-Fa-f]+|\d+)',
        re.IGNORECASE
    )
    for m in cmp_re.finditer(pseudocode):
        try:
            val = int(m.group(1), 0)
            if 0 < val < 0x10000:
                if val not in event_ids:
                    event_ids.append(val)
        except ValueError:
            pass

    return event_ids


def _extract_handler_stores(pseudocode, reg_func_ea):
    """Extract function pointers being stored (registered as handlers).

    Returns list of (ea, name) for handler functions.
    """
    handlers = []
    if not pseudocode:
        return handlers

    # Look for direct function address references in the pseudocode
    # Pattern: push_back(some_func) or map[id] = some_func
    func_ref_re = re.compile(
        r'(?:push_back|emplace_back|insert|=)\s*\(\s*'
        r'(?:&?\s*)?(\w+(?:::\w+)?)\s*[,)]'
    )
    for m in func_ref_re.finditer(pseudocode):
        ref_name = m.group(1)
        # Skip common non-function tokens
        if ref_name in ("this", "nullptr", "NULL", "0", "true", "false",
                         "void", "int", "char", "bool", "auto"):
            continue
        if ref_name.startswith("v") and ref_name[1:].isdigit():
            continue  # skip local variables like v5, v12
        if ref_name.startswith("a") and ref_name[1:].isdigit():
            continue  # skip parameters like a1, a2

        # Try to resolve the name to an address
        ref_ea = ida_name.get_name_ea(idaapi.BADADDR, ref_name)
        if ref_ea != idaapi.BADADDR:
            func = ida_funcs.get_func(ref_ea)
            if func:
                handlers.append((func.start_ea, ref_name))

    # Also look for direct address assignments: *(ptr + offset) = 0x7FF...
    addr_store_re = re.compile(
        r'=\s*(0x[0-9A-Fa-f]{8,16})\b'
    )
    for m in addr_store_re.finditer(pseudocode):
        try:
            addr = int(m.group(1), 16)
            func = ida_funcs.get_func(addr)
            if func:
                fname = ida_name.get_name(func.start_ea) or ea_str(func.start_ea)
                handlers.append((func.start_ea, fname))
        except ValueError:
            pass

    return handlers


def _get_callers(ea):
    """Get all functions that call the given address.

    Returns list of (caller_ea, caller_name) sorted by ea.
    """
    callers = []
    seen = set()

    for xref in idautils.XrefsTo(ea, 0):
        caller_func = ida_funcs.get_func(xref.frm)
        if not caller_func:
            continue
        caller_ea = caller_func.start_ea
        if caller_ea in seen:
            continue
        seen.add(caller_ea)

        caller_name = ida_name.get_name(caller_ea) or ea_str(caller_ea)
        callers.append((caller_ea, caller_name))

    return sorted(callers, key=lambda x: x[0])


def _analyze_caller_registrations(reg_ea, reg_name, callers, seen_keys):
    """When a registration function has no explicit event IDs in its body,
    analyze its callers to find what event IDs they pass.
    """
    registrations = []

    for caller_ea, caller_name in callers[:50]:  # limit to prevent runaway
        pseudocode = get_decompiled_text(caller_ea)
        if not pseudocode:
            continue

        # Find calls to the registration function with event ID arguments
        # Pattern: RegisterEvent(EVENT_ID, handler)
        # We search for the registration function name followed by arguments
        call_re = re.compile(
            re.escape(reg_name) + r'\s*\(\s*(0x[0-9A-Fa-f]+|\d+)',
            re.IGNORECASE
        )
        for m in call_re.finditer(pseudocode):
            try:
                eid = int(m.group(1), 0)
                if 0 < eid < 0x100000:
                    key = (eid, caller_ea)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        registrations.append({
                            "event_id": eid,
                            "handler_ea": caller_ea,
                            "handler_name": caller_name,
                            "registrar_ea": reg_ea,
                            "registrar_name": reg_name,
                            "callers": [],
                            "system": "",
                        })
            except ValueError:
                pass

        # Also check for named event constant patterns
        named_event_re = re.compile(
            re.escape(reg_name) + r'\s*\(\s*(\w+Event\w*|\w+EVENT\w*)',
            re.IGNORECASE
        )
        for m in named_event_re.finditer(pseudocode):
            event_name = m.group(1)
            key = (event_name, caller_ea)
            if key not in seen_keys:
                seen_keys.add(key)
                registrations.append({
                    "event_id": event_name,
                    "handler_ea": caller_ea,
                    "handler_name": caller_name,
                    "registrar_ea": reg_ea,
                    "registrar_name": reg_name,
                    "callers": [],
                    "system": "",
                })

    return registrations


# ---------------------------------------------------------------------------
# Phase 3: Analyze emissions
# ---------------------------------------------------------------------------

def _analyze_emissions(emission_funcs, db):
    """Analyze emission functions to extract what events they fire and
    how many arguments they pass.
    """
    emissions = []
    seen_keys = set()

    for ea, name in emission_funcs:
        pseudocode = get_decompiled_text(ea)

        # Extract event IDs from the emission function
        event_ids = _extract_event_ids_from_body(pseudocode, name)
        arg_count = _estimate_arg_count(pseudocode, name)

        # Find who calls this emission function
        callers = _get_callers(ea)

        if event_ids:
            for eid in event_ids:
                key = (eid, ea)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                emissions.append({
                    "event_id": eid,
                    "emitter_ea": ea,
                    "emitter_name": name,
                    "arg_count": arg_count,
                    "caller_count": len(callers),
                    "callers": [
                        {"ea": c[0], "name": c[1]}
                        for c in callers[:5]
                    ],
                    "system": "",
                })
        else:
            # Analyze callers to find event IDs passed to emission functions
            caller_emissions = _analyze_caller_emissions(
                ea, name, callers, arg_count, seen_keys
            )
            emissions.extend(caller_emissions)

        # Even if we found event IDs, also record the emission function itself
        # as a general emitter if it has many callers
        if len(callers) >= 3 and not event_ids:
            key = ("dispatch", ea)
            if key not in seen_keys:
                seen_keys.add(key)
                emissions.append({
                    "event_id": "dispatch",
                    "emitter_ea": ea,
                    "emitter_name": name,
                    "arg_count": arg_count,
                    "caller_count": len(callers),
                    "callers": [
                        {"ea": c[0], "name": c[1]}
                        for c in callers[:5]
                    ],
                    "system": "",
                })

    return emissions


def _estimate_arg_count(pseudocode, func_name):
    """Estimate the number of arguments an event function takes."""
    if not pseudocode:
        return 0

    # Count parameters in function signature
    sig_re = re.compile(
        r'(?:__int64|void|int|bool|char|unsigned)\s+(?:__fastcall\s+)?'
        r'\w+\s*\(([^)]*)\)'
    )
    m = sig_re.search(pseudocode)
    if m:
        params = m.group(1).strip()
        if not params or params == "void":
            return 0
        return len([p.strip() for p in params.split(",") if p.strip()])

    return 0


def _analyze_caller_emissions(emit_ea, emit_name, callers, arg_count, seen_keys):
    """Analyze callers of emission functions to find event IDs they fire."""
    emissions = []

    for caller_ea, caller_name in callers[:50]:
        pseudocode = get_decompiled_text(caller_ea)
        if not pseudocode:
            continue

        # Find calls to the emission function with event ID arguments
        call_re = re.compile(
            re.escape(emit_name) + r'\s*\(\s*(0x[0-9A-Fa-f]+|\d+)',
            re.IGNORECASE
        )
        for m in call_re.finditer(pseudocode):
            try:
                eid = int(m.group(1), 0)
                if 0 < eid < 0x100000:
                    key = (eid, emit_ea)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        emissions.append({
                            "event_id": eid,
                            "emitter_ea": emit_ea,
                            "emitter_name": emit_name,
                            "arg_count": arg_count,
                            "caller_count": len(callers),
                            "callers": [
                                {"ea": caller_ea, "name": caller_name}
                            ],
                            "system": "",
                        })
            except ValueError:
                pass

    return emissions


# ---------------------------------------------------------------------------
# Phase 4: Timer/scheduled callback analysis
# ---------------------------------------------------------------------------

def _analyze_timers(timer_funcs, db):
    """Analyze timer-related functions to extract callback, interval, and
    one-shot vs repeating info.
    """
    timers = []
    seen_callbacks = set()

    for ea, name in timer_funcs:
        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            # Still record the timer function even without decompilation
            timers.append({
                "callback_ea": ea,
                "callback_name": name,
                "interval_ms": 0,
                "is_repeating": _guess_is_repeating(name),
                "source": "name_match",
                "system": "",
            })
            continue

        # Extract timer parameters
        timer_info = _extract_timer_params(pseudocode, ea, name)
        for ti in timer_info:
            cb_key = ti.get("callback_ea", ea)
            if cb_key in seen_callbacks:
                continue
            seen_callbacks.add(cb_key)
            timers.append(ti)

        # If no specific timer info extracted, record the function itself
        if not timer_info and ea not in seen_callbacks:
            seen_callbacks.add(ea)
            timers.append({
                "callback_ea": ea,
                "callback_name": name,
                "interval_ms": 0,
                "is_repeating": _guess_is_repeating(name),
                "source": "name_match",
                "system": "",
            })

    return timers


def _guess_is_repeating(name):
    """Heuristic: is a timer function repeating or one-shot?"""
    name_lower = name.lower()
    if any(kw in name_lower for kw in ("once", "timeout", "delayed", "single")):
        return False
    if any(kw in name_lower for kw in ("periodic", "interval", "repeating",
                                        "heartbeat", "tick", "update")):
        return True
    return True  # default assumption for game timers


def _extract_timer_params(pseudocode, func_ea, func_name):
    """Extract timer callback, interval, and repeat mode from pseudocode."""
    timers = []

    # Pattern 1: CreateTimerQueueTimer(&timer, queue, callback, ctx, due, period, flags)
    create_timer_re = re.compile(
        r'CreateTimerQueueTimer\s*\(\s*'
        r'[^,]+,\s*'           # &timer
        r'[^,]+,\s*'           # queue (or NULL)
        r'(\w+)\s*,\s*'        # callback
        r'[^,]+,\s*'           # context
        r'(0x[0-9A-Fa-f]+|\d+)\s*,\s*'  # dueTime
        r'(0x[0-9A-Fa-f]+|\d+)\s*,?\s*' # period
        r'([^)]*)\)',                     # flags
        re.IGNORECASE
    )
    for m in create_timer_re.finditer(pseudocode):
        callback_name = m.group(1)
        due_time = _safe_int(m.group(2))
        period = _safe_int(m.group(3))

        callback_ea = _resolve_name_to_ea(callback_name)
        timers.append({
            "callback_ea": callback_ea if callback_ea else func_ea,
            "callback_name": callback_name,
            "interval_ms": period if period > 0 else due_time,
            "is_repeating": period > 0,
            "source": "CreateTimerQueueTimer",
            "system": "",
        })

    # Pattern 2: SetTimer(hwnd, id, interval, callback)
    set_timer_re = re.compile(
        r'SetTimer\s*\(\s*'
        r'[^,]+,\s*'           # hwnd
        r'(0x[0-9A-Fa-f]+|\d+)\s*,\s*'  # timer ID
        r'(0x[0-9A-Fa-f]+|\d+)\s*,\s*'  # interval
        r'(\w+)\s*\)',                    # callback
        re.IGNORECASE
    )
    for m in set_timer_re.finditer(pseudocode):
        timer_id = _safe_int(m.group(1))
        interval = _safe_int(m.group(2))
        callback_name = m.group(3)

        callback_ea = _resolve_name_to_ea(callback_name)
        timers.append({
            "callback_ea": callback_ea if callback_ea else func_ea,
            "callback_name": callback_name,
            "interval_ms": interval,
            "is_repeating": True,
            "timer_id": timer_id,
            "source": "SetTimer",
            "system": "",
        })

    # Pattern 3: Generic interval assignment: this->m_interval = 1000;
    interval_assign_re = re.compile(
        r'(?:interval|period|timer_ms|update_ms|tick_ms|heartbeat_ms)\s*=\s*'
        r'(0x[0-9A-Fa-f]+|\d+)',
        re.IGNORECASE
    )
    for m in interval_assign_re.finditer(pseudocode):
        interval = _safe_int(m.group(1))
        if 0 < interval < 3600000:  # reasonable range: 1ms to 1 hour
            timers.append({
                "callback_ea": func_ea,
                "callback_name": func_name,
                "interval_ms": interval,
                "is_repeating": True,
                "source": "interval_assignment",
                "system": "",
            })

    # Pattern 4: Callback function pointer passed to a scheduling function
    schedule_re = re.compile(
        r'(?:Schedule|AddTimer|RegisterTimer|QueueCallback)\s*\(\s*'
        r'(?:[^,]+,\s*)?'  # optional first arg (context/id)
        r'(0x[0-9A-Fa-f]+|\d+)\s*,\s*'  # interval
        r'(\w+)\s*',                      # callback
        re.IGNORECASE
    )
    for m in schedule_re.finditer(pseudocode):
        interval = _safe_int(m.group(1))
        callback_name = m.group(2)
        if 0 < interval < 3600000:
            callback_ea = _resolve_name_to_ea(callback_name)
            timers.append({
                "callback_ea": callback_ea if callback_ea else func_ea,
                "callback_name": callback_name,
                "interval_ms": interval,
                "is_repeating": True,
                "source": "schedule_call",
                "system": "",
            })

    return timers


# ---------------------------------------------------------------------------
# Phase 5: Observer pattern recovery
# ---------------------------------------------------------------------------

def _recover_observer_patterns(db):
    """Recover observer patterns by analyzing vtable data.

    Strategy:
      1. Load vtable data from the DB
      2. Find classes with multiple virtual OnXXX methods (observer interfaces)
      3. Find classes that maintain lists of such interfaces (subjects)
      4. Map concrete implementations via vtable inheritance
    """
    observer_patterns = []

    # Load vtable data
    vtables = db.fetchall(
        "SELECT * FROM vtables ORDER BY class_name"
    ) if _table_exists(db, "vtables") else []

    if not vtables:
        # Try kv_store fallback
        vtable_data = db.kv_get("vtable_analysis")
        if vtable_data and isinstance(vtable_data, dict):
            vtables_list = vtable_data.get("vtables", [])
            return _recover_observers_from_kv(vtables_list)
        msg_warn("  No vtable data available — skipping observer recovery")
        return observer_patterns

    # Build class → vtable entries map
    class_vtables = defaultdict(list)
    for vt in vtables:
        class_name = vt["class_name"] or ""
        if class_name:
            class_vtables[class_name].append(vt)

    # Load vtable entries for OnXXX method detection
    vtable_entries = {}
    if _table_exists(db, "vtable_entries"):
        entries = db.fetchall("SELECT * FROM vtable_entries")
        for entry in entries:
            vt_ea = entry["vtable_ea"]
            if vt_ea not in vtable_entries:
                vtable_entries[vt_ea] = []
            vtable_entries[vt_ea].append(entry)

    # Phase 5a: Find observer interfaces (classes with virtual OnXXX methods)
    observer_interfaces = {}
    for class_name, class_vts in class_vtables.items():
        on_methods = []
        for vt in class_vts:
            vt_ea = vt["ea"]
            entries = vtable_entries.get(vt_ea, [])
            for entry in entries:
                fname = entry["func_name"] or ""
                if _is_observer_method(fname):
                    on_methods.append({
                        "name": fname,
                        "slot": entry["slot_index"],
                        "ea": entry["func_ea"],
                    })

        if len(on_methods) >= 2:
            observer_interfaces[class_name] = on_methods

    msg_info(f"  Found {len(observer_interfaces)} potential observer interfaces")

    # Phase 5b: Find subject classes (those that call OnXXX methods on lists)
    for iface_name, methods in observer_interfaces.items():
        # Find all vtables that share these OnXXX method slots
        # (concrete implementations of the interface)
        implementations = _find_interface_implementations(
            iface_name, methods, class_vtables, vtable_entries
        )

        # Find the subject class that holds/iterates the observer list
        subject_class = _find_subject_class(iface_name, methods, db)

        notification_methods = [m["name"] for m in methods]

        observer_patterns.append({
            "subject_class": subject_class,
            "observer_interface": iface_name,
            "implementations": implementations,
            "notification_methods": notification_methods,
            "method_count": len(methods),
            "impl_count": len(implementations),
            "system": _classify_system(iface_name),
        })

    return observer_patterns


def _is_observer_method(name):
    """Check if a method name looks like an observer callback."""
    if not name:
        return False
    # Match OnXXX, HandleXXX, NotifyXXX patterns
    observer_prefixes = [
        "On", "Handle", "Notify", "Before", "After",
        "Will", "Did", "Should", "Can",
    ]
    for prefix in observer_prefixes:
        if name.startswith(prefix) and len(name) > len(prefix):
            # Next char should be uppercase
            next_char = name[len(prefix)]
            if next_char.isupper() or next_char == '_':
                return True
    return False


def _find_interface_implementations(iface_name, methods, class_vtables,
                                     vtable_entries):
    """Find classes that implement the same virtual OnXXX methods
    (likely concrete observers)."""
    implementations = []
    method_names = {m["name"] for m in methods}

    for class_name, class_vts in class_vtables.items():
        if class_name == iface_name:
            continue

        shared_methods = set()
        for vt in class_vts:
            vt_ea = vt["ea"]
            entries = vtable_entries.get(vt_ea, [])
            for entry in entries:
                fname = entry["func_name"] or ""
                if fname in method_names:
                    shared_methods.add(fname)

        # If class shares more than half the observer methods,
        # it's likely an implementation
        if len(shared_methods) >= max(1, len(method_names) // 2):
            total_methods = len(method_names) or 1  # guard div-by-zero
            implementations.append({
                "class_name": class_name,
                "shared_methods": sorted(shared_methods),
                "coverage": round(len(shared_methods) / total_methods * 100, 1),
            })

    return sorted(implementations, key=lambda x: -x["coverage"])[:20]


def _find_subject_class(iface_name, methods, db):
    """Try to find the subject class that maintains and notifies observers.

    Heuristic: look for functions that iterate over a list and call
    the observer's OnXXX methods.
    """
    # Search for functions that reference the observer interface name
    # and contain iteration + callback patterns
    for method_info in methods[:3]:
        method_ea = method_info.get("ea", 0)
        if not method_ea:
            continue

        # Check xrefs TO this method — who calls it?
        for xref in idautils.XrefsTo(method_ea, 0):
            caller_func = ida_funcs.get_func(xref.frm)
            if not caller_func:
                continue

            caller_name = ida_name.get_name(caller_func.start_ea)
            if not caller_name or caller_name.startswith("sub_"):
                continue

            # Check if this caller iterates over a collection
            pseudocode = get_decompiled_text(caller_func.start_ea)
            if pseudocode and _CALLBACK_ITERATE_RE.search(pseudocode):
                # Extract the class part of the name
                parts = caller_name.split("::")
                if len(parts) >= 2:
                    return parts[0]
                return caller_name

    # Fallback: derive subject name from interface name
    # e.g., ISpellObserver → SpellManager
    if iface_name.startswith("I"):
        base = iface_name[1:]
        for suffix in ("Observer", "Listener", "Handler", "Callback"):
            if base.endswith(suffix):
                return base[:-len(suffix)] + "Manager"
    return f"Unknown_Subject_for_{iface_name}"


def _recover_observers_from_kv(vtables_list):
    """Recover observer patterns from kv-stored vtable data (fallback)."""
    observer_patterns = []
    class_methods = defaultdict(list)

    for vt in vtables_list:
        class_name = vt.get("class_name") or vt.get("name") or ""
        entries = vt.get("entries", [])
        for entry in entries:
            fname = entry.get("name", "")
            if _is_observer_method(fname):
                class_methods[class_name].append(fname)

    for class_name, methods in class_methods.items():
        if len(methods) >= 2:
            observer_patterns.append({
                "subject_class": f"Unknown_Subject_for_{class_name}",
                "observer_interface": class_name,
                "implementations": [],
                "notification_methods": methods,
                "method_count": len(methods),
                "impl_count": 0,
                "system": _classify_system(class_name),
            })

    return observer_patterns


# ---------------------------------------------------------------------------
# Phase 6: Signal/slot detection
# ---------------------------------------------------------------------------

def _detect_signal_slots(db):
    """Detect signal/slot patterns in the binary.

    WoW uses internal signal mechanisms primarily in the UI layer.
    Look for:
      - Signal emission patterns (call through function pointer arrays)
      - Connect/Disconnect function pairs
      - Slot function registration
    """
    signal_slots = []
    seen = set()

    # Search for functions with "Signal" or "Slot" in their name
    signal_funcs = []
    connect_funcs = []

    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if not name or name.startswith("sub_"):
            continue

        name_lower = name.lower()
        if "signal" in name_lower:
            signal_funcs.append((ea, name))
        if "connect" in name_lower and ("signal" in name_lower or
                                         "slot" in name_lower or
                                         "event" in name_lower):
            connect_funcs.append((ea, name))

    msg_info(f"  Found {len(signal_funcs)} signal functions, "
             f"{len(connect_funcs)} connect functions")

    # Analyze connect functions
    for ea, name in connect_funcs:
        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        # Extract signal-slot connections from the pseudocode
        for m in _SIGNAL_CONNECT_RE.finditer(pseudocode):
            signal_name = m.group(1) or m.group(3) or ""
            slot_name = m.group(2) or ""

            key = (signal_name, slot_name, ea)
            if key in seen:
                continue
            seen.add(key)

            signal_slots.append({
                "signal": signal_name,
                "slot": slot_name,
                "connector_ea": ea,
                "connector_name": name,
                "system": _classify_system(name),
            })

    # Analyze signal emission functions
    for ea, name in signal_funcs:
        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        # Check for iteration-based emission (calling all connected slots)
        if _CALLBACK_ITERATE_RE.search(pseudocode):
            key = (name, "broadcast", ea)
            if key not in seen:
                seen.add(key)
                signal_slots.append({
                    "signal": name,
                    "slot": "<broadcast>",
                    "connector_ea": ea,
                    "connector_name": name,
                    "system": _classify_system(name),
                })

    # Also analyze callers of connect functions to find wiring sites
    for ea, name in connect_funcs[:20]:
        callers = _get_callers(ea)
        for caller_ea, caller_name in callers[:10]:
            pseudocode = get_decompiled_text(caller_ea)
            if not pseudocode:
                continue

            # Look for the connect call in the caller's code
            connect_call_re = re.compile(
                re.escape(name) + r'\s*\(\s*(?:&?\s*)?(\w+(?:::\w+)?)\s*,'
                r'\s*(?:&?\s*)?(\w+(?:::\w+)?)',
                re.IGNORECASE
            )
            for m in connect_call_re.finditer(pseudocode):
                sig = m.group(1)
                slt = m.group(2)
                key = (sig, slt, caller_ea)
                if key not in seen:
                    seen.add(key)
                    signal_slots.append({
                        "signal": sig,
                        "slot": slt,
                        "connector_ea": caller_ea,
                        "connector_name": caller_name,
                        "system": _classify_system(caller_name),
                    })

    return signal_slots


# ---------------------------------------------------------------------------
# Phase 7: Periodic update pattern detection
# ---------------------------------------------------------------------------

def _detect_periodic_updates(db):
    """Detect periodic update patterns that don't use explicit timer APIs.

    Many game systems use a pattern like:
        void System::Update(uint32 diff) {
            m_timer -= diff;
            if (m_timer <= 0) {
                DoPeriodicWork();
                m_timer = INTERVAL;
            }
        }

    We find these by looking for:
      1. Functions named *Update* that take a time diff parameter
      2. Elapsed time comparisons inside those functions
      3. Timer reset patterns
    """
    periodic_updates = []
    seen = set()

    # Find Update-like functions
    update_funcs = []
    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if not name or name.startswith("sub_"):
            continue

        name_lower = name.lower()
        if any(kw in name_lower for kw in ("update", "tick", "heartbeat",
                                            "pulse", "poll", "periodic")):
            update_funcs.append((ea, name))

    msg_info(f"  Scanning {len(update_funcs)} update/tick functions...")

    for ea, name in update_funcs:
        if ea in seen:
            continue

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        # Check for elapsed time patterns
        elapsed_matches = list(_ELAPSED_CHECK_RE.finditer(pseudocode))
        if not elapsed_matches:
            continue

        # Extract interval values
        for m in elapsed_matches:
            interval_str = m.group(1) or m.group(3) or "0"
            try:
                interval = int(interval_str, 0) if isinstance(interval_str, str) \
                    else int(interval_str)
            except (ValueError, TypeError):
                interval = 0

            if interval <= 0 or interval > 3600000:
                continue

            # Determine what function gets called inside the timer check
            # Look for function calls near the elapsed check
            check_pos = m.end()
            nearby_code = pseudocode[check_pos:check_pos + 500]
            called_funcs = _extract_called_functions(nearby_code)

            callback_name = called_funcs[0] if called_funcs else name
            callback_ea = ea

            if called_funcs:
                resolved = _resolve_name_to_ea(called_funcs[0])
                if resolved:
                    callback_ea = resolved

            if callback_ea not in seen:
                seen.add(callback_ea)
                periodic_updates.append({
                    "callback_ea": callback_ea,
                    "callback_name": callback_name,
                    "interval_ms": interval,
                    "is_repeating": True,
                    "source": "periodic_update_pattern",
                    "update_func_ea": ea,
                    "update_func_name": name,
                    "system": "",
                })

    return periodic_updates


def _extract_called_functions(code_snippet):
    """Extract function call names from a code snippet."""
    call_re = re.compile(r'(\w+(?:::\w+)?)\s*\(')
    names = []
    skip = {"if", "while", "for", "switch", "return", "case", "sizeof",
            "static_cast", "dynamic_cast", "reinterpret_cast", "const_cast",
            "LODWORD", "HIDWORD", "LOWORD", "HIWORD", "LOBYTE", "HIBYTE",
            "BYTE1", "BYTE2", "BYTE3", "BYTE4", "WORD1", "WORD2",
            "__int64", "unsigned", "signed", "void", "int", "char", "bool",
            "float", "double", "DWORD"}
    for m in call_re.finditer(code_snippet):
        name = m.group(1)
        if name not in skip and not name.startswith("v") or \
           (name.startswith("v") and not name[1:].isdigit()):
            if "::" in name or (name[0].isupper() and len(name) > 2):
                names.append(name)
    return names


# ---------------------------------------------------------------------------
# Phase 8: Event topology construction
# ---------------------------------------------------------------------------

def _build_event_topology(registrations, emissions):
    """Build the event flow graph and detect chains and cycles.

    An event chain is: emitter fires event A -> handler for A fires event B
                       -> handler for B fires event C ...

    A circular dependency is when a chain loops back to an earlier event.
    """
    # Build lookup structures
    # event_id -> list of handler EAs
    event_handlers = defaultdict(list)
    for reg in registrations:
        eid = reg["event_id"]
        event_handlers[eid].append(reg["handler_ea"])

    # handler EA -> list of event_ids it emits
    handler_emissions = defaultdict(list)
    for em in emissions:
        eid = em["event_id"]
        # Check all callers of the emission function
        for caller in em.get("callers", []):
            handler_emissions[caller["ea"]].append(eid)
        # Also check the emitter itself
        handler_emissions[em["emitter_ea"]].append(eid)

    # Build adjacency: event_id -> list of downstream event_ids
    event_graph = defaultdict(set)
    for eid, handlers in event_handlers.items():
        for handler_ea in handlers:
            downstream_events = handler_emissions.get(handler_ea, [])
            for downstream_eid in downstream_events:
                if downstream_eid != eid:  # skip trivial self-loops
                    event_graph[eid].add(downstream_eid)

    # Find all chains using DFS
    event_chains = []
    circular_deps = []
    visited_global = set()

    all_events = set(event_handlers.keys()) | set(
        eid for em in emissions for eid in [em["event_id"]]
    )

    for start_event in sorted(all_events, key=str):
        if start_event in visited_global:
            continue

        # DFS from this event
        chains, cycles = _dfs_event_chains(start_event, event_graph)
        event_chains.extend(chains)
        circular_deps.extend(cycles)

        for chain in chains:
            for eid in chain["chain"]:
                visited_global.add(eid)

    # Deduplicate chains and cycles
    event_chains = _deduplicate_chains(event_chains)
    circular_deps = _deduplicate_chains(circular_deps)

    return event_chains, circular_deps


def _dfs_event_chains(start, graph, max_depth=20):
    """DFS traversal to find event chains and cycles starting from 'start'."""
    chains = []
    cycles = []

    def _dfs(current, path, path_set, depth):
        if depth > max_depth:
            return

        downstream = graph.get(current, set())
        if not downstream:
            # End of chain
            if len(path) >= 2:
                systems = set()
                for eid in path:
                    sys = _classify_system(str(eid))
                    if sys != "Other":
                        systems.add(sys)

                chains.append({
                    "chain": list(path),
                    "depth": len(path),
                    "systems_involved": sorted(systems),
                })
            return

        for next_event in sorted(downstream, key=str):
            if next_event in path_set:
                # Cycle detected
                cycle_start = path.index(next_event)
                cycle = list(path[cycle_start:]) + [next_event]
                cycles.append({
                    "cycle": cycle,
                    "depth": len(cycle),
                    "systems_involved": sorted(set(
                        _classify_system(str(e))
                        for e in cycle
                        if _classify_system(str(e)) != "Other"
                    )),
                })
                continue

            path.append(next_event)
            path_set.add(next_event)
            _dfs(next_event, path, path_set, depth + 1)
            path.pop()
            path_set.discard(next_event)

    _dfs(start, [start], {start}, 0)
    return chains, cycles


def _deduplicate_chains(items):
    """Remove duplicate chains/cycles based on their event sequences."""
    seen = set()
    unique = []
    for item in items:
        key_list = item.get("chain") or item.get("cycle", [])
        key = tuple(str(e) for e in key_list)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


# ---------------------------------------------------------------------------
# Phase 9: System classification
# ---------------------------------------------------------------------------

def _classify_system(name):
    """Classify a function/event name into a game system."""
    if not name:
        return "Other"
    name_upper = str(name).upper()
    for system, keywords in _SYSTEM_PATTERNS.items():
        for kw in keywords:
            if kw in name_upper:
                return system
    return "Other"


def _assign_systems(items):
    """Assign system classification to a list of event dicts."""
    for item in items:
        if not item.get("system"):
            # Try registrar/emitter name first, then handler name
            for name_key in ("registrar_name", "emitter_name", "handler_name",
                             "callback_name"):
                name = item.get(name_key, "")
                if name:
                    system = _classify_system(name)
                    if system != "Other":
                        item["system"] = system
                        break
            if not item.get("system"):
                item["system"] = "Other"


def _assign_systems_timers(timers):
    """Assign system classification to timer entries."""
    for timer in timers:
        if not timer.get("system"):
            name = timer.get("callback_name", "") or timer.get(
                "update_func_name", "")
            timer["system"] = _classify_system(name)


def _assign_systems_observers(observers):
    """Assign system classification to observer patterns."""
    for obs in observers:
        if not obs.get("system"):
            iface = obs.get("observer_interface", "")
            subject = obs.get("subject_class", "")
            obs["system"] = _classify_system(iface)
            if obs["system"] == "Other":
                obs["system"] = _classify_system(subject)


# ---------------------------------------------------------------------------
# Phase 10: Cross-system event bridges
# ---------------------------------------------------------------------------

def _find_cross_system_events(registrations, emissions, observer_patterns):
    """Identify events that bridge between different game systems.

    A cross-system event is one where:
      - The emitter belongs to system A
      - The handler belongs to system B (A != B)
    """
    cross_system = []
    seen = set()

    # Build emission system map: event_id -> emitter system
    emission_systems = defaultdict(set)
    for em in emissions:
        eid = em["event_id"]
        system = em.get("system", "Other")
        if system != "Other":
            emission_systems[eid].add(system)

    # Check registrations for cross-system bridges
    for reg in registrations:
        eid = reg["event_id"]
        handler_system = reg.get("system", "Other")

        emitter_systems = emission_systems.get(eid, set())
        for emitter_sys in emitter_systems:
            if emitter_sys != handler_system and handler_system != "Other":
                key = (eid, emitter_sys, handler_system)
                if key not in seen:
                    seen.add(key)
                    cross_system.append({
                        "event_id": eid,
                        "emitter_system": emitter_sys,
                        "handler_system": handler_system,
                        "handler_name": reg.get("handler_name", ""),
                        "emitter_name": "",  # filled below
                    })

    # Fill emitter names
    emitter_by_event = {}
    for em in emissions:
        emitter_by_event[em["event_id"]] = em.get("emitter_name", "")
    for cs in cross_system:
        cs["emitter_name"] = emitter_by_event.get(cs["event_id"], "")

    # Also add observer-based cross-system bridges
    for obs in observer_patterns:
        obs_system = obs.get("system", "Other")
        for impl in obs.get("implementations", []):
            impl_system = _classify_system(impl.get("class_name", ""))
            if impl_system != obs_system and impl_system != "Other" and \
               obs_system != "Other":
                key = (obs.get("observer_interface", ""), obs_system, impl_system)
                if key not in seen:
                    seen.add(key)
                    cross_system.append({
                        "event_id": obs.get("observer_interface", ""),
                        "emitter_system": obs_system,
                        "handler_system": impl_system,
                        "handler_name": impl.get("class_name", ""),
                        "emitter_name": obs.get("subject_class", ""),
                    })

    return sorted(cross_system, key=lambda x: (
        x["emitter_system"], x["handler_system"]
    ))


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _safe_int(val):
    """Safely convert a string to integer, supporting hex."""
    if val is None:
        return 0
    try:
        return int(val, 0) if isinstance(val, str) else int(val)
    except (ValueError, TypeError):
        return 0


def _resolve_name_to_ea(name):
    """Resolve a symbol name to an effective address. Returns None on failure."""
    if not name:
        return None
    ea = ida_name.get_name_ea(idaapi.BADADDR, name)
    if ea != idaapi.BADADDR:
        return ea
    # Try with common prefixes
    for prefix in ("?", "_", "__", "j_"):
        ea = ida_name.get_name_ea(idaapi.BADADDR, prefix + name)
        if ea != idaapi.BADADDR:
            return ea
    return None


def _table_exists(db, table_name):
    """Check if a table exists in the knowledge DB."""
    try:
        result = db.fetchall(
            f"SELECT name FROM sqlite_master WHERE type='table' "
            f"AND name='{table_name}'"
        )
        return len(result) > 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public retrieval API
# ---------------------------------------------------------------------------

def get_event_system(session):
    """Retrieve stored event system data.

    Returns the complete event system topology dictionary, or an empty dict
    if no analysis has been run yet.
    """
    return session.db.kv_get("event_system") or {}


def get_event_registrations(session, system_filter=None):
    """Get event registrations, optionally filtered by game system."""
    data = get_event_system(session)
    regs = data.get("event_registrations", [])
    if system_filter:
        regs = [r for r in regs if r.get("system") == system_filter]
    return regs


def get_event_emissions(session, system_filter=None):
    """Get event emissions, optionally filtered by game system."""
    data = get_event_system(session)
    ems = data.get("event_emissions", [])
    if system_filter:
        ems = [e for e in ems if e.get("system") == system_filter]
    return ems


def get_timers(session, system_filter=None):
    """Get timer/scheduled callbacks, optionally filtered by game system."""
    data = get_event_system(session)
    tmrs = data.get("timers", [])
    if system_filter:
        tmrs = [t for t in tmrs if t.get("system") == system_filter]
    return tmrs


def get_observer_patterns(session, system_filter=None):
    """Get observer patterns, optionally filtered by game system."""
    data = get_event_system(session)
    obs = data.get("observer_patterns", [])
    if system_filter:
        obs = [o for o in obs if o.get("system") == system_filter]
    return obs


def get_event_chains(session, min_depth=2):
    """Get event chains with minimum depth."""
    data = get_event_system(session)
    chains = data.get("event_chains", [])
    return [c for c in chains if c.get("depth", 0) >= min_depth]


def get_circular_dependencies(session):
    """Get circular event dependencies."""
    data = get_event_system(session)
    return data.get("circular_dependencies", [])


def get_cross_system_events(session):
    """Get events that bridge between game systems."""
    data = get_event_system(session)
    return data.get("cross_system_events", [])


def get_event_summary(session):
    """Get a high-level summary of the event system topology."""
    data = get_event_system(session)
    if not data:
        return "No event system analysis available. Run recover_event_system() first."

    lines = [
        "Event System Topology Summary",
        "=" * 40,
        f"Total registrations:   {len(data.get('event_registrations', []))}",
        f"Total emissions:       {len(data.get('event_emissions', []))}",
        f"Total timers:          {data.get('total_timers', 0)}",
        f"Total observers:       {data.get('total_observers', 0)}",
        f"Total signal/slots:    {data.get('total_signal_slots', 0)}",
        f"Event chains:          {len(data.get('event_chains', []))}",
        f"Circular deps:         {len(data.get('circular_dependencies', []))}",
        f"Cross-system events:   {len(data.get('cross_system_events', []))}",
        f"Analysis time:         {data.get('analysis_time_sec', 0)}s",
        "",
    ]

    # System breakdown
    system_counts = defaultdict(lambda: {"regs": 0, "emits": 0, "timers": 0})
    for reg in data.get("event_registrations", []):
        system_counts[reg.get("system", "Other")]["regs"] += 1
    for em in data.get("event_emissions", []):
        system_counts[em.get("system", "Other")]["emits"] += 1
    for tmr in data.get("timers", []):
        system_counts[tmr.get("system", "Other")]["timers"] += 1

    if system_counts:
        lines.append("Per-system breakdown:")
        lines.append(f"  {'System':<20} {'Regs':>6} {'Emits':>6} {'Timers':>6}")
        lines.append("  " + "-" * 44)
        for system in sorted(system_counts.keys()):
            c = system_counts[system]
            lines.append(
                f"  {system:<20} {c['regs']:>6} {c['emits']:>6} {c['timers']:>6}"
            )

    # Top event chains
    chains = data.get("event_chains", [])
    if chains:
        lines.append("")
        lines.append(f"Top event chains (deepest first, max 10):")
        for chain in sorted(chains, key=lambda c: -c.get("depth", 0))[:10]:
            chain_str = " -> ".join(str(e) for e in chain.get("chain", []))
            systems = ", ".join(chain.get("systems_involved", []))
            lines.append(f"  depth={chain['depth']}: {chain_str}")
            if systems:
                lines.append(f"    systems: {systems}")

    # Circular dependencies
    circs = data.get("circular_dependencies", [])
    if circs:
        lines.append("")
        lines.append(f"Circular dependencies ({len(circs)}):")
        for circ in circs[:10]:
            cycle_str = " -> ".join(str(e) for e in circ.get("cycle", []))
            lines.append(f"  {cycle_str}")

    return "\n".join(lines)


def generate_tc_event_hooks(session, system_filter=None):
    """Generate TrinityCore-style event hook registration code from
    recovered event topology.

    Example output:
        // Housing system events
        void HousingEventHooks::Register()
        {
            RegisterEvent(EVENT_PLOT_CLAIMED, &OnPlotClaimed);
            RegisterEvent(EVENT_DECOR_PLACED, &OnDecorPlaced);
        }
    """
    data = get_event_system(session)
    if not data:
        return "// No event system data available\n"

    regs = data.get("event_registrations", [])
    if system_filter:
        regs = [r for r in regs if r.get("system") == system_filter]

    if not regs:
        return f"// No event registrations found for system: {system_filter}\n"

    # Group by system
    system_regs = defaultdict(list)
    for reg in regs:
        system_regs[reg.get("system", "Other")].append(reg)

    lines = ["// Auto-generated event hook registrations from binary analysis", ""]

    for system in sorted(system_regs.keys()):
        sys_regs = system_regs[system]
        class_name = system.replace(" ", "") + "EventHooks"

        lines.append(f"// {system} system events ({len(sys_regs)} registrations)")
        lines.append(f"void {class_name}::Register()")
        lines.append("{")

        for reg in sorted(sys_regs, key=lambda r: str(r.get("event_id", ""))):
            eid = reg["event_id"]
            handler = reg.get("handler_name", "Unknown")
            # Clean up handler name for C++
            handler_clean = handler.split("::")[-1] if "::" in handler else handler
            if isinstance(eid, int):
                lines.append(f"    RegisterEvent(0x{eid:X}, &{handler_clean});  "
                             f"// {handler}")
            else:
                lines.append(f"    RegisterEvent({eid}, &{handler_clean});  "
                             f"// {handler}")

        lines.append("}")
        lines.append("")

    return "\n".join(lines)
