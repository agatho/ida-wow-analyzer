"""
State Machine Recovery
Traces implicit state machines from WoW binary handlers by analyzing
enum comparisons, state variable reads/writes, and transition patterns.

Recovers state machine definitions that can be:
  - Visualized as directed graphs
  - Exported as C++ enum + transition table for TC
  - Used for validation (are all states reachable? dead states?)
"""

import json
import re

import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


def recover_state_machines(session, system_filter=None):
    """Recover state machines from handler functions.

    Strategy:
      1. Find functions that compare a field against multiple constants
         (switch statements or if-chains on a state variable)
      2. Trace which handlers transition between states
      3. Build a state graph with edges labeled by the triggering opcode

    Args:
        system_filter: Only analyze functions in this system

    Returns number of state machines recovered.
    """
    db = session.db

    # Get candidate functions: those with switch statements or many
    # comparisons against the same offset
    query = "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL"
    if system_filter:
        query += f" AND (tc_name LIKE '%{system_filter}%' OR jam_type LIKE '%{system_filter}%')"
    handlers = db.fetchall(query)

    msg_info(f"Scanning {len(handlers)} handlers for state machines...")

    machines = {}  # keyed by state variable description
    transitions = []

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"handler_0x{ea:X}"

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        # Look for switch statements (clearest state machine indicator)
        switch_machines = _find_switch_state_machines(pseudocode, tc_name, ea)
        for sm in switch_machines:
            key = sm["state_variable"]
            if key not in machines:
                machines[key] = {
                    "name": key,
                    "states": set(),
                    "transitions": [],
                    "handlers": [],
                }
            machines[key]["states"].update(sm["states"])
            machines[key]["transitions"].extend(sm["transitions"])
            machines[key]["handlers"].append(tc_name)

        # Look for if-chain comparisons against a member offset
        ifchain_machines = _find_ifchain_state_machines(pseudocode, tc_name, ea)
        for sm in ifchain_machines:
            key = sm["state_variable"]
            if key not in machines:
                machines[key] = {
                    "name": key,
                    "states": set(),
                    "transitions": [],
                    "handlers": [],
                }
            machines[key]["states"].update(sm["states"])
            machines[key]["transitions"].extend(sm["transitions"])
            machines[key]["handlers"].append(tc_name)

    # Convert sets to lists for JSON serialization
    results = []
    for key, sm in machines.items():
        if len(sm["states"]) < 2:
            continue  # not a real state machine

        sm_entry = {
            "name": sm["name"],
            "states": sorted(sm["states"]),
            "transitions": sm["transitions"],
            "handlers": sm["handlers"],
            "state_count": len(sm["states"]),
            "transition_count": len(sm["transitions"]),
        }
        results.append(sm_entry)

    # Store
    db.kv_set("state_machines", results)
    db.commit()

    msg_info(f"Recovered {len(results)} state machines "
             f"({sum(sm['state_count'] for sm in results)} total states)")
    for sm in results:
        msg_info(f"  {sm['name']}: {sm['state_count']} states, "
                 f"{sm['transition_count']} transitions")

    return len(results)


def _find_switch_state_machines(pseudocode, handler_name, handler_ea):
    """Find switch-based state machines in pseudocode."""
    machines = []

    # Match: switch ( *(type *)(ptr + offset) )
    switch_pattern = re.compile(
        r'switch\s*\(\s*\*?\(?\s*(?:\w+\s*\*?\s*\))?\s*\(?\s*(\w+)\s*'
        r'(?:\+\s*(0x[0-9A-Fa-f]+|\d+))?\s*\)?\s*\)',
        re.MULTILINE
    )

    case_pattern = re.compile(r'case\s+(0x[0-9A-Fa-f]+|\d+)\s*:')

    for switch_match in switch_pattern.finditer(pseudocode):
        var_name = switch_match.group(1)
        offset = switch_match.group(2) or "0"
        state_var = f"{var_name}+{offset}"

        # Find all case values after this switch
        switch_pos = switch_match.end()
        # Get the next ~2000 chars for case scanning
        block = pseudocode[switch_pos:switch_pos + 2000]

        states = set()
        transitions_local = []
        for case_match in case_pattern.finditer(block):
            state_val = case_match.group(1)
            try:
                state_int = int(state_val, 0)
                states.add(state_int)
            except ValueError:
                states.add(state_val)

        if len(states) >= 2:
            # Each case is a state the handler recognizes
            for state in states:
                transitions_local.append({
                    "from_state": state,
                    "handler": handler_name,
                    "handler_ea": handler_ea,
                })

            machines.append({
                "state_variable": state_var,
                "states": states,
                "transitions": transitions_local,
            })

    return machines


def _find_ifchain_state_machines(pseudocode, handler_name, handler_ea):
    """Find if-chain state comparisons (if state == X ... else if state == Y)."""
    machines = []

    # Match patterns like: if ( *(a1 + 0x48) == 3 )
    compare_pattern = re.compile(
        r'if\s*\(\s*\*?\(?\s*(?:\w+\s*\*?\s*\))?\s*\(?\s*(\w+)\s*'
        r'\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*'
        r'([!=<>]=?)\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
    )

    # Group by (variable + offset)
    var_states = {}
    for m in compare_pattern.finditer(pseudocode):
        var_name = m.group(1)
        offset = m.group(2)
        operator = m.group(3)
        value = m.group(4)

        if operator not in ("==", "!="):
            continue  # only equality checks suggest state enums

        key = f"{var_name}+{offset}"
        if key not in var_states:
            var_states[key] = set()

        try:
            var_states[key].add(int(value, 0))
        except ValueError:
            var_states[key].add(value)

    for key, states in var_states.items():
        if len(states) >= 2:
            transitions_local = [
                {
                    "from_state": s,
                    "handler": handler_name,
                    "handler_ea": handler_ea,
                }
                for s in states
            ]
            machines.append({
                "state_variable": key,
                "states": states,
                "transitions": transitions_local,
            })

    return machines


def generate_state_enum(session, machine_name):
    """Generate C++ enum for a recovered state machine.

    Example output:
        enum class HousingState : uint32
        {
            None          = 0,
            BrowsingPlots = 1,
            PlotSelected  = 2,
            Confirming    = 3,
            Owned         = 4,
        };
    """
    machines = session.db.kv_get("state_machines") or []

    target = None
    for sm in machines:
        if sm["name"] == machine_name or machine_name in sm["name"]:
            target = sm
            break

    if not target:
        return f"// State machine '{machine_name}' not found\n"

    # Generate enum name from state variable
    enum_name = machine_name.replace("+", "_offset_").replace("0x", "")
    enum_name = "".join(p.capitalize() for p in re.split(r'[_\s]+', enum_name))
    enum_name += "State"

    lines = [f"enum class {enum_name} : uint32", "{"]
    for i, state in enumerate(sorted(target["states"])):
        if isinstance(state, int):
            lines.append(f"    State_{state:<12} = {state},")
        else:
            lines.append(f"    State_{state:<12} = {state},")
    lines.append("};")

    return "\n".join(lines) + "\n"


def generate_transition_table(session, machine_name):
    """Generate C++ state transition validation table."""
    machines = session.db.kv_get("state_machines") or []

    target = None
    for sm in machines:
        if sm["name"] == machine_name or machine_name in sm["name"]:
            target = sm
            break

    if not target:
        return f"// State machine '{machine_name}' not found\n"

    lines = [
        f"// State machine: {target['name']}",
        f"// {target['state_count']} states, "
        f"{target['transition_count']} transitions",
        f"// Handlers: {', '.join(target['handlers'][:5])}",
        "",
        "static const std::unordered_map<uint32, std::vector<uint32>> "
        "ValidTransitions = {",
    ]

    # Group transitions by from_state
    from_states = {}
    for t in target["transitions"]:
        fs = t["from_state"]
        if fs not in from_states:
            from_states[fs] = set()
        # All other states are potential targets (heuristic)
        for s in target["states"]:
            if s != fs:
                from_states[fs].add(s)

    for from_state in sorted(from_states.keys()):
        targets = sorted(from_states[from_state])
        targets_str = ", ".join(str(t) for t in targets)
        lines.append(f"    {{ {from_state}, {{ {targets_str} }} }},")

    lines.append("};")
    return "\n".join(lines) + "\n"


def get_state_machines(session):
    """Retrieve stored state machine data."""
    return session.db.kv_get("state_machines") or []
