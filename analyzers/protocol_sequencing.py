"""
Implicit Sequencing Protocol Recovery
Traces read-after-write dependencies across CMSG handlers to recover
the global packet protocol state machine.

Handler B reads a state variable that handler A sets. By building these
dependencies across ALL handlers, we recover the complete sequencing rules:
"Client must send CMSG_A before CMSG_B."

Produces:
  - Dependency graph of handler ordering constraints
  - Protocol phases (topological ordering of handler groups)
  - Pattern classification (handshake, workflow, gate, teardown, ping-pong)
  - Human-readable protocol documentation
  - C++ sequence validator code generation
"""

import json
import re
import time
from collections import defaultdict, deque

import ida_funcs
import ida_name
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Regex patterns for state variable access in Hex-Rays pseudocode
# ---------------------------------------------------------------------------

# Dereference read in if-condition:
#   if ( *(type *)(a1 + 0x48) == 3 )
#   if ( *(a1 + 0x48) != 0 )
#   if ( *((_DWORD *)(a1 + 0x120)) > 5 )
_IF_DEREF_READ = re.compile(
    r'if\s*\(\s*'
    r'\*\s*\(?\s*(?:(?:unsigned\s+)?(?:_?[A-Z]+|char|int|__int\d+|_DWORD|_BYTE|_WORD|_QWORD)'
    r'\s*\*\s*\))?\s*'
    r'\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*'
    r'([!=<>]=?|[<>])\s*'
    r'(-?0x[0-9A-Fa-f]+|-?\d+)\s*\)',
    re.MULTILINE
)

# Dereference read in if-condition with logical NOT or falsy check:
#   if ( !*(a1 + 0x48) )
_IF_DEREF_READ_FALSY = re.compile(
    r'if\s*\(\s*!\s*'
    r'\*\s*\(?\s*(?:(?:unsigned\s+)?(?:_?[A-Z]+|char|int|__int\d+|_DWORD|_BYTE|_WORD|_QWORD)'
    r'\s*\*\s*\))?\s*'
    r'\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*\)',
    re.MULTILINE
)

# Switch on dereferenced field:
#   switch ( *(type *)(a1 + 0x48) )
_SWITCH_DEREF = re.compile(
    r'switch\s*\(\s*'
    r'\*\s*\(?\s*(?:(?:unsigned\s+)?(?:_?[A-Z]+|char|int|__int\d+|_DWORD|_BYTE|_WORD|_QWORD)'
    r'\s*\*\s*\))?\s*'
    r'\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*\)',
    re.MULTILINE
)

# Local variable assigned from dereference, then compared:
#   v5 = *(type *)(a1 + 0x48);
_VAR_FROM_DEREF = re.compile(
    r'(\w+)\s*=\s*'
    r'\*\s*\(?\s*(?:(?:unsigned\s+)?(?:_?[A-Z]+|char|int|__int\d+|_DWORD|_BYTE|_WORD|_QWORD)'
    r'\s*\*\s*\))?\s*'
    r'\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*;',
    re.MULTILINE
)

# Comparison of a previously-assigned local variable:
#   if ( v5 == 3 )
_VAR_CMP = re.compile(
    r'if\s*\(\s*(\w+)\s*([!=<>]=?|[<>])\s*(-?0x[0-9A-Fa-f]+|-?\d+)\s*\)',
    re.MULTILINE
)

# Direct assignment (write):
#   *(type *)(a1 + 0x48) = 4;
_DEREF_ASSIGN = re.compile(
    r'\*\s*\(?\s*(?:(?:unsigned\s+)?(?:_?[A-Z]+|char|int|__int\d+|_DWORD|_BYTE|_WORD|_QWORD)'
    r'\s*\*\s*\))?\s*'
    r'\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*'
    r'=\s*(-?0x[0-9A-Fa-f]+|-?\d+)\s*;',
    re.MULTILINE
)

# OR-flag assignment:
#   *(a1 + 0x48) |= FLAG;
_DEREF_OR_FLAG = re.compile(
    r'\*\s*\(?\s*(?:(?:unsigned\s+)?(?:_?[A-Z]+|char|int|__int\d+|_DWORD|_BYTE|_WORD|_QWORD)'
    r'\s*\*\s*\))?\s*'
    r'\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*'
    r'\|=\s*(-?0x[0-9A-Fa-f]+|-?\d+)\s*;',
    re.MULTILINE
)

# AND-clear-flag assignment:
#   *(a1 + 0x48) &= ~FLAG;
_DEREF_CLEAR_FLAG = re.compile(
    r'\*\s*\(?\s*(?:(?:unsigned\s+)?(?:_?[A-Z]+|char|int|__int\d+|_DWORD|_BYTE|_WORD|_QWORD)'
    r'\s*\*\s*\))?\s*'
    r'\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*'
    r'&=\s*~?\s*(-?0x[0-9A-Fa-f]+|-?\d+)\s*;',
    re.MULTILINE
)

# Increment/decrement:
#   ++*(a1 + 0x48);  or  *(a1 + 0x48) += 1;
_DEREF_INCREMENT = re.compile(
    r'(?:\+\+\s*\*\s*\(?\s*(?:(?:unsigned\s+)?(?:_?[A-Z]+|char|int|__int\d+|_DWORD|_BYTE|_WORD|_QWORD)'
    r'\s*\*\s*\))?\s*\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?'
    r'|'
    r'\*\s*\(?\s*(?:(?:unsigned\s+)?(?:_?[A-Z]+|char|int|__int\d+|_DWORD|_BYTE|_WORD|_QWORD)'
    r'\s*\*\s*\))?\s*\(?\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*'
    r'\+=\s*(-?0x[0-9A-Fa-f]+|-?\d+)\s*;)',
    re.MULTILINE
)

# Return after a failed guard check
_EARLY_RETURN = re.compile(
    r'return\s*(?:0x[0-9A-Fa-f]+|\d+|void|;)',
    re.MULTILINE
)

# case VALUE:
_CASE_PATTERN = re.compile(r'case\s+(0x[0-9A-Fa-f]+|-?\d+)\s*:')


def _parse_int(s):
    """Parse a string as an integer, handling hex and decimal."""
    if s is None:
        return None
    s = s.strip()
    try:
        return int(s, 0)
    except (ValueError, TypeError):
        return None


def _normalize_state_key(var_name, offset_str):
    """Normalize a state key to a canonical form like 'a1+0x48'."""
    offset = _parse_int(offset_str)
    if offset is not None:
        return f"{var_name}+0x{offset:X}"
    return f"{var_name}+{offset_str}"


def _is_guard_check(lines, line_idx):
    """Determine if an if-statement at line_idx is a guard (early return on mismatch).

    A guard check is an if-statement whose body contains an early return,
    meaning the handler exits if the condition fails -- a precondition.
    """
    if line_idx >= len(lines):
        return False

    # Scan the next few lines for a return within the if-block
    brace_depth = 0
    for j in range(line_idx, min(line_idx + 8, len(lines))):
        line = lines[j]
        brace_depth += line.count("{") - line.count("}")
        if _EARLY_RETURN.search(line) and j > line_idx:
            return True
        # Also check single-line: if (...) return;
        if j == line_idx and "return" in line:
            return True
        if brace_depth <= 0 and j > line_idx:
            break

    return False


def _determine_condition_path(lines, line_idx):
    """Determine which execution path a write is on (success, error, specific case)."""
    # Walk backwards to find the nearest if/else/case context
    for j in range(line_idx - 1, max(line_idx - 15, -1), -1):
        stripped = lines[j].strip()
        if stripped.startswith("else"):
            return "else path"
        if stripped.startswith("if"):
            return "conditional path"
        if "case " in stripped:
            case_match = _CASE_PATTERN.search(stripped)
            if case_match:
                return f"case {case_match.group(1)}"
        if stripped.startswith("default:"):
            return "default path"

    return "success path"


# ---------------------------------------------------------------------------
# State reads (preconditions)
# ---------------------------------------------------------------------------

def _extract_state_reads(pseudocode, handler_name):
    """Find state preconditions in handler pseudocode.

    Identifies state variables that the handler reads (checks) before
    proceeding. These indicate what state must be established by a prior
    handler.

    Returns list of dicts:
        {state_key, expected_value, operator, is_guard, line}
    """
    reads = []
    lines = pseudocode.split("\n")

    # Track local variables assigned from dereferences so we can resolve
    # indirect reads: v5 = *(a1+0x48); if (v5 == 3) ...
    local_var_sources = {}  # local_var_name -> state_key

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track local variable assignments from dereferences
        for m in _VAR_FROM_DEREF.finditer(stripped):
            local_name = m.group(1)
            var_name = m.group(2)
            offset = m.group(3)
            # Only track first-parameter dereferences (session/this pointer)
            if var_name in ("a1", "a2", "this", "v1"):
                local_var_sources[local_name] = _normalize_state_key(var_name, offset)

        # Direct dereference read in if-condition
        for m in _IF_DEREF_READ.finditer(stripped):
            var_name = m.group(1)
            offset = m.group(2)
            operator = m.group(3)
            value_str = m.group(4)

            if var_name not in ("a1", "a2", "this", "v1"):
                continue

            state_key = _normalize_state_key(var_name, offset)
            expected = _parse_int(value_str)
            is_guard = _is_guard_check(lines, i)

            reads.append({
                "state_key": state_key,
                "expected_value": expected,
                "operator": operator,
                "is_guard": is_guard,
                "line": i,
            })

        # Falsy check: if ( !*(a1 + 0x48) ) -- equivalent to == 0 guard
        for m in _IF_DEREF_READ_FALSY.finditer(stripped):
            var_name = m.group(1)
            offset = m.group(2)

            if var_name not in ("a1", "a2", "this", "v1"):
                continue

            state_key = _normalize_state_key(var_name, offset)
            is_guard = _is_guard_check(lines, i)

            reads.append({
                "state_key": state_key,
                "expected_value": 0,
                "operator": "==",
                "is_guard": is_guard,
                "line": i,
            })

        # Switch on dereference -- reads state, behavior depends on value
        for m in _SWITCH_DEREF.finditer(stripped):
            var_name = m.group(1)
            offset = m.group(2)

            if var_name not in ("a1", "a2", "this", "v1"):
                continue

            state_key = _normalize_state_key(var_name, offset)

            # Collect case values from subsequent lines
            case_values = []
            for j in range(i + 1, min(i + 60, len(lines))):
                case_m = _CASE_PATTERN.search(lines[j])
                if case_m:
                    val = _parse_int(case_m.group(1))
                    if val is not None:
                        case_values.append(val)
                # Stop at next switch or function end
                if "switch" in lines[j] and j > i + 1:
                    break

            for cv in case_values:
                reads.append({
                    "state_key": state_key,
                    "expected_value": cv,
                    "operator": "==",
                    "is_guard": False,  # switch cases are not guards, they're branches
                    "line": i,
                })

        # Indirect reads via local variable
        for m in _VAR_CMP.finditer(stripped):
            local_name = m.group(1)
            operator = m.group(2)
            value_str = m.group(3)

            if local_name not in local_var_sources:
                continue

            state_key = local_var_sources[local_name]
            expected = _parse_int(value_str)
            is_guard = _is_guard_check(lines, i)

            reads.append({
                "state_key": state_key,
                "expected_value": expected,
                "operator": operator,
                "is_guard": is_guard,
                "line": i,
            })

    return reads


# ---------------------------------------------------------------------------
# State writes (postconditions)
# ---------------------------------------------------------------------------

def _extract_state_writes(pseudocode, handler_name):
    """Find state postconditions in handler pseudocode.

    Identifies state variables that the handler writes (sets), which
    establish preconditions for subsequent handlers.

    Returns list of dicts:
        {state_key, new_value, operation, line, condition}
    """
    writes = []
    lines = pseudocode.split("\n")

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Direct assignment: *(a1 + 0x48) = 4;
        for m in _DEREF_ASSIGN.finditer(stripped):
            var_name = m.group(1)
            offset = m.group(2)
            value_str = m.group(3)

            if var_name not in ("a1", "a2", "this", "v1"):
                continue

            state_key = _normalize_state_key(var_name, offset)
            new_value = _parse_int(value_str)
            condition = _determine_condition_path(lines, i)

            writes.append({
                "state_key": state_key,
                "new_value": new_value,
                "operation": "assign",
                "line": i,
                "condition": condition,
            })

        # OR-flag: *(a1 + 0x48) |= FLAG;
        for m in _DEREF_OR_FLAG.finditer(stripped):
            var_name = m.group(1)
            offset = m.group(2)
            flag_str = m.group(3)

            if var_name not in ("a1", "a2", "this", "v1"):
                continue

            state_key = _normalize_state_key(var_name, offset)
            flag_value = _parse_int(flag_str)
            condition = _determine_condition_path(lines, i)

            writes.append({
                "state_key": state_key,
                "new_value": flag_value,
                "operation": "or_flag",
                "line": i,
                "condition": condition,
            })

        # Clear-flag: *(a1 + 0x48) &= ~FLAG;
        for m in _DEREF_CLEAR_FLAG.finditer(stripped):
            var_name = m.group(1)
            offset = m.group(2)
            flag_str = m.group(3)

            if var_name not in ("a1", "a2", "this", "v1"):
                continue

            state_key = _normalize_state_key(var_name, offset)
            flag_value = _parse_int(flag_str)
            condition = _determine_condition_path(lines, i)

            writes.append({
                "state_key": state_key,
                "new_value": flag_value,
                "operation": "clear_flag",
                "line": i,
                "condition": condition,
            })

        # Increment: ++*(a1 + 0x48); or *(a1 + 0x48) += 1;
        for m in _DEREF_INCREMENT.finditer(stripped):
            # The regex has two alternatives, check which matched
            if m.group(1) is not None:
                var_name = m.group(1)
                offset = m.group(2)
            elif m.group(3) is not None:
                var_name = m.group(3)
                offset = m.group(4)
            else:
                continue

            if var_name not in ("a1", "a2", "this", "v1"):
                continue

            state_key = _normalize_state_key(var_name, offset)
            condition = _determine_condition_path(lines, i)

            # For += N, capture the delta
            delta_str = m.group(5)
            delta = _parse_int(delta_str) if delta_str else 1

            writes.append({
                "state_key": state_key,
                "new_value": "incremented" if delta == 1 else f"incremented_by_{delta}",
                "operation": "increment",
                "line": i,
                "condition": condition,
            })

    return writes


# ---------------------------------------------------------------------------
# Dependency graph construction
# ---------------------------------------------------------------------------

def _build_dependency_graph(handler_states):
    """Build handler-to-handler dependencies from state read/write pairs.

    Args:
        handler_states: dict of handler_name -> {reads: [...], writes: [...], ea, direction}

    Returns dict:
        {
            "edges": [{from_handler, to_handler, state_key, written_value,
                        expected_value, is_required}],
            "nodes": {handler_name: {reads, writes, ea, direction}},
            "cycles": [[handler_a, handler_b, ...]],
        }
    """
    edges = []
    # Index: for each (state_key, value_written), which handlers write it
    write_index = defaultdict(list)  # (state_key, value) -> [handler_name]

    for handler_name, info in handler_states.items():
        for w in info["writes"]:
            key = w["state_key"]
            val = w["new_value"]
            write_index[(key, val)].append(handler_name)

            # For increments, we cannot match exact values but we know
            # the key is being modified
            if w["operation"] == "increment":
                write_index[(key, "incremented")].append(handler_name)

    # For each handler that reads a state, find which handler writes that state
    for reader_name, reader_info in handler_states.items():
        for r in reader_info["reads"]:
            key = r["state_key"]
            expected = r["expected_value"]
            is_guard = r["is_guard"]
            operator = r["operator"]

            # Direct match: handler B reads state_key X expecting value V,
            # handler A writes V to X
            writers = write_index.get((key, expected), [])

            # For inequality checks (!=), the dependency is weaker:
            # any handler writing to this key could be relevant
            if not writers and operator == "!=":
                # Find any handler that writes to this state_key
                for (wk, wv), wh_list in write_index.items():
                    if wk == key and wv != expected:
                        writers.extend(wh_list)

            # For >= or > checks, find handlers writing values >= threshold
            if not writers and operator in (">=", ">"):
                threshold = expected if operator == ">=" else (expected + 1 if expected is not None else None)
                if threshold is not None:
                    for (wk, wv), wh_list in write_index.items():
                        if wk == key and isinstance(wv, int) and wv >= threshold:
                            writers.extend(wh_list)

            # For increment-based sequences, match increment writers
            if not writers:
                inc_writers = write_index.get((key, "incremented"), [])
                if inc_writers:
                    writers.extend(inc_writers)

            # Deduplicate and exclude self-dependencies
            seen_writers = set()
            for writer_name in writers:
                if writer_name == reader_name:
                    continue
                if writer_name in seen_writers:
                    continue
                seen_writers.add(writer_name)

                edges.append({
                    "from_handler": writer_name,
                    "to_handler": reader_name,
                    "state_key": key,
                    "written_value": expected,
                    "expected_value": expected,
                    "operator": operator,
                    "is_required": is_guard,
                })

    # Detect cycles using DFS
    adjacency = defaultdict(set)
    for e in edges:
        adjacency[e["from_handler"]].add(e["to_handler"])

    cycles = _detect_cycles(adjacency)

    return {
        "edges": edges,
        "nodes": {name: {
            "reads": info["reads"],
            "writes": info["writes"],
            "ea": info["ea"],
            "direction": info["direction"],
        } for name, info in handler_states.items()},
        "cycles": cycles,
    }


def _detect_cycles(adjacency):
    """Detect all cycles in a directed graph using iterative DFS with
    back-edge detection.

    Returns list of cycles, each cycle is a list of node names.
    """
    WHITE, GRAY, BLACK = 0, 1, 2
    color = defaultdict(int)
    parent = {}
    cycles = []

    all_nodes = set(adjacency.keys())
    for targets in adjacency.values():
        all_nodes.update(targets)

    for start in all_nodes:
        if color[start] != WHITE:
            continue

        stack = [(start, iter(adjacency.get(start, set())))]
        color[start] = GRAY

        while stack:
            node, neighbors = stack[-1]
            try:
                neighbor = next(neighbors)
                if color[neighbor] == GRAY:
                    # Back edge found -- extract cycle
                    cycle = [neighbor]
                    for frame_node, _ in reversed(stack):
                        cycle.append(frame_node)
                        if frame_node == neighbor:
                            break
                    cycle.reverse()
                    # Deduplicate by canonical rotation
                    min_idx = cycle.index(min(cycle))
                    canonical = cycle[min_idx:] + cycle[:min_idx]
                    if canonical not in cycles:
                        cycles.append(canonical)
                elif color[neighbor] == WHITE:
                    color[neighbor] = GRAY
                    parent[neighbor] = node
                    stack.append((neighbor, iter(adjacency.get(neighbor, set()))))
            except StopIteration:
                color[node] = BLACK
                stack.pop()

    return cycles


def _compute_transitive_closure(edges):
    """Compute transitive dependencies.

    Returns dict: handler -> set of all transitive prerequisites.
    """
    adjacency = defaultdict(set)
    for e in edges:
        adjacency[e["to_handler"]].add(e["from_handler"])

    all_nodes = set()
    for e in edges:
        all_nodes.add(e["from_handler"])
        all_nodes.add(e["to_handler"])

    closure = {}
    for node in all_nodes:
        visited = set()
        queue = deque([node])
        while queue:
            current = queue.popleft()
            for prereq in adjacency.get(current, set()):
                if prereq not in visited and prereq != node:
                    visited.add(prereq)
                    queue.append(prereq)
        closure[node] = visited

    return closure


# ---------------------------------------------------------------------------
# Protocol phase detection
# ---------------------------------------------------------------------------

def _detect_protocol_phases(dependency_graph):
    """Identify protocol phases based on dependency ordering.

    Phase 0: handlers with no preconditions (can be sent anytime)
    Phase N: handlers whose dependencies are all in phases < N

    Returns:
        {
            "phases": {0: [handlers], 1: [handlers], ...},
            "handler_phase": {handler: phase_num},
            "critical_path": [handler_a, handler_b, ...],
            "critical_path_length": int,
        }
    """
    edges = dependency_graph["edges"]
    nodes = set(dependency_graph["nodes"].keys())

    # Build prerequisite map (only from required/guard edges)
    prereqs = defaultdict(set)
    for e in edges:
        if e["is_required"]:
            prereqs[e["to_handler"]].add(e["from_handler"])

    # Also include non-required edges for handlers that ONLY have non-required deps
    # (they still have ordering constraints, just weaker ones)
    all_prereqs = defaultdict(set)
    for e in edges:
        all_prereqs[e["to_handler"]].add(e["from_handler"])

    # Topological sort into phases
    handler_phase = {}
    phases = defaultdict(list)
    assigned = set()

    # Phase 0: handlers with no prerequisites at all
    for node in nodes:
        if node not in all_prereqs or not all_prereqs[node]:
            handler_phase[node] = 0
            phases[0].append(node)
            assigned.add(node)

    # Iteratively assign phases
    max_iterations = len(nodes) + 1
    current_phase = 1
    for _ in range(max_iterations):
        newly_assigned = []
        for node in nodes:
            if node in assigned:
                continue
            # Check if all prerequisites are assigned
            node_prereqs = all_prereqs.get(node, set())
            if node_prereqs.issubset(assigned):
                handler_phase[node] = current_phase
                phases[current_phase].append(node)
                newly_assigned.append(node)

        if not newly_assigned:
            break

        assigned.update(newly_assigned)
        current_phase += 1

    # Any remaining nodes are in cycles -- assign them to a special phase
    for node in nodes:
        if node not in assigned:
            handler_phase[node] = current_phase
            phases[current_phase].append(node)

    # Find critical path (longest dependency chain)
    critical_path = _find_critical_path(all_prereqs, handler_phase, nodes)

    return {
        "phases": dict(phases),
        "handler_phase": handler_phase,
        "critical_path": critical_path,
        "critical_path_length": len(critical_path),
    }


def _find_critical_path(prereqs, handler_phase, nodes):
    """Find the longest dependency chain (critical path)."""
    # Build reverse adjacency for forward traversal
    successors = defaultdict(set)
    for node, preds in prereqs.items():
        for pred in preds:
            successors[pred].add(node)

    # Find longest path using dynamic programming on topological order
    sorted_nodes = sorted(nodes, key=lambda n: handler_phase.get(n, 0))

    dist = {n: 0 for n in nodes}
    predecessor = {n: None for n in nodes}

    for node in sorted_nodes:
        for succ in successors.get(node, set()):
            if dist[node] + 1 > dist[succ]:
                dist[succ] = dist[node] + 1
                predecessor[succ] = node

    # Find the endpoint of the longest path
    if not dist:
        return []

    end_node = max(dist, key=dist.get)
    if dist[end_node] == 0:
        return [end_node] if nodes else []

    # Trace back
    path = []
    current = end_node
    while current is not None:
        path.append(current)
        current = predecessor[current]

    path.reverse()
    return path


# ---------------------------------------------------------------------------
# Protocol pattern detection
# ---------------------------------------------------------------------------

def _detect_protocol_patterns(sequences):
    """Identify common protocol patterns in the dependency graph.

    Patterns:
        handshake: A -> B -> A (request/response/ack)
        workflow:  A -> B -> C -> D (linear chain)
        gate:      A enables {B, C, D} (one handler opens multiple)
        teardown:  reverse of a setup sequence
        ping_pong: alternating client/server exchanges
    """
    edges = sequences.get("edges", [])
    cycles = sequences.get("cycles", [])
    nodes = sequences.get("nodes", {})

    patterns = []

    # Build adjacency maps
    successors = defaultdict(set)
    predecessors = defaultdict(set)
    for e in edges:
        successors[e["from_handler"]].add(e["to_handler"])
        predecessors[e["to_handler"]].add(e["from_handler"])

    # Detect handshake patterns: cycles of length 2-3
    for cycle in cycles:
        if 2 <= len(cycle) <= 3:
            patterns.append({
                "type": "handshake",
                "handlers": cycle,
                "description": f"Handshake: {' -> '.join(cycle)} -> {cycle[0]}",
            })

    # Detect gate patterns: one handler with 3+ successors
    for handler, succs in successors.items():
        if len(succs) >= 3:
            patterns.append({
                "type": "gate",
                "handlers": [handler] + sorted(succs),
                "description": f"Gate: {handler} enables {{{', '.join(sorted(succs))}}}",
            })

    # Detect workflow patterns: linear chains of length >= 3
    visited_in_chains = set()
    for handler in nodes:
        if handler in visited_in_chains:
            continue
        if len(predecessors.get(handler, set())) > 0:
            continue  # only start from roots

        chain = _trace_linear_chain(handler, successors, predecessors)
        if len(chain) >= 3:
            patterns.append({
                "type": "workflow",
                "handlers": chain,
                "description": f"Workflow: {' -> '.join(chain)}",
            })
            visited_in_chains.update(chain)

    # Detect teardown patterns: look for sequences that reverse a setup sequence
    # A teardown is when handler B's write undoes handler A's write (same key, value=0)
    setup_writes = {}  # (handler, state_key) -> value
    teardown_writes = {}

    for handler_name, info in nodes.items():
        for w in info.get("writes", []):
            key = w["state_key"]
            val = w["new_value"]
            if isinstance(val, int) and val > 0:
                setup_writes[(handler_name, key)] = val
            elif isinstance(val, int) and val == 0:
                teardown_writes[(handler_name, key)] = val

    for (tear_handler, key), tear_val in teardown_writes.items():
        for (setup_handler, s_key), s_val in setup_writes.items():
            if key == s_key and setup_handler != tear_handler:
                patterns.append({
                    "type": "teardown",
                    "handlers": [setup_handler, tear_handler],
                    "description": (f"Teardown: {tear_handler} resets {key} "
                                    f"(set by {setup_handler} to {s_val})"),
                })

    # Detect ping-pong patterns: alternating CMSG/SMSG in chains
    for handler in nodes:
        if len(predecessors.get(handler, set())) > 0:
            continue

        chain = _trace_linear_chain(handler, successors, predecessors)
        if len(chain) < 4:
            continue

        directions = [nodes[h].get("direction", "") for h in chain]
        is_alternating = all(
            directions[j] != directions[j + 1]
            for j in range(len(directions) - 1)
            if directions[j] and directions[j + 1]
        )
        if is_alternating and any(d == "CMSG" for d in directions) and any(d == "SMSG" for d in directions):
            patterns.append({
                "type": "ping_pong",
                "handlers": chain,
                "description": f"Ping-Pong: {' <-> '.join(chain)}",
            })

    return patterns


def _trace_linear_chain(start, successors, predecessors):
    """Trace a linear chain from start following single-successor edges."""
    chain = [start]
    current = start
    visited = {start}

    while True:
        succs = successors.get(current, set())
        # Follow only single-successor edges where the successor has single predecessor
        candidates = [s for s in succs
                       if len(predecessors.get(s, set())) == 1 and s not in visited]
        if len(candidates) != 1:
            break
        nxt = candidates[0]
        chain.append(nxt)
        visited.add(nxt)
        current = nxt

    return chain


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def recover_protocol_sequence(session, system_filter=None):
    """Recover implicit packet sequencing rules from handler state dependencies.

    For each CMSG handler:
      1. Identify state variables it READS (preconditions)
      2. Identify state variables it WRITES (postconditions)
    Then build a dependency graph: handler B depends on handler A if B reads
    a state that A writes.

    Args:
        session: PluginSession with session.db
        system_filter: Optional string to filter handlers by name (e.g. 'Housing')

    Returns:
        Number of sequencing rules (edges) found.
    """
    db = session.db

    query = "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL"
    if system_filter:
        query += (f" AND (tc_name LIKE '%{system_filter}%' "
                  f"OR jam_type LIKE '%{system_filter}%')")
    handlers = db.fetchall(query)

    msg_info(f"Protocol Sequencing: scanning {len(handlers)} handlers...")

    # Phase 1: Extract state reads and writes from each handler
    handler_states = {}
    handlers_with_reads = 0
    handlers_with_writes = 0

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or handler["jam_type"] or f"handler_0x{ea:X}"
        direction = handler["direction"] or "CMSG"
        # Treat 'unknown' direction as CMSG for sequencing purposes
        if direction == "unknown":
            direction = "CMSG"

        pseudocode = get_decompiled_text(ea, db=db)
        if not pseudocode:
            continue

        reads = _extract_state_reads(pseudocode, tc_name)
        writes = _extract_state_writes(pseudocode, tc_name)

        if reads or writes:
            handler_states[tc_name] = {
                "reads": reads,
                "writes": writes,
                "ea": ea,
                "direction": direction,
            }

        if reads:
            handlers_with_reads += 1
        if writes:
            handlers_with_writes += 1

    msg_info(f"  {handlers_with_reads} handlers read state, "
             f"{handlers_with_writes} handlers write state")

    if not handler_states:
        msg_warn("No state reads or writes found in any handler")
        db.kv_set("protocol_sequences", {
            "edges": [], "nodes": {}, "cycles": [],
            "phases": {}, "patterns": [], "handler_phase": {},
            "critical_path": [], "critical_path_length": 0,
        })
        db.commit()
        return 0

    # Phase 2: Build dependency graph
    dep_graph = _build_dependency_graph(handler_states)

    msg_info(f"  {len(dep_graph['edges'])} dependency edges, "
             f"{len(dep_graph['cycles'])} cycles detected")

    # Phase 3: Detect protocol phases
    phase_info = _detect_protocol_phases(dep_graph)

    msg_info(f"  {len(phase_info['phases'])} protocol phases, "
             f"critical path length: {phase_info['critical_path_length']}")

    # Phase 4: Detect protocol patterns
    patterns = _detect_protocol_patterns(dep_graph)

    msg_info(f"  {len(patterns)} protocol patterns detected")
    for p in patterns[:10]:
        msg_info(f"    [{p['type']}] {p['description']}")

    # Phase 5: Log phase summary
    for phase_num in sorted(phase_info["phases"].keys()):
        phase_handlers = phase_info["phases"][phase_num]
        msg_info(f"  Phase {phase_num}: {len(phase_handlers)} handlers")
        for h in phase_handlers[:5]:
            msg_info(f"    - {h}")
        if len(phase_handlers) > 5:
            msg_info(f"    ... and {len(phase_handlers) - 5} more")

    if phase_info["critical_path"]:
        msg_info(f"  Critical path: {' -> '.join(phase_info['critical_path'])}")

    # Serialize for storage (convert sets to lists, ints to JSON-safe)
    serializable_edges = []
    for e in dep_graph["edges"]:
        se = dict(e)
        # Ensure all values are JSON-serializable
        if isinstance(se.get("written_value"), int):
            pass  # already fine
        elif se.get("written_value") is None:
            se["written_value"] = None
        else:
            se["written_value"] = str(se["written_value"])
        serializable_edges.append(se)

    serializable_nodes = {}
    for name, info in dep_graph["nodes"].items():
        serializable_nodes[name] = {
            "reads": info["reads"],
            "writes": info["writes"],
            "ea": info["ea"],
            "direction": info["direction"],
        }

    result = {
        "edges": serializable_edges,
        "nodes": serializable_nodes,
        "cycles": dep_graph["cycles"],
        "phases": {str(k): v for k, v in phase_info["phases"].items()},
        "handler_phase": phase_info["handler_phase"],
        "critical_path": phase_info["critical_path"],
        "critical_path_length": phase_info["critical_path_length"],
        "patterns": patterns,
        "total_handlers_analyzed": len(handler_states),
        "timestamp": time.time(),
    }

    db.kv_set("protocol_sequences", result)
    db.commit()

    edge_count = len(dep_graph["edges"])
    msg_info(f"Protocol Sequencing complete: {edge_count} sequencing rules stored")
    return edge_count


# ---------------------------------------------------------------------------
# Documentation generation
# ---------------------------------------------------------------------------

def generate_protocol_doc(session, system_filter=None):
    """Generate human-readable protocol sequencing documentation.

    Args:
        session: PluginSession
        system_filter: Optional filter to limit to a subsystem

    Returns:
        Formatted documentation string.
    """
    sequences = get_protocol_sequences(session)
    if not sequences or not sequences.get("edges"):
        return "No protocol sequences recovered. Run recover_protocol_sequence() first.\n"

    nodes = sequences.get("nodes", {})
    phases = sequences.get("phases", {})
    patterns = sequences.get("patterns", [])
    critical_path = sequences.get("critical_path", [])
    cycles = sequences.get("cycles", [])

    # Apply filter if specified
    if system_filter:
        filter_upper = system_filter.upper()
        relevant_handlers = {
            name for name in nodes
            if filter_upper in name.upper()
        }
    else:
        relevant_handlers = set(nodes.keys())

    lines = []

    # Title
    title = f"{system_filter} Protocol Sequence" if system_filter else "Protocol Sequence Map"
    lines.append(f"## {title}")
    lines.append("")

    # Phase breakdown
    for phase_key in sorted(phases.keys(), key=lambda x: int(x)):
        phase_num = int(phase_key)
        phase_handlers = [h for h in phases[phase_key] if h in relevant_handlers]
        if not phase_handlers:
            continue

        if phase_num == 0:
            lines.append(f"### Phase {phase_num}: Initialization (no preconditions)")
        else:
            lines.append(f"### Phase {phase_num} (requires Phase {phase_num - 1})")
        lines.append("")

        for handler_name in sorted(phase_handlers):
            info = nodes.get(handler_name, {})
            reads = info.get("reads", [])
            writes = info.get("writes", [])

            # Format preconditions
            guard_reads = [r for r in reads if r.get("is_guard")]
            if guard_reads:
                precond_parts = []
                for r in guard_reads:
                    val = r.get("expected_value")
                    op = r.get("operator", "==")
                    key = r.get("state_key", "?")
                    if val is not None:
                        precond_parts.append(f"{key} {op} {val}")
                    else:
                        precond_parts.append(f"{key} is set")
                precond_str = ", ".join(precond_parts)
                lines.append(f"- **{handler_name}** (requires {precond_str})")
            else:
                lines.append(f"- **{handler_name}** (no preconditions)")

            # Format postconditions
            for w in writes:
                key = w.get("state_key", "?")
                val = w.get("new_value")
                op = w.get("operation", "assign")
                cond = w.get("condition", "")

                if op == "assign" and val is not None:
                    lines.append(f"  -> Sets {key} = {val}")
                elif op == "or_flag":
                    lines.append(f"  -> Sets flag {key} |= {val}")
                elif op == "clear_flag":
                    lines.append(f"  -> Clears flag {key} &= ~{val}")
                elif op == "increment":
                    lines.append(f"  -> Increments {key}")

                if cond and cond != "success path":
                    lines[-1] += f" ({cond})"

            lines.append("")

    # Patterns section
    filtered_patterns = [
        p for p in patterns
        if not system_filter or any(
            system_filter.upper() in h.upper()
            for h in p.get("handlers", [])
        )
    ]

    if filtered_patterns:
        lines.append("### Detected Patterns")
        lines.append("")
        for p in filtered_patterns:
            lines.append(f"- **{p['type'].upper()}**: {p['description']}")
        lines.append("")

    # Cycles section
    filtered_cycles = [
        c for c in cycles
        if not system_filter or any(
            system_filter.upper() in h.upper() for h in c
        )
    ]

    if filtered_cycles:
        lines.append("### Cycles (Repeatable Protocols)")
        lines.append("")
        for cycle in filtered_cycles:
            lines.append(f"- {' -> '.join(cycle)} -> {cycle[0]}")
        lines.append("")

    # Critical path
    filtered_path = [
        h for h in critical_path if h in relevant_handlers
    ] if critical_path else []

    if filtered_path:
        lines.append(f"### Critical Path: {' -> '.join(filtered_path)} "
                      f"({len(filtered_path)} steps)")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# C++ validator code generation
# ---------------------------------------------------------------------------

def generate_sequence_validator_cpp(session, system_filter=None):
    """Generate C++ code that validates packet sequencing at runtime.

    Produces a switch-based validator function that checks whether an opcode
    is valid given the current session state.

    Args:
        session: PluginSession
        system_filter: Optional filter

    Returns:
        C++ source code string.
    """
    sequences = get_protocol_sequences(session)
    if not sequences or not sequences.get("edges"):
        return ("// No protocol sequences recovered.\n"
                "// Run recover_protocol_sequence() first.\n")

    nodes = sequences.get("nodes", {})
    edges = sequences.get("edges", [])
    phases = sequences.get("phases", {})

    # Filter if needed
    if system_filter:
        filter_upper = system_filter.upper()
        relevant_handlers = {
            name for name in nodes
            if filter_upper in name.upper()
        }
        relevant_edges = [
            e for e in edges
            if e["to_handler"] in relevant_handlers
        ]
    else:
        relevant_handlers = set(nodes.keys())
        relevant_edges = edges

    # Collect all state keys used in guards
    all_state_keys = set()
    handler_guards = defaultdict(list)  # handler -> list of guard conditions

    for e in relevant_edges:
        if e.get("is_required"):
            handler_guards[e["to_handler"]].append(e)
            all_state_keys.add(e["state_key"])

    # Also collect from direct reads
    for handler_name in relevant_handlers:
        info = nodes.get(handler_name, {})
        for r in info.get("reads", []):
            if r.get("is_guard"):
                all_state_keys.add(r["state_key"])

    # Generate state enum
    system_prefix = system_filter.upper() if system_filter else "PROTOCOL"
    enum_name = f"{system_prefix.replace(' ', '_')}_STATE"

    lines = [
        "// Auto-generated protocol sequence validator",
        f"// Generated by TC WoW Analyzer - Protocol Sequencing Recovery",
        f"// {len(relevant_handlers)} handlers, {len(relevant_edges)} sequencing rules",
        "",
    ]

    # Generate state variable enum from phase info
    # Each unique state_key + value combination gets an enum entry
    state_values = set()
    for handler_name in relevant_handlers:
        info = nodes.get(handler_name, {})
        for w in info.get("writes", []):
            if isinstance(w.get("new_value"), int):
                state_values.add((w["state_key"], w["new_value"]))
        for r in info.get("reads", []):
            if r.get("is_guard") and isinstance(r.get("expected_value"), int):
                state_values.add((r["state_key"], r["expected_value"]))

    # Group by state_key for enum generation
    state_key_values = defaultdict(set)
    for key, val in state_values:
        state_key_values[key].add(val)

    for key in sorted(state_key_values.keys()):
        safe_name = key.replace("+", "_").replace("0x", "x").upper()
        lines.append(f"enum {enum_name}_{safe_name}")
        lines.append("{")
        for val in sorted(state_key_values[key]):
            lines.append(f"    {enum_name}_{safe_name}_{val} = {val},")
        lines.append("};")
        lines.append("")

    # Generate validator function
    lines.append(f"bool Validate{system_prefix.title().replace(' ', '')}PacketSequence("
                 f"uint32 opcode, WorldSession const* session)")
    lines.append("{")
    lines.append("    switch (opcode)")
    lines.append("    {")

    for handler_name in sorted(relevant_handlers):
        info = nodes.get(handler_name, {})
        guard_reads = [r for r in info.get("reads", []) if r.get("is_guard")]

        if not guard_reads:
            continue

        lines.append(f"        case {handler_name}:")

        conditions = []
        for r in guard_reads:
            key = r["state_key"]
            op = r.get("operator", "==")
            val = r.get("expected_value")
            safe_key = key.replace("+", "_").replace("0x", "x")

            if val is not None:
                if op == "==":
                    conditions.append(f"session->Get{safe_key}() == {val}")
                elif op == "!=":
                    conditions.append(f"session->Get{safe_key}() != {val}")
                elif op == ">=":
                    conditions.append(f"session->Get{safe_key}() >= {val}")
                elif op == ">":
                    conditions.append(f"session->Get{safe_key}() > {val}")
                elif op == "<=":
                    conditions.append(f"session->Get{safe_key}() <= {val}")
                elif op == "<":
                    conditions.append(f"session->Get{safe_key}() < {val}")
            else:
                conditions.append(f"session->Get{safe_key}() != 0")

        if conditions:
            combined = " && ".join(conditions)
            lines.append(f"            return {combined};")
        else:
            lines.append("            return true;")

    lines.append("        default:")
    lines.append("            return true; // No sequencing constraint")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    # Generate state transition applier
    lines.append(f"void Apply{system_prefix.title().replace(' ', '')}StateTransition("
                 f"uint32 opcode, WorldSession* session)")
    lines.append("{")
    lines.append("    switch (opcode)")
    lines.append("    {")

    for handler_name in sorted(relevant_handlers):
        info = nodes.get(handler_name, {})
        writes = info.get("writes", [])

        if not writes:
            continue

        # Only emit for writes on the success path
        success_writes = [w for w in writes
                          if w.get("condition", "success path") == "success path"
                          and isinstance(w.get("new_value"), int)]
        if not success_writes:
            continue

        lines.append(f"        case {handler_name}:")
        for w in success_writes:
            key = w["state_key"]
            val = w["new_value"]
            op = w.get("operation", "assign")
            safe_key = key.replace("+", "_").replace("0x", "x")

            if op == "assign":
                lines.append(f"            session->Set{safe_key}({val});")
            elif op == "or_flag":
                lines.append(f"            session->Set{safe_key}("
                             f"session->Get{safe_key}() | {val});")
            elif op == "clear_flag":
                lines.append(f"            session->Set{safe_key}("
                             f"session->Get{safe_key}() & ~{val});")
            elif op == "increment":
                lines.append(f"            session->Set{safe_key}("
                             f"session->Get{safe_key}() + 1);")

        lines.append("            break;")

    lines.append("        default:")
    lines.append("            break;")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_protocol_sequences(session):
    """Retrieve stored protocol sequence data from the knowledge DB.

    Returns the full protocol_sequences dict, or empty dict if not yet analyzed.
    """
    return session.db.kv_get("protocol_sequences") or {}


def get_handler_prerequisites(session, handler_name):
    """Get the prerequisite handlers for a specific handler.

    Args:
        session: PluginSession
        handler_name: The handler name (e.g. 'CMSG_HOUSING_SELECT_PLOT')

    Returns:
        dict with:
            direct_prerequisites: handlers that must run immediately before
            transitive_prerequisites: all handlers that must have run at some point
            required_state: state variables that must be set
            phase: which protocol phase this handler is in
        Or None if handler not found.
    """
    sequences = get_protocol_sequences(session)
    if not sequences:
        return None

    edges = sequences.get("edges", [])
    nodes = sequences.get("nodes", {})
    handler_phase = sequences.get("handler_phase", {})

    if handler_name not in nodes:
        # Try partial match
        matches = [n for n in nodes if handler_name.upper() in n.upper()]
        if len(matches) == 1:
            handler_name = matches[0]
        elif len(matches) > 1:
            msg_warn(f"Ambiguous handler name '{handler_name}', "
                     f"matches: {matches[:5]}")
            return None
        else:
            return None

    # Direct prerequisites: handlers with edges pointing to this handler
    direct_prereqs = []
    for e in edges:
        if e["to_handler"] == handler_name:
            direct_prereqs.append({
                "handler": e["from_handler"],
                "state_key": e["state_key"],
                "expected_value": e.get("expected_value"),
                "is_required": e.get("is_required", False),
            })

    # Transitive prerequisites
    closure = _compute_transitive_closure(edges)
    transitive = sorted(closure.get(handler_name, set()))

    # Required state from the handler's own reads
    info = nodes.get(handler_name, {})
    required_state = [
        {
            "state_key": r["state_key"],
            "expected_value": r.get("expected_value"),
            "operator": r.get("operator", "=="),
        }
        for r in info.get("reads", [])
        if r.get("is_guard")
    ]

    phase = handler_phase.get(handler_name)

    return {
        "handler": handler_name,
        "direct_prerequisites": direct_prereqs,
        "transitive_prerequisites": transitive,
        "required_state": required_state,
        "phase": phase,
    }
