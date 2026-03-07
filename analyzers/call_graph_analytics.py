"""
Call Graph Analytics — Graph Theory Analysis of the Function Call Graph

Applies graph theory algorithms to the full function call graph extracted from
the IDB to discover architectural patterns, module boundaries, hub functions,
and bottlenecks.

Algorithms implemented:
  1. Full call graph construction with edge weights
  2. PageRank — find the most architecturally significant functions
  3. Betweenness centrality (sample-based approximation)
  4. Community detection via label propagation
  5. HITS (hub/authority) analysis
  6. Strongly connected components (Tarjan's algorithm)
  7. Call depth analysis from handler entry points
  8. Cross-system edge analysis and system-level dependency graph

Results are stored in the knowledge DB kv_store under key "call_graph_analytics".
"""

import json
import re
import time
from collections import defaultdict, Counter, deque
import math
import random

import ida_funcs
import ida_name
import ida_segment
import ida_xref
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str
)


# ---------------------------------------------------------------------------
# System classification patterns (shared with dependency_mapper)
# ---------------------------------------------------------------------------

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

# Compiler runtime and CRT functions to exclude from the call graph
_COMPILER_RUNTIME_PREFIXES = (
    "__",          # __security_check_cookie, __GSHandlerCheck, etc.
    "_RTC",        # runtime checks
    "_CRT",        # CRT init
    "_Init_",      # CRT initializers
    "??_",         # MSVC internal mangled names
    "memcpy",
    "memset",
    "memmove",
    "strlen",
    "strcmp",
    "strcpy",
    "strcat",
    "sprintf",
    "printf",
    "malloc",
    "free",
    "realloc",
    "operator new",
    "operator delete",
)

# Import DLL function prefixes to skip
_IMPORT_PREFIXES = (
    "KERNEL32_",
    "NTDLL_",
    "ADVAPI32_",
    "USER32_",
    "GDI32_",
    "WS2_32_",
    "CRYPT32_",
    "WINHTTP_",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _classify_system(name):
    """Classify a function name into a game system."""
    name_upper = name.upper()
    for system, keywords in SYSTEM_PATTERNS.items():
        for kw in keywords:
            if kw in name_upper:
                return system
    return "Other"


def _classify_system_from_db(db, ea):
    """Look up system classification from the functions table."""
    row = db.fetchone(
        "SELECT system FROM functions WHERE ea = ?", (ea,))
    if row and row["system"]:
        return row["system"]
    return None


def _is_thunk(func):
    """Check if a function is a thunk (single jmp instruction)."""
    if func is None:
        return False
    if func.flags & idaapi.FUNC_THUNK:
        return True
    # Very short functions (< 8 bytes) that are just a jump
    if func.size() < 8:
        return True
    return False


def _is_compiler_runtime(name):
    """Check if a function name belongs to compiler runtime / CRT."""
    if not name:
        return False
    for prefix in _COMPILER_RUNTIME_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


def _is_import_function(name):
    """Check if a name is an import from a system DLL."""
    if not name:
        return False
    name_upper = name.upper()
    for prefix in _IMPORT_PREFIXES:
        if name_upper.startswith(prefix):
            return True
    return False


def _get_text_segment_range():
    """Return (start_ea, end_ea) for the .text segment, or None."""
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name in (".text", "_text", "CODE", ".code"):
            return (seg.start_ea, seg.end_ea)
    # Fallback: return the first executable segment
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg and (seg.perm & 1):  # executable
            return (seg.start_ea, seg.end_ea)
    return None


def _get_function_name(ea):
    """Get a meaningful function name at ea."""
    name = ida_name.get_name(ea)
    if name and not name.startswith("sub_") and not name.startswith("nullsub_"):
        return name
    return None


# ---------------------------------------------------------------------------
# 1. Call Graph Construction
# ---------------------------------------------------------------------------

class CallGraph:
    """In-memory call graph with forward/reverse adjacency and edge weights."""

    def __init__(self):
        # Node set: ea values of all valid functions
        self.nodes = set()
        # Forward adjacency: caller_ea -> {callee_ea: edge_weight}
        self.forward = defaultdict(lambda: defaultdict(int))
        # Reverse adjacency: callee_ea -> {caller_ea: edge_weight}
        self.reverse = defaultdict(lambda: defaultdict(int))
        # Function metadata
        self.node_name = {}      # ea -> name (only for named functions)
        self.node_system = {}    # ea -> system classification

    @property
    def num_nodes(self):
        return len(self.nodes)

    @property
    def num_edges(self):
        count = 0
        for callees in self.forward.values():
            count += len(callees)
        return count

    def out_degree(self, ea):
        """Number of distinct callees."""
        return len(self.forward.get(ea, {}))

    def in_degree(self, ea):
        """Number of distinct callers."""
        return len(self.reverse.get(ea, {}))

    def degree(self, ea):
        return self.out_degree(ea) + self.in_degree(ea)

    def callees(self, ea):
        """Return set of callees for a function."""
        return set(self.forward.get(ea, {}).keys())

    def callers(self, ea):
        """Return set of callers for a function."""
        return set(self.reverse.get(ea, {}).keys())

    def add_edge(self, caller_ea, callee_ea):
        """Add or increment a call edge."""
        self.forward[caller_ea][callee_ea] += 1
        self.reverse[callee_ea][caller_ea] += 1

    def stats(self):
        """Compute basic graph statistics."""
        n = self.num_nodes
        e = self.num_edges
        if n == 0:
            return {
                "nodes": 0, "edges": 0, "avg_degree": 0.0,
                "max_degree": 0, "density": 0.0,
            }

        degrees = [self.degree(ea) for ea in self.nodes]
        max_deg = max(degrees) if degrees else 0
        avg_deg = sum(degrees) / n if n > 0 else 0.0
        # Density for directed graph: e / (n * (n-1))
        density = e / (n * (n - 1)) if n > 1 else 0.0

        return {
            "nodes": n,
            "edges": e,
            "avg_degree": round(avg_deg, 3),
            "max_degree": max_deg,
            "density": round(density, 8),
        }


def _build_call_graph(db):
    """Construct the full call graph from the IDB.

    Iterates all functions in the .text segment, extracts call references,
    and builds weighted adjacency lists.

    Returns a CallGraph instance.
    """
    graph = CallGraph()
    t0 = time.time()

    text_range = _get_text_segment_range()
    if text_range is None:
        msg_warn("No .text segment found; scanning all functions")
        text_start, text_end = 0, 0xFFFFFFFFFFFFFFFF
    else:
        text_start, text_end = text_range
        msg_info(f"Text segment: {ea_str(text_start)} - {ea_str(text_end)}")

    # Load system labels from DB for all known functions
    db_systems = {}
    try:
        rows = db.fetchall(
            "SELECT ea, system FROM functions WHERE system IS NOT NULL")
        for row in rows:
            db_systems[row["ea"]] = row["system"]
    except Exception:
        pass

    # Phase 1: Enumerate all eligible functions
    skipped_thunks = 0
    skipped_runtime = 0
    skipped_imports = 0
    skipped_outside = 0

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if func is None:
            continue

        # Filter: must be in .text segment
        if text_range and (func_ea < text_start or func_ea >= text_end):
            skipped_outside += 1
            continue

        # Filter: skip thunks
        if _is_thunk(func):
            skipped_thunks += 1
            continue

        name = ida_name.get_name(func_ea)

        # Filter: skip compiler runtime
        if _is_compiler_runtime(name):
            skipped_runtime += 1
            continue

        # Filter: skip imports
        if _is_import_function(name):
            skipped_imports += 1
            continue

        graph.nodes.add(func_ea)

        # Store name if meaningful
        if name and not name.startswith("sub_") and not name.startswith("nullsub_"):
            graph.node_name[func_ea] = name

        # System classification: DB first, then name heuristic
        if func_ea in db_systems:
            graph.node_system[func_ea] = db_systems[func_ea]
        elif name:
            sys_class = _classify_system(name)
            if sys_class != "Other":
                graph.node_system[func_ea] = sys_class

    msg_info(f"Graph nodes: {graph.num_nodes} functions "
             f"(skipped {skipped_thunks} thunks, {skipped_runtime} runtime, "
             f"{skipped_imports} imports, {skipped_outside} outside .text)")

    # Phase 2: Build edges from code cross-references
    edge_count = 0
    for func_ea in graph.nodes:
        func = ida_funcs.get_func(func_ea)
        if func is None:
            continue

        # Scan all heads within the function for call references
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                # Only call references (near call, far call)
                if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN):
                    continue

                target_ea = xref.to
                # Resolve to function start
                target_func = ida_funcs.get_func(target_ea)
                if target_func is None:
                    continue
                target_start = target_func.start_ea

                # Skip self-references
                if target_start == func_ea:
                    continue

                # Target must be in our node set
                if target_start not in graph.nodes:
                    continue

                graph.add_edge(func_ea, target_start)
                edge_count += 1

    elapsed = time.time() - t0
    msg_info(f"Call graph built: {graph.num_nodes} nodes, "
             f"{graph.num_edges} unique edges ({edge_count} call sites) "
             f"in {elapsed:.1f}s")

    return graph


# ---------------------------------------------------------------------------
# 2. PageRank
# ---------------------------------------------------------------------------

def _compute_pagerank(graph, damping=0.85, max_iter=100, tol=1e-6):
    """Compute PageRank scores for all nodes in the call graph.

    Uses the iterative power method:
        PR(f) = (1-d)/N + d * sum(PR(caller) / out_degree(caller))

    Returns dict: ea -> pagerank_score
    """
    t0 = time.time()
    N = graph.num_nodes
    if N == 0:
        return {}

    nodes = list(graph.nodes)
    node_idx = {ea: i for i, ea in enumerate(nodes)}

    # Initialize uniform
    pr = [1.0 / N] * N
    base_score = (1.0 - damping) / N

    # Precompute: for each node, list of (caller_index, caller_out_degree)
    caller_info = []
    for ea in nodes:
        callers = graph.reverse.get(ea, {})
        info = []
        for caller_ea in callers:
            ci = node_idx.get(caller_ea)
            if ci is not None:
                out_deg = graph.out_degree(caller_ea)
                if out_deg > 0:
                    info.append((ci, out_deg))
        caller_info.append(info)

    # Dangling nodes (no outgoing edges) — distribute their PR uniformly
    dangling = [i for i, ea in enumerate(nodes) if graph.out_degree(ea) == 0]

    converged_iter = max_iter
    for iteration in range(max_iter):
        new_pr = [0.0] * N

        # Dangling node contribution
        dangling_sum = sum(pr[i] for i in dangling)
        dangling_contrib = damping * dangling_sum / N

        for i in range(N):
            rank = base_score + dangling_contrib
            for ci, out_deg in caller_info[i]:
                rank += damping * pr[ci] / out_deg
            new_pr[i] = rank

        # Check convergence
        delta = sum(abs(new_pr[i] - pr[i]) for i in range(N))
        pr = new_pr

        if delta < tol:
            converged_iter = iteration + 1
            break

    elapsed = time.time() - t0
    msg_info(f"PageRank converged in {converged_iter} iterations ({elapsed:.2f}s)")

    return {nodes[i]: pr[i] for i in range(N)}


# ---------------------------------------------------------------------------
# 3. Betweenness Centrality (Sample-Based Approximation)
# ---------------------------------------------------------------------------

def _compute_betweenness_centrality(graph, num_samples=500):
    """Approximate betweenness centrality using BFS from random source nodes.

    For each sampled source, run BFS and count how many shortest paths
    pass through each intermediate node.

    Returns dict: ea -> centrality_score (normalized).
    """
    t0 = time.time()
    N = graph.num_nodes
    if N < 3:
        return {}

    nodes = list(graph.nodes)
    centrality = defaultdict(float)

    # Sample source nodes
    sample_size = min(num_samples, N)
    sources = random.sample(nodes, sample_size)

    for src_ea in sources:
        # BFS from source using forward edges
        dist = {src_ea: 0}
        num_paths = {src_ea: 1}
        predecessors = defaultdict(list)
        queue = deque([src_ea])
        order = []  # nodes in BFS order

        while queue:
            v = queue.popleft()
            order.append(v)
            d_v = dist[v]

            for w in graph.forward.get(v, {}):
                if w not in graph.nodes:
                    continue
                if w not in dist:
                    dist[w] = d_v + 1
                    num_paths[w] = 0
                    queue.append(w)
                if dist[w] == d_v + 1:
                    num_paths[w] += num_paths[v]
                    predecessors[w].append(v)

        # Accumulate dependency scores (Brandes' algorithm, single source)
        dependency = defaultdict(float)
        for w in reversed(order):
            np_w = num_paths.get(w, 1)
            if np_w == 0:
                continue
            for v in predecessors.get(w, []):
                np_v = num_paths.get(v, 1)
                if np_v == 0:
                    continue
                frac = np_v / np_w
                dependency[v] += frac * (1.0 + dependency[w])
            if w != src_ea:
                centrality[w] += dependency[w]

    # Normalize: divide by number of samples and scale
    scale = 1.0 / sample_size if sample_size > 0 else 1.0
    for ea in centrality:
        centrality[ea] *= scale

    elapsed = time.time() - t0
    msg_info(f"Betweenness centrality computed ({sample_size} samples, "
             f"{elapsed:.2f}s)")

    return dict(centrality)


# ---------------------------------------------------------------------------
# 4. Community Detection (Label Propagation)
# ---------------------------------------------------------------------------

def _detect_communities(graph, max_iter=30):
    """Detect communities using asynchronous label propagation.

    Each node starts with a unique label. Iteratively, each node adopts the
    most frequent label among its neighbors (both callers and callees).
    Ties are broken randomly.

    Returns dict: ea -> community_label (int).
    """
    t0 = time.time()
    N = graph.num_nodes
    if N == 0:
        return {}

    nodes = list(graph.nodes)
    # Initialize: each node gets its own label (use index)
    labels = {ea: i for i, ea in enumerate(nodes)}

    for iteration in range(max_iter):
        changed = 0
        # Process nodes in random order for asynchronous propagation
        order = list(nodes)
        random.shuffle(order)

        for ea in order:
            # Gather neighbor labels (both directions) weighted by edge count
            neighbor_labels = Counter()

            for callee_ea, weight in graph.forward.get(ea, {}).items():
                if callee_ea in labels:
                    neighbor_labels[labels[callee_ea]] += weight

            for caller_ea, weight in graph.reverse.get(ea, {}).items():
                if caller_ea in labels:
                    neighbor_labels[labels[caller_ea]] += weight

            if not neighbor_labels:
                continue

            # Find the label with maximum total weight
            max_count = max(neighbor_labels.values())
            candidates = [
                lbl for lbl, cnt in neighbor_labels.items()
                if cnt == max_count
            ]
            chosen = random.choice(candidates)

            if chosen != labels[ea]:
                labels[ea] = chosen
                changed += 1

        # Convergence check
        if changed == 0:
            msg_info(f"Label propagation converged at iteration {iteration + 1}")
            break
    else:
        msg_info(f"Label propagation: max iterations ({max_iter}) reached, "
                 f"{changed} nodes still changing")

    elapsed = time.time() - t0
    msg_info(f"Community detection completed in {elapsed:.2f}s")

    return labels


def _analyze_communities(graph, labels):
    """Analyze detected communities and compare with system labels.

    Returns:
        communities: list of {id, size, dominant_system, members_sample}
        misclassified: list of {ea, name, current_system, community_system}
    """
    # Group nodes by community label
    community_members = defaultdict(list)
    for ea, label in labels.items():
        community_members[label].append(ea)

    communities = []
    misclassified = []

    for label, members in sorted(community_members.items(),
                                  key=lambda x: -len(x[1])):
        size = len(members)
        if size < 2:
            continue  # skip singletons

        # Determine dominant system in this community
        system_counts = Counter()
        for ea in members:
            sys = graph.node_system.get(ea, "Other")
            system_counts[sys] += 1

        dominant_system = system_counts.most_common(1)[0][0]
        dominant_count = system_counts[dominant_system]

        # Sample some named members for reporting
        named_members = []
        for ea in members:
            name = graph.node_name.get(ea)
            if name and len(named_members) < 10:
                named_members.append({"ea": ea, "name": name})

        communities.append({
            "id": int(label),
            "size": size,
            "dominant_system": dominant_system,
            "dominant_ratio": round(dominant_count / size, 3),
            "system_breakdown": dict(system_counts.most_common(5)),
            "members_sample": named_members,
        })

        # Find misclassified: nodes whose system label disagrees with community
        if dominant_system != "Other":
            for ea in members:
                current_sys = graph.node_system.get(ea)
                if (current_sys and current_sys != "Other"
                        and current_sys != dominant_system):
                    name = graph.node_name.get(ea, ea_str(ea))
                    misclassified.append({
                        "ea": ea,
                        "name": name,
                        "current_system": current_sys,
                        "community_system": dominant_system,
                    })

    return communities, misclassified


# ---------------------------------------------------------------------------
# 5. HITS (Hub/Authority) Analysis
# ---------------------------------------------------------------------------

def _compute_hits(graph, max_iter=50, tol=1e-6):
    """Compute HITS hub and authority scores.

    Hubs = functions that CALL many authorities (dispatchers, routers).
    Authorities = functions CALLED BY many hubs (core utilities).

    Iterative:
        auth(f) = sum(hub(caller) for caller in callers(f))
        hub(f)  = sum(auth(callee) for callee in callees(f))
        Normalize both vectors after each step.

    Returns (hub_scores, auth_scores) as dicts: ea -> score
    """
    t0 = time.time()
    N = graph.num_nodes
    if N == 0:
        return {}, {}

    nodes = list(graph.nodes)
    node_idx = {ea: i for i, ea in enumerate(nodes)}

    hub = [1.0] * N
    auth = [1.0] * N

    # Precompute adjacency as index lists
    forward_idx = []  # i -> [callee indices]
    reverse_idx = []  # i -> [caller indices]
    for ea in nodes:
        fwd = [node_idx[c] for c in graph.forward.get(ea, {})
               if c in node_idx]
        rev = [node_idx[c] for c in graph.reverse.get(ea, {})
               if c in node_idx]
        forward_idx.append(fwd)
        reverse_idx.append(rev)

    for iteration in range(max_iter):
        # Update authority scores
        new_auth = [0.0] * N
        for i in range(N):
            for ci in reverse_idx[i]:
                new_auth[i] += hub[ci]

        # Update hub scores
        new_hub = [0.0] * N
        for i in range(N):
            for ci in forward_idx[i]:
                new_hub[i] += auth[ci]

        # Normalize
        auth_norm = math.sqrt(sum(a * a for a in new_auth)) or 1.0
        hub_norm = math.sqrt(sum(h * h for h in new_hub)) or 1.0
        new_auth = [a / auth_norm for a in new_auth]
        new_hub = [h / hub_norm for h in new_hub]

        # Convergence check
        delta_a = sum(abs(new_auth[i] - auth[i]) for i in range(N))
        delta_h = sum(abs(new_hub[i] - hub[i]) for i in range(N))

        auth = new_auth
        hub = new_hub

        if delta_a < tol and delta_h < tol:
            msg_info(f"HITS converged at iteration {iteration + 1}")
            break

    elapsed = time.time() - t0
    msg_info(f"HITS analysis completed in {elapsed:.2f}s")

    hub_scores = {nodes[i]: hub[i] for i in range(N)}
    auth_scores = {nodes[i]: auth[i] for i in range(N)}
    return hub_scores, auth_scores


# ---------------------------------------------------------------------------
# 6. Strongly Connected Components (Tarjan's Algorithm)
# ---------------------------------------------------------------------------

def _find_sccs(graph):
    """Find all strongly connected components using Tarjan's algorithm.

    Returns list of SCCs (each SCC is a list of ea values).
    Only returns non-trivial SCCs (size > 1).

    Uses an iterative (non-recursive) implementation to avoid Python's
    recursion limit on large graphs.
    """
    t0 = time.time()

    index_counter = [0]
    stack = []
    on_stack = set()
    index = {}     # ea -> discovery index
    lowlink = {}   # ea -> lowlink value
    sccs = []

    # Iterative Tarjan's using an explicit call stack
    # Each frame: (node, neighbor_iterator, is_initial_visit)
    for start_ea in graph.nodes:
        if start_ea in index:
            continue

        call_stack = [(start_ea, iter(graph.forward.get(start_ea, {}).keys()), True)]

        while call_stack:
            v, neighbors, is_init = call_stack[-1]

            if is_init:
                # First visit to this node
                index[v] = index_counter[0]
                lowlink[v] = index_counter[0]
                index_counter[0] += 1
                stack.append(v)
                on_stack.add(v)
                # Mark as no longer initial
                call_stack[-1] = (v, neighbors, False)

            found_unvisited = False
            for w in neighbors:
                if w not in graph.nodes:
                    continue
                if w not in index:
                    # Unvisited neighbor: "recurse"
                    call_stack.append(
                        (w, iter(graph.forward.get(w, {}).keys()), True))
                    found_unvisited = True
                    break
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index[w])

            if found_unvisited:
                continue

            # All neighbors processed — check if v is a root
            if lowlink[v] == index[v]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    scc.append(w)
                    if w == v:
                        break
                if len(scc) > 1:
                    sccs.append(scc)

            # Pop this frame and update parent's lowlink
            call_stack.pop()
            if call_stack:
                parent_v = call_stack[-1][0]
                lowlink[parent_v] = min(lowlink[parent_v], lowlink[v])

    elapsed = time.time() - t0
    msg_info(f"SCC detection: found {len(sccs)} non-trivial SCCs in {elapsed:.2f}s")

    return sccs


def _analyze_sccs(graph, sccs):
    """Summarize SCCs for reporting."""
    results = []
    for scc in sorted(sccs, key=len, reverse=True):
        # Determine dominant system
        system_counts = Counter()
        named_members = []
        for ea in scc:
            sys = graph.node_system.get(ea, "Other")
            system_counts[sys] += 1
            name = graph.node_name.get(ea)
            if name and len(named_members) < 10:
                named_members.append({"ea": ea, "name": name})

        dominant = system_counts.most_common(1)[0][0] if system_counts else "Other"

        results.append({
            "size": len(scc),
            "system": dominant,
            "system_breakdown": dict(system_counts.most_common(5)),
            "members_sample": named_members,
        })

    return results


# ---------------------------------------------------------------------------
# 7. Depth Analysis — Call Chain Depths
# ---------------------------------------------------------------------------

def _compute_depth_analysis(graph, db):
    """Compute call chain depths from handler entry points.

    Identifies handler functions (from the opcodes table), then does BFS
    from each to measure maximum call depth.

    Returns depth_stats dict.
    """
    t0 = time.time()

    # Gather handler entry points from the DB
    handler_eas = set()
    try:
        rows = db.fetchall(
            "SELECT handler_ea FROM opcodes WHERE handler_ea IS NOT NULL")
        for row in rows:
            ea = row["handler_ea"]
            if ea in graph.nodes:
                handler_eas.add(ea)
    except Exception:
        pass

    if not handler_eas:
        # Fallback: use functions with no callers (root functions)
        for ea in graph.nodes:
            if graph.in_degree(ea) == 0 and graph.out_degree(ea) > 0:
                handler_eas.add(ea)

    msg_info(f"Depth analysis: {len(handler_eas)} entry points")

    deepest_chains = []
    all_depths = []

    for handler_ea in handler_eas:
        # BFS to find max depth
        visited = {handler_ea: 0}
        queue = deque([handler_ea])
        max_depth = 0

        while queue:
            v = queue.popleft()
            d = visited[v]
            if d > max_depth:
                max_depth = d

            # Limit BFS depth to avoid explosion
            if d >= 200:
                continue

            for callee_ea in graph.forward.get(v, {}):
                if callee_ea in graph.nodes and callee_ea not in visited:
                    visited[callee_ea] = d + 1
                    queue.append(callee_ea)

        all_depths.append(max_depth)

        handler_name = graph.node_name.get(handler_ea, ea_str(handler_ea))
        deepest_chains.append({
            "handler_ea": handler_ea,
            "handler_name": handler_name,
            "depth": max_depth,
            "reachable_count": len(visited),
        })

    # Sort by depth descending
    deepest_chains.sort(key=lambda x: -x["depth"])

    max_depth = max(all_depths) if all_depths else 0
    avg_depth = (sum(all_depths) / len(all_depths)) if all_depths else 0.0

    elapsed = time.time() - t0
    msg_info(f"Depth analysis: max={max_depth}, avg={avg_depth:.1f} ({elapsed:.2f}s)")

    return {
        "max_depth": max_depth,
        "avg_depth": round(avg_depth, 2),
        "handler_count": len(handler_eas),
        "deepest_chains": deepest_chains[:50],  # top-50
    }


# ---------------------------------------------------------------------------
# 8. Cross-System Edge Analysis
# ---------------------------------------------------------------------------

def _analyze_cross_system_edges(graph):
    """Analyze edges between functions classified in different game systems.

    Counts inter-system edges, identifies gateway functions, and builds
    a system-level dependency graph.

    Returns:
        cross_system_edges: list of {from_system, to_system, edge_count, gateway_functions}
    """
    t0 = time.time()

    # Count edges between system pairs
    system_edge_counts = defaultdict(int)
    system_gateway_funcs = defaultdict(lambda: defaultdict(int))

    for caller_ea in graph.nodes:
        caller_sys = graph.node_system.get(caller_ea, "Other")
        if caller_sys == "Other":
            continue

        for callee_ea in graph.forward.get(caller_ea, {}):
            callee_sys = graph.node_system.get(callee_ea, "Other")
            if callee_sys == "Other" or callee_sys == caller_sys:
                continue

            key = (caller_sys, callee_sys)
            weight = graph.forward[caller_ea][callee_ea]
            system_edge_counts[key] += weight

            # The callee is a "gateway" function receiving cross-system calls
            callee_name = graph.node_name.get(callee_ea, ea_str(callee_ea))
            system_gateway_funcs[key][callee_name] += weight

    # Build results sorted by edge count
    results = []
    for (from_sys, to_sys), count in sorted(
            system_edge_counts.items(), key=lambda x: -x[1]):
        gateways = system_gateway_funcs[(from_sys, to_sys)]
        top_gateways = sorted(gateways.items(), key=lambda x: -x[1])[:5]

        results.append({
            "from_system": from_sys,
            "to_system": to_sys,
            "edge_count": count,
            "gateway_functions": [
                {"name": name, "call_count": cnt}
                for name, cnt in top_gateways
            ],
        })

    elapsed = time.time() - t0
    msg_info(f"Cross-system analysis: {len(results)} system pairs ({elapsed:.2f}s)")

    return results


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _format_pagerank_top(graph, pagerank, n=100):
    """Format the top-N PageRank results for storage."""
    sorted_pr = sorted(pagerank.items(), key=lambda x: -x[1])[:n]
    results = []
    for ea, score in sorted_pr:
        results.append({
            "ea": ea,
            "name": graph.node_name.get(ea, ea_str(ea)),
            "score": round(score, 10),
            "system": graph.node_system.get(ea, "Other"),
        })
    return results


def _format_centrality_top(graph, centrality, n=100):
    """Format the top-N betweenness centrality results."""
    sorted_bc = sorted(centrality.items(), key=lambda x: -x[1])[:n]
    results = []
    for ea, score in sorted_bc:
        # Determine which systems this function bridges
        caller_systems = set()
        callee_systems = set()
        for caller_ea in graph.reverse.get(ea, {}):
            sys = graph.node_system.get(caller_ea)
            if sys and sys != "Other":
                caller_systems.add(sys)
        for callee_ea in graph.forward.get(ea, {}):
            sys = graph.node_system.get(callee_ea)
            if sys and sys != "Other":
                callee_systems.add(sys)

        bridges = sorted(caller_systems | callee_systems)

        results.append({
            "ea": ea,
            "name": graph.node_name.get(ea, ea_str(ea)),
            "score": round(score, 8),
            "bridges_systems": bridges,
        })
    return results


def _format_hubs_top(graph, hub_scores, n=50):
    """Format the top-N hub results."""
    sorted_hubs = sorted(hub_scores.items(), key=lambda x: -x[1])[:n]
    results = []
    for ea, score in sorted_hubs:
        results.append({
            "ea": ea,
            "name": graph.node_name.get(ea, ea_str(ea)),
            "score": round(score, 10),
            "callee_count": graph.out_degree(ea),
            "system": graph.node_system.get(ea, "Other"),
        })
    return results


def _format_authorities_top(graph, auth_scores, n=50):
    """Format the top-N authority results."""
    sorted_auth = sorted(auth_scores.items(), key=lambda x: -x[1])[:n]
    results = []
    for ea, score in sorted_auth:
        results.append({
            "ea": ea,
            "name": graph.node_name.get(ea, ea_str(ea)),
            "score": round(score, 10),
            "caller_count": graph.in_degree(ea),
            "system": graph.node_system.get(ea, "Other"),
        })
    return results


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_call_graph(session):
    """Run full call graph analytics suite.

    Builds the call graph, then runs: PageRank, betweenness centrality,
    community detection, HITS, SCC detection, depth analysis, and
    cross-system edge analysis.

    Stores results in session.db.kv_set("call_graph_analytics", {...}).

    Args:
        session: PluginSession with db attribute.

    Returns:
        int: Number of insights (top functions, communities, SCCs, etc.) found.
    """
    msg("=" * 70)
    msg("Call Graph Analytics — Starting full analysis")
    msg("=" * 70)

    db = session.db
    t_total = time.time()

    # ── Step 1: Build the call graph ──────────────────────────────────────
    msg_info("Phase 1/8: Building call graph...")
    graph = _build_call_graph(db)

    if graph.num_nodes < 10:
        msg_warn("Call graph too small for meaningful analysis "
                 f"({graph.num_nodes} nodes). Aborting.")
        return 0

    graph_stats = graph.stats()
    msg_info(f"  Nodes: {graph_stats['nodes']:,}")
    msg_info(f"  Edges: {graph_stats['edges']:,}")
    msg_info(f"  Avg degree: {graph_stats['avg_degree']:.2f}")
    msg_info(f"  Max degree: {graph_stats['max_degree']}")
    msg_info(f"  Density: {graph_stats['density']:.8f}")

    # ── Step 2: PageRank ──────────────────────────────────────────────────
    msg_info("Phase 2/8: Computing PageRank...")
    pagerank = _compute_pagerank(graph)
    pagerank_top = _format_pagerank_top(graph, pagerank, n=100)

    if pagerank_top:
        msg_info("Top-10 PageRank functions:")
        for entry in pagerank_top[:10]:
            msg(f"  {entry['score']:.8f}  {entry['name']}  [{entry['system']}]")

    # ── Step 3: Betweenness Centrality ────────────────────────────────────
    msg_info("Phase 3/8: Computing betweenness centrality (sampling)...")
    # Scale samples with graph size, cap at 500
    sample_count = min(500, max(50, graph.num_nodes // 200))
    centrality = _compute_betweenness_centrality(graph, num_samples=sample_count)
    centrality_top = _format_centrality_top(graph, centrality, n=100)

    if centrality_top:
        msg_info("Top-10 betweenness centrality (bottleneck) functions:")
        for entry in centrality_top[:10]:
            bridges = ", ".join(entry["bridges_systems"][:3]) or "n/a"
            msg(f"  {entry['score']:.6f}  {entry['name']}  bridges: [{bridges}]")

    # ── Step 4: Community Detection ───────────────────────────────────────
    msg_info("Phase 4/8: Detecting communities via label propagation...")
    labels = _detect_communities(graph, max_iter=30)
    communities, misclassified = _analyze_communities(graph, labels)

    num_communities = len(communities)
    msg_info(f"Discovered {num_communities} communities (size > 1)")
    for comm in communities[:10]:
        msg(f"  Community {comm['id']}: {comm['size']} members, "
            f"dominant={comm['dominant_system']} ({comm['dominant_ratio']:.0%})")

    if misclassified:
        msg_info(f"Found {len(misclassified)} potentially misclassified functions:")
        for mc in misclassified[:10]:
            msg(f"  {mc['name']}: labeled={mc['current_system']}, "
                f"community says={mc['community_system']}")

    # ── Step 5: HITS Hub/Authority Analysis ───────────────────────────────
    msg_info("Phase 5/8: Computing HITS hub/authority scores...")
    hub_scores, auth_scores = _compute_hits(graph)
    hubs_top = _format_hubs_top(graph, hub_scores, n=50)
    authorities_top = _format_authorities_top(graph, auth_scores, n=50)

    if hubs_top:
        msg_info("Top-10 hub functions (dispatchers/managers):")
        for entry in hubs_top[:10]:
            msg(f"  {entry['score']:.8f}  {entry['name']}  "
                f"(calls {entry['callee_count']} functions)")

    if authorities_top:
        msg_info("Top-10 authority functions (core utilities):")
        for entry in authorities_top[:10]:
            msg(f"  {entry['score']:.8f}  {entry['name']}  "
                f"(called by {entry['caller_count']} functions)")

    # ── Step 6: Strongly Connected Components ─────────────────────────────
    msg_info("Phase 6/8: Finding strongly connected components (Tarjan)...")
    raw_sccs = _find_sccs(graph)
    scc_results = _analyze_sccs(graph, raw_sccs)

    if scc_results:
        msg_info(f"Non-trivial SCCs: {len(scc_results)}")
        for scc_info in scc_results[:10]:
            sample_names = [m["name"] for m in scc_info["members_sample"][:3]]
            msg(f"  SCC size={scc_info['size']}, system={scc_info['system']}, "
                f"sample: {sample_names}")

    # ── Step 7: Depth Analysis ────────────────────────────────────────────
    msg_info("Phase 7/8: Analyzing call chain depths...")
    depth_stats = _compute_depth_analysis(graph, db)

    if depth_stats["deepest_chains"]:
        msg_info(f"Max call depth: {depth_stats['max_depth']}, "
                 f"avg: {depth_stats['avg_depth']}")
        msg_info("Deepest call chains:")
        for chain in depth_stats["deepest_chains"][:10]:
            msg(f"  depth={chain['depth']}, reachable={chain['reachable_count']}, "
                f"handler={chain['handler_name']}")

    # ── Step 8: Cross-System Edge Analysis ────────────────────────────────
    msg_info("Phase 8/8: Analyzing cross-system edges...")
    cross_system_edges = _analyze_cross_system_edges(graph)

    if cross_system_edges:
        msg_info(f"Cross-system dependency pairs: {len(cross_system_edges)}")
        for edge_info in cross_system_edges[:10]:
            gw_names = [g["name"] for g in edge_info["gateway_functions"][:2]]
            msg(f"  {edge_info['from_system']} -> {edge_info['to_system']}: "
                f"{edge_info['edge_count']} edges, gateways: {gw_names}")

    # ── Store Results ─────────────────────────────────────────────────────
    # Convert ea values to strings for JSON serialization (int64 safety)
    def _ea_safe(obj):
        """Recursively convert large ints to hex strings for JSON compat."""
        if isinstance(obj, dict):
            return {k: _ea_safe(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_ea_safe(v) for v in obj]
        if isinstance(obj, int) and (obj > 2**53 or obj < -(2**53)):
            return f"0x{obj:X}"
        return obj

    results = {
        "timestamp": time.time(),
        "graph_stats": graph_stats,
        "pagerank_top100": _ea_safe(pagerank_top),
        "centrality_top100": _ea_safe(centrality_top),
        "communities": _ea_safe(communities[:100]),
        "misclassified_functions": _ea_safe(misclassified[:200]),
        "hubs_top50": _ea_safe(hubs_top),
        "authorities_top50": _ea_safe(authorities_top),
        "sccs": _ea_safe(scc_results[:100]),
        "cross_system_edges": _ea_safe(cross_system_edges),
        "depth_stats": _ea_safe(depth_stats),
    }

    db.kv_set("call_graph_analytics", results)
    db.commit()

    # Count total insights
    total_insights = (
        len(pagerank_top)
        + len(centrality_top)
        + num_communities
        + len(misclassified)
        + len(hubs_top)
        + len(authorities_top)
        + len(scc_results)
        + len(cross_system_edges)
    )

    elapsed = time.time() - t_total
    msg("=" * 70)
    msg(f"Call Graph Analytics complete: {total_insights} insights in {elapsed:.1f}s")
    msg(f"  PageRank top functions:   {len(pagerank_top)}")
    msg(f"  Centrality bottlenecks:   {len(centrality_top)}")
    msg(f"  Communities detected:     {num_communities}")
    msg(f"  Misclassified functions:  {len(misclassified)}")
    msg(f"  Hub functions:            {len(hubs_top)}")
    msg(f"  Authority functions:      {len(authorities_top)}")
    msg(f"  Non-trivial SCCs:         {len(scc_results)}")
    msg(f"  Cross-system pairs:       {len(cross_system_edges)}")
    msg(f"  Max call depth:           {depth_stats['max_depth']}")
    msg("=" * 70)

    return total_insights


# ---------------------------------------------------------------------------
# Report retrieval
# ---------------------------------------------------------------------------

def get_call_graph_report(session):
    """Retrieve stored call graph analytics data.

    Args:
        session: PluginSession with db attribute.

    Returns:
        dict with all analysis results, or empty dict if not yet run.
    """
    return session.db.kv_get("call_graph_analytics") or {}
