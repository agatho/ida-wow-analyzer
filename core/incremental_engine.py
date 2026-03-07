"""
Incremental Analysis Engine for TC WoW Analyzer.

Instead of re-running all 51 analyzers from scratch every time, this engine:
  1. Detects which functions changed since the last analysis run
  2. Determines which analyzers are affected based on a dependency DAG
  3. Topologically sorts affected analyzers and re-runs only those
  4. Tracks run times, changelogs, and per-analyzer staleness

State is persisted in the kv_store table:
  - "incremental_state"     : per-function hashes and analyzer last-run timestamps
  - "incremental_changelog" : history of incremental runs
  - "analyzer_run_times"    : per-analyzer timing data

Usage:
    from tc_wow_analyzer.core.incremental_engine import IncrementalEngine
    engine = IncrementalEngine(session)
    changes = engine.detect_changes()
    plan = engine.plan_reanalysis(changes)
    results = engine.execute_plan(plan)
"""

import json
import time
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Callable

import ida_funcs
import ida_name
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text,
)


# ---------------------------------------------------------------------------
# Analyzer Dependency DAG
# ---------------------------------------------------------------------------
# Keys are analyzer names; values are lists of analyzers that MUST run before
# them.  An analyzer with an empty list has no prerequisites.
# ---------------------------------------------------------------------------

ANALYZER_DEPS = {
    # --- Standalone (Round 1) ---
    "lua_api": [],
    "vtables": [],
    "db2_metadata": [],
    "opcode_dispatcher": [],

    # --- Round 1 dependent ---
    "jam_recovery": ["opcode_dispatcher"],
    "update_fields": ["jam_recovery"],
    "handler_jam_linking": ["opcode_dispatcher", "jam_recovery"],

    # --- Quality Enhancement (Round 2) ---
    "db2_drift": ["db2_metadata"],
    "validation_extractor": ["opcode_dispatcher"],
    "conformance": ["opcode_dispatcher", "validation_extractor"],
    "state_machines": ["opcode_dispatcher"],
    "dependency_mapper": ["opcode_dispatcher", "vtables"],
    "test_generator": ["conformance", "validation_extractor", "behavioral_spec"],
    "packet_replay": ["wire_format", "jam_recovery"],

    # --- Deep Extraction (Round 3) ---
    "wire_format": ["jam_recovery"],
    "enum_recovery": ["opcode_dispatcher"],
    "constant_mining": ["opcode_dispatcher"],
    "object_layout": ["vtables"],
    "response_reconstruction": ["opcode_dispatcher"],

    # --- Behavioral Analysis ---
    "taint_analysis": ["opcode_dispatcher", "wire_format"],
    "behavioral_spec": ["opcode_dispatcher", "wire_format", "validation_extractor"],
    "protocol_sequencing": ["opcode_dispatcher", "behavioral_spec"],
    "build_delta": [],
    "callee_contracts": ["opcode_dispatcher"],

    # --- Synthesis & Generation ---
    "pseudocode_transpiler": ["opcode_dispatcher", "wire_format", "enum_recovery"],
    "object_lifecycle": ["vtables", "object_layout"],
    "lua_contracts": ["lua_api", "vtables"],

    # --- Intelligence & Enrichment ---
    "idb_enrichment": [
        "opcode_dispatcher", "vtables", "jam_recovery", "enum_recovery",
    ],
    "string_intelligence": [],
    "cross_synthesis": [
        "conformance", "validation_extractor", "behavioral_spec",
        "wire_format", "taint_analysis",
    ],

    # --- Data & Verification ---
    "db2_data_content": ["db2_metadata"],
    "sniff_verification": ["wire_format"],
    "multi_build_temporal": ["build_delta"],

    # --- Structural Analysis ---
    "function_similarity": [],
    "shared_code_detection": ["opcode_dispatcher"],
    "thread_safety_map": [],

    # --- Gap & Completeness ---
    "negative_space": ["opcode_dispatcher", "validation_extractor"],
    "updatefield_descriptors": ["update_fields"],
    "alloc_class_catalog": ["vtables"],

    # --- PE & Low-Level ---
    "pe_metadata": [],
    "data_archaeology": [],
    "cvar_extraction": [],

    # --- Graph & Architecture ---
    "call_graph_analytics": ["opcode_dispatcher"],
    "indirect_call_resolver": ["vtables", "pe_metadata"],
    "event_system": ["vtables"],

    # --- Semantic Analysis ---
    "symbolic_constraints": ["opcode_dispatcher", "wire_format"],
    "binary_tc_alignment": ["opcode_dispatcher"],
    "return_value_semantics": ["opcode_dispatcher"],

    # --- Pattern Mining ---
    "instruction_ngrams": [],
    "execution_trace": ["opcode_dispatcher", "wire_format"],
    "compiler_artifacts": [],

    # --- Round 5 ---
    "llm_semantic_decompiler": [
        "opcode_dispatcher", "wire_format", "symbolic_constraints",
        "enum_recovery", "conformance",
    ],
    "handler_scaffolding": [
        "wire_format", "symbolic_constraints", "behavioral_spec",
        "response_reconstruction", "validation_extractor",
    ],
    "cross_build_migration": ["function_similarity", "instruction_ngrams"],
    "sniff_conformance_loop": [
        "wire_format", "sniff_verification", "binary_tc_alignment",
    ],
}

# Canonical ordered list mapping display names to internal keys.
# Kept in sync with analyzers/__init__.py run_all_analyzers().
ANALYZER_DISPLAY_NAMES = {
    "lua_api": "Lua API",
    "vtables": "VTables",
    "db2_metadata": "DB2 Metadata",
    "opcode_dispatcher": "Opcode Dispatcher",
    "jam_recovery": "JAM Recovery",
    "update_fields": "Update Fields",
    "handler_jam_linking": "Handler-JAM Linking",
    "db2_drift": "DB2 Drift",
    "validation_extractor": "Validation Extractor",
    "conformance": "Conformance Scoring",
    "state_machines": "State Machine Recovery",
    "dependency_mapper": "Dependency Mapper",
    "test_generator": "Test Generator",
    "packet_replay": "Packet Replay",
    "wire_format": "Wire Format Recovery",
    "enum_recovery": "Enum Recovery",
    "constant_mining": "Game Constants",
    "object_layout": "Object Layout",
    "response_reconstruction": "Response Reconstruction",
    "taint_analysis": "Taint Analysis",
    "behavioral_spec": "Behavioral Spec",
    "protocol_sequencing": "Protocol Sequencing",
    "build_delta": "Build Delta",
    "callee_contracts": "Callee Contracts",
    "pseudocode_transpiler": "Pseudocode Transpiler",
    "object_lifecycle": "Object Lifecycle",
    "lua_contracts": "Lua Contracts",
    "idb_enrichment": "IDB Enrichment",
    "string_intelligence": "String Intelligence",
    "cross_synthesis": "Cross-Analyzer Synthesis",
    "db2_data_content": "DB2 Data Content",
    "sniff_verification": "Sniff Verification",
    "multi_build_temporal": "Multi-Build Temporal",
    "function_similarity": "Function Similarity",
    "shared_code_detection": "Shared Code Detection",
    "thread_safety_map": "Thread Safety Map",
    "negative_space": "Negative Space",
    "updatefield_descriptors": "UpdateField Descriptors",
    "alloc_class_catalog": "Allocation Class Catalog",
    "pe_metadata": "PE Metadata",
    "data_archaeology": "Data Section Archaeology",
    "cvar_extraction": "CVar Extraction",
    "call_graph_analytics": "Call Graph Analytics",
    "indirect_call_resolver": "Indirect Call Resolution",
    "event_system": "Event System Recovery",
    "symbolic_constraints": "Symbolic Constraints",
    "binary_tc_alignment": "Binary-TC Alignment",
    "return_value_semantics": "Return Value Semantics",
    "instruction_ngrams": "Instruction N-grams",
    "execution_trace": "Execution Trace Simulation",
    "compiler_artifacts": "Compiler Artifacts",
    "llm_semantic_decompiler": "LLM Semantic Decompiler",
    "handler_scaffolding": "Handler Scaffolding",
    "cross_build_migration": "Cross-Build Migration",
    "sniff_conformance_loop": "Sniff Conformance Loop",
}

# Mapping from analyzer key to (module_path, function_name).
# Used by execute_plan() to dynamically invoke individual analyzers.
ANALYZER_ENTRY_POINTS = {
    "lua_api": ("tc_wow_analyzer.analyzers.lua_api", "analyze_lua_api"),
    "vtables": ("tc_wow_analyzer.analyzers.vtable_analyzer", "analyze_vtables"),
    "db2_metadata": ("tc_wow_analyzer.analyzers.db2_metadata", "analyze_db2_metadata"),
    "opcode_dispatcher": (
        "tc_wow_analyzer.analyzers.opcode_dispatcher", "analyze_opcode_dispatcher",
    ),
    "jam_recovery": ("tc_wow_analyzer.analyzers.jam_recovery", "analyze_jam_types"),
    "update_fields": ("tc_wow_analyzer.analyzers.update_fields", "analyze_update_fields"),
    "handler_jam_linking": (
        "tc_wow_analyzer.analyzers.opcode_dispatcher", "analyze_handler_jam_types",
    ),
    "db2_drift": ("tc_wow_analyzer.analyzers.db2_drift", "analyze_db2_drift"),
    "validation_extractor": (
        "tc_wow_analyzer.analyzers.validation_extractor", "extract_validations",
    ),
    "conformance": ("tc_wow_analyzer.analyzers.conformance", "analyze_conformance"),
    "state_machines": ("tc_wow_analyzer.analyzers.state_machine", "recover_state_machines"),
    "dependency_mapper": (
        "tc_wow_analyzer.analyzers.dependency_mapper", "analyze_dependencies",
    ),
    "test_generator": ("tc_wow_analyzer.analyzers.test_generator", "generate_tests"),
    "packet_replay": (
        "tc_wow_analyzer.analyzers.packet_replay", "analyze_packet_replay",
    ),
    "wire_format": (
        "tc_wow_analyzer.analyzers.wire_format_recovery", "analyze_wire_formats",
    ),
    "enum_recovery": ("tc_wow_analyzer.analyzers.enum_recovery", "recover_enums"),
    "constant_mining": ("tc_wow_analyzer.analyzers.constant_mining", "mine_constants"),
    "object_layout": (
        "tc_wow_analyzer.analyzers.object_layout", "recover_object_layouts",
    ),
    "response_reconstruction": (
        "tc_wow_analyzer.analyzers.response_reconstruction", "reconstruct_responses",
    ),
    "taint_analysis": (
        "tc_wow_analyzer.analyzers.taint_analysis", "analyze_taint_flows",
    ),
    "behavioral_spec": (
        "tc_wow_analyzer.analyzers.behavioral_spec", "generate_behavioral_specs",
    ),
    "protocol_sequencing": (
        "tc_wow_analyzer.analyzers.protocol_sequencing", "recover_protocol_sequence",
    ),
    "build_delta": (
        "tc_wow_analyzer.analyzers.build_delta", "analyze_build_delta",
    ),
    "callee_contracts": (
        "tc_wow_analyzer.analyzers.callee_contracts", "recover_contracts",
    ),
    "pseudocode_transpiler": (
        "tc_wow_analyzer.analyzers.pseudocode_transpiler", "transpile_all_handlers",
    ),
    "object_lifecycle": (
        "tc_wow_analyzer.analyzers.object_lifecycle", "recover_object_lifecycles",
    ),
    "lua_contracts": (
        "tc_wow_analyzer.analyzers.lua_contracts", "analyze_lua_contracts",
    ),
    "idb_enrichment": ("tc_wow_analyzer.analyzers.idb_enrichment", "enrich_idb"),
    "string_intelligence": (
        "tc_wow_analyzer.analyzers.string_intelligence", "analyze_string_intelligence",
    ),
    "cross_synthesis": (
        "tc_wow_analyzer.analyzers.cross_analyzer_synthesis", "synthesize_all",
    ),
    "db2_data_content": (
        "tc_wow_analyzer.analyzers.db2_data_content", "analyze_db2_content",
    ),
    "sniff_verification": (
        "tc_wow_analyzer.analyzers.sniff_verification", "verify_sniff_formats",
    ),
    "multi_build_temporal": (
        "tc_wow_analyzer.analyzers.multi_build_temporal", "analyze_temporal_evolution",
    ),
    "function_similarity": (
        "tc_wow_analyzer.analyzers.function_similarity", "cluster_similar_functions",
    ),
    "shared_code_detection": (
        "tc_wow_analyzer.analyzers.shared_code_detection", "detect_shared_code",
    ),
    "thread_safety_map": (
        "tc_wow_analyzer.analyzers.thread_safety_map", "map_thread_safety",
    ),
    "negative_space": (
        "tc_wow_analyzer.analyzers.negative_space", "analyze_negative_space",
    ),
    "updatefield_descriptors": (
        "tc_wow_analyzer.analyzers.updatefield_descriptor",
        "extract_updatefield_descriptors",
    ),
    "alloc_class_catalog": (
        "tc_wow_analyzer.analyzers.alloc_class_catalog", "build_class_catalog",
    ),
    "pe_metadata": ("tc_wow_analyzer.analyzers.pe_metadata", "analyze_pe_metadata"),
    "data_archaeology": (
        "tc_wow_analyzer.analyzers.data_section_archaeology", "mine_data_sections",
    ),
    "cvar_extraction": ("tc_wow_analyzer.analyzers.cvar_extraction", "extract_cvars"),
    "call_graph_analytics": (
        "tc_wow_analyzer.analyzers.call_graph_analytics", "analyze_call_graph",
    ),
    "indirect_call_resolver": (
        "tc_wow_analyzer.analyzers.indirect_call_resolver", "resolve_indirect_calls",
    ),
    "event_system": (
        "tc_wow_analyzer.analyzers.event_system_recovery", "recover_event_system",
    ),
    "symbolic_constraints": (
        "tc_wow_analyzer.analyzers.symbolic_constraints", "propagate_constraints",
    ),
    "binary_tc_alignment": (
        "tc_wow_analyzer.analyzers.binary_tc_alignment", "align_binary_to_tc",
    ),
    "return_value_semantics": (
        "tc_wow_analyzer.analyzers.return_value_semantics", "analyze_return_semantics",
    ),
    "instruction_ngrams": (
        "tc_wow_analyzer.analyzers.instruction_ngram", "analyze_instruction_ngrams",
    ),
    "execution_trace": (
        "tc_wow_analyzer.analyzers.execution_trace_sim", "simulate_execution",
    ),
    "compiler_artifacts": (
        "tc_wow_analyzer.analyzers.compiler_artifacts", "mine_compiler_artifacts",
    ),
    # Round 5 — entry points may not exist yet; execute_plan handles import errors.
    "llm_semantic_decompiler": (
        "tc_wow_analyzer.analyzers.llm_semantic_decompiler",
        "decompile_with_llm",
    ),
    "handler_scaffolding": (
        "tc_wow_analyzer.analyzers.handler_scaffolding",
        "scaffold_handlers",
    ),
    "cross_build_migration": (
        "tc_wow_analyzer.analyzers.cross_build_migration",
        "migrate_cross_build",
    ),
    "sniff_conformance_loop": (
        "tc_wow_analyzer.analyzers.sniff_conformance_loop",
        "run_sniff_conformance",
    ),
}

# Mapping from analyzer key to game systems it primarily operates on.
# Used by plan_reanalysis to scope function sets per analyzer.
ANALYZER_SYSTEMS = {
    "lua_api": {"lua_api"},
    "vtables": set(),  # operates on all functions
    "db2_metadata": {"database"},
    "opcode_dispatcher": {"networking"},
    "jam_recovery": {"networking"},
    "update_fields": {"networking"},
    "handler_jam_linking": {"networking"},
    "db2_drift": {"database"},
    "validation_extractor": {"networking"},
    "conformance": {"networking"},
    "state_machines": {"networking"},
    "dependency_mapper": set(),
    "test_generator": {"networking"},
    "packet_replay": {"networking"},
    "wire_format": {"networking"},
    "enum_recovery": {"networking"},
    "constant_mining": set(),
    "object_layout": set(),
    "response_reconstruction": {"networking"},
    "taint_analysis": {"networking"},
    "behavioral_spec": {"networking"},
    "protocol_sequencing": {"networking"},
    "build_delta": set(),
    "callee_contracts": {"networking"},
    "pseudocode_transpiler": {"networking"},
    "object_lifecycle": set(),
    "lua_contracts": {"lua_api"},
    "idb_enrichment": set(),
    "string_intelligence": set(),
    "cross_synthesis": {"networking"},
    "db2_data_content": {"database"},
    "sniff_verification": {"networking"},
    "multi_build_temporal": set(),
    "function_similarity": set(),
    "shared_code_detection": {"networking"},
    "thread_safety_map": set(),
    "negative_space": {"networking"},
    "updatefield_descriptors": {"networking"},
    "alloc_class_catalog": set(),
    "pe_metadata": set(),
    "data_archaeology": set(),
    "cvar_extraction": set(),
    "call_graph_analytics": set(),
    "indirect_call_resolver": set(),
    "event_system": set(),
    "symbolic_constraints": {"networking"},
    "binary_tc_alignment": {"networking"},
    "return_value_semantics": set(),
    "instruction_ngrams": set(),
    "execution_trace": {"networking"},
    "compiler_artifacts": set(),
    "llm_semantic_decompiler": {"networking"},
    "handler_scaffolding": {"networking"},
    "cross_build_migration": set(),
    "sniff_conformance_loop": {"networking"},
}


# ---------------------------------------------------------------------------
# KV Store Keys
# ---------------------------------------------------------------------------

KV_INCREMENTAL_STATE = "incremental_state"
KV_INCREMENTAL_CHANGELOG = "incremental_changelog"
KV_ANALYZER_RUN_TIMES = "analyzer_run_times"

# Maximum changelog entries to keep
MAX_CHANGELOG_ENTRIES = 200

# How many functions to batch-decompile at once before yielding to IDA
DECOMPILE_BATCH_SIZE = 500

# Default estimated seconds per function for time estimation
DEFAULT_SECONDS_PER_FUNCTION = 0.05

# Default estimated seconds per analyzer when no history is available
DEFAULT_ANALYZER_SECONDS = 30.0


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class ChangeSet:
    """Describes what changed since the last analysis run."""

    modified_functions: set = field(default_factory=set)
    """EAs of functions whose decompilation text changed."""

    renamed_functions: set = field(default_factory=set)
    """EAs of functions that were renamed (in IDA) since last scan."""

    new_functions: set = field(default_factory=set)
    """EAs of functions that did not exist in the previous baseline."""

    removed_functions: set = field(default_factory=set)
    """EAs of functions in the baseline that no longer exist in IDA."""

    type_changed_functions: set = field(default_factory=set)
    """EAs of functions whose type signature changed."""

    affected_systems: set = field(default_factory=set)
    """Game systems (housing, combat, ...) with changed functions."""

    timestamp: float = 0.0
    """When this changeset was computed."""

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def total_changes(self) -> int:
        """Total number of individual function changes."""
        return (
            len(self.modified_functions)
            + len(self.renamed_functions)
            + len(self.new_functions)
            + len(self.removed_functions)
            + len(self.type_changed_functions)
        )

    @property
    def all_changed_eas(self) -> set:
        """Union of all function EAs that changed in any way."""
        return (
            self.modified_functions
            | self.renamed_functions
            | self.new_functions
            | self.type_changed_functions
        )

    @property
    def is_empty(self) -> bool:
        return self.total_changes == 0

    def summary(self) -> str:
        parts = []
        if self.modified_functions:
            parts.append(f"{len(self.modified_functions)} modified")
        if self.renamed_functions:
            parts.append(f"{len(self.renamed_functions)} renamed")
        if self.new_functions:
            parts.append(f"{len(self.new_functions)} new")
        if self.removed_functions:
            parts.append(f"{len(self.removed_functions)} removed")
        if self.type_changed_functions:
            parts.append(f"{len(self.type_changed_functions)} type-changed")
        if not parts:
            return "No changes detected"
        return ", ".join(parts)

    def to_dict(self) -> dict:
        return {
            "modified": len(self.modified_functions),
            "renamed": len(self.renamed_functions),
            "new": len(self.new_functions),
            "removed": len(self.removed_functions),
            "type_changed": len(self.type_changed_functions),
            "affected_systems": sorted(self.affected_systems),
            "timestamp": self.timestamp,
        }


@dataclass
class AnalysisPlan:
    """Describes which analyzers need to re-run and on which functions."""

    analyzers_to_run: list = field(default_factory=list)
    """Analyzer keys in topologically-sorted dependency order."""

    functions_per_analyzer: dict = field(default_factory=dict)
    """Mapping from analyzer key to the set of function EAs it should process."""

    estimated_time: float = 0.0
    """Estimated wall-clock seconds based on historical run times."""

    reason: str = ""
    """Human-readable reason why this plan was generated."""

    skipped_analyzers: list = field(default_factory=list)
    """Analyzer keys that were considered but not included (e.g. already current)."""

    @property
    def is_empty(self) -> bool:
        return len(self.analyzers_to_run) == 0

    def summary(self) -> str:
        if self.is_empty:
            return "Nothing to do — all analyzers are current."
        lines = [
            f"Plan: {len(self.analyzers_to_run)} analyzer(s), "
            f"est. {self.estimated_time:.0f}s",
        ]
        for key in self.analyzers_to_run:
            display = ANALYZER_DISPLAY_NAMES.get(key, key)
            n_funcs = len(self.functions_per_analyzer.get(key, set()))
            lines.append(f"  - {display} ({n_funcs} functions)")
        if self.skipped_analyzers:
            lines.append(
                f"  Skipped (current): {', '.join(self.skipped_analyzers)}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "analyzers_to_run": self.analyzers_to_run,
            "functions_per_analyzer": {
                k: len(v) for k, v in self.functions_per_analyzer.items()
            },
            "estimated_time": self.estimated_time,
            "reason": self.reason,
            "skipped": self.skipped_analyzers,
        }


# ---------------------------------------------------------------------------
# Topological Sort Utilities
# ---------------------------------------------------------------------------

def _topological_sort(graph: dict) -> list:
    """Kahn's algorithm for topological sort.

    *graph* maps node -> list of predecessors (dependencies).
    Returns a list in dependency order (predecessors first).
    Raises ValueError if a cycle is detected.
    """
    # Build adjacency list (edge = dependency -> dependent)
    successors = defaultdict(set)
    in_degree = defaultdict(int)

    all_nodes = set(graph.keys())
    for node, deps in graph.items():
        for dep in deps:
            if dep in all_nodes:
                successors[dep].add(node)
                in_degree[node] += 1
        # Ensure nodes with no in-edges are counted
        if node not in in_degree:
            in_degree[node] = in_degree.get(node, 0)

    queue = deque(n for n in all_nodes if in_degree.get(n, 0) == 0)
    result = []

    while queue:
        node = queue.popleft()
        result.append(node)
        for succ in sorted(successors.get(node, [])):
            in_degree[succ] -= 1
            if in_degree[succ] == 0:
                queue.append(succ)

    if len(result) != len(all_nodes):
        # Cycle detected — return what we have plus remaining in arbitrary order
        remaining = all_nodes - set(result)
        msg_warn(
            f"Cycle detected in analyzer dependency graph involving: "
            f"{', '.join(sorted(remaining))}"
        )
        result.extend(sorted(remaining))

    return result


def _get_transitive_dependents(analyzer: str) -> set:
    """Return all analyzers that transitively depend on *analyzer*."""
    dependents = set()
    queue = deque([analyzer])
    visited = set()

    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        for key, deps in ANALYZER_DEPS.items():
            if current in deps and key not in dependents:
                dependents.add(key)
                queue.append(key)

    return dependents


def _get_transitive_dependencies(analyzer: str) -> set:
    """Return all analyzers that *analyzer* transitively depends on."""
    deps = set()
    queue = deque([analyzer])
    visited = set()

    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        for dep in ANALYZER_DEPS.get(current, []):
            if dep not in deps:
                deps.add(dep)
                queue.append(dep)

    return deps


def _subset_topological_sort(analyzers: set) -> list:
    """Topological sort of a *subset* of the full DAG."""
    subgraph = {}
    for key in analyzers:
        subgraph[key] = [
            dep for dep in ANALYZER_DEPS.get(key, []) if dep in analyzers
        ]
    return _topological_sort(subgraph)


# ---------------------------------------------------------------------------
# Hashing Helpers
# ---------------------------------------------------------------------------

def _hash_text(text: str) -> str:
    """SHA-256 of text, truncated to 16 hex chars for compactness."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _compute_function_hash(ea: int) -> Optional[str]:
    """Compute a deterministic hash of a function's decompiled text.

    Returns None if decompilation fails (thunk, leaf, data, etc.).
    """
    text = get_decompiled_text(ea)
    if text is None:
        return None
    return _hash_text(text)


def _get_function_name(ea: int) -> Optional[str]:
    """Get the current IDA name for a function EA."""
    name = ida_name.get_name(ea)
    return name if name else None


def _get_function_type_str(ea: int) -> Optional[str]:
    """Get the type string (prototype) for a function, if set."""
    tinfo = idaapi.tinfo_t()
    if idaapi.get_tinfo(tinfo, ea):
        return str(tinfo)
    return None


# ---------------------------------------------------------------------------
# State Persistence
# ---------------------------------------------------------------------------

class _StateStore:
    """Wrapper around kv_store for incremental engine state.

    Stored schema:
        incremental_state = {
            "baseline_timestamp": float,
            "function_hashes": { "<ea_hex>": "<hash>" },
            "function_names":  { "<ea_hex>": "<name>" },
            "function_types":  { "<ea_hex>": "<type_str>" },
            "analyzer_last_run": { "<key>": float_timestamp },
            "total_functions": int,
        }
    """

    def __init__(self, db):
        self._db = db

    def load(self) -> dict:
        """Load the incremental state from kv_store."""
        state = self._db.kv_get(KV_INCREMENTAL_STATE)
        if state is None:
            return self._empty_state()
        if isinstance(state, str):
            try:
                state = json.loads(state)
            except json.JSONDecodeError:
                msg_warn("Corrupted incremental state — resetting")
                return self._empty_state()
        return state

    def save(self, state: dict):
        """Persist the incremental state to kv_store."""
        self._db.kv_set(KV_INCREMENTAL_STATE, state)
        self._db.commit()

    def load_changelog(self) -> list:
        """Load the incremental changelog."""
        data = self._db.kv_get(KV_INCREMENTAL_CHANGELOG)
        if data is None:
            return []
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                return []
        return data if isinstance(data, list) else []

    def save_changelog(self, entries: list):
        """Persist changelog, truncating to MAX_CHANGELOG_ENTRIES."""
        self._db.kv_set(
            KV_INCREMENTAL_CHANGELOG,
            entries[-MAX_CHANGELOG_ENTRIES:],
        )
        self._db.commit()

    def load_run_times(self) -> dict:
        """Load per-analyzer run time history."""
        data = self._db.kv_get(KV_ANALYZER_RUN_TIMES)
        if data is None:
            return {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                return {}
        return data if isinstance(data, dict) else {}

    def save_run_times(self, run_times: dict):
        """Persist per-analyzer run time data."""
        self._db.kv_set(KV_ANALYZER_RUN_TIMES, run_times)
        self._db.commit()

    @staticmethod
    def _empty_state() -> dict:
        return {
            "baseline_timestamp": 0.0,
            "function_hashes": {},
            "function_names": {},
            "function_types": {},
            "analyzer_last_run": {},
            "total_functions": 0,
        }


# ---------------------------------------------------------------------------
# IncrementalEngine
# ---------------------------------------------------------------------------

class IncrementalEngine:
    """Orchestrates incremental analysis: change detection, planning, execution.

    Usage:
        engine = IncrementalEngine(session)

        # Detect what changed
        changes = engine.detect_changes()

        # Build a re-analysis plan
        plan = engine.plan_reanalysis(changes)
        msg(plan.summary())

        # Execute
        results = engine.execute_plan(plan)
    """

    def __init__(self, session):
        """Initialize with a PluginSession that has an open database.

        Args:
            session: A PluginSession instance with session.db available.
        """
        self.session = session
        self._store = _StateStore(session.db)
        self._change_log = []

    # ------------------------------------------------------------------
    # Change Detection
    # ------------------------------------------------------------------

    def detect_changes(
        self,
        function_eas: Optional[set] = None,
        skip_decompile: bool = False,
        progress_callback: Optional[Callable] = None,
    ) -> ChangeSet:
        """Scan functions for changes since the last analysis run.

        Args:
            function_eas: If provided, only scan these specific EAs.
                          If None, scan all functions in the IDB.
            skip_decompile: If True, only check name/type changes (much faster).
            progress_callback: Optional callable(current, total, message) for UI.

        Returns:
            A ChangeSet describing all detected changes.
        """
        state = self._store.load()
        old_hashes = state.get("function_hashes", {})
        old_names = state.get("function_names", {})
        old_types = state.get("function_types", {})
        old_eas = set(int(ea, 16) for ea in old_hashes.keys())

        changeset = ChangeSet(timestamp=time.time())

        # Enumerate current functions
        if function_eas is not None:
            current_eas = set(function_eas)
        else:
            current_eas = set()
            for seg_ea in idautils.Segments():
                func = ida_funcs.get_next_func(seg_ea - 1)
                while func is not None:
                    if func.start_ea >= idaapi.get_segm_by_sel(
                        idaapi.getseg(seg_ea).sel
                    ).end_ea if idaapi.getseg(seg_ea) else True:
                        break
                    current_eas.add(func.start_ea)
                    func = ida_funcs.get_next_func(func.start_ea)

            # Simpler fallback — iterate all functions in the IDB
            if not current_eas:
                current_eas = self._enumerate_all_functions()

        total = len(current_eas)

        # New and removed functions
        if old_eas:
            changeset.new_functions = current_eas - old_eas
            changeset.removed_functions = old_eas - current_eas
        else:
            # First run — everything is "new"
            changeset.new_functions = current_eas.copy()

        # Scan each function for name/type/hash changes
        scan_count = 0
        eas_to_scan = current_eas - changeset.new_functions  # Only check existing
        for ea in sorted(eas_to_scan):
            scan_count += 1
            if progress_callback and scan_count % 1000 == 0:
                progress_callback(
                    scan_count, total,
                    f"Scanning function {ea_str(ea)} ({scan_count}/{total})",
                )

            ea_key = f"{ea:X}"

            # Name change?
            current_name = _get_function_name(ea)
            old_name = old_names.get(ea_key)
            if current_name != old_name and old_name is not None:
                changeset.renamed_functions.add(ea)

            # Type change?
            current_type = _get_function_type_str(ea)
            old_type = old_types.get(ea_key)
            if current_type != old_type and old_type is not None:
                changeset.type_changed_functions.add(ea)

            # Decompilation hash change?
            if not skip_decompile:
                current_hash = _compute_function_hash(ea)
                old_hash = old_hashes.get(ea_key)
                if current_hash is not None and current_hash != old_hash:
                    changeset.modified_functions.add(ea)

        # Also compute hashes for new functions if not skipping decompile
        if not skip_decompile:
            new_count = 0
            for ea in sorted(changeset.new_functions):
                new_count += 1
                if progress_callback and new_count % 1000 == 0:
                    progress_callback(
                        scan_count + new_count, total,
                        f"Hashing new function {ea_str(ea)} "
                        f"({scan_count + new_count}/{total})",
                    )

        # Determine affected systems
        changeset.affected_systems = self._determine_affected_systems(
            changeset.all_changed_eas
        )

        if progress_callback:
            progress_callback(total, total, "Change detection complete")

        msg_info(f"Change detection: {changeset.summary()}")
        if changeset.affected_systems:
            msg_info(
                f"  Affected systems: {', '.join(sorted(changeset.affected_systems))}"
            )

        return changeset

    def full_scan(
        self,
        progress_callback: Optional[Callable] = None,
    ) -> ChangeSet:
        """Scan ALL functions and establish (or update) the baseline.

        This is the initial scan that populates function_hashes, function_names,
        and function_types in the incremental state.  Subsequent calls to
        detect_changes() will diff against this baseline.

        Returns:
            A ChangeSet relative to the previous baseline (or everything-is-new
            if no baseline existed).
        """
        msg_info("Starting full function scan...")
        start = time.time()

        all_eas = self._enumerate_all_functions()
        total = len(all_eas)
        msg_info(f"  Enumerating {total} functions in IDB")

        state = self._store.load()
        old_hashes = state.get("function_hashes", {})
        old_names = state.get("function_names", {})
        old_types = state.get("function_types", {})
        old_eas = set(int(ea_hex, 16) for ea_hex in old_hashes.keys())

        changeset = ChangeSet(timestamp=time.time())
        new_hashes = {}
        new_names = {}
        new_types = {}

        decompile_failures = 0
        scan_count = 0

        for ea in sorted(all_eas):
            scan_count += 1
            if progress_callback and scan_count % 500 == 0:
                progress_callback(
                    scan_count, total,
                    f"Full scan: {scan_count}/{total} "
                    f"({scan_count * 100 // total}%)",
                )

            ea_key = f"{ea:X}"

            # Compute current state
            current_name = _get_function_name(ea)
            current_type = _get_function_type_str(ea)
            current_hash = _compute_function_hash(ea)

            if current_hash is None:
                decompile_failures += 1
            else:
                new_hashes[ea_key] = current_hash

            if current_name is not None:
                new_names[ea_key] = current_name
            if current_type is not None:
                new_types[ea_key] = current_type

            # Diff against old state
            if ea not in old_eas:
                changeset.new_functions.add(ea)
            else:
                old_hash = old_hashes.get(ea_key)
                if current_hash is not None and current_hash != old_hash:
                    changeset.modified_functions.add(ea)

                old_name = old_names.get(ea_key)
                if current_name != old_name and old_name is not None:
                    changeset.renamed_functions.add(ea)

                old_type = old_types.get(ea_key)
                if current_type != old_type and old_type is not None:
                    changeset.type_changed_functions.add(ea)

        # Removed functions
        changeset.removed_functions = old_eas - all_eas

        # Affected systems
        changeset.affected_systems = self._determine_affected_systems(
            changeset.all_changed_eas
        )

        # Persist new baseline
        state["function_hashes"] = new_hashes
        state["function_names"] = new_names
        state["function_types"] = new_types
        state["baseline_timestamp"] = time.time()
        state["total_functions"] = total
        self._store.save(state)

        elapsed = time.time() - start
        msg_info(
            f"Full scan complete in {elapsed:.1f}s: "
            f"{total} functions ({decompile_failures} decompile failures)"
        )
        msg_info(f"  Changes: {changeset.summary()}")

        if progress_callback:
            progress_callback(total, total, "Full scan complete")

        return changeset

    # ------------------------------------------------------------------
    # Plan Generation
    # ------------------------------------------------------------------

    def plan_reanalysis(
        self,
        changes: ChangeSet,
        force_analyzers: Optional[set] = None,
        include_stale: bool = True,
    ) -> AnalysisPlan:
        """Determine which analyzers need to re-run given a ChangeSet.

        Args:
            changes: The detected changes from detect_changes() or full_scan().
            force_analyzers: If provided, always include these analyzer keys
                             regardless of whether their inputs changed.
            include_stale: If True, also include analyzers that have never run.

        Returns:
            An AnalysisPlan with analyzers in dependency order.
        """
        state = self._store.load()
        analyzer_last_run = state.get("analyzer_last_run", {})
        run_times = self._store.load_run_times()

        affected = set()
        skipped = []

        # Step 1: Determine directly affected analyzers from changes
        if not changes.is_empty:
            affected.update(
                self._find_affected_analyzers(changes, analyzer_last_run)
            )

        # Step 2: Force-include requested analyzers
        if force_analyzers:
            for key in force_analyzers:
                if key in ANALYZER_DEPS:
                    affected.add(key)

        # Step 3: Include stale (never-run) analyzers
        if include_stale:
            for key in ANALYZER_DEPS:
                if key not in analyzer_last_run:
                    affected.add(key)

        # Step 4: Propagate to dependents — if an analyzer is affected,
        # everything that depends on it is also affected.
        propagated = set()
        for key in list(affected):
            dependents = _get_transitive_dependents(key)
            propagated.update(dependents)
        affected.update(propagated)

        # Step 5: Also include prerequisites of affected analyzers
        # that have never been run (required for correct execution).
        prerequisites = set()
        for key in list(affected):
            for dep in _get_transitive_dependencies(key):
                if dep not in analyzer_last_run:
                    prerequisites.add(dep)
        affected.update(prerequisites)

        # Determine which known analyzers are NOT affected
        for key in ANALYZER_DEPS:
            if key not in affected:
                skipped.append(key)

        # Step 6: Topological sort the affected set
        ordered = _subset_topological_sort(affected)

        # Step 7: Compute per-analyzer function sets
        functions_per_analyzer = self._scope_functions_per_analyzer(
            ordered, changes
        )

        # Step 8: Estimate run time
        estimated_time = self._estimate_run_time(ordered, run_times)

        # Build reason string
        if changes.is_empty and not force_analyzers and not include_stale:
            reason = "No changes detected and no forced analyzers."
        else:
            parts = []
            if not changes.is_empty:
                parts.append(f"detected {changes.total_changes} function changes")
            if force_analyzers:
                parts.append(
                    f"forced: {', '.join(sorted(force_analyzers))}"
                )
            never_run = [
                k for k in ordered if k not in analyzer_last_run
            ]
            if never_run:
                parts.append(f"{len(never_run)} never-run analyzers")
            if propagated:
                parts.append(
                    f"{len(propagated)} transitively affected"
                )
            reason = "; ".join(parts) if parts else "Incremental reanalysis"

        plan = AnalysisPlan(
            analyzers_to_run=ordered,
            functions_per_analyzer=functions_per_analyzer,
            estimated_time=estimated_time,
            reason=reason,
            skipped_analyzers=sorted(skipped),
        )

        msg_info(f"Analysis plan: {len(ordered)} analyzers, "
                 f"est. {estimated_time:.0f}s")
        return plan

    # ------------------------------------------------------------------
    # Plan Execution
    # ------------------------------------------------------------------

    def execute_plan(
        self,
        plan: AnalysisPlan,
        progress_callback: Optional[Callable] = None,
        stop_on_error: bool = False,
    ) -> dict:
        """Execute an incremental analysis plan.

        Runs each analyzer in the plan's dependency order, records timing,
        updates the baseline, and appends to the changelog.

        Args:
            plan: The plan from plan_reanalysis().
            progress_callback: Optional callable(current, total, message).
            stop_on_error: If True, abort on the first analyzer failure.

        Returns:
            A dict mapping analyzer key -> {"status", "count", "duration", "error"}.
        """
        if plan.is_empty:
            msg_info("Nothing to execute — plan is empty.")
            return {}

        results = {}
        state = self._store.load()
        run_times = self._store.load_run_times()
        total_analyzers = len(plan.analyzers_to_run)
        overall_start = time.time()

        msg_info(f"Executing incremental plan: {total_analyzers} analyzers")
        msg_info(f"  Reason: {plan.reason}")

        for idx, key in enumerate(plan.analyzers_to_run):
            display = ANALYZER_DISPLAY_NAMES.get(key, key)

            if progress_callback:
                progress_callback(
                    idx, total_analyzers,
                    f"Running {display} ({idx + 1}/{total_analyzers})",
                )

            msg_info(f"=== [{idx + 1}/{total_analyzers}] {display} ===")

            entry_point = ANALYZER_ENTRY_POINTS.get(key)
            if entry_point is None:
                msg_warn(f"  No entry point registered for '{key}' — skipping")
                results[key] = {
                    "status": "skipped",
                    "count": 0,
                    "duration": 0.0,
                    "error": "No entry point",
                }
                continue

            module_path, func_name = entry_point
            analyzer_start = time.time()

            try:
                # Dynamic import
                mod = self._import_analyzer_module(module_path)
                if mod is None:
                    raise ImportError(
                        f"Could not import {module_path}"
                    )

                func = getattr(mod, func_name, None)
                if func is None:
                    raise AttributeError(
                        f"{module_path}.{func_name} not found"
                    )

                # Special case: build_delta takes an extra arg
                if key == "build_delta":
                    count = func(self.session, None)
                else:
                    count = func(self.session)

                if count is None:
                    count = 0

                duration = time.time() - analyzer_start
                results[key] = {
                    "status": "success",
                    "count": count,
                    "duration": duration,
                    "error": None,
                }

                # Update last-run timestamp
                state.setdefault("analyzer_last_run", {})[key] = time.time()

                # Update run time history
                run_times[key] = {
                    "last_run": time.time(),
                    "duration": duration,
                    "items": count,
                }

                msg_info(f"  -> {display}: {count} items in {duration:.1f}s")

            except Exception as e:
                duration = time.time() - analyzer_start
                error_msg = str(e)
                results[key] = {
                    "status": "error",
                    "count": 0,
                    "duration": duration,
                    "error": error_msg,
                }
                msg_error(f"  -> {display} FAILED ({duration:.1f}s): {error_msg}")

                if stop_on_error:
                    msg_error("  Stopping execution due to stop_on_error=True")
                    break

        # Persist state updates
        self._store.save(state)
        self._store.save_run_times(run_times)

        # Append changelog entry
        overall_duration = time.time() - overall_start
        self._append_changelog_entry(plan, results, overall_duration)

        # Summary
        succeeded = sum(1 for r in results.values() if r["status"] == "success")
        failed = sum(1 for r in results.values() if r["status"] == "error")
        total_items = sum(r["count"] for r in results.values())
        msg_info(
            f"Incremental run complete in {overall_duration:.1f}s: "
            f"{succeeded} succeeded, {failed} failed, {total_items} total items"
        )

        if progress_callback:
            progress_callback(
                total_analyzers, total_analyzers,
                f"Complete: {succeeded}/{total_analyzers} analyzers",
            )

        return results

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_last_run_info(self) -> dict:
        """Get info about the last analysis run.

        Returns:
            A dict with keys: baseline_timestamp, total_functions,
            analyzer_count, last_changelog_entry, etc.
        """
        state = self._store.load()
        changelog = self._store.load_changelog()

        analyzer_last_run = state.get("analyzer_last_run", {})
        last_entry = changelog[-1] if changelog else None

        return {
            "baseline_timestamp": state.get("baseline_timestamp", 0.0),
            "baseline_age_hours": (
                (time.time() - state["baseline_timestamp"]) / 3600.0
                if state.get("baseline_timestamp") else None
            ),
            "total_functions": state.get("total_functions", 0),
            "analyzers_ever_run": len(analyzer_last_run),
            "analyzers_total": len(ANALYZER_DEPS),
            "analyzers_never_run": len(ANALYZER_DEPS) - len(analyzer_last_run),
            "last_changelog_entry": last_entry,
            "changelog_entries": len(changelog),
        }

    def get_stale_analyzers(self) -> list:
        """Get analyzers that have never been run or whose inputs changed.

        Returns:
            A list of analyzer keys that are stale, sorted by dependency order.
        """
        state = self._store.load()
        analyzer_last_run = state.get("analyzer_last_run", {})

        stale = set()
        for key in ANALYZER_DEPS:
            if key not in analyzer_last_run:
                stale.add(key)
                continue

            # Check if any prerequisite has run MORE RECENTLY than this analyzer
            my_last_run = analyzer_last_run[key]
            for dep in ANALYZER_DEPS.get(key, []):
                dep_last_run = analyzer_last_run.get(dep, 0.0)
                if dep_last_run > my_last_run:
                    stale.add(key)
                    break

        return _subset_topological_sort(stale)

    def get_analyzer_status(self) -> dict:
        """Get the status of every registered analyzer.

        Returns:
            A dict mapping analyzer key -> {
                "status": "never_run" | "stale" | "current",
                "last_run": float or None,
                "last_duration": float or None,
                "last_items": int or None,
                "display_name": str,
                "deps": list[str],
                "dependents": list[str],
            }
        """
        state = self._store.load()
        analyzer_last_run = state.get("analyzer_last_run", {})
        run_times = self._store.load_run_times()

        stale_set = set(self.get_stale_analyzers())
        result = {}

        for key in sorted(ANALYZER_DEPS.keys()):
            if key not in analyzer_last_run:
                status = "never_run"
            elif key in stale_set:
                status = "stale"
            else:
                status = "current"

            rt = run_times.get(key, {})
            dependents_list = sorted(
                k for k, deps in ANALYZER_DEPS.items() if key in deps
            )

            result[key] = {
                "status": status,
                "last_run": analyzer_last_run.get(key),
                "last_duration": rt.get("duration"),
                "last_items": rt.get("items"),
                "display_name": ANALYZER_DISPLAY_NAMES.get(key, key),
                "deps": ANALYZER_DEPS.get(key, []),
                "dependents": dependents_list,
            }

        return result

    def invalidate_analyzer(self, key: str, cascade: bool = True):
        """Mark an analyzer (and optionally its dependents) as stale.

        This removes the analyzer's last-run timestamp so it will be
        included in the next plan_reanalysis() call.

        Args:
            key: Analyzer key to invalidate.
            cascade: If True, also invalidate all transitive dependents.
        """
        state = self._store.load()
        analyzer_last_run = state.get("analyzer_last_run", {})

        to_invalidate = {key}
        if cascade:
            to_invalidate.update(_get_transitive_dependents(key))

        invalidated = []
        for k in to_invalidate:
            if k in analyzer_last_run:
                del analyzer_last_run[k]
                invalidated.append(k)

        state["analyzer_last_run"] = analyzer_last_run
        self._store.save(state)

        if invalidated:
            msg_info(
                f"Invalidated {len(invalidated)} analyzer(s): "
                f"{', '.join(sorted(invalidated))}"
            )
        else:
            msg_info(f"Analyzer '{key}' was not in the run history.")

    def invalidate_all(self):
        """Reset all analyzer last-run timestamps, forcing a full re-run."""
        state = self._store.load()
        state["analyzer_last_run"] = {}
        self._store.save(state)
        msg_info("All analyzer timestamps reset — next plan will include all.")

    def update_baseline_for_functions(self, eas: set):
        """Update the stored hashes/names/types for specific functions.

        Call this after manually editing functions so the next detect_changes()
        won't report them as modified.
        """
        state = self._store.load()
        hashes = state.get("function_hashes", {})
        names = state.get("function_names", {})
        types = state.get("function_types", {})

        updated = 0
        for ea in eas:
            ea_key = f"{ea:X}"
            h = _compute_function_hash(ea)
            if h is not None:
                hashes[ea_key] = h
                updated += 1
            n = _get_function_name(ea)
            if n is not None:
                names[ea_key] = n
            t = _get_function_type_str(ea)
            if t is not None:
                types[ea_key] = t

        state["function_hashes"] = hashes
        state["function_names"] = names
        state["function_types"] = types
        self._store.save(state)
        msg_info(f"Baseline updated for {updated} function(s)")

    def reset_baseline(self):
        """Completely clear the incremental baseline.

        The next detect_changes() will treat every function as new.
        """
        self._store.save(self._store._empty_state())
        msg_info("Incremental baseline reset.")

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _enumerate_all_functions(self) -> set:
        """Enumerate all function start EAs in the IDB."""
        eas = set()
        for ea in idautils.Functions():
            eas.add(ea)
        return eas

    def _determine_affected_systems(self, changed_eas: set) -> set:
        """Look up which game systems the changed functions belong to."""
        if not changed_eas or not self.session.db:
            return set()

        systems = set()
        db = self.session.db

        # Batch query — SQLite IN clause with bound params
        # Process in chunks to avoid SQLite variable limits
        chunk_size = 500
        ea_list = sorted(changed_eas)
        for i in range(0, len(ea_list), chunk_size):
            chunk = ea_list[i : i + chunk_size]
            placeholders = ", ".join("?" * len(chunk))
            rows = db.fetchall(
                f"SELECT DISTINCT system FROM functions "
                f"WHERE ea IN ({placeholders}) AND system IS NOT NULL",
                chunk,
            )
            for row in rows:
                systems.add(row["system"])

        return systems

    def _find_affected_analyzers(
        self, changes: ChangeSet, analyzer_last_run: dict
    ) -> set:
        """Determine which analyzers are directly affected by the changes.

        This maps changed functions to game systems, then checks which
        analyzers operate on those systems.  Analyzers with empty system
        sets (operate on all functions) are affected if ANY function changed.
        """
        affected = set()

        # If there are any changes at all, every "global" analyzer is affected
        has_changes = not changes.is_empty

        for key in ANALYZER_DEPS:
            analyzer_systems = ANALYZER_SYSTEMS.get(key, set())

            if not analyzer_systems:
                # Global analyzer — affected by any change
                if has_changes:
                    affected.add(key)
            else:
                # System-specific analyzer — affected if its systems overlap
                if changes.affected_systems & analyzer_systems:
                    affected.add(key)

        # Renames and type changes affect enrichment-related analyzers
        if changes.renamed_functions or changes.type_changed_functions:
            rename_sensitive = {
                "idb_enrichment", "string_intelligence", "function_similarity",
                "call_graph_analytics", "binary_tc_alignment",
            }
            affected.update(
                k for k in rename_sensitive if k in ANALYZER_DEPS
            )

        return affected

    def _scope_functions_per_analyzer(
        self, ordered_analyzers: list, changes: ChangeSet
    ) -> dict:
        """Build per-analyzer function sets.

        Analyzers with a specific system scope only get functions from those
        systems.  Global analyzers get all changed functions.
        """
        all_changed = changes.all_changed_eas
        result = {}

        for key in ordered_analyzers:
            analyzer_systems = ANALYZER_SYSTEMS.get(key, set())

            if not analyzer_systems:
                # Global — gets everything
                result[key] = all_changed.copy()
            else:
                # Filter to functions in the analyzer's target systems
                scoped = set()
                if self.session.db:
                    chunk_size = 500
                    ea_list = sorted(all_changed)
                    system_placeholders = ", ".join(
                        "?" * len(analyzer_systems)
                    )
                    system_params = sorted(analyzer_systems)

                    for i in range(0, len(ea_list), chunk_size):
                        chunk = ea_list[i : i + chunk_size]
                        ea_placeholders = ", ".join("?" * len(chunk))
                        rows = self.session.db.fetchall(
                            f"SELECT ea FROM functions "
                            f"WHERE ea IN ({ea_placeholders}) "
                            f"AND system IN ({system_placeholders})",
                            chunk + system_params,
                        )
                        for row in rows:
                            scoped.add(row["ea"])

                # If we could not scope (no DB data), fall back to all changed
                if not scoped and all_changed:
                    scoped = all_changed.copy()

                result[key] = scoped

        return result

    def _estimate_run_time(
        self, ordered_analyzers: list, run_times: dict
    ) -> float:
        """Estimate total run time based on historical data."""
        total = 0.0
        for key in ordered_analyzers:
            rt = run_times.get(key)
            if rt and "duration" in rt:
                total += rt["duration"]
            else:
                total += DEFAULT_ANALYZER_SECONDS
        return total

    def _append_changelog_entry(
        self, plan: AnalysisPlan, results: dict, duration: float
    ):
        """Append a new entry to the incremental changelog."""
        changelog = self._store.load_changelog()

        entry = {
            "timestamp": time.time(),
            "reason": plan.reason,
            "analyzers_run": plan.analyzers_to_run,
            "results_summary": {
                k: {
                    "status": v["status"],
                    "count": v["count"],
                    "duration": round(v["duration"], 2),
                }
                for k, v in results.items()
            },
            "succeeded": sum(
                1 for v in results.values() if v["status"] == "success"
            ),
            "failed": sum(
                1 for v in results.values() if v["status"] == "error"
            ),
            "total_items": sum(v["count"] for v in results.values()),
            "duration": round(duration, 2),
        }

        changelog.append(entry)
        self._store.save_changelog(changelog)

    @staticmethod
    def _import_analyzer_module(module_path: str):
        """Dynamically import an analyzer module.

        Returns the module object, or None if import fails.
        """
        import importlib
        try:
            return importlib.import_module(module_path)
        except ImportError as e:
            msg_warn(f"Could not import {module_path}: {e}")
            return None
        except Exception as e:
            msg_error(f"Error importing {module_path}: {e}")
            return None


# ---------------------------------------------------------------------------
# Module-Level Convenience Functions
# ---------------------------------------------------------------------------

def get_analyzer_status(session) -> dict:
    """Get the status of every registered analyzer.

    Convenience wrapper around IncrementalEngine.get_analyzer_status().

    Args:
        session: A PluginSession with an open database.

    Returns:
        A dict mapping analyzer key -> status info dict.
        Each status dict contains:
            - "status": "never_run" | "stale" | "current"
            - "last_run": timestamp float or None
            - "last_duration": seconds float or None
            - "last_items": int or None
            - "display_name": human-readable name
            - "deps": list of prerequisite analyzer keys
            - "dependents": list of dependent analyzer keys
    """
    engine = IncrementalEngine(session)
    return engine.get_analyzer_status()


def get_dependency_graph() -> dict:
    """Return the full analyzer dependency DAG for visualization.

    Returns:
        A dict mapping analyzer key -> {
            "deps": [prerequisite keys],
            "dependents": [dependent keys],
            "display_name": str,
            "systems": [game system names],
            "depth": int (longest path from root),
        }
    """
    # Compute topological depth for each analyzer
    depths = {}

    def _compute_depth(key: str, visiting: set = None) -> int:
        if key in depths:
            return depths[key]
        if visiting is None:
            visiting = set()
        if key in visiting:
            # Cycle — assign depth 0 to break it
            return 0
        visiting.add(key)

        deps = ANALYZER_DEPS.get(key, [])
        if not deps:
            depth = 0
        else:
            depth = 1 + max(
                _compute_depth(d, visiting) for d in deps
                if d in ANALYZER_DEPS
            ) if any(d in ANALYZER_DEPS for d in deps) else 0

        visiting.discard(key)
        depths[key] = depth
        return depth

    for key in ANALYZER_DEPS:
        _compute_depth(key)

    graph = {}
    for key in sorted(ANALYZER_DEPS.keys()):
        dependents = sorted(
            k for k, deps in ANALYZER_DEPS.items() if key in deps
        )
        graph[key] = {
            "deps": ANALYZER_DEPS.get(key, []),
            "dependents": dependents,
            "display_name": ANALYZER_DISPLAY_NAMES.get(key, key),
            "systems": sorted(ANALYZER_SYSTEMS.get(key, set())),
            "depth": depths.get(key, 0),
        }

    return graph


def estimate_full_run_time(session) -> float:
    """Estimate the wall-clock time for running all analyzers from scratch.

    Uses historical run times from previous executions when available,
    and falls back to DEFAULT_ANALYZER_SECONDS for unknown analyzers.

    Args:
        session: A PluginSession with an open database.

    Returns:
        Estimated total seconds.
    """
    engine = IncrementalEngine(session)
    run_times = engine._store.load_run_times()

    total = 0.0
    known = 0
    unknown = 0

    for key in ANALYZER_DEPS:
        rt = run_times.get(key)
        if rt and "duration" in rt:
            total += rt["duration"]
            known += 1
        else:
            total += DEFAULT_ANALYZER_SECONDS
            unknown += 1

    if known > 0:
        msg_info(
            f"Estimated full run time: {total:.0f}s "
            f"({known} from history, {unknown} estimated)"
        )
    else:
        msg_info(
            f"Estimated full run time: {total:.0f}s "
            f"(all estimated, no historical data)"
        )

    return total


def get_incremental_changelog(session) -> list:
    """Return the incremental analysis changelog.

    Args:
        session: A PluginSession with an open database.

    Returns:
        A list of changelog entry dicts, newest last. Each entry:
            - timestamp: float
            - reason: str
            - analyzers_run: list of keys
            - results_summary: dict of per-analyzer results
            - succeeded: int
            - failed: int
            - total_items: int
            - duration: float
    """
    engine = IncrementalEngine(session)
    return engine._store.load_changelog()


def run_incremental(
    session,
    force_analyzers: Optional[set] = None,
    skip_decompile: bool = False,
    progress_callback: Optional[Callable] = None,
    stop_on_error: bool = False,
) -> dict:
    """One-call convenience function for incremental analysis.

    Detects changes, builds a plan, and executes it. This is the recommended
    entry point for most callers.

    Args:
        session: A PluginSession with an open database.
        force_analyzers: Optional set of analyzer keys to always include.
        skip_decompile: If True, skip decompilation hash checks (faster).
        progress_callback: Optional callable(current, total, message).
        stop_on_error: If True, stop on first analyzer failure.

    Returns:
        Results dict from execute_plan(), or empty dict if nothing to do.
    """
    engine = IncrementalEngine(session)

    # Step 1: Detect changes
    msg_info("Step 1/3: Detecting changes...")
    changes = engine.detect_changes(
        skip_decompile=skip_decompile,
        progress_callback=progress_callback,
    )

    # Step 2: Plan reanalysis
    msg_info("Step 2/3: Planning reanalysis...")
    plan = engine.plan_reanalysis(
        changes,
        force_analyzers=force_analyzers,
        include_stale=True,
    )

    if plan.is_empty:
        msg_info("All analyzers are current — nothing to do.")
        return {}

    msg_info(plan.summary())

    # Step 3: Execute
    msg_info("Step 3/3: Executing plan...")
    results = engine.execute_plan(
        plan,
        progress_callback=progress_callback,
        stop_on_error=stop_on_error,
    )

    return results


def run_single_analyzer(
    session,
    analyzer_key: str,
    include_deps: bool = True,
    progress_callback: Optional[Callable] = None,
) -> dict:
    """Run a single analyzer, optionally including its unmet dependencies.

    Args:
        session: A PluginSession with an open database.
        analyzer_key: The key of the analyzer to run (e.g. "wire_format").
        include_deps: If True, also run any never-run prerequisites.
        progress_callback: Optional callable(current, total, message).

    Returns:
        Results dict from execute_plan().
    """
    if analyzer_key not in ANALYZER_DEPS:
        msg_error(f"Unknown analyzer: '{analyzer_key}'")
        msg_info(f"Available: {', '.join(sorted(ANALYZER_DEPS.keys()))}")
        return {}

    engine = IncrementalEngine(session)

    to_run = {analyzer_key}

    if include_deps:
        state = engine._store.load()
        analyzer_last_run = state.get("analyzer_last_run", {})

        # Add unmet dependencies
        all_deps = _get_transitive_dependencies(analyzer_key)
        for dep in all_deps:
            if dep not in analyzer_last_run:
                to_run.add(dep)

    ordered = _subset_topological_sort(to_run)

    # Build a minimal plan
    plan = AnalysisPlan(
        analyzers_to_run=ordered,
        functions_per_analyzer={k: set() for k in ordered},
        estimated_time=engine._estimate_run_time(
            ordered, engine._store.load_run_times()
        ),
        reason=f"Manual run of {analyzer_key}"
        + (f" (+ {len(ordered) - 1} deps)" if len(ordered) > 1 else ""),
    )

    msg_info(plan.summary())
    return engine.execute_plan(plan, progress_callback=progress_callback)


def print_dependency_tree(analyzer_key: Optional[str] = None):
    """Print the dependency tree to the IDA output window.

    If analyzer_key is given, print only its subtree.
    Otherwise print the full DAG layered by depth.
    """
    graph = get_dependency_graph()

    if analyzer_key:
        if analyzer_key not in graph:
            msg_error(f"Unknown analyzer: '{analyzer_key}'")
            return

        msg(f"Dependency tree for: {analyzer_key}")
        _print_subtree(analyzer_key, graph, prefix="", visited=set())
    else:
        # Print by depth layers
        max_depth = max(v["depth"] for v in graph.values()) if graph else 0
        for depth in range(max_depth + 1):
            layer = sorted(
                k for k, v in graph.items() if v["depth"] == depth
            )
            msg(f"--- Depth {depth} ({len(layer)} analyzers) ---")
            for key in layer:
                info = graph[key]
                deps_str = (
                    f" <- [{', '.join(info['deps'])}]"
                    if info["deps"] else ""
                )
                msg(f"  {key}{deps_str}")


def _print_subtree(
    key: str, graph: dict, prefix: str, visited: set
):
    """Recursively print a dependency subtree."""
    if key in visited:
        msg(f"{prefix}{key} (circular ref)")
        return

    visited.add(key)
    info = graph.get(key, {})
    display = info.get("display_name", key)
    msg(f"{prefix}{key} ({display})")

    deps = info.get("deps", [])
    for i, dep in enumerate(deps):
        is_last = i == len(deps) - 1
        connector = "`-- " if is_last else "|-- "
        child_prefix = prefix + ("    " if is_last else "|   ")
        _print_subtree(dep, graph, prefix + connector, visited.copy())


def get_quick_status_summary(session) -> str:
    """Return a one-line summary suitable for status bars.

    Example: "Incremental: 45/55 current, 3 stale, 7 never-run"
    """
    engine = IncrementalEngine(session)
    status = engine.get_analyzer_status()

    current = sum(1 for v in status.values() if v["status"] == "current")
    stale = sum(1 for v in status.values() if v["status"] == "stale")
    never_run = sum(1 for v in status.values() if v["status"] == "never_run")
    total = len(status)

    parts = [f"{current}/{total} current"]
    if stale:
        parts.append(f"{stale} stale")
    if never_run:
        parts.append(f"{never_run} never-run")

    return "Incremental: " + ", ".join(parts)


def validate_dependency_graph() -> list:
    """Validate the ANALYZER_DEPS graph for consistency errors.

    Checks for:
        - References to unknown analyzer keys
        - Missing display names
        - Missing entry points
        - Missing system definitions
        - Cycles (reported as warnings, not errors, since we handle them)

    Returns:
        A list of warning/error strings. Empty list means all is well.
    """
    issues = []

    all_keys = set(ANALYZER_DEPS.keys())

    # Check for unknown dependencies
    for key, deps in ANALYZER_DEPS.items():
        for dep in deps:
            if dep not in all_keys:
                issues.append(
                    f"ERROR: '{key}' depends on unknown analyzer '{dep}'"
                )

    # Check display names
    for key in all_keys:
        if key not in ANALYZER_DISPLAY_NAMES:
            issues.append(f"WARNING: '{key}' has no display name")

    # Check entry points
    for key in all_keys:
        if key not in ANALYZER_ENTRY_POINTS:
            issues.append(f"WARNING: '{key}' has no entry point registered")

    # Check system definitions
    for key in all_keys:
        if key not in ANALYZER_SYSTEMS:
            issues.append(f"WARNING: '{key}' has no system scope defined")

    # Check for cycles
    try:
        topo = _topological_sort(ANALYZER_DEPS)
        if len(topo) != len(all_keys):
            missing = all_keys - set(topo)
            issues.append(
                f"WARNING: Possible cycle involving: "
                f"{', '.join(sorted(missing))}"
            )
    except Exception as e:
        issues.append(f"ERROR: Topological sort failed: {e}")

    # Check for self-dependencies
    for key, deps in ANALYZER_DEPS.items():
        if key in deps:
            issues.append(f"ERROR: '{key}' depends on itself")

    if not issues:
        msg_info("Dependency graph validation passed: no issues found.")
    else:
        for issue in issues:
            if issue.startswith("ERROR"):
                msg_error(issue)
            else:
                msg_warn(issue)

    return issues
