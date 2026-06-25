"""
Analyzer registry — single source of truth for the analyzer surface.

Maps every registered analyzer to its category, the kv_store key it writes
(if any), and the primary SQLite table it populates (if any). This is what
the Analyzer Index UI uses to make ALL 70 analyzers reachable, and what lets
us reconcile the run loop, the run_report, and the kv_store without the
name/key drift that previously hid ~18 analyzers (e.g. the analyzer named
"JAM Type Discovery" writes kv key "jam_discovery", not "jam_type_discovery").

`name` MUST match the display name in analyzers/__init__.py:run_all_analyzers
exactly — `verify(run_names)` asserts this and is called by the Analyzer Index.

kv_key / db_table values were extracted deterministically from the source
(grep of kv_set(...) and the importer/analyzer upserts), not guessed.
"""

from collections import namedtuple

# kv_key: primary kv_store blob (None if the analyzer writes only DB/IDB/files)
# db_table: primary SQLite table it populates (None if kv/IDB/files only)
AnalyzerInfo = namedtuple("AnalyzerInfo", ["name", "category", "kv_key", "db_table"])

# Order matches run_all_analyzers. Categories mirror the run-loop comment groups.
REGISTRY = [
    # ── Core protocol/data recovery ──
    AnalyzerInfo("Lua API",                 "core",        None,                       "lua_api"),
    AnalyzerInfo("VTables",                 "core",        None,                       "vtables"),
    AnalyzerInfo("RTTI to SQL",             "core",        "rtti_to_sql",              "vtables"),
    AnalyzerInfo("DB2 Metadata",            "core",        None,                       "db2_tables"),
    AnalyzerInfo("DB2 LoadInfo Codegen",    "codegen",     "db2_loadinfo_codegen",     None),
    AnalyzerInfo("Opcode Dispatcher",       "core",        "auto_detected_dispatcher", "opcodes"),
    AnalyzerInfo("JAM Recovery",            "core",        None,                       "jam_types"),
    AnalyzerInfo("Update Fields",           "core",        None,                       "update_fields"),
    AnalyzerInfo("Handler-JAM Linking",     "core",        None,                       "opcodes"),
    # ── Quality enhancement ──
    AnalyzerInfo("DB2 Drift",               "quality",     "db2_drift_report",         None),
    AnalyzerInfo("Validation Extractor",    "quality",     "validation_comparison_report", None),
    AnalyzerInfo("Conformance Scoring",     "quality",     "conformance_report",       None),
    AnalyzerInfo("State Machine Recovery",  "quality",     "state_machines",           None),
    AnalyzerInfo("Dependency Mapper",       "quality",     "dependency_map",           None),
    AnalyzerInfo("Test Generator",          "quality",     "generated_tests",          None),
    AnalyzerInfo("Packet Replay",           "quality",     "packet_replay_report",     None),
    # ── Deep extraction ──
    AnalyzerInfo("Wire Format Recovery",    "deep",        "wire_formats",             None),
    AnalyzerInfo("Enum Recovery",           "deep",        "recovered_enums",          None),
    AnalyzerInfo("Game Constants",          "deep",        "game_constants",           None),
    AnalyzerInfo("Object Layout",           "deep",        "object_layouts",           None),
    AnalyzerInfo("Response Reconstruction", "deep",        "response_packets",         None),
    # ── Behavioral analysis ──
    AnalyzerInfo("Taint Analysis",          "behavioral",  "taint_analysis",           None),
    AnalyzerInfo("Protocol Sequencing",     "behavioral",  "protocol_sequences",       None),
    AnalyzerInfo("Auth Lifecycle",          "behavioral",  "auth_lifecycle",           None),
    AnalyzerInfo("Build Delta",             "cross_build", "build_delta",              None),
    AnalyzerInfo("Callee Contracts",        "behavioral",  "callee_contracts",         None),
    # ── Synthesis & generation ──
    AnalyzerInfo("Pseudocode Transpiler",   "synthesis",   "transpiled_handlers",      None),
    AnalyzerInfo("Object Lifecycle",        "synthesis",   "object_lifecycles",        None),
    AnalyzerInfo("Lua Contracts",           "synthesis",   "lua_contracts",            None),
    # ── Intelligence & enrichment ──
    AnalyzerInfo("Subsystem Catalog",       "enrichment",  "subsystem_catalog",        None),
    AnalyzerInfo("IDB Enrichment",          "enrichment",  "idb_enrichment",           None),
    AnalyzerInfo("JAM Metadata Apply",      "enrichment",  "jam_metadata_apply",       None),
    AnalyzerInfo("JAM Caller Index",        "enrichment",  "jam_caller_index",         None),
    AnalyzerInfo("JAM Type Discovery",      "enrichment",  "jam_discovery",            None),  # key drift fixed here
    AnalyzerInfo("TC Opcode Xref",          "enrichment",  "tc_opcode_xref",           None),
    AnalyzerInfo("Topic Deep Extractor",    "enrichment",  "topic_deep_extractor",     None),
    AnalyzerInfo("Lua API Tag",             "enrichment",  "lua_api_tag",              None),
    AnalyzerInfo("Hash Resolution",         "enrichment",  "hash_resolution",          None),
    AnalyzerInfo("CVar Callback Rename",    "enrichment",  "cvar_callback_rename",     None),
    AnalyzerInfo("Hash Function Naming",    "enrichment",  "hash_func_naming",         None),
    AnalyzerInfo("CVar Consumer Tag",       "enrichment",  "cvar_consumer_tag",        None),
    AnalyzerInfo("Cfunc Pattern Tag",       "enrichment",  "cfunc_pattern_tag",        None),
    AnalyzerInfo("Typename Apply",          "enrichment",  "typename_apply",           None),
    AnalyzerInfo("String Intelligence",     "enrichment",  "string_intelligence",      None),
    AnalyzerInfo("Cross-Analyzer Synthesis","enrichment",  "synthesis_report",         None),
    # ── Data & verification ──
    AnalyzerInfo("DB2 Data Content",        "data",        "db2_data_content",         None),
    AnalyzerInfo("Sniff Verification",      "data",        "sniff_verification",       None),
    AnalyzerInfo("Multi-Build Temporal",    "cross_build", "temporal_evolution",       None),
    # ── Structural analysis ──
    AnalyzerInfo("Function Similarity",     "structural",  "function_similarity",      None),
    AnalyzerInfo("Shared Code Detection",   "structural",  "shared_code",              None),
    AnalyzerInfo("Thread Safety Map",       "structural",  "thread_safety_map",        None),
    # ── Gap & completeness ──
    AnalyzerInfo("Negative Space",          "gap",         "negative_space",           None),
    AnalyzerInfo("UpdateField Descriptors", "gap",         "updatefield_descriptors",  None),
    AnalyzerInfo("Allocation Class Catalog","gap",         "class_catalog",            None),
    # ── PE & low-level ──
    AnalyzerInfo("PE Metadata",             "low_level",   "pe_metadata",              None),
    AnalyzerInfo("Data Section Archaeology","low_level",   "data_archaeology",         None),
    AnalyzerInfo("CVar Extraction",         "low_level",   "cvars",                    None),
    # ── Graph & architecture ──
    AnalyzerInfo("Call Graph Analytics",    "graph",       "call_graph_analytics",     None),
    AnalyzerInfo("Indirect Call Resolution","graph",       "indirect_calls",           None),
    AnalyzerInfo("Event System Recovery",   "graph",       "event_system",             None),
    # ── Semantic analysis ──
    AnalyzerInfo("Symbolic Constraints",    "semantic",    "symbolic_constraints",     None),
    AnalyzerInfo("Binary-TC Alignment",     "semantic",    "binary_tc_alignment",      None),
    AnalyzerInfo("Return Value Semantics",  "semantic",    "return_value_semantics",   None),
    # ── Pattern mining ──
    AnalyzerInfo("Instruction N-grams",     "pattern",     "instruction_ngrams",       None),
    AnalyzerInfo("Execution Trace Simulation","pattern",   "execution_traces",         None),
    AnalyzerInfo("Compiler Artifacts",      "pattern",     "compiler_artifacts",       None),
    # ── LLM & code generation ──
    AnalyzerInfo("LLM Semantic Decompiler", "llm_codegen", None,                       None),
    AnalyzerInfo("Handler Scaffolding",     "codegen",     None,                       None),
    # ── Cross-build & conformance ──
    AnalyzerInfo("Cross-Build Migration",   "cross_build", None,                       None),
    AnalyzerInfo("Sniff Conformance Loop",  "cross_build", None,                       None),
]

BY_NAME = {a.name: a for a in REGISTRY}


def verify(run_names):
    """Reconcile the registry against the run loop's analyzer name list.

    Returns (missing, extra): names in the run loop but not the registry, and
    names in the registry but not the run loop. Both empty == in sync. Used by
    the Analyzer Index to surface drift instead of silently hiding analyzers."""
    reg = set(BY_NAME)
    run = set(run_names)
    return sorted(run - reg), sorted(reg - run)


def categories():
    """Ordered, de-duplicated list of categories as they first appear."""
    seen = []
    for a in REGISTRY:
        if a.category not in seen:
            seen.append(a.category)
    return seen
