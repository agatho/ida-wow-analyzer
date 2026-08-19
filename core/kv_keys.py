"""
Canonical kv_store keys for the TC WoW Analyzer.

WHY THIS EXISTS
---------------
Analyzer results are exchanged through ``KnowledgeDB.kv_set``/``kv_get`` with
plain string keys.  A producer/consumer pair that spells the key differently
fails *silently*: ``kv_get`` returns ``None``, the consumer takes its "no data"
branch, and the run still reports OK.  A single audit found seven such
mismatches (behavioral_spec, enum_recovery, conformance, mined_constants,
scaffolds, validation_constraints, vtable_master) -- every one of them a total,
undetected loss of that analyzer's contribution.

Import the constants from here instead of typing literals.  Every constant
below is derived from an actual ``kv_set`` call in the code base, and
``tests/test_kv_keys.py`` re-derives the list and fails if a constant loses its
writer -- so a rename can no longer create a one-sided key.

NOTE: keys built at runtime (``f"behavioral_spec:{tc_name}"`` and friends) are
exposed as a PREFIX constant plus a helper function, see the bottom of the file.
"""

# ---------------------------------------------------------------------------
# Static keys (auto-derived from kv_set call sites -- do not hand-edit)
# ---------------------------------------------------------------------------
AUTH_LIFECYCLE = "auth_lifecycle"  # written by auth_lifecycle.py
AUTO_DETECTED_DISPATCHER = "auto_detected_dispatcher"  # written by opcode_dispatcher.py
AUTODUMP_SIMHASH = "autodump_simhash"  # written by importer.py
BEHAVIORAL_SPECS = "behavioral_specs"  # written by behavioral_spec.py, execution_trace_sim.py
BINARY_TC_ALIGNMENT = "binary_tc_alignment"  # written by binary_tc_alignment.py
BUILD_BASELINE = "build_baseline"  # written by build_delta.py
BUILD_DELTA = "build_delta"  # written by build_delta.py
BUILD_DELTA_MIGRATION_REPORT = "build_delta_migration_report"  # written by build_delta.py
BUILD_DELTA_PATCH = "build_delta_patch"  # written by build_delta.py
CALL_GRAPH_ANALYTICS = "call_graph_analytics"  # written by call_graph_analytics.py
CALLEE_CONTRACT_VIOLATIONS = "callee_contract_violations"  # written by callee_contracts.py
CALLEE_CONTRACTS = "callee_contracts"  # written by callee_contracts.py
CFUNC_PATTERN_TAG = "cfunc_pattern_tag"  # written by cfunc_pattern_tag.py
CLASS_CATALOG = "class_catalog"  # written by alloc_class_catalog.py
COMPILER_ARTIFACTS = "compiler_artifacts"  # written by compiler_artifacts.py
CONFORMANCE_REPORT = "conformance_report"  # written by conformance.py
CROSS_BUILD_MIGRATION = "cross_build_migration"  # written by cross_build_migration.py
CVAR_CALLBACK_RENAME = "cvar_callback_rename"  # written by cvar_callback_rename.py
CVAR_CONSUMER_TAG = "cvar_consumer_tag"  # written by cvar_consumer_tag.py
CVARS = "cvars"  # written by cvar_extraction.py
CVARS_PHASE3_CHECKPOINT = "cvars_phase3_checkpoint"  # written by cvar_extraction.py
DATA_ARCHAEOLOGY = "data_archaeology"  # written by data_section_archaeology.py
DB2_DATA_CONTENT = "db2_data_content"  # written by db2_data_content.py
DB2_DRIFT_REPORT = "db2_drift_report"  # written by db2_drift.py
DB2_LOADINFO_CODEGEN = "db2_loadinfo_codegen"  # written by db2_loadinfo_codegen.py
DEPENDENCY_MAP = "dependency_map"  # written by dependency_mapper.py
EVENT_SYSTEM = "event_system"  # written by event_system_recovery.py
EXECUTION_TRACES = "execution_traces"  # written by execution_trace_sim.py
FDID_RESOLUTION = "fdid_resolution"  # written by fdid_resolution.py
FUNCTION_SIMILARITY = "function_similarity"  # written by function_similarity.py
GAME_CONSTANT_MISMATCHES = "game_constant_mismatches"  # written by constant_mining.py
GAME_CONSTANTS = "game_constants"  # written by constant_mining.py
GENERATED_TESTS = "generated_tests"  # written by test_generator.py
HANDLER_SCAFFOLDING = "handler_scaffolding"  # written by handler_scaffolding.py
HASH_FUNC_NAMING = "hash_func_naming"  # written by hash_func_naming.py
HASH_RESOLUTION = "hash_resolution"  # written by hash_resolution.py
IDB_ENRICHMENT = "idb_enrichment"  # written by idb_enrichment.py
IDB_ENRICHMENT_PHASE4_CHECKPOINT = "idb_enrichment_phase4_checkpoint"  # written by idb_enrichment.py
INDIRECT_CALLS = "indirect_calls"  # written by indirect_call_resolver.py
INSTRUCTION_NGRAMS = "instruction_ngrams"  # written by instruction_ngram.py
JAM_CALLER_INDEX = "jam_caller_index"  # written by jam_caller_index.py
JAM_DISCOVERY = "jam_discovery"  # written by jam_type_discovery.py
JAM_METADATA_APPLY = "jam_metadata_apply"  # written by jam_metadata_apply.py
LAST_DIFF = "last_diff"  # written by build_differ.py
LAST_IMPORT = "last_import"  # written by importer.py
LLM_SEMANTIC_DECOMPILATION = "llm_semantic_decompilation"  # written by llm_semantic_decompiler.py
LUA_API_TAG = "lua_api_tag"  # written by lua_api_tag.py
LUA_COMPLETENESS_SCORE = "lua_completeness_score"  # written by lua_contracts.py
LUA_CONTRACTS = "lua_contracts"  # written by lua_contracts.py
LUA_TC_COMPARISON = "lua_tc_comparison"  # written by lua_contracts.py
LUMINA_PULL = "lumina_pull"  # written by lumina_integration.py
NEGATIVE_SPACE = "negative_space"  # written by negative_space.py
OBJECT_LAYOUT_TC_COMPARISON = "object_layout_tc_comparison"  # written by object_layout.py
OBJECT_LAYOUTS = "object_layouts"  # written by object_layout.py
OBJECT_LIFECYCLE_COMPARISONS = "object_lifecycle_comparisons"  # written by object_lifecycle.py
OBJECT_LIFECYCLE_ISSUES = "object_lifecycle_issues"  # written by object_lifecycle.py
OBJECT_LIFECYCLES = "object_lifecycles"  # written by object_lifecycle.py
PACKET_REPLAY_REPORT = "packet_replay_report"  # written by packet_replay.py
PACKET_STRUCTS_CHECKPOINT = "packet_structs_checkpoint"  # written by idb_enrichment.py
PE_METADATA = "pe_metadata"  # written by pe_metadata.py
PROTOCOL_SEQUENCES = "protocol_sequences"  # written by protocol_sequencing.py
RECOVERED_ENUMS = "recovered_enums"  # written by enum_recovery.py, importer.py
RESPONSE_PACKETS = "response_packets"  # written by response_reconstruction.py
RETURN_VALUE_SEMANTICS = "return_value_semantics"  # written by return_value_semantics.py
RETURN_VALUE_SEMANTICS_CHECKPOINT = "return_value_semantics_checkpoint"  # written by return_value_semantics.py
RTTI_TO_SQL = "rtti_to_sql"  # written by rtti_to_sql.py
SHARED_CODE = "shared_code"  # written by shared_code_detection.py
SHARED_CODE_FORMULAS = "shared_code:formulas"  # written by shared_code_detection.py
SHARED_CODE_PROTOCOL_CONSTANTS = "shared_code:protocol_constants"  # written by shared_code_detection.py
SHARED_CODE_SERIALIZATION_PAIRS = "shared_code:serialization_pairs"  # written by shared_code_detection.py
SHARED_CODE_SHARED_CONSTANTS = "shared_code:shared_constants"  # written by shared_code_detection.py
SHARED_CODE_SHARED_UTILITIES = "shared_code:shared_utilities"  # written by shared_code_detection.py
SHARED_CODE_VALIDATIONS = "shared_code:validations"  # written by shared_code_detection.py
SNIFF_VERIFICATION = "sniff_verification"  # written by sniff_verification.py
STATE_MACHINES = "state_machines"  # written by state_machine.py
STRING_INTELLIGENCE = "string_intelligence"  # written by string_intelligence.py
SUBSYSTEM_CATALOG = "subsystem_catalog"  # written by subsystem_catalog.py
SYMBOLIC_CONSTRAINTS = "symbolic_constraints"  # written by symbolic_constraints.py
SYMBOLIC_CONSTRAINTS_HEADER = "symbolic_constraints_header"  # written by symbolic_constraints.py
SYNTHESIS_REPORT = "synthesis_report"  # written by cross_analyzer_synthesis.py
TAINT_ANALYSIS = "taint_analysis"  # written by taint_analysis.py
TAINT_ANALYSIS_MARKDOWN = "taint_analysis_markdown"  # written by taint_analysis.py
TC_OPCODE_XREF = "tc_opcode_xref"  # written by tc_opcode_xref.py
TEMPORAL_EVOLUTION = "temporal_evolution"  # written by multi_build_temporal.py
THREAD_SAFETY_MAP = "thread_safety_map"  # written by thread_safety_map.py
TOPIC_DEEP_EXTRACTOR = "topic_deep_extractor"  # written by topic_deep_extractor.py
TRANSPILED_HANDLERS = "transpiled_handlers"  # written by pseudocode_transpiler.py
TYPENAME_APPLY = "typename_apply"  # written by typename_apply.py
UPDATEFIELD_DESCRIPTORS = "updatefield_descriptors"  # written by updatefield_descriptor.py
VALIDATION_COMPARISON_REPORT = "validation_comparison_report"  # written by validation_extractor.py
WIRE_FORMATS = "wire_formats"  # written by wire_format_recovery.py
WIRE_FORMATS_EXPORT_TIME = "wire_formats_export_time"  # written by wire_format_recovery.py


# ---------------------------------------------------------------------------
# Dynamic (per-subject) keys
# ---------------------------------------------------------------------------
CODEGEN_LAST_RUN = "codegen_last_run"  # written by codegen/writer.py
VTABLE_ANALYSIS = "vtable_analysis"    # written by analyzers/vtable_analyzer.py
OPCODE_DISPATCH_CANDIDATES = "opcode_dispatch_candidates"  # written by analyzers/opcode_dispatch_recovery.py

BEHAVIORAL_SPEC_PREFIX = "behavioral_spec:"
EXECUTION_TRACE_PREFIX = "execution_trace:"
SPEC_VERIFICATION_PREFIX = "spec_verification:"
CONSTANTS_PREFIX = "constants:"
IMPORT_YIELD_PREFIX = "import_yield:"


def behavioral_spec_key(tc_name):
    """kv key holding the behavioural spec of a single handler."""
    return f"{BEHAVIORAL_SPEC_PREFIX}{tc_name}"


def execution_trace_key(tc_name):
    """kv key holding the execution trace of a single handler."""
    return f"{EXECUTION_TRACE_PREFIX}{tc_name}"


def import_yield_key(stem):
    """kv key holding the per-file record count of the last AutoDump import."""
    return f"{IMPORT_YIELD_PREFIX}{stem}"
