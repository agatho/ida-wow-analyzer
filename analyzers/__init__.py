"""
TC WoW Analyzer — Analyzer Orchestration
Runs all analysis passes in dependency order.
"""

from tc_wow_analyzer.core.utils import msg_info, msg_error


def run_all_analyzers(session):
    """Run all analyzers in dependency order.

    Order matters:
      1. Lua API — standalone, no deps
      2. VTables — standalone, no deps
      3. DB2 Metadata — standalone, no deps
      4. Opcode Dispatcher — benefits from existing function names
      5. JAM Recovery — benefits from opcode→handler mapping
      6. Update Fields — benefits from JAM type knowledge
      7. Handler↔JAM linking — cross-references opcodes with JAM types
      --- Quality Enhancement Analyzers ---
      8. DB2 Drift — compares binary DB2 metadata vs TC LoadInfo
      9. Validation Extractor — extracts guard checks from handlers
     10. Conformance Scoring — scores TC handler fidelity vs binary
     11. State Machine Recovery — recovers implicit state machines
     12. Dependency Mapper — maps cross-system dependencies
     13. Test Generator — generates test cases from binary analysis
     14. Packet Replay — replays packet captures for conformance
      --- Deep Extraction Analyzers ---
     15. Wire Format Recovery — bit-level serialization tracing
     16. Enum Universe — aggregated enum recovery across all functions
     17. Game Constants — magic number extraction with context
     18. Object Layout — C++ class member layout recovery
     19. Response Reconstruction — SMSG packet construction extraction
      --- Behavioral Analysis ---
     20. Taint Analysis — user input flow tracking for security
     21. Behavioral Spec — per-handler execution path enumeration
     22. Protocol Sequencing — implicit packet ordering recovery
     23. Build Delta — cross-build semantic diffing
     24. Callee Contracts — shared utility function contracts
      --- Synthesis & Generation ---
     25. Pseudocode Transpiler — Hex-Rays → TC C++ translation
     26. Object Lifecycle — allocation/destruction pattern recovery
     27. Lua Contracts — Lua↔C++ interface completeness
      --- Intelligence & Enrichment ---
     28. IDB Enrichment — auto-rename/retype from analysis, iterative convergence
     29. String Intelligence — error/debug/assert string mining for naming
     30. Cross-Analyzer Synthesis — unified per-handler specs from all analyzers
      --- Data & Verification ---
     31. DB2 Data Content — actual DB2 file row-level analysis
     32. Sniff Verification — packet capture validation against wire formats
     33. Multi-Build Temporal — evolution tracking across WoW builds
      --- Structural Analysis ---
     34. Function Similarity — structural fingerprint clustering
     35. Shared Code Detection — client/server shared logic identification
     36. Thread Safety Map — mutex/lock pattern and threading analysis
      --- Gap & Completeness ---
     37. Negative Space — missing validation/notification detection
     38. UpdateField Descriptors — .rdata descriptor table extraction
     39. Allocation Class Catalog — operator new size → class catalog
      --- PE & Low-Level ---
     40. PE Metadata Deep Dive — exception tables, CFG, debug directory
     41. Data Section Archaeology — .rdata/.data table and array mining
     42. CVar Extraction — console variable definitions and flags
      --- Graph & Architecture ---
     43. Call Graph Analytics — PageRank, centrality, community detection
     44. Indirect Call Resolution — virtual dispatch and CFG target resolution
     45. Event System Recovery — event/callback/timer topology
      --- Semantic Analysis ---
     46. Symbolic Constraint Propagation — exact valid input range recovery
     47. Binary↔TC Source Alignment — direct structural diff
     48. Return Value Semantics — return convention and unchecked return detection
      --- Pattern Mining ---
     49. Instruction N-gram Mining — assembly pattern frequency analysis
     50. Execution Trace Simulation — pseudocode-level symbolic execution
     51. Compiler Artifact Mining — hot/cold split, SIMD, /GS, COMDAT
      --- LLM & Code Generation ---
     52. LLM Semantic Decompiler — LLM-powered variable naming and code annotation
     53. Handler Scaffolding — automated TC handler C++ code generation
      --- Cross-Build & Conformance ---
     54. Cross-Build Migration — automatic migration patches between WoW builds
     55. Sniff Conformance Loop — packet capture → divergence → auto-fix pipeline
    """
    results = {}

    analyzers = [
        ("Lua API", _run_lua_api),
        ("VTables", _run_vtables),
        ("DB2 Metadata", _run_db2_metadata),
        ("Opcode Dispatcher", _run_opcode_dispatcher),
        ("JAM Recovery", _run_jam_recovery),
        ("Update Fields", _run_update_fields),
        ("Handler-JAM Linking", _run_handler_jam_linking),
        # Quality enhancement analyzers
        ("DB2 Drift", _run_db2_drift),
        ("Validation Extractor", _run_validation_extractor),
        ("Conformance Scoring", _run_conformance),
        ("State Machine Recovery", _run_state_machines),
        ("Dependency Mapper", _run_dependency_mapper),
        ("Test Generator", _run_test_generator),
        ("Packet Replay", _run_packet_replay),
        # Deep extraction analyzers
        ("Wire Format Recovery", _run_wire_format),
        ("Enum Recovery", _run_enum_recovery),
        ("Game Constants", _run_constant_mining),
        ("Object Layout", _run_object_layout),
        ("Response Reconstruction", _run_response_reconstruction),
        # Behavioral analysis
        ("Taint Analysis", _run_taint_analysis),
        ("Behavioral Spec", _run_behavioral_spec),
        ("Protocol Sequencing", _run_protocol_sequencing),
        ("Build Delta", _run_build_delta),
        ("Callee Contracts", _run_callee_contracts),
        # Synthesis & generation
        ("Pseudocode Transpiler", _run_pseudocode_transpiler),
        ("Object Lifecycle", _run_object_lifecycle),
        ("Lua Contracts", _run_lua_contracts),
        # Intelligence & enrichment
        ("IDB Enrichment", _run_idb_enrichment),
        ("String Intelligence", _run_string_intelligence),
        ("Cross-Analyzer Synthesis", _run_cross_synthesis),
        # Data & verification
        ("DB2 Data Content", _run_db2_data_content),
        ("Sniff Verification", _run_sniff_verification),
        ("Multi-Build Temporal", _run_multi_build_temporal),
        # Structural analysis
        ("Function Similarity", _run_function_similarity),
        ("Shared Code Detection", _run_shared_code_detection),
        ("Thread Safety Map", _run_thread_safety_map),
        # Gap & completeness
        ("Negative Space", _run_negative_space),
        ("UpdateField Descriptors", _run_updatefield_descriptors),
        ("Allocation Class Catalog", _run_alloc_class_catalog),
        # PE & low-level
        ("PE Metadata", _run_pe_metadata),
        ("Data Section Archaeology", _run_data_archaeology),
        ("CVar Extraction", _run_cvar_extraction),
        # Graph & architecture
        ("Call Graph Analytics", _run_call_graph_analytics),
        ("Indirect Call Resolution", _run_indirect_call_resolver),
        ("Event System Recovery", _run_event_system),
        # Semantic analysis
        ("Symbolic Constraints", _run_symbolic_constraints),
        ("Binary-TC Alignment", _run_binary_tc_alignment),
        ("Return Value Semantics", _run_return_semantics),
        # Pattern mining
        ("Instruction N-grams", _run_instruction_ngrams),
        ("Execution Trace Simulation", _run_execution_trace),
        ("Compiler Artifacts", _run_compiler_artifacts),
        # LLM & generation
        ("LLM Semantic Decompiler", _run_llm_semantic_decompiler),
        ("Handler Scaffolding", _run_handler_scaffolding),
        # Cross-build & conformance
        ("Cross-Build Migration", _run_cross_build_migration),
        ("Sniff Conformance Loop", _run_sniff_conformance_loop),
    ]

    total = 0
    for name, func in analyzers:
        msg_info(f"=== Running analyzer: {name} ===")
        try:
            count = func(session)
            results[name] = count
            total += count
            msg_info(f"  -> {name}: {count} items processed")
        except Exception as e:
            msg_error(f"  -> {name} FAILED: {e}")
            results[name] = -1

    msg_info(f"=== Analysis complete: {total} total items across "
             f"{len(analyzers)} analyzers ===")
    return results


def _run_lua_api(session):
    from tc_wow_analyzer.analyzers.lua_api import analyze_lua_api
    return analyze_lua_api(session)


def _run_vtables(session):
    from tc_wow_analyzer.analyzers.vtable_analyzer import analyze_vtables
    return analyze_vtables(session)


def _run_db2_metadata(session):
    from tc_wow_analyzer.analyzers.db2_metadata import analyze_db2_metadata
    return analyze_db2_metadata(session)


def _run_opcode_dispatcher(session):
    from tc_wow_analyzer.analyzers.opcode_dispatcher import analyze_opcode_dispatcher
    return analyze_opcode_dispatcher(session)


def _run_jam_recovery(session):
    from tc_wow_analyzer.analyzers.jam_recovery import analyze_jam_types
    return analyze_jam_types(session)


def _run_update_fields(session):
    from tc_wow_analyzer.analyzers.update_fields import analyze_update_fields
    return analyze_update_fields(session)


def _run_handler_jam_linking(session):
    from tc_wow_analyzer.analyzers.opcode_dispatcher import analyze_handler_jam_types
    return analyze_handler_jam_types(session)


def _run_db2_drift(session):
    from tc_wow_analyzer.analyzers.db2_drift import analyze_db2_drift
    return analyze_db2_drift(session)


def _run_validation_extractor(session):
    from tc_wow_analyzer.analyzers.validation_extractor import extract_validations
    return extract_validations(session)


def _run_conformance(session):
    from tc_wow_analyzer.analyzers.conformance import analyze_conformance
    return analyze_conformance(session)


def _run_state_machines(session):
    from tc_wow_analyzer.analyzers.state_machine import recover_state_machines
    return recover_state_machines(session)


def _run_dependency_mapper(session):
    from tc_wow_analyzer.analyzers.dependency_mapper import analyze_dependencies
    return analyze_dependencies(session)


def _run_test_generator(session):
    from tc_wow_analyzer.analyzers.test_generator import generate_tests
    return generate_tests(session)


def _run_packet_replay(session):
    from tc_wow_analyzer.analyzers.packet_replay import analyze_packet_replay
    return analyze_packet_replay(session)


# Deep extraction analyzers

def _run_wire_format(session):
    from tc_wow_analyzer.analyzers.wire_format_recovery import analyze_wire_formats
    return analyze_wire_formats(session)


def _run_enum_recovery(session):
    from tc_wow_analyzer.analyzers.enum_recovery import recover_enums
    return recover_enums(session)


def _run_constant_mining(session):
    from tc_wow_analyzer.analyzers.constant_mining import mine_constants
    return mine_constants(session)


def _run_object_layout(session):
    from tc_wow_analyzer.analyzers.object_layout import recover_object_layouts
    return recover_object_layouts(session)


def _run_response_reconstruction(session):
    from tc_wow_analyzer.analyzers.response_reconstruction import reconstruct_responses
    return reconstruct_responses(session)


# Behavioral analysis

def _run_taint_analysis(session):
    from tc_wow_analyzer.analyzers.taint_analysis import analyze_taint_flows
    return analyze_taint_flows(session)


def _run_behavioral_spec(session):
    from tc_wow_analyzer.analyzers.behavioral_spec import generate_behavioral_specs
    return generate_behavioral_specs(session)


def _run_protocol_sequencing(session):
    from tc_wow_analyzer.analyzers.protocol_sequencing import recover_protocol_sequence
    return recover_protocol_sequence(session)


def _run_build_delta(session):
    from tc_wow_analyzer.analyzers.build_delta import analyze_build_delta
    return analyze_build_delta(session, None)


def _run_callee_contracts(session):
    from tc_wow_analyzer.analyzers.callee_contracts import recover_contracts
    return recover_contracts(session)


# Synthesis & generation

def _run_pseudocode_transpiler(session):
    from tc_wow_analyzer.analyzers.pseudocode_transpiler import transpile_all_handlers
    return transpile_all_handlers(session)


def _run_object_lifecycle(session):
    from tc_wow_analyzer.analyzers.object_lifecycle import recover_object_lifecycles
    return recover_object_lifecycles(session)


def _run_lua_contracts(session):
    from tc_wow_analyzer.analyzers.lua_contracts import analyze_lua_contracts
    return analyze_lua_contracts(session)


# Intelligence & enrichment

def _run_idb_enrichment(session):
    from tc_wow_analyzer.analyzers.idb_enrichment import enrich_idb
    return enrich_idb(session)


def _run_string_intelligence(session):
    from tc_wow_analyzer.analyzers.string_intelligence import analyze_string_intelligence
    return analyze_string_intelligence(session)


def _run_cross_synthesis(session):
    from tc_wow_analyzer.analyzers.cross_analyzer_synthesis import synthesize_all
    return synthesize_all(session)


# Data & verification

def _run_db2_data_content(session):
    from tc_wow_analyzer.analyzers.db2_data_content import analyze_db2_content
    return analyze_db2_content(session)


def _run_sniff_verification(session):
    from tc_wow_analyzer.analyzers.sniff_verification import verify_sniff_formats
    return verify_sniff_formats(session)


def _run_multi_build_temporal(session):
    from tc_wow_analyzer.analyzers.multi_build_temporal import analyze_temporal_evolution
    return analyze_temporal_evolution(session)


# Structural analysis

def _run_function_similarity(session):
    from tc_wow_analyzer.analyzers.function_similarity import cluster_similar_functions
    return cluster_similar_functions(session)


def _run_shared_code_detection(session):
    from tc_wow_analyzer.analyzers.shared_code_detection import detect_shared_code
    return detect_shared_code(session)


def _run_thread_safety_map(session):
    from tc_wow_analyzer.analyzers.thread_safety_map import map_thread_safety
    return map_thread_safety(session)


# Gap & completeness

def _run_negative_space(session):
    from tc_wow_analyzer.analyzers.negative_space import analyze_negative_space
    return analyze_negative_space(session)


def _run_updatefield_descriptors(session):
    from tc_wow_analyzer.analyzers.updatefield_descriptor import extract_updatefield_descriptors
    return extract_updatefield_descriptors(session)


def _run_alloc_class_catalog(session):
    from tc_wow_analyzer.analyzers.alloc_class_catalog import build_class_catalog
    return build_class_catalog(session)


# PE & low-level

def _run_pe_metadata(session):
    from tc_wow_analyzer.analyzers.pe_metadata import analyze_pe_metadata
    return analyze_pe_metadata(session)


def _run_data_archaeology(session):
    from tc_wow_analyzer.analyzers.data_section_archaeology import mine_data_sections
    return mine_data_sections(session)


def _run_cvar_extraction(session):
    from tc_wow_analyzer.analyzers.cvar_extraction import extract_cvars
    return extract_cvars(session)


# Graph & architecture

def _run_call_graph_analytics(session):
    from tc_wow_analyzer.analyzers.call_graph_analytics import analyze_call_graph
    return analyze_call_graph(session)


def _run_indirect_call_resolver(session):
    from tc_wow_analyzer.analyzers.indirect_call_resolver import resolve_indirect_calls
    return resolve_indirect_calls(session)


def _run_event_system(session):
    from tc_wow_analyzer.analyzers.event_system_recovery import recover_event_system
    return recover_event_system(session)


# Semantic analysis

def _run_symbolic_constraints(session):
    from tc_wow_analyzer.analyzers.symbolic_constraints import propagate_constraints
    return propagate_constraints(session)


def _run_binary_tc_alignment(session):
    from tc_wow_analyzer.analyzers.binary_tc_alignment import align_binary_to_tc
    return align_binary_to_tc(session)


def _run_return_semantics(session):
    from tc_wow_analyzer.analyzers.return_value_semantics import analyze_return_semantics
    return analyze_return_semantics(session)


# Pattern mining

def _run_instruction_ngrams(session):
    from tc_wow_analyzer.analyzers.instruction_ngram import analyze_instruction_ngrams
    return analyze_instruction_ngrams(session)


def _run_execution_trace(session):
    from tc_wow_analyzer.analyzers.execution_trace_sim import simulate_execution
    return simulate_execution(session)


def _run_compiler_artifacts(session):
    from tc_wow_analyzer.analyzers.compiler_artifacts import mine_compiler_artifacts
    return mine_compiler_artifacts(session)


# LLM & generation

def _run_llm_semantic_decompiler(session):
    from tc_wow_analyzer.analyzers.llm_semantic_decompiler import semantically_decompile_all
    return semantically_decompile_all(session)


def _run_handler_scaffolding(session):
    from tc_wow_analyzer.analyzers.handler_scaffolding import generate_all_scaffolds
    return generate_all_scaffolds(session)


# Cross-build & conformance

def _run_cross_build_migration(session):
    from tc_wow_analyzer.analyzers.cross_build_migration import generate_migration
    return generate_migration(session)


def _run_sniff_conformance_loop(session):
    from tc_wow_analyzer.analyzers.sniff_conformance_loop import run_conformance_loop
    return run_conformance_loop(session)
