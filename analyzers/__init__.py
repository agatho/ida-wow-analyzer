"""
TC WoW Analyzer — Analyzer Orchestration
Runs all analysis passes in dependency order.
"""

import json
import os
import time
import traceback

from tc_wow_analyzer.core.utils import msg_info, msg_error, _init_log_file, _write_log


def _gc_resource_snapshot():
    """Best-effort memory + handle snapshot for resource tracking."""
    snap = {"ts": time.time()}
    try:
        import psutil, os as _os
        p = psutil.Process(_os.getpid())
        mi = p.memory_info()
        snap["rss_mb"] = round(mi.rss / (1024 * 1024), 1)
        snap["vms_mb"] = round(mi.vms / (1024 * 1024), 1)
        snap["num_threads"] = p.num_threads()
        try:
            snap["num_handles"] = p.num_handles()  # Windows only
        except AttributeError:
            pass
    except Exception:
        # psutil not installed — fallback to resource.getrusage on unix, skip otherwise
        pass
    return snap


def _report_path():
    """Path for the structured run report JSON, next to the IDB."""
    try:
        import ida_loader
        idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if idb:
            return os.path.splitext(idb)[0] + ".tc_wow_analyzer.run_report.json"
    except Exception:
        pass
    return os.path.join(os.path.dirname(__file__), "..", "..", "run_report.json")


def _progress_path():
    """Path for the tail-able per-analyzer progress feed (headless live status)."""
    try:
        import ida_loader
        idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if idb:
            return os.path.splitext(idb)[0] + ".tc_wow_analyzer.run_report.progress.jsonl"
    except Exception:
        pass
    return os.path.join(os.path.dirname(__file__), "..", "..", "run_report.progress.jsonl")


def _record_yield_and_regression(db, build, name, count, elapsed, run_id):
    """Record this analyzer's item yield and flag soft regressions vs the prior build.

    "Produced 5000 last build, 0 now" (a struct/pattern move) otherwise looks
    identical to status=OK and is the dominant new-build failure mode. Guarded —
    must never break the run."""
    if db is None or not build:
        return
    try:
        items = count if isinstance(count, int) and count >= 0 else 0
        prev = db.get_prev_yield(name, build)
        if prev is not None and prev >= 20:
            if items == 0:
                db.record_failure(build, "soft_zero", name, error_type="SoftZero",
                                  error_msg=f"produced 0 items; prior build produced {prev}",
                                  run_id=run_id)
            elif items < prev * 0.5:
                db.record_failure(build, "regression", name, error_type="YieldDrop",
                                  error_msg=f"produced {items}; prior build produced {prev} (drop >50%)",
                                  run_id=run_id)
        db.record_yield(build, name, items, status="OK",
                        elapsed_sec=round(elapsed, 1), run_id=run_id)
        db.commit()
    except Exception:
        pass


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
        ("RTTI to SQL", _run_rtti_to_sql),
        ("DB2 Metadata", _run_db2_metadata),
        ("DB2 LoadInfo Codegen", _run_db2_loadinfo_codegen),
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
        # Behavioral Spec merged into Execution Trace Simulation (which writes
        # `behavioral_spec:*` keys for backward compat with consumers).
        ("Protocol Sequencing", _run_protocol_sequencing),
        ("Auth Lifecycle", _run_auth_lifecycle),
        ("Build Delta", _run_build_delta),
        ("Callee Contracts", _run_callee_contracts),
        # Synthesis & generation
        ("Pseudocode Transpiler", _run_pseudocode_transpiler),
        ("Object Lifecycle", _run_object_lifecycle),
        ("Lua Contracts", _run_lua_contracts),
        # Intelligence & enrichment
        ("Subsystem Catalog", _run_subsystem_catalog),
        ("IDB Enrichment", _run_idb_enrichment),
        ("JAM Metadata Apply", _run_jam_metadata_apply),
        ("JAM Caller Index", _run_jam_caller_index),
        ("JAM Type Discovery", _run_jam_type_discovery),
        ("TC Opcode Xref", _run_tc_opcode_xref),
        ("Topic Deep Extractor", _run_topic_deep_extractor),
        ("Lua API Tag", _run_lua_api_tag),
        ("Hash Resolution", _run_hash_resolution),
        ("CVar Callback Rename", _run_cvar_callback_rename),
        ("Hash Function Naming", _run_hash_func_naming),
        ("CVar Consumer Tag", _run_cvar_consumer_tag),
        ("Cfunc Pattern Tag", _run_cfunc_pattern_tag),
        ("Typename Apply", _run_typename_apply),
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

    # Reconcile the registry (single source of truth for the UI/Analyzer Index)
    # against this run loop so an added analyzer can't silently desync the two.
    try:
        from tc_wow_analyzer.analyzers.registry import verify as _verify_registry
        _miss, _extra = _verify_registry([n for n, _ in analyzers])
        if _miss or _extra:
            msg_error(f"Analyzer registry drift — in run loop but not registry: "
                      f"{_miss}; in registry but not run loop: {_extra}")
    except Exception:
        pass

    total = 0
    details = []      # structured per-analyzer records
    run_start = time.time()
    start_snap = _gc_resource_snapshot()

    # Allow resume: skip analyzers listed in TC_SKIP_ANALYZERS env var (comma-separated).
    skip_set = {s.strip() for s in os.environ.get("TC_SKIP_ANALYZERS", "").split(",") if s.strip()}
    # Allow optional filter: only-run analyzers in TC_ONLY_ANALYZERS env var.
    only_set = {s.strip() for s in os.environ.get("TC_ONLY_ANALYZERS", "").split(",") if s.strip()}

    # ── Live-status + durable-failure wiring (all guarded — must never break a run) ──
    try:
        from tc_wow_analyzer.core.activity import ActivityManager
        _amgr = ActivityManager.get()
    except Exception:
        _amgr = None
    _db = getattr(session, "db", None)
    try:
        _build = int(session.cfg.build_number) if session and session.cfg else 0
    except Exception:
        _build = 0
    _run_id = str(int(run_start))
    _prog_path = _progress_path()
    _ran = 0  # count of analyzers that actually execute (not filter/env-skipped)
    _to_run = sum(1 for (n, _f) in analyzers
                  if (not only_set or n in only_set) and n not in skip_set)
    if _amgr:
        try:
            _amgr.extraction_start(_to_run or len(analyzers))
        except Exception:
            pass
    try:
        open(_prog_path, "w").close()  # truncate the progress feed at run start
    except Exception:
        pass

    def _emit_progress(rec):
        try:
            with open(_prog_path, "a", encoding="utf-8") as pf:
                pf.write(json.dumps(rec, default=str) + "\n")
        except Exception:
            pass

    for idx, (name, func) in enumerate(analyzers):
        if only_set and name not in only_set:
            details.append({"analyzer": name, "status": "SKIPPED_FILTER", "order": idx})
            continue
        if name in skip_set:
            msg_info(f"=== [{idx+1}/{len(analyzers)}] {name}: SKIPPED (TC_SKIP_ANALYZERS) ===")
            details.append({"analyzer": name, "status": "SKIPPED_ENV", "order": idx})
            results[name] = 0
            continue

        _ran += 1
        if _amgr:
            try:
                _amgr.extraction_step(_ran, name)
            except Exception:
                pass
        msg_info(f"=== [{idx+1}/{len(analyzers)}] Running analyzer: {name} ===")
        pre = _gc_resource_snapshot()
        t0 = time.time()
        record = {"analyzer": name, "order": idx, "start": pre.get("ts"),
                  "pre_mem_mb": pre.get("rss_mb")}

        try:
            count = func(session)
            elapsed = time.time() - t0
            post = _gc_resource_snapshot()
            results[name] = count
            total += (count if isinstance(count, int) and count >= 0 else 0)
            record.update({
                "status": "OK",
                "items": count,
                "elapsed_sec": round(elapsed, 2),
                "post_mem_mb": post.get("rss_mb"),
                "mem_delta_mb": (round(post["rss_mb"] - pre["rss_mb"], 1)
                                  if pre.get("rss_mb") and post.get("rss_mb") else None),
            })
            msg_info(f"  -> {name}: {count} items processed ({elapsed:.1f}s, "
                     f"mem {record.get('pre_mem_mb','?')}->{record.get('post_mem_mb','?')} MB)")
            if _amgr:
                try:
                    _amgr.extraction_done(name, "OK",
                                          count if isinstance(count, int) else -1,
                                          round(elapsed, 1))
                except Exception:
                    pass
            _record_yield_and_regression(_db, _build, name, count, elapsed, _run_id)
            _emit_progress({"ts": time.time(), "idx": _ran, "total": _to_run,
                            "name": name, "status": "OK",
                            "items": count if isinstance(count, int) else None,
                            "elapsed": round(elapsed, 1)})
        except Exception as e:
            elapsed = time.time() - t0
            post = _gc_resource_snapshot()
            tb = traceback.format_exc()
            record.update({
                "status": "FAILED",
                "error_type": type(e).__name__,
                "error_msg": str(e)[:500],
                "traceback": tb,
                "elapsed_sec": round(elapsed, 2),
                "post_mem_mb": post.get("rss_mb"),
            })
            results[name] = -1
            # Full traceback to the log file (single line -> multi-line appended)
            msg_error(f"  -> {name} FAILED after {elapsed:.1f}s: "
                      f"{type(e).__name__}: {e}")
            for tb_line in tb.rstrip().splitlines():
                _write_log("ERROR", f"    {tb_line}")
            if _amgr:
                try:
                    _amgr.extraction_done(name, "FAILED", -1, round(elapsed, 1))
                except Exception:
                    pass
            if _db is not None:
                _db.record_failure(_build, "analyzer_failed", name,
                                   error_type=type(e).__name__, error_msg=str(e),
                                   traceback=tb, run_id=_run_id)
                try:
                    _db.commit()
                except Exception:
                    pass
            _emit_progress({"ts": time.time(), "idx": _ran, "total": _to_run,
                            "name": name, "status": "FAILED",
                            "error": type(e).__name__, "elapsed": round(elapsed, 1)})

        details.append(record)

        # Write a checkpoint after every analyzer so a later crash still
        # produces a partial report we can diagnose.
        try:
            partial = {
                "run_start": run_start,
                "elapsed_sec": round(time.time() - run_start, 1),
                "complete": False,
                "analyzers_run": idx + 1,
                "analyzers_total": len(analyzers),
                "results": results,
                "details": details,
                "start_mem_mb": start_snap.get("rss_mb"),
            }
            with open(_report_path(), "w", encoding="utf-8") as f:
                json.dump(partial, f, indent=2, default=str)
        except Exception:
            pass  # checkpoint failures must never break the run

    # Final report
    elapsed_total = time.time() - run_start
    end_snap = _gc_resource_snapshot()
    summary_by_status = {}
    for d in details:
        s = d.get("status", "?")
        summary_by_status[s] = summary_by_status.get(s, 0) + 1

    final_report = {
        "run_start": run_start,
        "elapsed_sec": round(elapsed_total, 1),
        "complete": True,
        "analyzers_run": len(details),
        "analyzers_total": len(analyzers),
        "summary_by_status": summary_by_status,
        "results": results,
        "details": details,
        "start_mem_mb": start_snap.get("rss_mb"),
        "end_mem_mb": end_snap.get("rss_mb"),
    }
    try:
        with open(_report_path(), "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=2, default=str)
        msg_info(f"Run report written: {_report_path()}")
    except Exception as e:
        msg_error(f"Could not write run report: {e}")

    # Human-readable summary
    msg_info(f"=== Analysis complete: {total} total items across "
             f"{len(analyzers)} analyzers in {elapsed_total:.1f}s ===")
    msg_info(f"  Status: {summary_by_status}")
    failed = [d["analyzer"] for d in details if d.get("status") == "FAILED"]
    if failed:
        msg_error(f"  Failed analyzers ({len(failed)}): {', '.join(failed)}")
        msg_error(f"  Tracebacks in: {_report_path()}  (and .tc_wow_analyzer.log)")

    # Close out live status + reconcile the durable failure ledger.
    if _amgr:
        try:
            _amgr.extraction_end()
        except Exception:
            pass
    if _db is not None:
        try:
            # analyzers that were failing for this build but succeeded now -> resolved
            _db.resolve_failures(_build, "analyzer_failed", set(failed))
            _db.commit()
        except Exception:
            pass
    _emit_progress({"ts": time.time(), "event": "complete", "ran": _ran,
                    "total": _to_run, "failed": failed,
                    "summary": summary_by_status})
    return results


def _run_lua_api(session):
    from tc_wow_analyzer.analyzers.lua_api import analyze_lua_api
    return analyze_lua_api(session)


def _run_vtables(session):
    from tc_wow_analyzer.analyzers.vtable_analyzer import analyze_vtables
    return analyze_vtables(session)


def _run_rtti_to_sql(session):
    from tc_wow_analyzer.analyzers.rtti_to_sql import analyze_rtti_to_sql
    return analyze_rtti_to_sql(session)


def _run_db2_metadata(session):
    from tc_wow_analyzer.analyzers.db2_metadata import analyze_db2_metadata
    return analyze_db2_metadata(session)


def _run_db2_loadinfo_codegen(session):
    from tc_wow_analyzer.analyzers.db2_loadinfo_codegen import analyze_db2_loadinfo_codegen
    return analyze_db2_loadinfo_codegen(session)


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


def _run_auth_lifecycle(session):
    from tc_wow_analyzer.analyzers.auth_lifecycle import analyze_auth_lifecycle
    return analyze_auth_lifecycle(session)


def _run_subsystem_catalog(session):
    from tc_wow_analyzer.analyzers.subsystem_catalog import build_subsystem_catalog
    return build_subsystem_catalog(session)


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


def _run_jam_metadata_apply(session):
    from tc_wow_analyzer.analyzers.jam_metadata_apply import analyze_jam_metadata_apply
    return analyze_jam_metadata_apply(session)


def _run_jam_caller_index(session):
    from tc_wow_analyzer.analyzers.jam_caller_index import analyze_jam_caller_index
    return analyze_jam_caller_index(session)


def _run_lua_api_tag(session):
    from tc_wow_analyzer.analyzers.lua_api_tag import analyze_lua_api_tag
    return analyze_lua_api_tag(session)


def _run_jam_type_discovery(session):
    from tc_wow_analyzer.analyzers.jam_type_discovery import analyze_jam_type_discovery
    return analyze_jam_type_discovery(session)


def _run_tc_opcode_xref(session):
    from tc_wow_analyzer.analyzers.tc_opcode_xref import analyze_tc_opcode_xref
    return analyze_tc_opcode_xref(session)


def _run_topic_deep_extractor(session):
    from tc_wow_analyzer.analyzers.topic_deep_extractor import analyze_topic_deep_extractor
    return analyze_topic_deep_extractor(session)


def _run_hash_resolution(session):
    from tc_wow_analyzer.analyzers.hash_resolution import analyze_hash_resolution
    return analyze_hash_resolution(session)


def _run_cvar_callback_rename(session):
    from tc_wow_analyzer.analyzers.cvar_callback_rename import analyze_cvar_callback_rename
    return analyze_cvar_callback_rename(session)


def _run_hash_func_naming(session):
    from tc_wow_analyzer.analyzers.hash_func_naming import analyze_hash_func_naming
    return analyze_hash_func_naming(session)


def _run_cvar_consumer_tag(session):
    from tc_wow_analyzer.analyzers.cvar_consumer_tag import analyze_cvar_consumer_tag
    return analyze_cvar_consumer_tag(session)


def _run_cfunc_pattern_tag(session):
    from tc_wow_analyzer.analyzers.cfunc_pattern_tag import analyze_cfunc_pattern_tag
    return analyze_cfunc_pattern_tag(session)


def _run_typename_apply(session):
    from tc_wow_analyzer.analyzers.typename_apply import analyze_typename_apply
    return analyze_typename_apply(session)


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
