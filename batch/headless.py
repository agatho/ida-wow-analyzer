"""
Headless Pipeline Consolidation
Provides IDAPython script entry points for running the full analysis
pipeline in headless (batch) mode via IDA's -S flag.

Usage:
    ida64 -A -S"tc_wow_analyzer/batch/headless.py" wow_dump.bin

IDA 9.3+ supports passing arguments after the script path:
    ida64 -A -S"tc_wow_analyzer/batch/headless.py --preset full --output /tmp/out" wow_dump.bin

This replaces the need for separate orchestrator scripts by using
the plugin's unified analysis framework.
"""

import os
import sys
import time
import argparse
import traceback


def _parse_headless_args():
    """Parse command-line arguments passed via IDA's -S flag.

    IDA 9.3+ makes -S script arguments available via sys.argv.
    Returns parsed namespace with: preset, output_dir, skip_llm, max_iterations.
    """
    parser = argparse.ArgumentParser(
        description="TC WoW Analyzer headless pipeline",
        prog="headless.py",
    )
    parser.add_argument(
        "--preset", type=str, default="full",
        choices=["quick", "full", "complete", "llm_only", "extraction", "quality", "analyzers_only"],
        help="Batch preset to run (default: full). 'analyzers_only' skips imports/enrichment/LLM/QA — useful for per-analyzer probes when DB is already populated.",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output directory for exports",
    )
    parser.add_argument(
        "--skip-llm", action="store_true",
        help="Skip LLM-dependent tasks even if preset includes them",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=5,
        help="Max enrichment loop iterations. NOTE: enrich_idb() runs its own "
             "convergence loop and takes no iteration cap, so this value is "
             "advisory only (kept for CLI compatibility).",
    )
    parser.add_argument(
        "--system-filter", type=str, default=None,
        help="Only analyze functions in this system (e.g., housing)",
    )

    # IDA passes script args after the script path in sys.argv.
    # Match either the canonical entry (headless.py) or the space-free wrapper
    # (tc_wow_headless_run.py) — IDA's -S can't handle spaces in script paths,
    # so callers often invoke via the wrapper.
    script_args = []
    capture = False
    for arg in sys.argv:
        if capture:
            script_args.append(arg)
        elif arg.endswith("headless.py") or arg.endswith("tc_wow_headless_run.py"):
            capture = True

    try:
        return parser.parse_args(script_args)
    except SystemExit:
        # argparse calls sys.exit on error — catch it in IDA context. Falling
        # through to the defaults would silently run the HEAVIEST preset
        # ("full", multiple hours) after a typo, so say so loudly instead.
        print(f"[TC WoW] WARNING: could not parse script args {script_args!r} — "
              f"falling back to defaults (preset=full). Check your -S arguments.")
        return parser.parse_args([])


def run_headless_analysis():
    """Entry point for headless IDA analysis."""
    import idc
    import idaapi

    # Wait for auto-analysis to complete
    idaapi.auto_wait()

    args = _parse_headless_args()

    start = time.time()
    print(f"[TC WoW] Starting headless analysis pipeline (preset={args.preset})...")

    try:
        from tc_wow_analyzer.core.config import cfg
        from tc_wow_analyzer.core.db import KnowledgeDB
        from tc_wow_analyzer.core.session import PluginSession

        session = PluginSession()
        session.initialize()

        if args.output:
            print(f"[TC WoW] Output directory: {args.output}")
        if args.system_filter:
            print(f"[TC WoW] System filter: {args.system_filter}")

        # Preset-driven task selection
        skip_llm = args.skip_llm
        preset = args.preset
        step_results = {}

        def _step(number, title, presets, action):
            """Run one pipeline step in isolation.

            Every step import lives INSIDE this try. Before, the imports sat
            outside the enclosing try, so a single bad symbol (there were two:
            `batch_semantic_decompile` and `run_conformance_analysis`, neither
            of which exists) raised ImportError past the outer handler and
            called sys.exit(1) -- killing the report, the export AND the IDB
            save after a multi-hour run. A broken step must never cost the run
            its results.
            """
            if preset not in presets:
                step_results[title] = "skipped"
                return None
            print(f"[TC WoW] Step {number}: {title}...")
            t_step = time.time()
            try:
                value = action()
                step_results[title] = value
                print(f"[TC WoW]   {title}: {value} ({time.time() - t_step:.1f}s)")
                return value
            except Exception as step_exc:
                step_results[title] = f"FAILED: {type(step_exc).__name__}"
                print(f"[TC WoW]   {title} FAILED after {time.time() - t_step:.1f}s: "
                      f"{type(step_exc).__name__}: {step_exc}")
                traceback.print_exc()
                try:
                    session.db.record_failure(
                        int(session.cfg.build_number or 0), "pipeline_step", title,
                        error_type=type(step_exc).__name__,
                        error_msg=str(step_exc)[:500])
                    session.db.commit()
                except Exception:
                    pass
                return None

        # Step 1: Import existing extractions
        def _do_import():
            from tc_wow_analyzer.batch.importer import run_import
            results = run_import(session)
            return sum(v for v in results.values() if isinstance(v, int) and v > 0)

        _step(1, "Import AutoDump data", ("full", "complete", "quick", "extraction"),
              _do_import)

        # Step 2: Run all analyzers
        def _do_analyzers():
            from tc_wow_analyzer.analyzers import run_all_analyzers
            results = run_all_analyzers(session)
            for name, count in results.items():
                print(f"[TC WoW]     {name}: {count}")
            return sum(c for c in results.values() if isinstance(c, int) and c > 0)

        _step(2, "Run analyzers",
              ("full", "complete", "quick", "extraction", "analyzers_only"),
              _do_analyzers)

        # Step 3: Import TC source knowledge
        def _do_tc_source():
            from tc_wow_analyzer.batch.tc_source_importer import import_tc_source
            return import_tc_source(session)

        _step(3, "Import TrinityCore source", ("full", "complete", "extraction"),
              _do_tc_source)

        # Step 4: IDB Enrichment
        def _do_enrich():
            from tc_wow_analyzer.analyzers.idb_enrichment import enrich_idb
            return enrich_idb(session)

        _step(4, "IDB enrichment", ("full", "complete"), _do_enrich)

        # Step 5: LLM semantic decompilation
        def _do_llm():
            from tc_wow_analyzer.analyzers.llm_semantic_decompiler import (
                semantically_decompile_all, semantically_decompile_system)
            if args.system_filter:
                # --system-filter used to be silently dropped: the old call
                # passed system_filter= to a function that does not exist.
                return semantically_decompile_system(
                    session, args.system_filter, apply_to_idb_flag=True)
            total_llm = 0
            for direction in ("CMSG", "SMSG"):
                total_llm += semantically_decompile_all(
                    session, apply_to_idb_flag=True, direction=direction)
            return total_llm

        if skip_llm and preset in ("complete", "llm_only"):
            print("[TC WoW] Step 5: LLM semantic decompilation SKIPPED (--skip-llm)")
            step_results["LLM semantic decompilation"] = "skipped"
        else:
            _step(5, "LLM semantic decompilation", ("complete", "llm_only"), _do_llm)

        # Step 6: Quality analysis
        def _do_quality():
            from tc_wow_analyzer.analyzers.conformance import analyze_conformance
            return analyze_conformance(session, system_filter=args.system_filter)

        _step(6, "Conformance scoring", ("complete", "quality"), _do_quality)

        # Step 7: TrinityCore code generation
        # This is the plugin's actual product. It used to be reachable only
        # from the GUI batch dialog, so no headless preset ever emitted a
        # single .h file.
        def _do_codegen():
            from tc_wow_analyzer.codegen.writer import run_all_codegen, codegen_out_dir
            results = run_all_codegen(session)
            for name, count in sorted(results.items()):
                print(f"[TC WoW]     codegen {name}: {count}")
            print(f"[TC WoW]     output dir: {codegen_out_dir(session)}")
            return sum(c for c in results.values() if isinstance(c, int) and c > 0)

        _step(7, "TrinityCore codegen", ("full", "complete", "extraction"), _do_codegen)

        # Final: Generate reports
        print("[TC WoW] Generating reports...")
        print("[TC WoW]   Step summary:")
        for title, value in step_results.items():
            print(f"[TC WoW]     {title}: {value}")
        stats = session.db.get_stats()
        total = sum(stats.values())
        print(f"[TC WoW]   Knowledge DB: {total} records across {len(stats)} tables")
        for table, count in sorted(stats.items()):
            if count > 0:
                print(f"[TC WoW]     {table}: {count}")

        # Export. Without --output the export goes next to the IDB rather than
        # being skipped: a batch run that produces no artifacts at all is never
        # what the caller wanted.
        try:
            run_export(args.output, session=session)
        except Exception as exp_exc:
            print(f"[TC WoW]   Export failed: {exp_exc}")

        elapsed = time.time() - start
        print(f"[TC WoW] Headless analysis complete in {elapsed:.1f}s")

        # Save IDB unless explicitly opted out (per-probe runs set TC_SKIP_IDB_SAVE=1
        # so they don't drift the baseline between probe iters).
        skip_save = os.environ.get("TC_SKIP_IDB_SAVE", "").strip() not in ("", "0", "false", "False")
        if not skip_save:
            idc.save_database(idc.get_idb_path(), 0)
            print("[TC WoW] IDB saved.")

        session.shutdown()

    except Exception as e:
        print(f"[TC WoW] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def run_export(output_dir=None, session=None):
    """Export knowledge DB contents to JSON files for external use.

    Two fixes over the previous version:

      * It no longer builds a SECOND PluginSession. Doing so opened a second
        SQLite connection and then called shutdown() on it, which resets the
        module-level default DB and unregisters every UI action out from under
        the still-running outer session.
      * The export covered 5 of 20 tables. Everything an external consumer
        might want is exported now, and each table is isolated so one bad
        query cannot cost the rest their output.
    """
    import json

    owns_session = session is None
    if owns_session:
        from tc_wow_analyzer.core.session import PluginSession
        session = PluginSession()
        session.initialize()

    if not output_dir:
        # Default next to the IDB rather than a path relative to this file:
        # a run without --output used to write nothing at all.
        try:
            import ida_loader
            idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        except Exception:
            idb = None
        base = os.path.dirname(idb) if idb else os.getcwd()
        output_dir = os.path.join(base, "tc_wow_export")

    os.makedirs(output_dir, exist_ok=True)
    db = session.db

    exports = {
        "opcodes": "SELECT * FROM opcodes ORDER BY direction, internal_index",
        "jam_types": "SELECT * FROM jam_types ORDER BY name",
        "db2_tables": ("SELECT name, field_count, record_size, layout_hash, "
                       "file_data_id, index_field FROM db2_tables ORDER BY name"),
        "vtables": ("SELECT * FROM vtables WHERE class_name IS NOT NULL "
                    "ORDER BY class_name"),
        "functions_by_system": (
            "SELECT system, COUNT(*) as count FROM functions "
            "WHERE system IS NOT NULL GROUP BY system ORDER BY count DESC"),
        "functions_by_subsystem": (
            "SELECT subsystem, COUNT(*) as count FROM functions "
            "WHERE subsystem IS NOT NULL GROUP BY subsystem ORDER BY count DESC"),
        "named_functions": (
            "SELECT ea, rva, name, system, subsystem, confidence FROM functions "
            "WHERE name IS NOT NULL AND name != '' ORDER BY rva"),
        "update_fields": ("SELECT * FROM update_fields "
                          "ORDER BY object_type, field_offset"),
        "lua_api": "SELECT * FROM lua_api ORDER BY namespace, method",
        "tc_packets": "SELECT * FROM tc_packets ORDER BY name",
        "annotations": "SELECT * FROM annotations ORDER BY ea",
        "strings": ("SELECT ea, value, system, xref_count FROM strings "
                    "WHERE system IS NOT NULL ORDER BY ea"),
        "analyzer_yield": "SELECT * FROM analyzer_yield ORDER BY build DESC, analyzer",
        "failure_ledger": ("SELECT * FROM failure_ledger "
                           "ORDER BY build DESC, kind, subject"),
        "builds": "SELECT * FROM builds ORDER BY build_number DESC",
    }

    written = 0
    for name, sql in exports.items():
        try:
            rows = db.fetchall(sql)
        except Exception as exc:
            print(f"[TC WoW] Export skipped {name}: {exc}")
            continue
        filepath = os.path.join(output_dir, f"tc_{name}.json")
        try:
            data = [dict(r) for r in rows]
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            written += 1
            print(f"[TC WoW] Exported {len(data)} records to {filepath}")
        except Exception as exc:
            print(f"[TC WoW] Export failed for {name}: {exc}")

    print(f"[TC WoW] Export complete: {written}/{len(exports)} tables -> {output_dir}")

    if owns_session:
        session.shutdown()
    return output_dir


# Auto-run ONLY when IDA executes THIS FILE directly as its -S script.
#
# Two things this guard must not do:
#
#  1. Fire on a plain import. The old condition was
#     `__name__ == "__main__" or "idaapi" in sys.modules`, which is true for
#     ANY import inside idat — so `from tc_wow_analyzer.batch.headless import
#     run_export` re-launched the entire multi-hour pipeline as a side effect.
#
#  2. Fire when a wrapper drives us. `c:\dumps\pipeline\tc_wow_headless_run.py`
#     exists because idat's -S cannot handle the spaces in the plugin path; it
#     imports this module and calls run_headless_analysis() itself. Matching on
#     sys.argv[0] would fire here as well and run the whole pipeline TWICE.
#
# `__name__ == "__main__"` is true exactly when idat runs this file as the
# script and false when anyone imports it, which is precisely the distinction.
if __name__ == "__main__":
    try:
        import idaapi
        if idaapi.cvar.batch:
            run_headless_analysis()
    except ImportError:
        pass
