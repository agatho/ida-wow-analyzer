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

import sys
import time
import argparse


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
        choices=["quick", "full", "complete", "llm_only", "extraction", "quality"],
        help="Batch preset to run (default: full)",
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
        help="Max enrichment loop iterations (default: 5)",
    )
    parser.add_argument(
        "--system-filter", type=str, default=None,
        help="Only analyze functions in this system (e.g., housing)",
    )

    # IDA passes script args after the script path in sys.argv
    # Filter out IDA's own arguments
    script_args = []
    capture = False
    for arg in sys.argv:
        if capture:
            script_args.append(arg)
        elif arg.endswith("headless.py"):
            capture = True

    try:
        return parser.parse_args(script_args)
    except SystemExit:
        # argparse calls sys.exit on error — catch it in IDA context
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

        # Step 1: Import existing extractions
        if preset in ("full", "complete", "quick", "extraction"):
            print("[TC WoW] Step 1: Importing existing data...")
            from tc_wow_analyzer.batch.importer import run_import
            import_results = run_import(session)
            print(f"[TC WoW]   Imported {sum(v for v in import_results.values() if v > 0)} records")

        # Step 2: Run all analyzers
        if preset in ("full", "complete", "quick", "extraction"):
            print("[TC WoW] Step 2: Running analyzers...")
            from tc_wow_analyzer.analyzers import run_all_analyzers
            analysis_results = run_all_analyzers(session)
            for name, count in analysis_results.items():
                print(f"[TC WoW]   {name}: {count}")

        # Step 3: Import TC source knowledge
        if preset in ("full", "complete", "extraction"):
            print("[TC WoW] Step 3: Importing TrinityCore source...")
            from tc_wow_analyzer.batch.tc_source_importer import import_tc_source
            tc_count = import_tc_source(session)
            print(f"[TC WoW]   {tc_count} items from TC source")

        # Step 4: IDB Enrichment loop
        if preset in ("full", "complete"):
            print(f"[TC WoW] Step 4: IDB Enrichment (max {args.max_iterations} iterations)...")
            from tc_wow_analyzer.analyzers.idb_enrichment import enrich_idb
            enrich_count = enrich_idb(session)
            print(f"[TC WoW]   {enrich_count} enrichment changes")

        # Step 5: LLM semantic decompilation
        if preset in ("complete", "llm_only") and not skip_llm:
            print("[TC WoW] Step 5: LLM semantic decompilation...")
            from tc_wow_analyzer.analyzers.llm_semantic_decompiler import batch_semantic_decompile
            try:
                llm_count = batch_semantic_decompile(session, system_filter=args.system_filter)
                print(f"[TC WoW]   {llm_count} functions semantically decompiled")
            except Exception as llm_exc:
                print(f"[TC WoW]   LLM step failed: {llm_exc}")

        # Step 6: Quality analysis
        if preset in ("complete", "quality"):
            print("[TC WoW] Step 6: Quality analysis...")
            from tc_wow_analyzer.analyzers.conformance import run_conformance_analysis
            try:
                qa_count = run_conformance_analysis(session)
                print(f"[TC WoW]   {qa_count} conformance results")
            except Exception as qa_exc:
                print(f"[TC WoW]   Quality step failed: {qa_exc}")

        # Final: Generate reports
        print("[TC WoW] Generating reports...")
        stats = session.db.get_stats()
        total = sum(stats.values())
        print(f"[TC WoW]   Knowledge DB: {total} records across {len(stats)} tables")
        for table, count in sorted(stats.items()):
            if count > 0:
                print(f"[TC WoW]     {table}: {count}")

        # Export if output dir specified
        if args.output:
            run_export(args.output)

        elapsed = time.time() - start
        print(f"[TC WoW] Headless analysis complete in {elapsed:.1f}s")

        # Save IDB
        idc.save_database(idc.get_idb_path(), 0)
        print("[TC WoW] IDB saved.")

        session.shutdown()

    except Exception as e:
        print(f"[TC WoW] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def run_export(output_dir=None):
    """Export knowledge DB contents to JSON files for external use."""
    import os
    import json

    if not output_dir:
        output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "exports")
    os.makedirs(output_dir, exist_ok=True)

    from tc_wow_analyzer.core.session import PluginSession
    session = PluginSession()
    session.initialize()
    db = session.db

    exports = {
        "opcodes": db.fetchall("SELECT * FROM opcodes ORDER BY direction, internal_index"),
        "jam_types": db.fetchall("SELECT * FROM jam_types ORDER BY name"),
        "db2_tables": db.fetchall("SELECT name, field_count, record_size, layout_hash FROM db2_tables ORDER BY name"),
        "vtables": db.fetchall("SELECT * FROM vtables WHERE class_name IS NOT NULL ORDER BY class_name"),
        "functions_by_system": db.fetchall(
            "SELECT system, COUNT(*) as count FROM functions WHERE system IS NOT NULL "
            "GROUP BY system ORDER BY count DESC"),
    }

    for name, rows in exports.items():
        filepath = os.path.join(output_dir, f"tc_{name}.json")
        data = [dict(r) for r in rows]
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[TC WoW] Exported {len(data)} records to {filepath}")

    session.shutdown()


# Auto-run when executed as IDA script
if __name__ == "__main__" or "idaapi" in sys.modules:
    try:
        import idaapi
        if idaapi.cvar.batch:
            run_headless_analysis()
    except ImportError:
        pass
