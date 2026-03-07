"""
Settings Dialog
Provides a GUI for configuring plugin paths, build info, and selecting
which analysis tasks to run. Persists to tc_wow_config.json next to the IDB.

Uses ida_kernwin.Form (ASK_FORM) for IDA-native dialog integration.
"""

import os

import ida_kernwin
import idaapi

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


# ─── Settings Dialog ───────────────────────────────────────────────

class SettingsDialog(ida_kernwin.Form):
    """Main plugin settings form."""

    FORM_TEMPLATE = r"""STARTITEM 0
TC WoW Analyzer — Settings

<##Paths##Extraction directory (JSON exports)\::{iExtractionDir}>
<TrinityCore source directory\::{iTcSourceDir}>
<Pipeline directory (optional)\::{iPipelineDir}>

<##Build Configuration##Build number\::{iBuildNumber}>
<Image base (hex, 0x...)\::{iImageBase}>

<##Options##Auto-run analysis on plugin load\::{cAutoRun}>
<Install Hex-Rays annotations\::{cHexRays}>
<Register MCP tools\::{cMCP}>{cOptions}>

"""

    def __init__(self, cfg):
        self._cfg = cfg

        # Pre-fill from current config
        extraction_dir = cfg.extraction_dir or ""
        tc_source_dir = cfg.tc_source_dir or ""
        pipeline_dir = cfg.get("pipeline_dir") or ""
        build_number = str(cfg.build_number) if cfg.build_number else ""
        image_base = f"0x{cfg.image_base:X}" if cfg.image_base else ""

        auto_run = cfg.get("auto_run_analysis", default=False)
        hexrays = cfg.get("enable_hexrays_annotations", default=True)
        mcp = cfg.get("enable_mcp_tools", default=True)

        # Build form controls
        controls = {
            "iExtractionDir": ida_kernwin.Form.DirInput(
                value=extraction_dir,
                swidth=60,
            ),
            "iTcSourceDir": ida_kernwin.Form.DirInput(
                value=tc_source_dir,
                swidth=60,
            ),
            "iPipelineDir": ida_kernwin.Form.DirInput(
                value=pipeline_dir,
                swidth=60,
            ),
            "iBuildNumber": ida_kernwin.Form.StringInput(
                value=build_number,
                swidth=20,
            ),
            "iImageBase": ida_kernwin.Form.StringInput(
                value=image_base,
                swidth=20,
            ),
            "cOptions": ida_kernwin.Form.ChkGroupControl((
                "cAutoRun", "cHexRays", "cMCP",
            ), value=(
                (1 if auto_run else 0)
                | (2 if hexrays else 0)
                | (4 if mcp else 0)
            )),
        }

        super().__init__(self.FORM_TEMPLATE, controls)

    def apply_to_config(self):
        """Read form values and apply to the config object."""
        cfg = self._cfg

        extraction_dir = self.iExtractionDir.value.strip()
        tc_source_dir = self.iTcSourceDir.value.strip()
        pipeline_dir = self.iPipelineDir.value.strip()
        build_number = self.iBuildNumber.value.strip()
        image_base_str = self.iImageBase.value.strip()

        if extraction_dir:
            cfg.set("extraction_dir", extraction_dir)
        if tc_source_dir:
            cfg.set("tc_source_dir", tc_source_dir)
        if pipeline_dir:
            cfg.set("pipeline_dir", pipeline_dir)

        # Build-specific config
        if build_number:
            cfg.set("build_number", int(build_number))
            build_info = {}
            if extraction_dir:
                build_info["extraction_dir"] = extraction_dir
            if image_base_str:
                try:
                    build_info["image_base"] = int(image_base_str, 0)
                except ValueError:
                    pass
            if build_info:
                for k, v in build_info.items():
                    cfg.set("builds", build_number, k, v)

        # Options
        opts = self.cOptions.value
        cfg.set("auto_run_analysis", bool(opts & 1))
        cfg.set("enable_hexrays_annotations", bool(opts & 2))
        cfg.set("enable_mcp_tools", bool(opts & 4))


def show_settings(session):
    """Show the settings dialog and save if user clicks OK."""
    cfg = session.cfg
    dlg = SettingsDialog(cfg)
    dlg.Compile()

    ok = dlg.Execute()
    if ok == 1:
        dlg.apply_to_config()
        saved = cfg.save()
        if saved:
            msg_info(f"Settings saved to {saved}")
        else:
            msg_warn("Settings applied to current session (could not save to disk)")
    dlg.Free()
    return ok == 1


# ─── Task Registry with Phases & Dependencies ───────────────────

# Each task: (key, label, phase, requires)
# Phase determines execution order. Tasks in the same phase can run
# independently. A task's "requires" lists what must run first.
_TASK_REGISTRY = [
    # Phase 1: Data Import (no dependencies)
    ("import_extractions",      "Import JSON extractions",              1, []),
    ("import_tc_source",        "Import TrinityCore source",            1, []),
    # Phase 2: Core Binary Analysis (standalone)
    ("lua_api",                 "Lua API Analysis",                     2, []),
    ("vtable_analyzer",         "VTable Analysis",                      2, []),
    ("db2_metadata",            "DB2 Metadata Analysis",                2, []),
    ("pe_metadata",             "PE Metadata Deep Dive",                2, []),
    ("data_archaeology",        "Data Section Archaeology",             2, []),
    ("cvar_extraction",         "CVar Console Variable Extraction",     2, []),
    # Phase 3: Opcode & Structure (benefits from Phase 2)
    ("opcode_dispatcher",       "Opcode Dispatcher Analysis",           3, ["vtable_analyzer"]),
    ("jam_recovery",            "JAM Message Structure Recovery",       3, ["opcode_dispatcher"]),
    ("update_fields",           "Update Field Analysis",                3, ["jam_recovery"]),
    ("handler_jam_linking",     "Handler-JAM Linking",                  3, ["opcode_dispatcher", "jam_recovery"]),
    # Phase 4: Deep Extraction (needs opcodes + JAM)
    ("wire_format_recovery",    "Wire Format Recovery (bit-level)",     4, ["jam_recovery"]),
    ("enum_recovery",           "Enum Universe Recovery",               4, ["opcode_dispatcher"]),
    ("constant_mining",         "Game Constant Mining",                 4, []),
    ("object_layout",           "Object Layout Recovery",               4, ["vtable_analyzer"]),
    ("response_reconstruction", "Response Packet Reconstruction",       4, ["opcode_dispatcher", "jam_recovery"]),
    ("updatefield_descriptors", "UpdateField Descriptor Extraction",    4, ["update_fields"]),
    # Phase 5: Quality & Conformance (needs TC source + Phase 3)
    ("db2_drift",               "DB2 Schema Drift Detection",           5, ["db2_metadata", "import_tc_source"]),
    ("validation_extractor",    "Validation Rule Extraction",           5, ["opcode_dispatcher"]),
    ("conformance_scoring",     "Conformance Scoring",                  5, ["opcode_dispatcher", "import_tc_source"]),
    ("state_machine_recovery",  "State Machine Recovery",               5, ["opcode_dispatcher"]),
    ("dependency_mapper",       "Cross-System Dependency Mapping",      5, ["opcode_dispatcher", "handler_jam_linking"]),
    ("test_generator",          "Test Case Generation",                 5, ["conformance_scoring"]),
    ("packet_replay",           "Packet Replay Conformance",            5, ["wire_format_recovery"]),
    # Phase 6: Behavioral Analysis (needs Phase 3-4)
    ("taint_analysis",          "Data Flow Taint Analysis",             6, ["opcode_dispatcher"]),
    ("behavioral_spec",         "Handler Behavioral Specification",     6, ["opcode_dispatcher", "jam_recovery"]),
    ("protocol_sequencing",     "Protocol Sequencing Recovery",         6, ["opcode_dispatcher"]),
    ("build_delta",             "Cross-Build Delta Transpiler",         6, []),
    ("callee_contracts",        "Callee Behavioral Contracts",          6, ["opcode_dispatcher"]),
    # Phase 7: Structural & Graph (needs Phase 2-3)
    ("function_similarity",     "Function Similarity Clustering",       7, []),
    ("shared_code_detection",   "Client-Server Shared Code",            7, ["import_tc_source"]),
    ("thread_safety_map",       "Thread Safety Map",                    7, []),
    ("call_graph_analytics",    "Call Graph Analytics",                  7, []),
    ("indirect_call_resolution","Indirect Call Resolution",             7, ["vtable_analyzer"]),
    ("event_system_recovery",   "Event System Recovery",                7, ["opcode_dispatcher"]),
    ("alloc_class_catalog",     "Allocation Size Class Catalog",        7, ["vtable_analyzer"]),
    ("negative_space",          "Negative Space Analysis",              7, ["opcode_dispatcher", "jam_recovery"]),
    # Phase 8: Semantic & Pattern (needs Phase 3-6)
    ("symbolic_constraints",    "Symbolic Constraint Propagation",      8, ["opcode_dispatcher"]),
    ("binary_tc_alignment",     "Binary-TC Source Alignment",           8, ["import_tc_source", "opcode_dispatcher"]),
    ("return_value_semantics",  "Return Value Semantics",               8, ["opcode_dispatcher"]),
    ("instruction_ngrams",      "Instruction N-gram Mining",            8, []),
    ("execution_trace_sim",     "Execution Trace Simulation",           8, ["opcode_dispatcher"]),
    ("compiler_artifacts",      "Compiler Artifact Mining",             8, []),
    # Phase 9: Synthesis & Intelligence (needs most of the above)
    ("pseudocode_transpiler",   "Pseudocode-to-TC Transpiler",          9, ["opcode_dispatcher", "jam_recovery", "wire_format_recovery"]),
    ("object_lifecycle",        "Object Lifecycle Recovery",             9, ["vtable_analyzer", "object_layout"]),
    ("lua_contracts",           "Lua API Contract Analysis",            9, ["lua_api", "import_tc_source"]),
    ("string_intelligence",     "String-Driven Intelligence",           9, []),
    ("idb_enrichment",          "IDB Enrichment Feedback Loop",         9, ["opcode_dispatcher", "vtable_analyzer"]),
    ("cross_synthesis",         "Cross-Analyzer Synthesis",             9, ["opcode_dispatcher", "jam_recovery", "conformance_scoring"]),
    # Phase 10: Data Verification & Multi-Build
    ("db2_data_content",        "DB2 Data Content Analysis",           10, ["db2_metadata"]),
    ("sniff_verification",      "Sniff Format Verification",           10, ["wire_format_recovery"]),
    ("multi_build_temporal",    "Multi-Build Temporal Analysis",       10, []),
    ("cross_build_migration",   "Cross-Build Migration Pipeline",      10, ["opcode_dispatcher"]),
    ("sniff_conformance_loop",  "Sniff Conformance Auto-Fix Loop",     10, ["wire_format_recovery", "sniff_verification"]),
    # Phase 11: LLM-Powered (needs Phase 3+, requires LLM model)
    ("llm_semantic_decompiler", "LLM Semantic Decompiler",             11, ["opcode_dispatcher"]),
    ("handler_scaffolding",     "Handler Scaffolding Generator",       11, ["opcode_dispatcher", "jam_recovery", "wire_format_recovery"]),
    # Phase 12: Code Generation (needs analysis results)
    ("codegen_packets",         "Generate Packet Scaffolding",         12, ["jam_recovery", "wire_format_recovery"]),
    ("codegen_db2",             "Generate DB2 Stores",                 12, ["db2_metadata"]),
    ("codegen_updatefields",    "Generate UpdateFields",               12, ["update_fields"]),
    ("codegen_opcodes",         "Generate Opcode Enums",               12, ["opcode_dispatcher"]),
    # IDA 9.3+ Enhancements
    ("lumina_pull",             "Lumina: Pull Function Metadata",       0, []),
    ("lumina_push",             "Lumina: Push Named Functions",          0, ["idb_enrichment"]),
    ("apply_struct_types",      "Apply Struct Types to IDB (__fixed/__at)", 9, ["object_layout"]),
    ("build_decompile_cache",   "Build Decompilation Cache (headless)", 0, []),
    # Utility (standalone)
    ("web_dashboard",           "Launch Web Analysis Dashboard",        0, []),
]

# Build a lookup dict for quick access
_TASK_BY_KEY = {t[0]: t for t in _TASK_REGISTRY}

# ─── Predefined Batch Presets ────────────────────────────────────

_BATCH_PRESETS = [
    (
        "Quick Start",
        "Import data + core binary analysis (Phases 1-3, ~9 tasks)",
        lambda: [t[0] for t in _TASK_REGISTRY if t[2] in (1, 2, 3)],
    ),
    (
        "Full Analysis",
        "All binary analysis passes without LLM (Phases 1-10, ~51 tasks)",
        lambda: [t[0] for t in _TASK_REGISTRY if 1 <= t[2] <= 10],
    ),
    (
        "Complete + LLM",
        "Everything including LLM-powered analysis (Phases 1-12, ~55 tasks)",
        lambda: [t[0] for t in _TASK_REGISTRY if t[2] >= 1],
    ),
    (
        "Code Generation Only",
        "Generate TC C++ code from existing analysis (Phase 12)",
        lambda: [t[0] for t in _TASK_REGISTRY if t[2] == 12],
    ),
    (
        "Quality + Conformance",
        "Conformance scoring, drift detection, tests (Phase 5, needs Quick Start first)",
        lambda: [t[0] for t in _TASK_REGISTRY if t[2] == 5],
    ),
    (
        "Deep Extraction",
        "Wire formats, enums, object layouts (Phase 4, needs Quick Start first)",
        lambda: [t[0] for t in _TASK_REGISTRY if t[2] == 4],
    ),
    (
        "LLM Tasks Only",
        "LLM semantic decompiler + handler scaffolding (needs Quick Start first)",
        lambda: [t[0] for t in _TASK_REGISTRY if t[2] == 11],
    ),
    (
        "Custom...",
        "Pick individual tasks from the full list",
        None,  # triggers the detailed chooser
    ),
]


# ─── Preset Chooser ─────────────────────────────────────────────

class BatchPresetChooser(ida_kernwin.Choose):
    """First step: pick a predefined batch or go to custom selection."""

    def __init__(self):
        super().__init__(
            "TC WoW Analyzer — Select Task Batch",
            [
                ["Batch", 24],
                ["Description", 62],
            ],
            flags=ida_kernwin.Choose.CH_MODAL,
            width=95,
            height=12,
        )
        self._items = [[name, desc] for name, desc, _ in _BATCH_PRESETS]

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n]


# ─── Custom Task Chooser (multi-select with deps) ───────────────

class CustomTaskChooser(ida_kernwin.Choose):
    """Detailed task list with phase and dependency info. Multi-select."""

    def __init__(self):
        super().__init__(
            "TC WoW Analyzer — Custom Task Selection  (Ins/Space=toggle, Enter=run)",
            [
                ["Ph", 3],
                ["Task", 40],
                ["Requires", 40],
            ],
            flags=(ida_kernwin.Choose.CH_MULTI
                   | ida_kernwin.Choose.CH_MODAL),
            width=95,
            height=30,
        )
        self._items = []
        self._task_keys = []
        for key, label, phase, requires in _TASK_REGISTRY:
            if phase == 0:
                ph_str = "-"
            else:
                ph_str = str(phase)
            req_str = ", ".join(requires) if requires else "(none)"
            self._items.append([ph_str, label, req_str])
            self._task_keys.append(key)

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n]


# ─── show_task_runner ────────────────────────────────────────────

def show_task_runner(session):
    """Two-step task runner: check for resume, pick a preset batch, or custom."""

    # Check for interrupted batch first
    resume = _check_resume(session)
    if resume == "cancel":
        return  # user cancelled the resume dialog
    if resume:
        msg_info(f"Resuming interrupted batch ({len(resume)} tasks remaining)...")
        _execute_tasks(session, resume, batch_name="Resumed")
        return

    if not session.cfg.is_configured and not session.cfg.extraction_dir:
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "No extraction directory configured.\n"
            "Would you like to open Settings first?"
        )
        if answer == ida_kernwin.ASKBTN_YES:
            if not show_settings(session):
                return

    # Step 1: Pick a batch preset
    preset_chooser = BatchPresetChooser()
    sel = preset_chooser.Show(modal=True)

    # Normalize
    if isinstance(sel, list):
        sel = sel[0] if sel else -1
    if sel is None or sel < 0 or sel >= len(_BATCH_PRESETS):
        return

    name, desc, task_fn = _BATCH_PRESETS[sel]

    if task_fn is not None:
        # Predefined batch
        tasks = task_fn()
        count = len(tasks)
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            f"Run batch: {name}\n\n"
            f"{desc}\n\n"
            f"{count} tasks will execute in dependency order.\n"
            f"Continue?"
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return
    else:
        # Custom selection
        custom = CustomTaskChooser()
        selected = custom.Show(modal=True)

        # Normalize IDA return value
        if selected is None or selected == -1 or selected == []:
            msg_warn("No tasks selected")
            return
        if isinstance(selected, int):
            selected = [selected]

        tasks = [custom._task_keys[i] for i in selected]

        if not tasks:
            msg_warn("No tasks selected")
            return

    # Sort tasks by phase order for correct execution
    phase_order = {t[0]: t[2] for t in _TASK_REGISTRY}
    tasks.sort(key=lambda k: phase_order.get(k, 99))

    msg_info(f"Running {len(tasks)} tasks ({name})...")
    _execute_tasks(session, tasks, batch_name=name)


_BATCH_STATE_KEY = "task_batch_state"


def _load_batch_state(db):
    """Load saved batch progress from the knowledge DB."""
    return db.kv_get(_BATCH_STATE_KEY, default=None)


def _save_batch_state(db, state):
    """Save batch progress to the knowledge DB (crash-safe)."""
    db.kv_set(_BATCH_STATE_KEY, state)
    db.commit()


def _clear_batch_state(db):
    """Remove saved batch state after completion."""
    db.execute("DELETE FROM kv_store WHERE key = ?", (_BATCH_STATE_KEY,))
    db.commit()


def _check_resume(session):
    """Check for an interrupted batch and offer to resume.

    Returns the task list to resume, or None if no resume needed.
    """
    if not session.db:
        return None

    state = _load_batch_state(session.db)
    if not state or not isinstance(state, dict):
        return None

    all_tasks = state.get("tasks", [])
    completed = state.get("completed", [])
    batch_name = state.get("batch_name", "Unknown")
    remaining = [t for t in all_tasks if t not in completed]

    if not remaining:
        _clear_batch_state(session.db)
        return None

    import time
    started = state.get("started_at", 0)
    elapsed = ""
    if started:
        ago = time.time() - started
        if ago < 3600:
            elapsed = f" (started {int(ago / 60)}min ago)"
        else:
            elapsed = f" (started {ago / 3600:.1f}h ago)"

    answer = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_YES,
        f"Interrupted batch detected: {batch_name}{elapsed}\n\n"
        f"Completed: {len(completed)} / {len(all_tasks)} tasks\n"
        f"Remaining: {len(remaining)} tasks\n\n"
        f"Resume from where it left off?"
    )
    if answer == ida_kernwin.ASKBTN_YES:
        return remaining
    elif answer == ida_kernwin.ASKBTN_NO:
        _clear_batch_state(session.db)
        return None  # user wants fresh start
    else:
        return "cancel"  # user hit Cancel


_DECOMPILE_TASKS = {
    "alloc_class_catalog", "behavioral_spec", "binary_tc_alignment",
    "callee_contracts", "conformance_scoring", "constant_mining",
    "cross_build_migration", "cvar_extraction", "dependency_mapper",
    "enum_recovery", "event_system_recovery", "execution_trace_sim",
    "function_similarity", "handler_scaffolding", "idb_enrichment",
    "indirect_call_resolution", "jam_recovery", "llm_semantic_decompiler",
    "lua_contracts", "negative_space", "object_layout", "object_lifecycle",
    "packet_replay", "protocol_sequencing", "pseudocode_transpiler",
    "response_reconstruction", "return_value_semantics",
    "shared_code_detection", "state_machine_recovery", "string_intelligence",
    "symbolic_constraints", "taint_analysis", "test_generator",
    "thread_safety_map", "validation_extractor", "wire_format_recovery",
}


def _check_decompile_safety(session, tasks):
    """Check if batch needs decompilation and offer headless mode.

    Returns:
        "headless" — user chose headless decompile (will close IDA)
        "skip"     — user chose to skip decompilation (cache-only mode)
        "proceed"  — no decompilation needed, or user accepts risk
    """
    needs_decompile = [t for t in tasks if t in _DECOMPILE_TASKS]
    if not needs_decompile:
        return "proceed"

    # Check how many functions are already cached
    cached = 0
    total_funcs = 0
    try:
        import idautils
        total_funcs = sum(1 for _ in idautils.Functions())
        if session.db:
            row = session.db.fetchone("SELECT COUNT(*) as c FROM cfunc_cache")
            if row:
                cached = row["c"]
    except Exception:
        pass

    skip_count = 0
    try:
        from tc_wow_analyzer.core.utils import get_skiplist_count
        skip_count = get_skiplist_count()
    except Exception:
        pass

    msg = (
        f"{len(needs_decompile)} of your selected tasks use decompilation.\n"
        f"The decompiler can crash IDA on certain functions.\n\n"
        f"  Functions: ~{total_funcs:,}\n"
        f"  Cached: {cached:,}\n"
        f"  Skip list: {skip_count} (known crashers)\n\n"
        f"Options:\n"
        f"  YES  = Run headless decompilation first (safe, closes IDA)\n"
        f"  NO   = Use cached results only (no new decompilation)\n"
        f"  CANCEL = Proceed anyway (risk crash)\n"
    )

    answer = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_YES,
        f"TC WoW Analyzer — Decompilation Safety\n\n{msg}"
    )

    if answer == ida_kernwin.ASKBTN_YES:
        return "headless"
    elif answer == ida_kernwin.ASKBTN_NO:
        return "skip"
    else:
        return "proceed"


def _execute_tasks(session, tasks, batch_name="Custom"):
    """Execute the selected tasks in order with crash-safe checkpointing.

    After each task completes, progress is saved to the knowledge DB.
    If IDA crashes, the next run will detect the interrupted batch and
    offer to resume from the last completed task.
    """
    import time
    from tc_wow_analyzer.core.activity import ActivityManager

    # Check decompilation safety before starting
    decompile_mode = _check_decompile_safety(session, tasks)

    if decompile_mode == "headless":
        # Launch headless decompilation — this will close IDA.
        # Save the batch state so it resumes after IDA reopens.
        db = session.db
        state = {
            "batch_name": batch_name,
            "tasks": list(tasks),
            "completed": [],
            "results": {},
            "started_at": time.time(),
        }
        if db:
            _save_batch_state(db, state)
            db.commit()

        msg_info("Launching headless decompilation first...")
        msg_info("Batch will resume automatically when IDA reopens.")
        from tc_wow_analyzer.batch.headless_decompile import launch_headless_decompile
        launch_headless_decompile(session, reopen_after=True)
        return  # IDA will close

    if decompile_mode == "skip":
        # Enable cache-only mode — safe_decompile will return None for
        # uncached functions instead of calling the decompiler
        from tc_wow_analyzer.core import utils as _utils
        _utils._decompile_cache_only = True
        msg_info("Running in cache-only mode — no new decompilation")

    amgr = ActivityManager.get()
    results = {}
    db = session.db

    # Save initial batch state
    state = {
        "batch_name": batch_name,
        "tasks": list(tasks),
        "completed": [],
        "results": {},
        "started_at": time.time(),
    }
    if db:
        _save_batch_state(db, state)

    from tc_wow_analyzer.core.utils import maybe_autosave_idb

    amgr.batch_start(batch_name, tasks)

    # Auto-open the activity view so the user can see progress
    try:
        from tc_wow_analyzer.ui.activity_view import show_activity_view
        show_activity_view()
    except Exception:
        pass

    for i, task_name in enumerate(tasks):
        msg_info(f"[{i + 1}/{len(tasks)}] >>> {task_name}")
        amgr.task_start(task_name)
        amgr.task_progress(i + 1, len(tasks))
        try:
            count = _run_single_task(session, task_name)
            results[task_name] = count
            msg_info(f"    -> {count} items")
            amgr.task_end(task_name, count=count)
        except Exception as e:
            msg_error(f"    -> FAILED: {e}")
            import traceback
            traceback.print_exc()
            results[task_name] = -1
            amgr.task_end(task_name, result=f"FAILED: {e}")

        amgr.batch_task_done(task_name)

        # Checkpoint after each task
        state["completed"].append(task_name)
        state["results"][task_name] = results[task_name]
        if db:
            _save_batch_state(db, state)

        # Auto-save IDB every 5 minutes during long batches
        maybe_autosave_idb()

    # All done — clear the batch state
    if db:
        _clear_batch_state(db)

    amgr.batch_end()

    # Reset cache-only mode
    try:
        from tc_wow_analyzer.core import utils as _utils
        _utils._decompile_cache_only = False
    except Exception:
        pass

    # Summary
    msg_info("=" * 50)
    msg_info("Task execution summary:")
    for name, count in results.items():
        status = f"{count} items" if count >= 0 else "FAILED"
        msg_info(f"  {name}: {status}")
    total_ok = sum(1 for v in results.values() if v >= 0)
    total_fail = sum(1 for v in results.values() if v < 0)
    msg_info(f"Done: {total_ok} succeeded, {total_fail} failed")
    msg_info("=" * 50)


def _run_single_task(session, task_name):
    """Run a single named task."""
    if task_name == "import_extractions":
        from tc_wow_analyzer.batch.importer import run_import
        results = run_import(session)
        return sum(v for v in results.values() if v > 0)

    if task_name == "import_tc_source":
        from tc_wow_analyzer.batch.tc_source_importer import import_tc_source
        return import_tc_source(session)

    if task_name == "opcode_dispatcher":
        from tc_wow_analyzer.analyzers.opcode_dispatcher import analyze_opcode_dispatcher
        return analyze_opcode_dispatcher(session)

    if task_name == "jam_recovery":
        from tc_wow_analyzer.analyzers.jam_recovery import analyze_jam_types
        return analyze_jam_types(session)

    if task_name == "db2_metadata":
        from tc_wow_analyzer.analyzers.db2_metadata import analyze_db2_metadata
        return analyze_db2_metadata(session)

    if task_name == "vtable_analyzer":
        from tc_wow_analyzer.analyzers.vtable_analyzer import analyze_vtables
        return analyze_vtables(session)

    if task_name == "lua_api":
        from tc_wow_analyzer.analyzers.lua_api import analyze_lua_api
        return analyze_lua_api(session)

    if task_name == "update_fields":
        from tc_wow_analyzer.analyzers.update_fields import analyze_update_fields
        return analyze_update_fields(session)

    if task_name == "handler_jam_linking":
        from tc_wow_analyzer.analyzers.opcode_dispatcher import analyze_handler_jam_types
        return analyze_handler_jam_types(session)

    if task_name == "db2_drift":
        from tc_wow_analyzer.analyzers.db2_drift import analyze_db2_drift
        return analyze_db2_drift(session)

    if task_name == "validation_extractor":
        from tc_wow_analyzer.analyzers.validation_extractor import extract_validations
        return extract_validations(session)

    if task_name == "conformance_scoring":
        from tc_wow_analyzer.analyzers.conformance import analyze_conformance
        return analyze_conformance(session)

    if task_name == "state_machine_recovery":
        from tc_wow_analyzer.analyzers.state_machine import recover_state_machines
        return recover_state_machines(session)

    if task_name == "dependency_mapper":
        from tc_wow_analyzer.analyzers.dependency_mapper import analyze_dependencies
        return analyze_dependencies(session)

    if task_name == "test_generator":
        from tc_wow_analyzer.analyzers.test_generator import generate_tests
        return generate_tests(session)

    if task_name == "packet_replay":
        from tc_wow_analyzer.analyzers.packet_replay import analyze_packet_replay
        return analyze_packet_replay(session)

    # Deep extraction
    if task_name == "wire_format_recovery":
        from tc_wow_analyzer.analyzers.wire_format_recovery import analyze_wire_formats
        return analyze_wire_formats(session)

    if task_name == "enum_recovery":
        from tc_wow_analyzer.analyzers.enum_recovery import recover_enums
        return recover_enums(session)

    if task_name == "constant_mining":
        from tc_wow_analyzer.analyzers.constant_mining import mine_constants
        return mine_constants(session)

    if task_name == "object_layout":
        from tc_wow_analyzer.analyzers.object_layout import recover_object_layouts
        return recover_object_layouts(session)

    if task_name == "response_reconstruction":
        from tc_wow_analyzer.analyzers.response_reconstruction import reconstruct_responses
        return reconstruct_responses(session)

    # Behavioral analysis
    if task_name == "taint_analysis":
        from tc_wow_analyzer.analyzers.taint_analysis import analyze_taint_flows
        return analyze_taint_flows(session)

    if task_name == "behavioral_spec":
        from tc_wow_analyzer.analyzers.behavioral_spec import generate_behavioral_specs
        return generate_behavioral_specs(session)

    if task_name == "protocol_sequencing":
        from tc_wow_analyzer.analyzers.protocol_sequencing import recover_protocol_sequence
        return recover_protocol_sequence(session)

    if task_name == "build_delta":
        from tc_wow_analyzer.analyzers.build_delta import analyze_build_delta
        return analyze_build_delta(session, None)

    if task_name == "callee_contracts":
        from tc_wow_analyzer.analyzers.callee_contracts import recover_contracts
        return recover_contracts(session)

    # Synthesis & generation
    if task_name == "pseudocode_transpiler":
        from tc_wow_analyzer.analyzers.pseudocode_transpiler import transpile_all_handlers
        return transpile_all_handlers(session)

    if task_name == "object_lifecycle":
        from tc_wow_analyzer.analyzers.object_lifecycle import recover_object_lifecycles
        return recover_object_lifecycles(session)

    if task_name == "lua_contracts":
        from tc_wow_analyzer.analyzers.lua_contracts import analyze_lua_contracts
        return analyze_lua_contracts(session)

    # Intelligence & enrichment
    if task_name == "idb_enrichment":
        from tc_wow_analyzer.analyzers.idb_enrichment import enrich_idb
        return enrich_idb(session)

    if task_name == "string_intelligence":
        from tc_wow_analyzer.analyzers.string_intelligence import analyze_string_intelligence
        return analyze_string_intelligence(session)

    if task_name == "cross_synthesis":
        from tc_wow_analyzer.analyzers.cross_analyzer_synthesis import synthesize_all
        return synthesize_all(session)

    # Data & verification
    if task_name == "db2_data_content":
        from tc_wow_analyzer.analyzers.db2_data_content import analyze_db2_content
        return analyze_db2_content(session)

    if task_name == "sniff_verification":
        from tc_wow_analyzer.analyzers.sniff_verification import verify_sniff_formats
        return verify_sniff_formats(session)

    if task_name == "multi_build_temporal":
        from tc_wow_analyzer.analyzers.multi_build_temporal import analyze_temporal_evolution
        return analyze_temporal_evolution(session)

    # Structural analysis
    if task_name == "function_similarity":
        from tc_wow_analyzer.analyzers.function_similarity import cluster_similar_functions
        return cluster_similar_functions(session)

    if task_name == "shared_code_detection":
        from tc_wow_analyzer.analyzers.shared_code_detection import detect_shared_code
        return detect_shared_code(session)

    if task_name == "thread_safety_map":
        from tc_wow_analyzer.analyzers.thread_safety_map import map_thread_safety
        return map_thread_safety(session)

    # Gap & completeness
    if task_name == "negative_space":
        from tc_wow_analyzer.analyzers.negative_space import analyze_negative_space
        return analyze_negative_space(session)

    if task_name == "updatefield_descriptors":
        from tc_wow_analyzer.analyzers.updatefield_descriptor import extract_updatefield_descriptors
        return extract_updatefield_descriptors(session)

    if task_name == "alloc_class_catalog":
        from tc_wow_analyzer.analyzers.alloc_class_catalog import build_class_catalog
        return build_class_catalog(session)

    # PE & low-level
    if task_name == "pe_metadata":
        from tc_wow_analyzer.analyzers.pe_metadata import analyze_pe_metadata
        return analyze_pe_metadata(session)

    if task_name == "data_archaeology":
        from tc_wow_analyzer.analyzers.data_section_archaeology import mine_data_sections
        return mine_data_sections(session)

    if task_name == "cvar_extraction":
        from tc_wow_analyzer.analyzers.cvar_extraction import extract_cvars
        return extract_cvars(session)

    # Graph & architecture
    if task_name == "call_graph_analytics":
        from tc_wow_analyzer.analyzers.call_graph_analytics import analyze_call_graph
        return analyze_call_graph(session)

    if task_name == "indirect_call_resolution":
        from tc_wow_analyzer.analyzers.indirect_call_resolver import resolve_indirect_calls
        return resolve_indirect_calls(session)

    if task_name == "event_system_recovery":
        from tc_wow_analyzer.analyzers.event_system_recovery import recover_event_system
        return recover_event_system(session)

    # Semantic analysis
    if task_name == "symbolic_constraints":
        from tc_wow_analyzer.analyzers.symbolic_constraints import propagate_constraints
        return propagate_constraints(session)

    if task_name == "binary_tc_alignment":
        from tc_wow_analyzer.analyzers.binary_tc_alignment import align_binary_to_tc
        return align_binary_to_tc(session)

    if task_name == "return_value_semantics":
        from tc_wow_analyzer.analyzers.return_value_semantics import analyze_return_semantics
        return analyze_return_semantics(session)

    # Pattern mining
    if task_name == "instruction_ngrams":
        from tc_wow_analyzer.analyzers.instruction_ngram import analyze_instruction_ngrams
        return analyze_instruction_ngrams(session)

    if task_name == "execution_trace_sim":
        from tc_wow_analyzer.analyzers.execution_trace_sim import simulate_execution
        return simulate_execution(session)

    if task_name == "compiler_artifacts":
        from tc_wow_analyzer.analyzers.compiler_artifacts import mine_compiler_artifacts
        return mine_compiler_artifacts(session)

    # LLM & generation
    if task_name == "llm_semantic_decompiler":
        from tc_wow_analyzer.analyzers.llm_semantic_decompiler import semantically_decompile_all
        return semantically_decompile_all(session)

    if task_name == "handler_scaffolding":
        from tc_wow_analyzer.analyzers.handler_scaffolding import generate_all_scaffolds
        return generate_all_scaffolds(session)

    # Cross-build & conformance
    if task_name == "cross_build_migration":
        from tc_wow_analyzer.analyzers.cross_build_migration import generate_migration
        return generate_migration(session)

    if task_name == "sniff_conformance_loop":
        from tc_wow_analyzer.analyzers.sniff_conformance_loop import run_conformance_loop
        return run_conformance_loop(session)

    # Web dashboard
    if task_name == "web_dashboard":
        from tc_wow_analyzer.ui.web_dashboard import start_web_dashboard
        start_web_dashboard(session)
        return 1

    if task_name == "codegen_packets":
        return _run_codegen_packets(session)

    if task_name == "codegen_db2":
        return _run_codegen_db2(session)

    if task_name == "codegen_updatefields":
        return _run_codegen_updatefields(session)

    if task_name == "codegen_opcodes":
        return _run_codegen_opcodes(session)

    # IDA 9.3+ Enhancement tasks
    if task_name == "lumina_pull":
        from tc_wow_analyzer.core.lumina_integration import pull_metadata
        stats = pull_metadata(session.db)
        return stats.get("renamed", 0)

    if task_name == "lumina_push":
        from tc_wow_analyzer.core.lumina_integration import push_metadata
        stats = push_metadata(session.db)
        return stats.get("pushed", 0)

    if task_name == "apply_struct_types":
        from tc_wow_analyzer.analyzers.object_layout import apply_layouts_to_idb
        return apply_layouts_to_idb(session)

    if task_name == "build_decompile_cache":
        from tc_wow_analyzer.batch.headless_decompile import launch_headless_decompile
        success = launch_headless_decompile(session, reopen_after=True)
        return 1 if success else 0

    msg_warn(f"Unknown task: {task_name}")
    return 0


def _run_codegen_packets(session):
    """Generate packet scaffolding for all known JAM types with fields."""
    from tc_wow_analyzer.codegen.packet_scaffolding import generate_all_for_jam
    db = session.db
    rows = db.fetchall(
        "SELECT name FROM jam_types WHERE fields_json IS NOT NULL")
    count = 0
    for row in rows:
        result = generate_all_for_jam(session, row["name"])
        if result:
            count += 1
    return count


def _run_codegen_db2(session):
    """Generate DB2 store code for all known tables."""
    from tc_wow_analyzer.codegen.db2_stores import generate_loadinfo
    db = session.db
    rows = db.fetchall("SELECT name FROM db2_tables")
    count = 0
    for row in rows:
        code = generate_loadinfo(session, row["name"])
        if code and not code.startswith("//"):
            count += 1
    return count


def _run_codegen_updatefields(session):
    """Generate UpdateFields code for all object types."""
    from tc_wow_analyzer.codegen.update_fields_gen import generate_all_update_fields
    code = generate_all_update_fields(session)
    return len(code.split("struct ")) - 1 if code else 0


def _run_codegen_opcodes(session):
    """Generate opcode enum entries."""
    from tc_wow_analyzer.codegen.opcode_enums import generate_opcode_enum
    cmsg = generate_opcode_enum(session, "CMSG")
    smsg = generate_opcode_enum(session, "SMSG")
    return cmsg.count("\n") + smsg.count("\n")
