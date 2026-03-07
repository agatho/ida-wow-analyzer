"""
Plugin session manager.
Ties together config, database, hooks, and provides the central
coordination point for all plugin subsystems.
"""

import os
import time

import ida_kernwin
import idaapi

from tc_wow_analyzer.core.config import cfg
from tc_wow_analyzer.core.db import KnowledgeDB
from tc_wow_analyzer.core.hooks import HookManager
from tc_wow_analyzer.core.utils import msg, msg_info, msg_error, msg_warn


class PluginSession:
    """Central plugin session — one per IDB."""

    def __init__(self):
        self.cfg = cfg
        self.db = None
        self.hooks = None
        self._actions = []
        self._initialized = False
        self._init_time = 0

    def initialize(self):
        """Initialize all subsystems. Called once when plugin first activates."""
        if self._initialized:
            return
        start = time.time()

        msg("Initializing TC WoW Binary Analyzer v0.1.0...")

        # Re-load config now that the IDB is available (the config singleton
        # may have been created before the IDB was fully loaded).
        self.cfg._load()

        # 1. Open the knowledge database
        db_path = self.cfg.db_path
        if not db_path:
            msg_error("No IDB loaded — cannot determine database path")
            return

        msg_info(f"Knowledge DB: {db_path}")
        self.db = KnowledgeDB(db_path)
        self.db.open()

        # Log stats
        stats = self.db.get_stats()
        total = sum(stats.values())
        msg_info(f"DB contains {total} records across {len(stats)} tables")
        for table, count in sorted(stats.items()):
            if count > 0:
                msg(f"  {table}: {count}")

        # 2. Register UI actions
        self._register_actions()

        # 3. Install hooks
        self.hooks = HookManager(self)
        self.hooks.install()

        # 4. Auto-start scheduler if configured
        self._start_scheduler_if_configured()

        self._init_time = time.time() - start
        self._initialized = True
        msg(f"Initialization complete in {self._init_time:.1f}s")

        # First-run hint
        if not self.cfg.is_configured and total == 0:
            msg("")
            msg("  First time? Use 'TC WoW: Settings...' to configure paths,")
            msg("  then 'TC WoW: Run Tasks...' to import data and run analysis.")
            msg("")

    def _start_scheduler_if_configured(self):
        """Auto-start the scheduler if it's enabled in config."""
        try:
            from tc_wow_analyzer.core.scheduler import load_config, start_scheduler
            sched_cfg = load_config(self)
            if sched_cfg.enabled:
                start_scheduler(self)
        except Exception as e:
            msg_warn(f"Scheduler auto-start skipped: {e}")

    def shutdown(self):
        """Clean shutdown — save state, remove hooks, close DB."""
        if not self._initialized:
            return

        # Stop scheduler
        try:
            from tc_wow_analyzer.core.scheduler import stop_scheduler
            stop_scheduler()
        except Exception:
            pass

        msg("Shutting down...")

        # Remove hooks
        if self.hooks:
            self.hooks.remove()

        # Unregister actions
        self._unregister_actions()

        # Close DB
        if self.db:
            self.db.close()
            self.db = None

        self._initialized = False
        msg("Shutdown complete.")

    def get_registered_actions(self):
        """Return list of registered action names for context menus."""
        return [name for name, _, _ in self._actions]

    # ─── UI Actions ───────────────────────────────────────────────

    def _register_actions(self):
        """Register IDA UI actions for context menus and hotkeys.

        The label here becomes the text shown in the menu item.
        Menu structure is defined in tc_wow_analyzer.py _attach_menu_items().
        """
        actions = [
            ("tc_wow:show_dashboard", "Show Dashboard",
             "Ctrl+Shift+W", self._action_show_dashboard),
            ("tc_wow:settings", "Settings...",
             "", self._action_settings),
            ("tc_wow:run_tasks", "Run Tasks...",
             "Ctrl+Shift+A", self._action_run_tasks),
            ("tc_wow:analyze_function", "Analyze Current Function",
             "", self._action_analyze_function),
            ("tc_wow:lookup_opcode", "Lookup Opcode at Cursor",
             "", self._action_lookup_opcode),
            ("tc_wow:classify_function", "Classify Function",
             "", self._action_classify_function),
            ("tc_wow:import_data", "Import Existing Data",
             "", self._action_import_data),
            ("tc_wow:housing_view", "Housing Deep Dive",
             "", self._action_housing_view),
            ("tc_wow:quality_dashboard", "Quality Dashboard",
             "Ctrl+Shift+Q", self._action_quality_dashboard),
            ("tc_wow:web_dashboard", "Web Dashboard",
             "Ctrl+Shift+D", self._action_web_dashboard),
            ("tc_wow:scheduler", "Scheduler...",
             "", self._action_scheduler),
            ("tc_wow:llm_select", "Select Model...",
             "", self._action_llm_select),
            ("tc_wow:llm_run", "Run Task Now...",
             "Ctrl+Shift+L", self._action_llm_run),
            ("tc_wow:activity", "Activity Log",
             "Ctrl+Shift+G", self._action_activity_view),
        ]

        for action_name, label, hotkey, handler in actions:
            action_desc = idaapi.action_desc_t(
                action_name,
                label,
                _ActionHandler(handler),
                hotkey,
                label,
            )
            if idaapi.register_action(action_desc):
                self._actions.append((action_name, label, hotkey))

        msg_info(f"Registered {len(self._actions)} UI actions")

    def _unregister_actions(self):
        """Unregister all UI actions."""
        for action_name, _, _ in self._actions:
            idaapi.unregister_action(action_name)
        self._actions.clear()

    # ─── Action Handlers ──────────────────────────────────────────

    def _action_show_dashboard(self):
        """Show the main WoW System Navigator dashboard."""
        try:
            from tc_wow_analyzer.ui.dashboard import show_dashboard
            show_dashboard(self)
        except Exception as e:
            msg_error(f"Dashboard error: {e}")
            import traceback
            traceback.print_exc()

    def _action_analyze_function(self):
        """Analyze the function at the current cursor position.

        If Hex-Rays is available, offers to edit the function prototype
        using prompt_function_prototype_ex() (IDA 9.3+) which also
        returns the edited function name for further processing.
        """
        ea = ida_kernwin.get_screen_ea()
        if ea == idaapi.BADADDR:
            return

        import ida_funcs
        func = ida_funcs.get_func(ea)
        if not func:
            msg_warn(f"No function at 0x{ea:X}")
            return

        ea = func.start_ea
        msg_info(f"Analyzing function at 0x{ea:X}...")

        # Try IDA 9.3+ prompt_function_prototype_ex() for interactive editing
        try:
            import ida_hexrays
            if hasattr(ida_hexrays, 'prompt_function_prototype_ex'):
                result = ida_hexrays.prompt_function_prototype_ex(ea)
                if result:
                    new_name = result.get("name", "") if isinstance(result, dict) else str(result)
                    if new_name:
                        msg_info(f"Function prototype updated: {new_name}")
            elif hasattr(ida_hexrays, 'prompt_function_prototype'):
                ida_hexrays.prompt_function_prototype(ea)
        except (ImportError, AttributeError):
            pass
        except Exception as exc:
            msg_warn(f"Prototype edit: {exc}")

        # Run analysis via knowledge DB
        if self.db:
            func_row = self.db.get_function(ea)
            if func_row:
                msg(f"  System: {func_row['system'] or 'unknown'}")
                msg(f"  Subsystem: {func_row['subsystem'] or 'unknown'}")
                msg(f"  Confidence: {func_row['confidence']}%")
            else:
                msg(f"  Function not yet classified. Use 'Classify Function' first.")

    def _action_lookup_opcode(self):
        """Look up opcode info for the function at cursor."""
        ea = ida_kernwin.get_screen_ea()
        if ea == idaapi.BADADDR:
            return
        if not self.db:
            msg_error("No database loaded")
            return
        row = self.db.fetchone(
            "SELECT * FROM opcodes WHERE handler_ea = ?", (ea,))
        if row:
            msg(f"Opcode: {row['tc_name'] or 'unknown'} "
                f"({row['direction']} idx=0x{row['internal_index']:X})")
            if row['jam_type']:
                msg(f"  JAM type: {row['jam_type']}")
            msg(f"  Status: {row['status']}")
        else:
            msg(f"No opcode handler found at 0x{ea:X}")

    def _action_classify_function(self):
        """Manually classify the current function into a game system."""
        ea = ida_kernwin.get_screen_ea()
        if ea == idaapi.BADADDR:
            return
        systems = [
            "housing", "neighborhood", "combat", "quest", "inventory",
            "movement", "social", "pvp", "crafting", "achievement",
            "talent", "pet_battle", "loot", "auction", "mythic_plus",
            "vehicle", "delves", "garrison", "lua_api", "networking",
            "rendering", "audio", "crypto", "database", "scripting",
        ]
        choice = ida_kernwin.ask_str("", 0,
            "Enter system name:\n" + ", ".join(systems))
        if choice and self.db:
            self.db.upsert_function(ea, system=choice.strip())
            self.db.commit()
            msg_info(f"Classified 0x{ea:X} as '{choice.strip()}'")

    def _action_settings(self):
        """Open the plugin settings dialog."""
        try:
            from tc_wow_analyzer.ui.settings_dialog import show_settings
            show_settings(self)
        except Exception as e:
            msg_error(f"Settings dialog error: {e}")
            import traceback
            traceback.print_exc()

    def _action_run_tasks(self):
        """Open the task runner dialog to select and execute tasks."""
        if not self.db:
            msg_error("No database loaded")
            return
        try:
            from tc_wow_analyzer.ui.settings_dialog import show_task_runner
            show_task_runner(self)
        except Exception as e:
            msg_error(f"Task runner error: {e}")
            import traceback
            traceback.print_exc()

    def _action_import_data(self):
        """Import existing JSON extractions into the knowledge DB."""
        if not self.db:
            msg_error("No database loaded")
            return
        if not self.cfg.extraction_dir:
            msg_warn("No extraction directory configured. Open Settings first.")
            self._action_settings()
            return
        msg("Starting data import...")
        try:
            from tc_wow_analyzer.batch.importer import run_import
            run_import(self)
        except Exception as e:
            msg_error(f"Import failed: {e}")
            import traceback
            traceback.print_exc()

    def _action_housing_view(self):
        """Show the Housing System Deep Dive view."""
        try:
            from tc_wow_analyzer.ui.housing_view import show_housing_deep_dive
            show_housing_deep_dive(self)
        except Exception as e:
            msg_error(f"Housing view error: {e}")
            import traceback
            traceback.print_exc()

    def _action_quality_dashboard(self):
        """Show the Quality Analysis Dashboard."""
        if not self.db:
            msg_error("No database loaded")
            return
        try:
            from tc_wow_analyzer.ui.conformance_view import show_quality_dashboard
            show_quality_dashboard(self)
        except Exception as e:
            msg_error(f"Quality dashboard error: {e}")
            import traceback
            traceback.print_exc()

    def _action_web_dashboard(self):
        """Launch the interactive web analysis dashboard."""
        if not self.db:
            msg_error("No database loaded")
            return
        try:
            from tc_wow_analyzer.ui.web_dashboard import start_web_dashboard
            start_web_dashboard(self)
        except Exception as e:
            msg_error(f"Web dashboard error: {e}")
            import traceback
            traceback.print_exc()

    def _action_scheduler(self):
        """Open the LLM scheduler configuration dialog."""
        if not self.db:
            msg_error("No database loaded")
            return
        try:
            from tc_wow_analyzer.ui.scheduler_dialog import show_scheduler_dialog
            show_scheduler_dialog(self)
        except Exception as e:
            msg_error(f"Scheduler dialog error: {e}")
            import traceback
            traceback.print_exc()

    def _action_llm_select(self):
        """Open the LLM model selector dialog."""
        if not self.db:
            msg_error("No database loaded")
            return
        try:
            from tc_wow_analyzer.ui.llm_dialog import show_llm_selector
            show_llm_selector(self)
        except Exception as e:
            msg_error(f"LLM selector error: {e}")
            import traceback
            traceback.print_exc()

    def _action_activity_view(self):
        """Show the live activity log viewer."""
        try:
            from tc_wow_analyzer.ui.activity_view import show_activity_view
            show_activity_view()
        except Exception as e:
            msg_error(f"Activity view error: {e}")
            import traceback
            traceback.print_exc()

    def _action_llm_run(self):
        """Run an LLM task immediately with the selected model."""
        if not self.db:
            msg_error("No database loaded")
            return
        try:
            from tc_wow_analyzer.ui.llm_dialog import show_llm_run
            show_llm_run(self)
        except Exception as e:
            msg_error(f"LLM run error: {e}")
            import traceback
            traceback.print_exc()


class _ActionHandler(idaapi.action_handler_t):
    """Generic action handler that wraps a callable."""

    def __init__(self, callback):
        super().__init__()
        self._callback = callback

    def activate(self, ctx):
        self._callback()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
