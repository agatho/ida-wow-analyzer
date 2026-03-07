"""
TrinityCore WoW Binary Analyzer — IDA Pro 9.3 Plugin Entry Point
================================================================
Main loader that registers the plugin with IDA. The actual implementation
lives in the tc_wow_analyzer package.

Install: Copy this file + tc_wow_analyzer/ directory to IDA plugins folder.
Hotkey: Ctrl+Shift+W
Menu: Edit -> Plugins -> TC WoW Analyzer
"""

import sys
import os
import idaapi

# Ensure the plugins directory is on sys.path so our package can import
_plugins_dir = os.path.dirname(os.path.abspath(__file__))
if _plugins_dir not in sys.path:
    sys.path.insert(0, _plugins_dir)


def _unload_package(package_name):
    """Remove all modules belonging to a package from sys.modules for hot-reload."""
    to_remove = [
        name for name in sys.modules
        if name == package_name or name.startswith(package_name + ".")
    ]
    for name in to_remove:
        del sys.modules[name]


class TcWowAnalyzerPlugmod(idaapi.plugmod_t):
    """Plugin module — performs the actual work."""

    # Global reference so it survives garbage collection
    _instance = None

    def __init__(self):
        super().__init__()
        self._initialized = False
        self._session = None
        TcWowAnalyzerPlugmod._instance = self
        # Auto-initialize after IDA finishes loading the database
        self._schedule_auto_init()

    def _schedule_auto_init(self):
        """Schedule initialization after IDA's IDB is ready.

        IDA 9.x loads the IDB asynchronously — a 500ms timer is often too
        early.  We retry every 1s up to 30 times (30s) until the IDB path
        is available, then initialize.
        """
        self._init_retries = 0

        def _do_init():
            self._init_retries += 1
            # Check if IDB is available yet
            try:
                import ida_loader
                idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            except Exception:
                idb = None

            if not idb:
                if self._init_retries < 30:
                    return 1000  # retry in 1 second
                else:
                    print("[TC-WoW] Gave up waiting for IDB after 30s")
                    return -1  # stop

            self._ensure_init()
            return -1  # don't repeat
        idaapi.register_timer(1000, _do_init)

    def _ensure_init(self):
        """Initialize the plugin session and attach menu items."""
        if self._initialized:
            return True

        try:
            from tc_wow_analyzer.core.session import PluginSession
            self._session = PluginSession()
            self._session.initialize()

            # Only mark as initialized if session actually succeeded
            if not self._session._initialized:
                print("[TC-WoW] Session initialization incomplete — will retry on hotkey")
                return False

            self._initialized = True
            # Attach key actions to the main menu bar
            self._attach_menu_items()
            # Make session accessible from IDA Python console as `session`
            import builtins
            builtins.session = self._session
            print("[TC-WoW] 'session' variable available in Python console")
            return True
        except Exception as e:
            print(f"[TC-WoW] Initialization failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _attach_menu_items(self):
        """Attach plugin actions to IDA's Edit menu as a top-level submenu.

        Uses "Edit/TC WoW/<label>" path pattern — identical to how Gepetto
        uses "Edit/Gepetto/<label>".  This creates a proper cascading submenu
        under Edit.  The "Edit/Plugins/" path only shows flat plugin entries.

        The menu_path is the full path including the action's display label
        at the end.  IDA creates intermediate submenus automatically.
        """
        menu_items = [
            # ── Main ──
            ("tc_wow:show_dashboard",    "Edit/TC WoW/Show Dashboard"),
            ("tc_wow:run_tasks",         "Edit/TC WoW/Run Tasks..."),
            ("tc_wow:settings",          "Edit/TC WoW/Settings..."),
            # ── Analysis submenu ──
            ("tc_wow:analyze_function",  "Edit/TC WoW/Analysis/Analyze Current Function"),
            ("tc_wow:lookup_opcode",     "Edit/TC WoW/Analysis/Lookup Opcode at Cursor"),
            ("tc_wow:classify_function", "Edit/TC WoW/Analysis/Classify Function"),
            ("tc_wow:import_data",       "Edit/TC WoW/Analysis/Import Existing Data"),
            # ── Views submenu ──
            ("tc_wow:quality_dashboard", "Edit/TC WoW/Views/Quality Dashboard"),
            ("tc_wow:web_dashboard",     "Edit/TC WoW/Views/Web Dashboard"),
            ("tc_wow:housing_view",      "Edit/TC WoW/Views/Housing Deep Dive"),
            # ── LLM submenu ──
            ("tc_wow:llm_select",        "Edit/TC WoW/LLM/Select Model..."),
            ("tc_wow:llm_run",           "Edit/TC WoW/LLM/Run Task Now..."),
            ("tc_wow:scheduler",         "Edit/TC WoW/LLM/Scheduler..."),
        ]
        attached = 0
        for action_name, menu_path in menu_items:
            if idaapi.attach_action_to_menu(menu_path, action_name,
                                            idaapi.SETMENU_APP):
                attached += 1
        if attached:
            print(f"[TC-WoW] Attached {attached} items to Edit > TC WoW menu")

    def run(self, arg):
        """Called when the user activates the plugin (hotkey or menu)."""
        # Hot-reload for development: if Shift is held, reload all modules
        if arg == 1:
            print("[TC-WoW] Hot-reloading plugin modules...")
            self._initialized = False
            self._session = None
            _unload_package("tc_wow_analyzer")

        if not self._ensure_init():
            return

        # Show the main dashboard
        try:
            from tc_wow_analyzer.ui.dashboard import show_dashboard
            show_dashboard(self._session)
        except Exception as e:
            print(f"[TC-WoW] Dashboard error: {e}")
            import traceback
            traceback.print_exc()

    def __del__(self):
        if self._session:
            try:
                self._session.shutdown()
            except Exception:
                pass


class TcWowAnalyzerPlugin(idaapi.plugin_t):
    """Plugin registration — IDA loads this at startup."""

    flags = idaapi.PLUGIN_MULTI | idaapi.PLUGIN_FIX
    comment = "TrinityCore WoW Binary Analyzer"
    help = "Comprehensive WoW client analysis for TrinityCore server emulation"
    wanted_name = "TC WoW Analyzer"
    wanted_hotkey = "Ctrl-Shift-W"

    def init(self):
        # Only activate for x86-64 binaries (WoW client)
        # IDA 9.x: get_inf_structure() removed, use ida_ida module instead
        try:
            import ida_ida
            if not ida_ida.inf_is_64bit():
                return idaapi.PLUGIN_SKIP
        except (ImportError, AttributeError):
            # Fallback for older IDA versions
            try:
                info = idaapi.get_inf_structure()
                if not info.is_64bit():
                    return idaapi.PLUGIN_SKIP
            except AttributeError:
                pass  # Can't determine bitness, load anyway

        print("[TC-WoW] Plugin loaded. Press Ctrl+Shift+W to open dashboard.")
        print("[TC-WoW] Right-click -> TC WoW -> Settings... to configure paths.")
        print("[TC-WoW] Use Edit -> Plugins -> TC WoW Analyzer (arg=1) to hot-reload.")
        return TcWowAnalyzerPlugmod()

    def run(self, arg):
        pass  # Handled by plugmod_t

    def term(self):
        pass


def PLUGIN_ENTRY():
    return TcWowAnalyzerPlugin()
