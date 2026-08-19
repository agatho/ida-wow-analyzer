"""
IDA event hooks for the TC WoW Analyzer.
Keeps the knowledge database synchronized with IDA changes.
"""

import ida_idp
import ida_kernwin
import idaapi

from tc_wow_analyzer.core.utils import msg_info, msg_warn


class TcIDBHooks(ida_idp.IDB_Hooks):
    """Hooks into IDB modification events to track renames, type changes, etc."""

    def __init__(self, session):
        super().__init__()
        self._session = session
        self._enabled = True

    def renamed(self, ea, new_name, is_local):
        """Track function/variable renames."""
        if not self._enabled or not new_name:
            return 0
        try:
            db = self._session.db
            if db:
                import time
                db.execute("""
                    INSERT INTO annotations (ea, ann_type, value, source, confidence, created_at)
                    VALUES (?, 'name', ?, 'manual', 100, ?)
                    ON CONFLICT(ea, ann_type) DO UPDATE SET
                        value = excluded.value, source = excluded.source,
                        confidence = excluded.confidence, created_at = excluded.created_at
                """, (ea, new_name, time.time()))
                # Also update the function table if this is a function
                db.execute(
                    "UPDATE functions SET name = ?, updated_at = ? WHERE ea = ?",
                    (new_name, time.time(), ea))
                db.commit()
        except Exception:
            pass
        return 0

    def auto_empty_finally(self):
        """Called when auto-analysis finishes. Good time to run incremental analysis."""
        if not self._enabled:
            return 0
        try:
            from tc_wow_analyzer.core.utils import msg_info
            msg_info("Auto-analysis complete. Knowledge DB ready for updates.")
        except Exception:
            pass
        return 0


class TcUIHooks(ida_kernwin.UI_Hooks):
    """Hooks into UI events for context menu integration."""

    def __init__(self, session):
        super().__init__()
        self._session = session

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        """Add WoW-specific context menu items to disassembly/pseudocode views."""
        widget_type = ida_kernwin.get_widget_type(widget)

        # Only add to disassembly and pseudocode views
        if widget_type not in (
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_PSEUDOCODE
        ):
            return

        # Add separator and our menu items
        ida_kernwin.attach_action_to_popup(
            widget, popup_handle, "-", None)

        for action_name in self._session.get_registered_actions():
            ida_kernwin.attach_action_to_popup(
                widget, popup_handle, action_name, "TC WoW/")


class TcHexRaysHooks(object):
    """Hex-Rays integration.

    This used to be a self-contained hook whose callback was an empty
    ``return 0`` placeholder, while the real implementation —
    ``ui/hexrays_annotations.HexRaysAnnotator``, ~150 lines of opcode / JAM /
    Lua annotation plus the pseudocode popup — was never instantiated
    anywhere. It now delegates to that class, gated on the
    ``enable_hexrays_annotations`` setting (which previously did nothing).
    """

    def __init__(self, session):
        self._session = session
        self._installed = False
        self._annotator = None

    def install(self):
        """Install the annotator if the decompiler is available and enabled."""
        if self._installed:
            return
        try:
            enabled = self._session.cfg.get("enable_hexrays_annotations",
                                            default=True)
        except Exception:
            enabled = True
        if not enabled:
            msg_info("Hex-Rays annotations disabled in settings")
            return
        try:
            from tc_wow_analyzer.ui.hexrays_annotations import HexRaysAnnotator
            self._annotator = HexRaysAnnotator(self._session)
            self._annotator.install()
            self._installed = True
        except Exception as exc:
            msg_warn(f"Hex-Rays annotations unavailable: {exc}")
            self._annotator = None

    def remove(self):
        """Remove the Hex-Rays callback."""
        if not self._installed:
            return
        try:
            if self._annotator is not None:
                self._annotator.remove()
        except Exception:
            pass
        self._annotator = None
        self._installed = False


class HookManager:
    """Manages all IDA hooks for the plugin."""

    def __init__(self, session):
        self._session = session
        self.idb_hooks = TcIDBHooks(session)
        self.ui_hooks = TcUIHooks(session)
        self.hexrays_hooks = TcHexRaysHooks(session)
        self._installed = False

    def install(self):
        """Install all hooks."""
        if self._installed:
            return
        self.idb_hooks.hook()
        self.ui_hooks.hook()
        self.hexrays_hooks.install()
        self._installed = True
        from tc_wow_analyzer.core.utils import msg_info
        msg_info("Event hooks installed (IDB + UI + Hex-Rays)")

    def remove(self):
        """Remove all hooks."""
        if not self._installed:
            return
        self.idb_hooks.unhook()
        self.ui_hooks.unhook()
        self.hexrays_hooks.remove()
        self._installed = False
