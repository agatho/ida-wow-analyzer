"""
Activity View — Live Status Window
Dockable IDA viewer that shows real-time plugin activity: current task,
progress, and recent log entries. Auto-refreshes every second.
"""

import ida_kernwin
import idaapi

from tc_wow_analyzer.core.activity import ActivityManager

_TITLE = "TC WoW Activity"

# Module-level state for the refresh timer.
# The timer never holds a reference to the viewer instance — it looks up
# the widget by title each tick. This prevents crashes when the viewer is
# closed or the plugin is hot-reloaded (which destroys the C++ widget but
# leaves orphan Python timer callbacks alive).
_timer_active = False
_last_event_count = -1


def _timer_tick():
    """Global timer callback — safe to survive hot-reloads."""
    global _timer_active, _last_event_count

    # Check if the widget still exists by title lookup
    widget = ida_kernwin.find_widget(_TITLE)
    if not widget:
        _timer_active = False
        return -1  # stop timer

    try:
        mgr = ActivityManager.get()

        # Skip refresh if nothing changed
        if mgr._total_events == _last_event_count and not mgr._current_task:
            return 1000

        _last_event_count = mgr._total_events
        lines = mgr.get_status_lines()

        # Use get_custom_viewer_place to verify it's a valid custom viewer
        viewer = _get_viewer_instance()
        if viewer is None:
            _timer_active = False
            return -1

        viewer.ClearLines()
        for line in lines:
            viewer.AddLine(_colorize(line))
        viewer.Refresh()

    except Exception:
        # Any error — stop the timer to prevent crash loops
        _timer_active = False
        return -1

    return 1000  # repeat every 1s


def _get_viewer_instance():
    """Return the current viewer instance if it exists and is valid."""
    global _viewer_instance
    if _viewer_instance is None:
        return None
    # Verify the backing widget still exists
    if not ida_kernwin.find_widget(_TITLE):
        _viewer_instance = None
        return None
    return _viewer_instance


def _colorize(line):
    """Apply IDA color tags based on content."""
    try:
        if line.startswith("BATCH:") or line.startswith("RUNNING:"):
            return idaapi.COLSTR(line, idaapi.SCOLOR_AUTOCMT)
        if line.startswith("IDLE"):
            return idaapi.COLSTR(line, idaapi.SCOLOR_RPTCMT)
        if "ERROR" in line:
            return idaapi.COLSTR(line, idaapi.SCOLOR_ERROR)
        if "WARN" in line:
            return idaapi.COLSTR(line, idaapi.SCOLOR_CREFTAIL)
        if "TASK" in line:
            return idaapi.COLSTR(line, idaapi.SCOLOR_AUTOCMT)
        if line.startswith("=") or line.startswith("Events:"):
            return idaapi.COLSTR(line, idaapi.SCOLOR_RPTCMT)
    except (AttributeError, Exception):
        pass
    return line


def _ensure_timer():
    """Start the refresh timer if not already running."""
    global _timer_active
    if _timer_active:
        return
    _timer_active = True
    idaapi.register_timer(1000, _timer_tick)


class ActivityViewer(ida_kernwin.simplecustviewer_t):
    """Custom viewer that displays the activity log."""

    def Create(self):
        if not super().Create(_TITLE):
            return False
        # Initial content
        self.AddLine("TC WoW Activity Log")
        self.AddLine("Waiting for activity...")
        return True

    def OnClose(self):
        global _viewer_instance
        _viewer_instance = None


# Global viewer reference
_viewer_instance = None


def show_activity_view():
    """Show the activity view, creating it if needed."""
    global _viewer_instance

    # Check if already open
    widget = ida_kernwin.find_widget(_TITLE)
    if widget:
        ida_kernwin.activate_widget(widget, True)
        _ensure_timer()
        return

    viewer = ActivityViewer()
    if viewer.Create():
        _viewer_instance = viewer
        viewer.Show()

        # Dock next to Output window
        widget = ida_kernwin.find_widget(_TITLE)
        if widget:
            output = ida_kernwin.find_widget("Output window")
            if output:
                ida_kernwin.set_dock_pos(_TITLE, "Output window",
                                         ida_kernwin.DP_TAB)

        _ensure_timer()
    else:
        _viewer_instance = None
