"""
Activity View — Live Status Window
Dockable IDA viewer that shows real-time plugin activity: current task,
progress, and recent log entries. Auto-refreshes every second.
"""

import ida_kernwin
import idaapi

from tc_wow_analyzer.core.activity import ActivityManager

_TITLE = "TC WoW Activity"


class ActivityViewer(ida_kernwin.simplecustviewer_t):
    """Custom viewer that displays the activity log with auto-refresh."""

    def __init__(self):
        super().__init__()
        self._closed = False
        self._last_event_count = -1

    def Create(self):
        if not super().Create(_TITLE):
            return False
        self._closed = False
        self._refresh()
        self._start_timer()
        return True

    def OnClose(self):
        self._closed = True

    def _start_timer(self):
        viewer_ref = self

        def _tick():
            # Stop the timer if the viewer was closed
            if viewer_ref._closed:
                return -1
            try:
                viewer_ref._refresh()
            except Exception:
                return -1  # stop on any error to prevent crash loops
            return 1000  # repeat every 1s

        idaapi.register_timer(1000, _tick)

    def _refresh(self):
        """Rebuild the viewer content from the activity manager."""
        if self._closed:
            return

        # Verify the widget still exists
        if not ida_kernwin.find_widget(_TITLE):
            self._closed = True
            return

        mgr = ActivityManager.get()

        # Skip refresh if nothing changed
        if mgr._total_events == self._last_event_count and not mgr._current_task:
            return
        self._last_event_count = mgr._total_events

        lines = mgr.get_status_lines()

        self.ClearLines()
        for line in lines:
            colored = self._colorize(line)
            self.AddLine(colored)

        self.Refresh()

    def _colorize(self, line):
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


# Keep a reference to prevent GC
_viewer_instance = None


def show_activity_view():
    """Show the activity view, creating it if needed."""
    global _viewer_instance

    # Check if already open
    widget = ida_kernwin.find_widget(_TITLE)
    if widget:
        ida_kernwin.activate_widget(widget, True)
        return

    _viewer_instance = ActivityViewer()
    if _viewer_instance.Create():
        _viewer_instance.Show()

        # Try to dock it at the bottom next to Output
        widget = ida_kernwin.find_widget(_TITLE)
        if widget:
            output = ida_kernwin.find_widget("Output window")
            if output:
                ida_kernwin.set_dock_pos(_TITLE, "Output window",
                                         ida_kernwin.DP_TAB)
    else:
        _viewer_instance = None
