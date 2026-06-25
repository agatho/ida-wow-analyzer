"""
Analyzer Index — one Choose listing ALL registered analyzers, their last-run
status (from run_report.json) and whether their output is present, so every
analyzer is reachable. Double-click opens that analyzer's kv_store output in a
generic JSON viewer — fixing the old problem where ~18 kv-only analyzers
(hash_resolution, cvars, call_graph_analytics, taint, thread_safety, ...) had
no UI surface at all.

Driven entirely by analyzers/registry.py (the single source of truth), so adding
an analyzer there surfaces it here automatically.
"""

import json
import os

import ida_kernwin

from tc_wow_analyzer.analyzers.registry import REGISTRY, BY_NAME


def _run_report_path():
    try:
        import ida_loader
        idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if idb:
            return os.path.splitext(idb)[0] + ".tc_wow_analyzer.run_report.json"
    except Exception:
        pass
    return None


def _load_run_report():
    """Return {analyzer_name: detail_dict} from the last run, or {}."""
    p = _run_report_path()
    if not p or not os.path.isfile(p):
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            rep = json.load(f)
        return {d.get("analyzer"): d for d in rep.get("details", []) if d.get("analyzer")}
    except Exception:
        return {}


class AnalyzerIndex(ida_kernwin.Choose):
    """Master index of all analyzers — status + output reachability."""

    COLUMNS = [
        ["Category", 12],
        ["Analyzer", 28],
        ["Status", 10],
        ["Items", 8],
        ["Output", 26],
    ]

    def __init__(self, session, title="TC WoW Analyzer Index"):
        super().__init__(title, self.COLUMNS,
                         flags=ida_kernwin.Choose.CH_RESTORE)
        self._session = session
        self._rows = []   # parallel AnalyzerInfo list for OnSelectLine
        self._items = []
        self._build()

    def _build(self):
        self._rows = []
        self._items = []
        db = getattr(self._session, "db", None)
        report = _load_run_report()
        for a in REGISTRY:
            d = report.get(a.name, {})
            status = d.get("status", "")
            items = d.get("items")
            items_str = str(items) if isinstance(items, int) else ""
            out = ""
            if a.kv_key and db is not None:
                try:
                    present = db.kv_get(a.kv_key) is not None
                except Exception:
                    present = False
                out = f"kv:{a.kv_key}" + ("" if present else " (empty)")
            elif a.db_table and db is not None:
                try:
                    cnt = db.count(a.db_table)
                except Exception:
                    cnt = 0
                out = f"{a.db_table}={cnt}"
            elif not a.kv_key and not a.db_table:
                out = "(IDB / codegen files)"
            self._rows.append(a)
            self._items.append([a.category, a.name, status, items_str, out])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if 0 <= n < len(self._items) else ["", "", "", "", ""]

    def OnRefresh(self, n):
        self._build()
        return len(self._items)

    def OnSelectLine(self, n):
        sel = n[0] if isinstance(n, list) else n
        if sel < 0 or sel >= len(self._rows):
            return
        a = self._rows[sel]
        if a.kv_key:
            show_kv(self._session, a.kv_key, title=a.name)
        elif a.db_table:
            ida_kernwin.info(
                f"{a.name}: output is in SQLite table '{a.db_table}' — "
                f"see the main dashboard (Ctrl+Shift+W).")
        else:
            ida_kernwin.info(
                f"{a.name}: applies names/types to the IDB or writes codegen "
                f"files (no kv_store blob).")

    def OnClose(self):
        pass


# ── Generic kv_store JSON viewer ───────────────────────────────────

class _KVViewer(ida_kernwin.simplecustviewer_t):
    def make(self, title, lines):
        if not self.Create(title):
            return False
        for ln in lines:
            self.AddLine(ln)
        return True


_KV_VIEWERS = []  # keep references alive so widgets aren't GC'd


def show_kv(session, key, title=None):
    """Open a read-only viewer with the pretty-printed JSON of a kv_store key."""
    db = getattr(session, "db", None)
    if db is None:
        ida_kernwin.warning("No knowledge DB loaded.")
        return
    try:
        val = db.kv_get(key)
    except Exception as e:
        ida_kernwin.warning(f"kv_get({key}) failed: {e}")
        return
    if val is None:
        ida_kernwin.info(f"kv '{key}' is empty — run the analyzer that produces it.")
        return
    try:
        text = json.dumps(val, indent=2, default=str)
    except Exception:
        text = str(val)
    lines = text.splitlines()[:5000] or ["(empty)"]
    wtitle = f"kv: {title or key}"
    existing = ida_kernwin.find_widget(wtitle)
    if existing:
        ida_kernwin.activate_widget(existing, True)
        return
    v = _KVViewer()
    if v.make(wtitle, lines):
        v.Show()
        _KV_VIEWERS.append(v)


def show_analyzer_index(session):
    """Entry point — open (or focus) the Analyzer Index."""
    existing = ida_kernwin.find_widget("TC WoW Analyzer Index")
    if existing:
        ida_kernwin.activate_widget(existing, True)
        return
    AnalyzerIndex(session).Show()
