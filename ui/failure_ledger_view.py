"""
Failure Ledger view — a Choose listing the open (unresolved) rows of the durable
failure_ledger table. Double-click a row to jump to its address (if any) or open
its full error + traceback. Opened from the Extraction Monitor (double-click the
failures line) or Edit/TC WoW/Views/Failure Ledger.

Self-contained: opens the knowledge DB READ-ONLY by deriving the path from the
IDB, so it needs no PluginSession and never contends with the extraction writer.
"""
import os
import sqlite3
import time

import ida_kernwin
import idc

_TITLE = "TC WoW Failure Ledger"


def _db_path():
    try:
        idb = idc.get_idb_path()
        if idb:
            return os.path.splitext(idb)[0] + ".tc_wow.db"
    except Exception:
        pass
    return None


def _open_ro():
    p = _db_path()
    if not p or not os.path.exists(p):
        return None
    try:
        con = sqlite3.connect("file:%s?mode=ro" % p.replace("\\", "/"),
                              uri=True, timeout=1.0)
        con.row_factory = sqlite3.Row
        return con
    except Exception:
        return None


class FailureLedger(ida_kernwin.Choose):
    """Open rows of failure_ledger (resolved=0), newest first."""

    COLUMNS = [
        ["Kind", 16],
        ["Subject", 30],
        ["Error", 30],
        ["Seen", 5],
        ["Last", 12],
        ["Build", 8],
    ]

    def __init__(self, title=_TITLE):
        super().__init__(title, self.COLUMNS, flags=ida_kernwin.Choose.CH_RESTORE)
        self._rows = []    # (ea, error_msg, traceback, kind, subject)
        self._items = []
        self._build()

    def _build(self):
        self._rows = []
        self._items = []
        con = _open_ro()
        if con is None:
            self._items = [["(knowledge DB not found)", "", "", "", "", ""]]
            return
        try:
            tabs = set(r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"))
            if "failure_ledger" not in tabs:
                self._items = [["(no failure_ledger table yet)", "", "", "", "", ""]]
                return
            rows = con.execute(
                "SELECT kind, subject, ea, error_type, error_msg, traceback, "
                "seen_count, last_seen, build FROM failure_ledger "
                "WHERE resolved=0 ORDER BY last_seen DESC").fetchall()
        except Exception as e:
            self._items = [["(query failed)", str(e)[:30], "", "", "", ""]]
            con.close()
            return
        con.close()
        for r in rows:
            try:
                last_s = (time.strftime("%m-%d %H:%M", time.localtime(r["last_seen"]))
                          if r["last_seen"] else "")
            except Exception:
                last_s = ""
            err = r["error_msg"] or r["error_type"] or ""
            self._rows.append((r["ea"], err, r["traceback"], r["kind"], r["subject"]))
            self._items.append([
                str(r["kind"] or ""), str(r["subject"] or "")[:30], str(err)[:30],
                str(r["seen_count"] or ""), last_s, str(r["build"] or ""),
            ])
        if not self._items:
            self._items = [["(no open failures)", "", "", "", "", ""]]

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if 0 <= n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._build()
        return len(self._items)

    def OnSelectLine(self, n):
        sel = n[0] if isinstance(n, list) else n
        if sel < 0 or sel >= len(self._rows):
            return
        ea, msg, tb, kind, subj = self._rows[sel]
        if ea:
            try:
                ida_kernwin.jumpto(int(ea))
                return
            except Exception:
                pass
        lines = ["Kind   : %s" % kind, "Subject: %s" % subj, "",
                 "Error  : %s" % (msg or "")] + [""]
        lines += (tb.splitlines() if tb else ["(no traceback recorded)"])
        _show_text("Failure: %s" % (subj or kind or "?"), lines)

    def OnClose(self):
        pass


# ── plain text viewer for a single failure's traceback ────────────────────────
class _TextViewer(ida_kernwin.simplecustviewer_t):
    def make(self, title, lines):
        if not self.Create(title):
            return False
        for ln in lines:
            self.AddLine(ln)
        return True


_VIEWERS = []  # keep refs alive


def _show_text(title, lines):
    w = ida_kernwin.find_widget(title)
    if w:
        ida_kernwin.activate_widget(w, True)
        return
    v = _TextViewer()
    if v.make(title, lines or ["(empty)"]):
        v.Show()
        _VIEWERS.append(v)


def show_failure_ledger():
    """Open (or focus) the Failure Ledger."""
    w = ida_kernwin.find_widget(_TITLE)
    if w:
        ida_kernwin.activate_widget(w, True)
        return
    FailureLedger().Show()
