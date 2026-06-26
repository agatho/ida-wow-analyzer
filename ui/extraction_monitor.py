"""
Extraction Monitor — live, real-time status window for the analyzer pipeline.

Renders the cross-process progress feed
(<idb>.tc_wow_analyzer.run_report.progress.jsonl) that run_all_analyzers writes
one line per analyzer (start + finish). Because the feed is a FILE, this window
works whether extraction runs:
  * headless (a separate `idat -A` process) — the usual path; the GUI is idle so
    the 1s refresh timer fires freely, and
  * in-process in this GUI — the wait box in run_all_analyzers pumps the event
    loop so this repaints mid-run too.

IDA-native (simplecustviewer_t), no Qt — consistent with the rest of the plugin.
Open via Edit/TC WoW/Extraction Monitor (Ctrl+Shift+E).
"""
import json
import os
import sqlite3
import time

import ida_kernwin
import idaapi
import idc

_TITLE = "TC WoW Extraction"
_BARW = 34

_timer_active = False
_viewer = None
_last_sig = None

# ── KPI header (at-a-glance pipeline health) ──────────────────────────────────
# Headline inventory counts from the knowledge DB + a last-run delta. The DB is
# opened READ-ONLY (WAL allows concurrent readers, so it never fights the writer)
# and the result is cached a few seconds so the 700ms timer stays cheap.
_KPI_TABLES = [("cfuncs", "cfunc_cache"), ("funcs", "functions"),
               ("jam", "jam_types"), ("opcodes", "opcodes"),
               ("tc", "tc_packets"), ("db2", "db2_tables"),
               ("strings", "strings")]
_kpi_cache = {"ts": 0.0, "data": None}


def _db_path():
    try:
        idb = idc.get_idb_path()
        if idb:
            return os.path.splitext(idb)[0] + ".tc_wow.db"
    except Exception:
        pass
    return None


def _kpi_counts():
    now = time.time()
    if _kpi_cache["data"] is not None and now - _kpi_cache["ts"] < 4.0:
        return _kpi_cache["data"]
    path = _db_path()
    out = None
    if path and os.path.exists(path):
        try:
            con = sqlite3.connect("file:%s?mode=ro" % path.replace("\\", "/"),
                                  uri=True, timeout=1.0)
            try:
                tabs = set(r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"))
                out = {}
                for label, tab in _KPI_TABLES:
                    if tab in tabs:
                        try:
                            out[label] = con.execute(
                                "SELECT COUNT(*) FROM %s" % tab).fetchone()[0]
                        except Exception:
                            pass
                if "failure_ledger" in tabs:
                    try:
                        out["fail_open"] = con.execute(
                            "SELECT COUNT(*) FROM failure_ledger "
                            "WHERE resolved=0").fetchone()[0]
                    except Exception:
                        pass
            finally:
                con.close()
        except Exception:
            out = None
    _kpi_cache["ts"] = now
    _kpi_cache["data"] = out
    return out


def _snapshot_path():
    p = _db_path()
    return (os.path.splitext(p)[0] + "_kpi.json") if p else None


def _load_snap():
    try:
        sp = _snapshot_path()
        if sp and os.path.exists(sp):
            return json.load(open(sp, encoding="utf-8"))
    except Exception:
        pass
    return None


def _save_snap(d):
    try:
        sp = _snapshot_path()
        if sp:
            json.dump(d, open(sp, "w", encoding="utf-8"))
    except Exception:
        pass


def _sep(n):
    try:
        return "{:,}".format(int(n))
    except Exception:
        return str(n)


# ── feed location + parse ─────────────────────────────────────────────────────
def _progress_path():
    """Same path run_all_analyzers writes (kept in sync with analyzers/__init__)."""
    try:
        idb = idc.get_idb_path()
        if idb:
            return os.path.splitext(idb)[0] + ".tc_wow_analyzer.run_report.progress.jsonl"
    except Exception:
        pass
    return os.path.join(os.path.dirname(__file__), "..", "..",
                        "run_report.progress.jsonl")


def _registry_names():
    try:
        from tc_wow_analyzer.analyzers.registry import REGISTRY
        return [a.name for a in REGISTRY]
    except Exception:
        return None


def _read_feed(path):
    """Parse the jsonl feed into an ordered analyzer state."""
    order, state = [], {}
    first_ts = last_ts = None
    total = 0
    complete = cancelled = False
    failed = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    e = json.loads(ln)
                except Exception:
                    continue
                ts = e.get("ts")
                if ts:
                    first_ts = ts if first_ts is None else min(first_ts, ts)
                    last_ts = ts if last_ts is None else max(last_ts, ts)
                ev = e.get("event")
                if ev == "complete":
                    complete = True
                    failed = e.get("failed", []) or []
                    total = max(total, e.get("total", 0) or 0)
                    continue
                if ev == "cancelled":
                    cancelled = True
                    continue
                nm = e.get("name")
                if not nm:
                    continue
                total = max(total, e.get("total", 0) or 0)
                if nm not in state:
                    order.append(nm)
                    state[nm] = {}
                st = state[nm]
                st["status"] = e.get("status", st.get("status"))
                if e.get("items") is not None:
                    st["items"] = e["items"]
                if e.get("elapsed") is not None:
                    st["elapsed"] = e["elapsed"]
                if e.get("idx") is not None:
                    st["idx"] = e["idx"]
    except FileNotFoundError:
        return None
    except Exception:
        return None
    return {"order": order, "state": state, "first_ts": first_ts,
            "last_ts": last_ts, "total": total, "complete": complete,
            "cancelled": cancelled, "failed": failed}


# ── render ────────────────────────────────────────────────────────────────────
def _fmt_dur(sec):
    if sec is None or sec < 0:
        return "  --  "
    sec = int(sec)
    h, r = divmod(sec, 3600)
    m, s = divmod(r, 60)
    return ("%d:%02d:%02d" % (h, m, s)) if h else ("%02d:%02d" % (m, s))


def _bar(done, total):
    if not total:
        return "[" + "-" * _BARW + "]"
    fill = int(round(_BARW * min(done, total) / float(total)))
    return "[" + "#" * fill + "-" * (_BARW - fill) + "]"


def _kpi_lines(kpi, snap):
    """Inventory + health header lines (shown always, even when idle)."""
    out = []
    if not kpi:
        return out
    inv = ["%s %s" % (_sep(kpi[k]), k)
           for k, _t in _KPI_TABLES if k in kpi]
    if inv:
        out.append(" " + "  ".join(inv[:4]))
        if len(inv) > 4:
            out.append(" " + "  ".join(inv[4:]))
    health = []
    if snap and kpi.get("cfuncs") is not None and snap.get("cfuncs") is not None:
        d = kpi["cfuncs"] - snap["cfuncs"]
        if d:
            health.append("cfuncs {:+,} since last run".format(d))
    if kpi.get("fail_open"):
        health.append("%d failures open" % kpi["fail_open"])
    if health:
        out.append(" " + "  ·  ".join(health))
    return out


def _render(path):
    data = _read_feed(path)
    kpi = _kpi_counts()
    snap = _load_snap()
    L = []
    L.append("=" * 52)
    L.append(" TC WoW — Extraction Monitor")
    L.append("=" * 52)
    kl = _kpi_lines(kpi, snap)
    if kl:
        L.extend(kl)
        L.append("-" * 52)
    if data is None or (not data["order"] and not data["complete"]):
        L.append("")
        L.append("IDLE — no active extraction.")
        L.append("")
        L.append("Feed: %s" % path)
        L.append("(starts updating when run_all_analyzers runs,")
        L.append(" headless or in-GUI)")
        return L

    state = data["state"]
    order = data["order"]
    total = data["total"] or len(order)
    done = sum(1 for s in state.values() if s.get("status") in ("OK", "FAILED"))
    failed = [n for n, s in state.items() if s.get("status") == "FAILED"] or data["failed"]
    running = next((n for n in order if state[n].get("status") == "running"), None)

    if data["cancelled"]:
        status = "CANCELLED"
    elif data["complete"]:
        status = "COMPLETE" + (" (with failures)" if failed else "")
    elif running:
        status = "RUNNING"
    else:
        status = "IDLE"

    # wall clock + ETA
    if data["first_ts"]:
        end = data["last_ts"] if (data["complete"] or data["cancelled"]) else time.time()
        wall = max(0.0, end - data["first_ts"])
    else:
        wall = 0.0
    pct = int(round(100.0 * done / total)) if total else 0
    eta = None
    if running and done > 0 and total:
        eta = (wall / done) * (total - done)
    rate = (done / wall * 60.0) if wall > 0 else 0.0

    run_items = sum(s["items"] for s in state.values()
                    if isinstance(s.get("items"), int) and s["items"] >= 0)

    L.append(" Status   : %s" % status)
    L.append(" Progress : %s %d/%d  (%d%%)" % (_bar(done, total), done, total, pct))
    L.append(" Elapsed  : %s    ETA: %s    %.1f/min"
             % (_fmt_dur(wall), _fmt_dur(eta), rate))
    items_line = " Produced : %s items this run" % _sep(run_items)
    if snap and isinstance(snap.get("items"), int):
        items_line += "   (Δ {:+,} vs last run)".format(run_items - snap["items"])
    L.append(items_line)
    if running:
        L.append(" Current  : >> %s" % running)
    if failed:
        L.append(" Failures : %d  (%s%s)" % (len(failed), ", ".join(failed[:4]),
                                             " ..." if len(failed) > 4 else ""))
    L.append("-" * 52)

    # On completion, snapshot this run's totals so the NEXT run can show a delta.
    if data["complete"]:
        sig = data.get("first_ts")
        if not snap or snap.get("run_sig") != sig:
            _save_snap({"run_sig": sig, "items": run_items,
                        "cfuncs": (kpi or {}).get("cfuncs"), "ts": time.time()})

    # per-analyzer rows. If the feed is the full analyzer pipeline
    # (run_all_analyzers — every feed name is a registry analyzer), show the whole
    # registry so pending analyzers are visible too. Otherwise (task runner /
    # partial run) show just what the feed contains, in feed order.
    reg = _registry_names()
    if reg and order and all(n in set(reg) for n in order):
        names = reg
    else:
        names = order
    for i, nm in enumerate(names, 1):
        s = state.get(nm)
        if not s:
            mark, extra = "[..]", "pending"
        else:
            st = s.get("status")
            if st == "OK":
                items = s.get("items")
                mark = "[OK]"
                extra = "%8s items  %ss" % (
                    ("%d" % items) if isinstance(items, int) else "-",
                    s.get("elapsed", "-"))
            elif st == "FAILED":
                mark, extra = "[!!]", "FAILED  %ss" % s.get("elapsed", "-")
            elif st == "running":
                mark, extra = "[>>]", "running..."
            else:
                mark, extra = "[..]", str(st or "pending")
        L.append(" %s %-30s %s" % (mark, nm[:30], extra))

    L.append("-" * 52)
    L.append(" Feed: %s" % os.path.basename(path))
    L.append(" Live tail:  tail -f \"%s\"" % path)
    return L


def _colorize(ln):
    try:
        if ln.startswith("="):
            return idaapi.COLSTR(ln, idaapi.SCOLOR_RPTCMT)
        if "failures open" in ln:
            return idaapi.COLSTR(ln, idaapi.SCOLOR_ERROR)
        if "since last run" in ln or ln.startswith(" Produced"):
            return idaapi.COLSTR(ln, idaapi.SCOLOR_AUTOCMT)
        if ("  cfuncs" in ln or " cfuncs  " in ln) and "since" not in ln:
            return idaapi.COLSTR(ln, idaapi.SCOLOR_NUMBER)
        if "[OK]" in ln:
            return idaapi.COLSTR(ln, idaapi.SCOLOR_CREFTAIL)
        if "[!!]" in ln or "FAILED" in ln or "Failures" in ln:
            return idaapi.COLSTR(ln, idaapi.SCOLOR_ERROR)
        if "[>>]" in ln or ln.startswith(" Current") or "RUNNING" in ln:
            return idaapi.COLSTR(ln, idaapi.SCOLOR_AUTOCMT)
        if "COMPLETE" in ln:
            return idaapi.COLSTR(ln, idaapi.SCOLOR_CREFTAIL)
        if "[..]" in ln or ln.startswith(" Feed") or ln.startswith(" Live"):
            return idaapi.COLSTR(ln, idaapi.SCOLOR_RPTCMT)
    except Exception:
        pass
    return ln


# ── viewer + timer ────────────────────────────────────────────────────────────
class _Monitor(ida_kernwin.simplecustviewer_t):
    def Create(self):
        if not super().Create(_TITLE):
            return False
        for ln in _render(_progress_path()):
            self.AddLine(_colorize(ln))
        return True

    def OnClose(self):
        global _viewer
        _viewer = None


def _tick():
    global _timer_active, _last_sig, _viewer
    if not ida_kernwin.find_widget(_TITLE):
        _timer_active = False
        return -1
    try:
        path = _progress_path()
        # signature: redraw on file change OR while a run is active (live clock)
        try:
            sig = os.path.getmtime(path)
        except Exception:
            sig = None
        data = _read_feed(path)
        active = bool(data and data["order"] and not data["complete"]
                      and not data["cancelled"])
        if sig == _last_sig and not active:
            return 700
        _last_sig = sig
        if _viewer is None or not ida_kernwin.find_widget(_TITLE):
            _timer_active = False
            return -1
        _viewer.ClearLines()
        for ln in _render(path):
            _viewer.AddLine(_colorize(ln))
        _viewer.Refresh()
    except Exception:
        _timer_active = False
        return -1
    return 700


def _ensure_timer():
    global _timer_active
    if _timer_active:
        return
    _timer_active = True
    idaapi.register_timer(700, _tick)


def show_extraction_monitor():
    """Open (or focus) the live Extraction Monitor window."""
    global _viewer
    w = ida_kernwin.find_widget(_TITLE)
    if w:
        ida_kernwin.activate_widget(w, True)
        _ensure_timer()
        return
    v = _Monitor()
    if v.Create():
        _viewer = v
        v.Show()
        w = ida_kernwin.find_widget(_TITLE)
        if w:
            out = ida_kernwin.find_widget("Output window")
            if out:
                ida_kernwin.set_dock_pos(_TITLE, "Output window", ida_kernwin.DP_TAB)
        _ensure_timer()
    else:
        _viewer = None
