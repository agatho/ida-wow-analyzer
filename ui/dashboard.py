"""
WoW System Navigator — Main Dashboard
A custom ida_kernwin.Choose view showing all analysis results in a tree-like table.
"""

import ida_kernwin
import idaapi


class WoWDashboard(ida_kernwin.Choose):
    """Main dashboard chooser window showing analysis overview."""

    COLUMNS = [
        ["Category", 20],
        ["Name", 40],
        ["Address", 16],
        ["Status", 12],
        ["Details", 40],
    ]

    def __init__(self, session, title="TC WoW Analyzer"):
        super().__init__(
            title,
            self.COLUMNS,
            flags=(
                ida_kernwin.Choose.CH_MULTI
                | ida_kernwin.Choose.CH_RESTORE
            ),
        )
        self._session = session
        self._items = []
        self._build_items()

    def _build_items(self):
        """Build the display items from the knowledge database."""
        self._items = []
        db = self._session.db
        if not db:
            self._items.append(["ERROR", "No database loaded", "", "", ""])
            return

        stats = db.get_stats()

        # Header row: summary
        total = sum(stats.values())
        build = self._session.cfg.build_number
        self._items.append([
            "SUMMARY",
            f"Build {build}" if build else "Unknown Build",
            "",
            f"{total} records",
            f"DB: {db.path}"
        ])
        self._items.append(["", "", "", "", ""])  # separator

        # Analyzer run status (from the last run_report.json) + durable failures
        self._append_run_status()
        self._append_failures(db)

        # Opcodes section
        cmsg_count = len(db.fetchall(
            "SELECT 1 FROM opcodes WHERE direction = 'CMSG'"))
        smsg_count = len(db.fetchall(
            "SELECT 1 FROM opcodes WHERE direction = 'SMSG'"))
        self._items.append([
            "OPCODES",
            f"{cmsg_count} CMSG | {smsg_count} SMSG",
            "",
            f"{cmsg_count + smsg_count} total",
            ""
        ])

        # Show opcode details (first 50 for performance)
        for row in db.fetchall(
            "SELECT * FROM opcodes ORDER BY direction, internal_index LIMIT 50"
        ):
            tc_name = row["tc_name"] or f"unknown_0x{row['internal_index']:X}"
            handler_str = f"0x{row['handler_ea']:X}" if row["handler_ea"] else ""
            self._items.append([
                f"  {row['direction']}",
                tc_name,
                handler_str,
                row["status"] or "",
                row["jam_type"] or ""
            ])

        self._items.append(["", "", "", "", ""])

        # JAM Types section
        jam_count = stats.get("jam_types", 0)
        self._items.append([
            "JAM TYPES",
            f"{jam_count} message types",
            "",
            "",
            ""
        ])
        for row in db.fetchall(
            "SELECT * FROM jam_types ORDER BY name LIMIT 30"
        ):
            ser_str = f"0x{row['serializer_ea']:X}" if row["serializer_ea"] else ""
            self._items.append([
                "  JAM",
                row["name"],
                ser_str,
                row["status"] or "",
                f"{row['field_count']} fields" if row["field_count"] else ""
            ])

        self._items.append(["", "", "", "", ""])

        # DB2 Tables section
        db2_count = stats.get("db2_tables", 0)
        self._items.append([
            "DB2 TABLES",
            f"{db2_count} tables",
            "",
            "",
            ""
        ])
        for row in db.fetchall(
            "SELECT * FROM db2_tables ORDER BY name LIMIT 30"
        ):
            meta_str = f"0x{row['meta_ea']:X}" if row["meta_ea"] else ""
            self._items.append([
                "  DB2",
                row["name"],
                meta_str,
                f"{row['field_count']} fields" if row["field_count"] else "",
                f"layout=0x{row['layout_hash']:X}" if row["layout_hash"] else ""
            ])

        self._items.append(["", "", "", "", ""])

        # VTables section
        vt_count = stats.get("vtables", 0)
        self._items.append([
            "VTABLES",
            f"{vt_count} classes",
            "",
            f"{stats.get('vtable_entries', 0)} entries",
            ""
        ])
        for row in db.fetchall(
            "SELECT * FROM vtables WHERE class_name IS NOT NULL "
            "ORDER BY class_name LIMIT 30"
        ):
            self._items.append([
                "  CLASS",
                row["class_name"] or f"vtable_0x{row['ea']:X}",
                f"0x{row['ea']:X}",
                f"{row['entry_count']} entries",
                row["source"] or ""
            ])

        self._items.append(["", "", "", "", ""])

        # Lua API section
        lua_count = stats.get("lua_api", 0)
        self._items.append([
            "LUA API",
            f"{lua_count} functions",
            "",
            "",
            ""
        ])

        self._items.append(["", "", "", "", ""])

        # Functions section
        func_count = stats.get("functions", 0)
        self._items.append([
            "FUNCTIONS",
            f"{func_count} total",
            "",
            "",
            ""
        ])

        # Show system breakdown
        for row in db.fetchall(
            "SELECT system, COUNT(*) as cnt FROM functions "
            "WHERE system IS NOT NULL GROUP BY system ORDER BY cnt DESC LIMIT 20"
        ):
            self._items.append([
                "  SYSTEM",
                row["system"],
                "",
                f"{row['cnt']} functions",
                ""
            ])

    def _run_report_path(self):
        try:
            import ida_loader
            import os
            idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            if idb:
                return os.path.splitext(idb)[0] + ".tc_wow_analyzer.run_report.json"
        except Exception:
            pass
        return None

    def _append_run_status(self):
        """Surface the authoritative per-analyzer run_report.json (status/items/timing)."""
        import json
        import os
        import time
        p = self._run_report_path()
        if not p or not os.path.isfile(p):
            return
        try:
            with open(p, encoding="utf-8") as f:
                rep = json.load(f)
        except Exception:
            return
        summ = rep.get("summary_by_status", {}) or {}
        ran = rep.get("analyzers_run", 0)
        total = rep.get("analyzers_total", 0)
        when = ""
        try:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(rep.get("run_start", 0)))
        except Exception:
            pass
        comp = "complete" if rep.get("complete") else "PARTIAL (idat crash?)"
        self._items.append([
            "ANALYZERS", f"{ran}/{total} ran — {comp}", "",
            f"{rep.get('elapsed_sec', '?')}s", when])
        ok = summ.get("OK", 0)
        fail = summ.get("FAILED", 0)
        skip = sum(v for k, v in summ.items() if str(k).startswith("SKIP"))
        self._items.append([
            "  STATUS", f"{ok} OK | {fail} FAILED | {skip} skipped", "", "", ""])
        details = rep.get("details", []) or []

        def _key(d):
            it = d.get("items")
            return (d.get("status") != "FAILED",
                    -(it if isinstance(it, int) else 0))
        for d in sorted(details, key=_key)[:40]:
            st = d.get("status", "")
            it = d.get("items")
            self._items.append([
                "  " + ("FAIL" if st == "FAILED" else "ok"),
                d.get("analyzer", ""),
                "",
                (str(it) if isinstance(it, int) else st),
                (d.get("error_type", "") if st == "FAILED"
                 else f"{d.get('elapsed_sec', '')}s"),
            ])
        self._items.append(["", "", "", "", ""])

    def _append_failures(self, db):
        """Surface the durable cross-run/cross-build failure ledger."""
        if not db:
            return
        try:
            rows = db.get_failures(only_open=True)
        except Exception:
            return
        if not rows:
            return
        self._items.append([
            "FAILURES (ledger)", f"{len(rows)} open", "", "",
            "durable across runs/builds"])
        for r in rows[:30]:
            try:
                ea = r["ea"]
                self._items.append([
                    "  " + (r["kind"] or ""),
                    r["subject"] or "",
                    (f"0x{ea:X}" if ea else ""),
                    (f"x{r['seen_count']}" if r["seen_count"] else ""),
                    (r["error_msg"] or "")[:60],
                ])
            except Exception:
                continue
        self._items.append(["", "", "", "", ""])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        if n < len(self._items):
            return self._items[n]
        return ["", "", "", "", ""]

    def OnSelectLine(self, n):
        """Double-click: jump to address if available."""
        sel = n[0] if isinstance(n, list) else n
        if sel < len(self._items):
            addr_str = self._items[sel][2].strip()
            if addr_str.startswith("0x"):
                try:
                    ea = int(addr_str, 16)
                    idaapi.jumpto(ea)
                except ValueError:
                    pass

    def OnRefresh(self, n):
        """Refresh the list (F5 key)."""
        self._items.clear()
        self._build_items()
        return len(self._items)

    def OnClose(self):
        pass


def show_dashboard(session):
    """Show or bring to front the WoW System Navigator dashboard."""
    dashboard = WoWDashboard(session)
    dashboard.Show()
