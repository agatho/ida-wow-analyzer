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
