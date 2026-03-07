"""
Housing System Deep Dive View
Specialized dashboard showing all housing-related functions, opcodes,
JAM types, and their interconnections — purpose-built for the
TrinityCore housing system implementation.
"""

import ida_kernwin
import idaapi

from tc_wow_analyzer.core.utils import msg, msg_info


# Known housing-related JAM type prefixes
HOUSING_JAM_PREFIXES = (
    "JamCliHouse", "JamCliNeighborhood", "JamCliDecor",
    "JamCliPlot", "JamSvcsHouse", "JamSvcsNeighborhood",
    "JamSvcsDecor", "JamSvcsPlot",
    "JamHousing", "JamNeighborhood", "JamDecor",
)

# Known housing opcode substrings
HOUSING_OPCODE_KEYWORDS = (
    "housing", "house", "neighborhood", "neighbour", "decor",
    "plot", "interior", "room", "steward",
)


class HousingDeepDiveView(ida_kernwin.Choose):
    """Deep dive view for the housing system."""

    COLUMNS = [
        ["Section", 18],
        ["Name", 45],
        ["Address", 16],
        ["Direction", 8],
        ["Details", 50],
    ]

    def __init__(self, session, title="TC WoW: Housing Deep Dive"):
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
        """Build comprehensive housing system view."""
        self._items = []
        db = self._session.db
        if not db:
            self._items.append(["ERROR", "No database loaded", "", "", ""])
            return

        self._add_section_header("HOUSING OVERVIEW")

        # 1. Housing opcodes
        self._add_section_header("OPCODES (Housing)")
        housing_opcodes = db.fetchall(
            """SELECT * FROM opcodes
               WHERE tc_name LIKE '%Housing%'
                  OR tc_name LIKE '%House%'
                  OR tc_name LIKE '%Neighborhood%'
                  OR tc_name LIKE '%Decor%'
                  OR tc_name LIKE '%Plot%'
                  OR jam_type LIKE '%House%'
                  OR jam_type LIKE '%Neighborhood%'
                  OR jam_type LIKE '%Decor%'
               ORDER BY direction, internal_index""")

        if housing_opcodes:
            for row in housing_opcodes:
                tc_name = row["tc_name"] or f"idx_0x{row['internal_index']:X}"
                handler = f"0x{row['handler_ea']:X}" if row["handler_ea"] else ""
                jam = row["jam_type"] or ""
                self._items.append([
                    f"  {row['direction']}",
                    tc_name,
                    handler,
                    row["direction"],
                    f"JAM: {jam}" if jam else row["status"] or ""
                ])
        else:
            self._items.append(["  OPCODE", "(none found)", "", "",
                                "Run import or analysis first"])

        self._add_separator()

        # 2. Housing JAM types
        self._add_section_header("JAM TYPES (Housing)")
        housing_jams = db.fetchall(
            """SELECT * FROM jam_types
               WHERE name LIKE '%House%'
                  OR name LIKE '%Housing%'
                  OR name LIKE '%Neighborhood%'
                  OR name LIKE '%Decor%'
                  OR name LIKE '%Plot%'
                  OR name LIKE '%Interior%'
               ORDER BY name""")

        if housing_jams:
            for row in housing_jams:
                ser = f"0x{row['serializer_ea']:X}" if row["serializer_ea"] else ""
                fields = f"{row['field_count']} fields" if row["field_count"] else ""
                self._items.append([
                    "  JAM",
                    row["name"],
                    ser,
                    "",
                    f"{row['status']} | {fields}" if fields else row["status"] or ""
                ])
        else:
            self._items.append(["  JAM", "(none found)", "", "",
                                "Run import or analysis first"])

        self._add_separator()

        # 3. Housing functions
        self._add_section_header("FUNCTIONS (Housing)")
        housing_funcs = db.fetchall(
            """SELECT * FROM functions
               WHERE system = 'housing'
                  OR system = 'neighborhood'
                  OR name LIKE '%Housing%'
                  OR name LIKE '%House%'
                  OR name LIKE '%Neighborhood%'
                  OR name LIKE '%Decor%'
               ORDER BY name
               LIMIT 100""")

        if housing_funcs:
            for row in housing_funcs:
                self._items.append([
                    f"  {row['system'] or 'func'}",
                    row["name"] or f"sub_{row['ea']:X}",
                    f"0x{row['ea']:X}",
                    "",
                    row["subsystem"] or ""
                ])
        else:
            self._items.append(["  FUNC", "(none found)", "", "",
                                "Run import or analysis first"])

        self._add_separator()

        # 4. Housing DB2 tables
        self._add_section_header("DB2 TABLES (Housing)")
        housing_db2 = db.fetchall(
            """SELECT * FROM db2_tables
               WHERE name LIKE '%Housing%'
                  OR name LIKE '%House%'
                  OR name LIKE '%Neighborhood%'
                  OR name LIKE '%Decor%'
                  OR name LIKE '%Plot%'
                  OR name LIKE '%Room%'
                  OR name LIKE '%Interior%'
               ORDER BY name""")

        if housing_db2:
            for row in housing_db2:
                meta = f"0x{row['meta_ea']:X}" if row["meta_ea"] else ""
                self._items.append([
                    "  DB2",
                    row["name"],
                    meta,
                    "",
                    f"fields={row['field_count']} "
                    f"recSize={row['record_size']} "
                    f"fdid={row.get('file_data_id', '')}"
                ])
        else:
            self._items.append(["  DB2", "(none found)", "", "",
                                "Run import or analysis first"])

        self._add_separator()

        # 5. Housing vtables
        self._add_section_header("VTABLES (Housing)")
        housing_vts = db.fetchall(
            """SELECT * FROM vtables
               WHERE class_name LIKE '%Housing%'
                  OR class_name LIKE '%House%'
                  OR class_name LIKE '%Neighborhood%'
                  OR class_name LIKE '%Decor%'
               ORDER BY class_name""")

        if housing_vts:
            for row in housing_vts:
                self._items.append([
                    "  VTABLE",
                    row["class_name"] or f"vtable_0x{row['ea']:X}",
                    f"0x{row['ea']:X}",
                    "",
                    f"{row['entry_count']} entries | {row['source'] or ''}"
                ])
        else:
            self._items.append(["  VTABLE", "(none found)", "", "",
                                "Run import or analysis first"])

        self._add_separator()

        # 6. Housing strings
        self._add_section_header("STRINGS (Housing)")
        housing_strings = db.fetchall(
            """SELECT * FROM strings
               WHERE system = 'housing'
                  OR system = 'neighborhood'
                  OR value LIKE '%Housing%'
                  OR value LIKE '%Neighborhood%'
               ORDER BY xref_count DESC
               LIMIT 50""")

        if housing_strings:
            for row in housing_strings:
                val = row["value"]
                if len(val) > 60:
                    val = val[:57] + "..."
                self._items.append([
                    "  STRING",
                    val,
                    f"0x{row['ea']:X}",
                    "",
                    f"xrefs={row['xref_count']}"
                ])

    def _add_section_header(self, title):
        self._items.append([title, "", "", "", ""])

    def _add_separator(self):
        self._items.append(["", "", "", "", ""])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        if n < len(self._items):
            return self._items[n]
        return ["", "", "", "", ""]

    def OnSelectLine(self, n):
        """Double-click: jump to address."""
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
        self._items.clear()
        self._build_items()
        return len(self._items)

    def OnClose(self):
        pass


def show_housing_deep_dive(session):
    """Show the Housing System Deep Dive view."""
    view = HousingDeepDiveView(session)
    view.Show()
