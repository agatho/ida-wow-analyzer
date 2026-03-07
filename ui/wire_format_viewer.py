"""
Wire Format Viewer
Side panel showing JAM message structure for the handler at cursor.
Shows field layout, types, sizes, and wire offsets extracted from
serializer/deserializer decompilation.
"""

import ida_kernwin
import idaapi

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn


class WireFormatViewer(ida_kernwin.Choose):
    """Displays JAM message wire format for a selected opcode handler."""

    COLUMNS = [
        ["#", 4],
        ["Field", 30],
        ["Type", 12],
        ["Size", 6],
        ["Wire Offset", 10],
        ["Optional", 8],
    ]

    def __init__(self, session, jam_name=None, title=None):
        self._session = session
        self._jam_name = jam_name
        self._items = []

        display_title = title or f"Wire Format: {jam_name or 'none'}"
        super().__init__(
            display_title,
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE,
        )
        self._build_items()

    def _build_items(self):
        """Build field list from knowledge DB."""
        self._items = []
        db = self._session.db
        if not db or not self._jam_name:
            self._items.append(["", "No JAM type selected", "", "", "", ""])
            return

        row = db.fetchone(
            "SELECT * FROM jam_types WHERE name = ?", (self._jam_name,))
        if not row:
            self._items.append(["", f"JAM type '{self._jam_name}' not found",
                                "", "", "", ""])
            return

        # Header info
        ser_str = f"0x{row['serializer_ea']:X}" if row["serializer_ea"] else "unknown"
        deser_str = f"0x{row['deserializer_ea']:X}" if row["deserializer_ea"] else "unknown"
        self._items.append([
            "", f"Type: {self._jam_name}", "", "",
            f"ser={ser_str}", ""
        ])
        self._items.append([
            "", f"Status: {row['status']}", "", "",
            f"deser={deser_str}", ""
        ])
        self._items.append(["", "", "", "", "", ""])

        # Parse fields from fields_json
        import json
        fields_json = row.get("fields_json")
        if not fields_json:
            self._items.append([
                "", "No fields extracted yet", "", "",
                "Run JAM field recovery", ""
            ])
            return

        try:
            fields = json.loads(fields_json)
        except (json.JSONDecodeError, TypeError):
            self._items.append(["", "Invalid fields_json", "", "", "", ""])
            return

        total_size = 0
        for field in fields:
            idx = str(field.get("index", ""))
            fname = field.get("name", f"field_{idx}")
            ftype = field.get("type", "unknown")
            fsize = field.get("size", 0)
            offset = field.get("wire_offset", total_size)
            optional = "yes" if field.get("is_optional") else ""

            self._items.append([
                idx, fname, ftype, str(fsize),
                f"0x{offset:X}" if offset else "0",
                optional
            ])
            total_size += fsize

        # Summary
        self._items.append(["", "", "", "", "", ""])
        self._items.append([
            "", f"Total: {len(fields)} fields",
            "", f"{total_size}",
            "bytes total", ""
        ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        if n < len(self._items):
            return self._items[n]
        return ["", "", "", "", "", ""]

    def OnSelectLine(self, n):
        """Double-click on a field — jump to serializer."""
        db = self._session.db
        if db and self._jam_name:
            row = db.fetchone(
                "SELECT serializer_ea FROM jam_types WHERE name = ?",
                (self._jam_name,))
            if row and row["serializer_ea"]:
                idaapi.jumpto(row["serializer_ea"])

    def OnRefresh(self, n):
        self._items.clear()
        self._build_items()
        return len(self._items)

    def OnClose(self):
        pass


def show_wire_format(session, jam_name=None):
    """Show wire format viewer for a JAM type.

    If jam_name is None, tries to determine it from the function at cursor.
    """
    if not jam_name:
        ea = ida_kernwin.get_screen_ea()
        if ea != idaapi.BADADDR and session.db:
            # Check if cursor is on an opcode handler
            row = session.db.fetchone(
                "SELECT jam_type FROM opcodes WHERE handler_ea = ?", (ea,))
            if row and row["jam_type"]:
                jam_name = row["jam_type"]

    if not jam_name:
        jam_name = ida_kernwin.ask_str("", 0,
            "Enter JAM type name (e.g. JamCliHouseDecorAction):")
        if not jam_name:
            return

    viewer = WireFormatViewer(session, jam_name)
    viewer.Show()


def show_wire_format_for_handler(session):
    """Show wire format for the opcode handler at cursor position."""
    ea = ida_kernwin.get_screen_ea()
    if ea == idaapi.BADADDR:
        msg_warn("No address at cursor")
        return

    if not session.db:
        msg_warn("No database loaded")
        return

    row = session.db.fetchone(
        "SELECT jam_type FROM opcodes WHERE handler_ea = ?", (ea,))
    if row and row["jam_type"]:
        show_wire_format(session, row["jam_type"])
    else:
        msg(f"No opcode handler found at 0x{ea:X}")
        # Offer to search by cursor function
        show_wire_format(session)
