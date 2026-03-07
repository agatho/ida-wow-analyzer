"""
Hex-Rays Decompiler Annotations
Adds inline comments and variable renaming hints to decompiled pseudocode
based on knowledge DB data (opcode names, JAM types, DB2 tables, etc.).
"""

import re

import ida_hexrays
import ida_kernwin
import idaapi

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn


class HexRaysAnnotator:
    """Annotates Hex-Rays decompiled output with WoW-specific knowledge."""

    def __init__(self, session):
        self._session = session
        self._callback_installed = False

    def install(self):
        """Install the Hex-Rays callback for annotation."""
        if self._callback_installed:
            return
        if not ida_hexrays.init_hexrays_plugin():
            msg_warn("Hex-Rays not available — annotations disabled")
            return

        ida_hexrays.install_hexrays_callback(self._on_hexrays_event)
        self._callback_installed = True
        msg_info("Hex-Rays annotations enabled")

    def remove(self):
        """Remove the Hex-Rays callback."""
        if self._callback_installed:
            ida_hexrays.remove_hexrays_callback(self._on_hexrays_event)
            self._callback_installed = False

    def _on_hexrays_event(self, event, *args):
        """Handle Hex-Rays events for annotation."""
        if event == ida_hexrays.hxe_maturity:
            cfunc = args[0]
            maturity = args[1]
            if maturity == ida_hexrays.CMAT_FINAL:
                self._annotate_cfunc(cfunc)
        elif event == ida_hexrays.hxe_populating_popup:
            widget = args[0]
            popup = args[1]
            vu = args[2]
            self._populate_popup(widget, popup, vu)
        return 0

    def _annotate_cfunc(self, cfunc):
        """Add annotations to a decompiled function."""
        db = self._session.db
        if not db:
            return

        ea = cfunc.entry_ea

        # Check if this function is a known opcode handler
        row = db.fetchone(
            "SELECT * FROM opcodes WHERE handler_ea = ?", (ea,))
        if row:
            tc_name = row["tc_name"] or f"opcode_0x{row['internal_index']:X}"
            jam_type = row["jam_type"] or ""
            comment = f"[TC] {row['direction']} handler: {tc_name}"
            if jam_type:
                comment += f"\n[TC] JAM type: {jam_type}"
            cfunc.user_cmts = cfunc.user_cmts or ida_hexrays.user_cmts_new()
            _add_func_comment(cfunc, comment)

        # Check if this is a known JAM serializer/deserializer
        row = db.fetchone(
            "SELECT * FROM jam_types WHERE serializer_ea = ? "
            "OR deserializer_ea = ?", (ea, ea))
        if row:
            role = "serializer" if row["serializer_ea"] == ea else "deserializer"
            comment = f"[TC] JAM {role}: {row['name']}"
            if row["field_count"]:
                comment += f" ({row['field_count']} fields)"
            cfunc.user_cmts = cfunc.user_cmts or ida_hexrays.user_cmts_new()
            _add_func_comment(cfunc, comment)

        # Check if this is a Lua API handler
        row = db.fetchone(
            "SELECT * FROM lua_api WHERE handler_ea = ?", (ea,))
        if row:
            ns = row["namespace"]
            method = row["method"]
            full_name = f"{ns}.{method}" if ns else method
            comment = f"[TC] Lua API: {full_name}"
            if row["arg_count"] >= 0:
                comment += f" (args: {row['arg_count']})"
            cfunc.user_cmts = cfunc.user_cmts or ida_hexrays.user_cmts_new()
            _add_func_comment(cfunc, comment)

    def _populate_popup(self, widget, popup, vu):
        """Add TC WoW items to the pseudocode right-click menu."""
        session = self._session

        # Add "Show Wire Format" if on a handler
        ea = vu.cfunc.entry_ea if vu.cfunc else None
        if ea and session.db:
            row = session.db.fetchone(
                "SELECT jam_type FROM opcodes WHERE handler_ea = ?", (ea,))
            if row and row["jam_type"]:
                ida_kernwin.attach_action_to_popup(
                    widget, popup, "tc_wow:show_wire_format", "TC WoW/")

        # Always show general TC actions
        for action_name in session.get_registered_actions():
            if action_name != "tc_wow:show_dashboard":
                ida_kernwin.attach_action_to_popup(
                    widget, popup, action_name, "TC WoW/")

    def annotate_serializer_calls(self, cfunc):
        """Annotate known serializer function calls in pseudocode.

        Adds inline comments like:
          // [TC] WriteUInt32 — field: DecorEntryId (offset 0x48)
        """
        db = self._session.db
        if not db:
            return

        # This requires walking the ctree — deferred to full implementation
        pass


def _add_func_comment(cfunc, text):
    """Add a comment at the top of a decompiled function."""
    try:
        treeloc = ida_hexrays.treeloc_t()
        treeloc.ea = cfunc.entry_ea
        treeloc.itp = ida_hexrays.ITP_BLOCK1
        if cfunc.user_cmts is None:
            cfunc.user_cmts = ida_hexrays.user_cmts_new()
        # Check if comment already exists
        it = cfunc.user_cmts.find(treeloc)
        if it != cfunc.user_cmts.end():
            existing = cfunc.user_cmts[treeloc].c_str()
            if text in existing:
                return  # already annotated
        citem = ida_hexrays.citem_cmt_t(text)
        cfunc.user_cmts.insert(treeloc, citem)
        cfunc.save_user_cmts()
    except Exception:
        pass  # annotation is best-effort
