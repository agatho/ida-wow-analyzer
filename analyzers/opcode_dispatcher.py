"""
Opcode Dispatcher Analyzer
Automatically identifies the main CMSG dispatch switch statement,
extracts handler function addresses, and maps them to TrinityCore names.
"""

import ida_bytes
import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


def analyze_opcode_dispatcher(session):
    """Find and analyze the main opcode dispatch table.

    Strategy:
      1. Use the known dispatcher RVA from config (if available)
      2. Otherwise, find the largest switch statement in the binary
      3. Extract handler pointers from the dispatch table
      4. Map handlers to TrinityCore opcode names via string refs
    """
    db = session.db
    cfg = session.cfg
    disp = cfg.dispatch_range

    if not disp:
        msg_error("No dispatch range configured")
        return 0

    dispatcher_rva = cfg.known_rvas.get("main_dispatcher")
    if not dispatcher_rva:
        msg_warn("No known dispatcher RVA — auto-detection not yet implemented")
        return 0

    dispatcher_ea = cfg.rva_to_ea(dispatcher_rva)
    msg_info(f"Analyzing dispatcher at {ea_str(dispatcher_ea)}")

    # Get the dispatcher function
    func = ida_funcs.get_func(dispatcher_ea)
    if not func:
        msg_error(f"No function at dispatcher address {ea_str(dispatcher_ea)}")
        return 0

    func_name = ida_name.get_name(func.start_ea)
    msg_info(f"Dispatcher function: {func_name or ea_str(func.start_ea)} "
             f"(size={func.size()})")

    # Find all functions called by the dispatcher (these are the handlers)
    callees = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type in (ida_xref.fl_CF, ida_xref.fl_CN, ida_xref.fl_JF, ida_xref.fl_JN):
                target_func = ida_funcs.get_func(xref.to)
                if target_func and target_func.start_ea != func.start_ea:
                    callees.add(target_func.start_ea)

    msg_info(f"Found {len(callees)} unique callee functions")

    # Try to identify handler functions by looking for functions that
    # call known deserializer patterns (WriteUInt32, etc.)
    count = 0
    dispatch_start = disp.get("start", 0x420000)
    dispatch_count = disp.get("count", 891)

    for i, callee_ea in enumerate(sorted(callees)):
        callee_name = ida_name.get_name(callee_ea)
        callee_rva = cfg.ea_to_rva(callee_ea)

        # Store as opcode handler
        internal_index = dispatch_start + i
        if i >= dispatch_count:
            break

        # Try to determine TC name from existing function name
        tc_name = None
        status = "unknown"
        if callee_name and not callee_name.startswith("sub_"):
            # Existing names from enrichment pipeline
            if callee_name.startswith("CMSG_") or "Handler" in callee_name:
                tc_name = callee_name
                status = "matched"
            elif "Housing" in callee_name or "Neighborhood" in callee_name:
                tc_name = callee_name
                status = "matched"

        db.upsert_opcode(
            direction="CMSG",
            internal_index=internal_index,
            handler_ea=callee_ea,
            tc_name=tc_name,
            status=status,
        )
        count += 1

    db.commit()
    msg_info(f"Stored {count} CMSG handler entries")
    return count


def analyze_handler_jam_types(session):
    """For each opcode handler, identify which JAM type it deserializes.

    Strategy: look at the first few callees of each handler for known
    JAM deserializer function patterns (by name or by calling serializer RVAs).
    """
    db = session.db
    cfg = session.cfg

    serializer_eas = set()
    for name, rva in cfg.serializer_rvas.items():
        if rva:
            serializer_eas.add(cfg.rva_to_ea(rva))

    if not serializer_eas:
        msg_warn("No serializer RVAs configured — JAM type detection skipped")
        return 0

    handlers = db.fetchall("SELECT * FROM opcodes WHERE handler_ea IS NOT NULL")
    updated = 0

    for handler in handlers:
        handler_ea = handler["handler_ea"]
        func = ida_funcs.get_func(handler_ea)
        if not func:
            continue

        # Check first-level callees for JAM deserializer patterns
        for head in idautils.Heads(func.start_ea,
                                    min(func.end_ea, func.start_ea + 0x200)):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN):
                    continue
                callee_name = ida_name.get_name(xref.to)
                if callee_name and callee_name.startswith("Jam"):
                    # Found a JAM type reference
                    jam_name = callee_name.split("::")[0] if "::" in callee_name else callee_name
                    db.upsert_opcode(
                        direction=handler["direction"],
                        internal_index=handler["internal_index"],
                        jam_type=jam_name,
                    )
                    # Also ensure JAM type exists in jam_types table
                    db.upsert_jam_type(
                        name=jam_name,
                        deserializer_ea=xref.to,
                    )
                    updated += 1
                    break

    db.commit()
    msg_info(f"Linked {updated} handlers to JAM types")
    return updated
