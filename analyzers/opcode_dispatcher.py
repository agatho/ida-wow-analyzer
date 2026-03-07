"""
Opcode Dispatcher Analyzer
Automatically identifies the main CMSG dispatch switch statement,
extracts handler function addresses, and maps them to TrinityCore names.
"""

import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# ---------------------------------------------------------------------------
# Auto-detection helpers
# ---------------------------------------------------------------------------

def _find_dispatcher_by_fanout(cfg):
    """Find functions with the highest number of unique callees.

    The CMSG dispatcher calls one handler per opcode, typically producing
    500-2000 unique call targets.  We scan all executable segments for
    large functions and rank them by callee count.

    Returns a list of (func_ea, callee_count, func_size) tuples,
    sorted by callee count descending, top 10.
    """
    candidates = []
    seg = ida_segment.get_first_seg()
    while seg:
        if seg.perm & 1:  # executable
            for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
                func = ida_funcs.get_func(func_ea)
                if not func:
                    continue
                # The dispatcher is a large function; skip small ones
                if func.size() < 0x1000:
                    continue
                callees = set()
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    for xref in idautils.XrefsFrom(head, 0):
                        if xref.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                            tf = ida_funcs.get_func(xref.to)
                            if tf and tf.start_ea != func.start_ea:
                                callees.add(tf.start_ea)
                if len(callees) > 100:
                    candidates.append((func_ea, len(callees), func.size()))
        seg = ida_segment.get_next_seg(seg.start_ea)

    candidates.sort(key=lambda x: -x[1])
    return candidates[:10]


def _find_dispatcher_by_switch_table(cfg):
    """Find functions containing the largest switch/jump tables.

    IDA marks switch jump tables with data cross-references from a
    single indirect jump instruction.  The CMSG dispatcher typically
    has 800-2000+ case entries in a single switch.

    Returns a list of (func_ea, case_count, func_size) tuples,
    sorted by case count descending, top 10.
    """
    import ida_nalt

    candidates = []
    seg = ida_segment.get_first_seg()
    while seg:
        if seg.perm & 1:  # executable
            for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
                func = ida_funcs.get_func(func_ea)
                if not func or func.size() < 0x800:
                    continue
                max_cases = 0
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    si = ida_nalt.get_switch_info(head)
                    if si is not None:
                        ncases = si.get_jtable_size()
                        if ncases > max_cases:
                            max_cases = ncases
                if max_cases > 100:
                    candidates.append((func_ea, max_cases, func.size()))
        seg = ida_segment.get_next_seg(seg.start_ea)

    candidates.sort(key=lambda x: -x[1])
    return candidates[:10]


def _score_candidate(func_ea, callee_count, switch_cases, func_size, cfg):
    """Score a dispatcher candidate on multiple heuristics.

    Higher score = more likely to be the CMSG dispatcher.
    """
    score = 0.0

    # Callee count is the strongest signal: 500-2000 unique call targets
    if callee_count >= 800:
        score += 50.0
    elif callee_count >= 500:
        score += 40.0
    elif callee_count >= 300:
        score += 25.0
    elif callee_count >= 100:
        score += 10.0

    # Switch table size: 800-2000 cases is typical for the dispatcher
    if switch_cases >= 800:
        score += 40.0
    elif switch_cases >= 500:
        score += 30.0
    elif switch_cases >= 200:
        score += 15.0
    elif switch_cases >= 100:
        score += 5.0

    # Function size: the dispatcher is typically very large (>64KB)
    if func_size >= 0x10000:
        score += 10.0
    elif func_size >= 0x8000:
        score += 5.0

    # Check for CMSG-related names in the function or its callees
    func_name = ida_name.get_name(func_ea) or ""
    name_lower = func_name.lower()
    if "dispatch" in name_lower or "opcode" in name_lower or "cmsg" in name_lower:
        score += 20.0
    if "handler" in name_lower or "packet" in name_lower or "message" in name_lower:
        score += 10.0

    return score


def _detect_dispatcher(session):
    """Auto-detect the CMSG dispatcher function.

    Combines two strategies:
      1. Find functions with the highest call fan-out
      2. Find functions with the largest switch/jump tables
    Then scores and ranks all candidates.

    Returns the EA of the best candidate, or 0 on failure.
    """
    cfg = session.cfg
    db = session.db

    msg_info("Auto-detecting CMSG dispatcher (this may take a while)...")

    # Strategy 1: fan-out analysis
    msg_info("Strategy 1: Scanning for functions with high call fan-out...")
    fanout_candidates = _find_dispatcher_by_fanout(cfg)
    if fanout_candidates:
        msg_info(f"  Found {len(fanout_candidates)} high-fanout candidates:")
        for ea, cnt, sz in fanout_candidates[:5]:
            name = ida_name.get_name(ea) or ea_str(ea)
            msg(f"    {name} — {cnt} callees, size={sz:#x}")
    else:
        msg_warn("  No high-fanout functions found")

    # Strategy 2: switch table analysis
    msg_info("Strategy 2: Scanning for large switch/jump tables...")
    switch_candidates = _find_dispatcher_by_switch_table(cfg)
    if switch_candidates:
        msg_info(f"  Found {len(switch_candidates)} switch-table candidates:")
        for ea, cnt, sz in switch_candidates[:5]:
            name = ida_name.get_name(ea) or ea_str(ea)
            msg(f"    {name} — {cnt} switch cases, size={sz:#x}")
    else:
        msg_warn("  No large switch tables found")

    if not fanout_candidates and not switch_candidates:
        msg_error("Auto-detection failed: no dispatcher candidates found")
        return 0

    # Merge candidates: build {func_ea: (callee_count, switch_cases, func_size)}
    merged = {}
    for ea, cnt, sz in fanout_candidates:
        merged[ea] = (cnt, 0, sz)
    for ea, cnt, sz in switch_candidates:
        if ea in merged:
            old_callees, _, old_sz = merged[ea]
            merged[ea] = (old_callees, cnt, max(old_sz, sz))
        else:
            merged[ea] = (0, cnt, sz)

    # Score and rank
    scored = []
    for ea, (callees, cases, sz) in merged.items():
        s = _score_candidate(ea, callees, cases, sz, cfg)
        scored.append((ea, s, callees, cases, sz))
    scored.sort(key=lambda x: -x[1])

    msg_info("Ranked dispatcher candidates:")
    for ea, s, callees, cases, sz in scored[:5]:
        name = ida_name.get_name(ea) or ea_str(ea)
        msg(f"  score={s:.1f}  {name}  callees={callees}  switch={cases}  size={sz:#x}")

    best_ea, best_score = scored[0][0], scored[0][1]
    if best_score < 20.0:
        msg_error("Auto-detection: no candidate scored high enough "
                  f"(best={best_score:.1f}, need >=20)")
        return 0

    best_name = ida_name.get_name(best_ea) or ea_str(best_ea)
    best_rva = cfg.ea_to_rva(best_ea)
    msg_info(f"Selected dispatcher: {best_name} at {ea_str(best_ea)} "
             f"(RVA={best_rva:#x}, score={best_score:.1f})")

    # Persist the discovered RVA into the config for future runs
    cfg.set("known_rvas", "main_dispatcher", best_rva)
    cfg.save()
    msg_info(f"Saved dispatcher RVA {best_rva:#x} to config")

    # Also store in the KV store so the DB records the discovery
    if db:
        db.kv_set("auto_detected_dispatcher", {
            "ea": best_ea,
            "rva": best_rva,
            "score": best_score,
            "name": best_name,
        })
        db.commit()

    return best_ea


def analyze_opcode_dispatcher(session):
    """Find and analyze the main opcode dispatch table.

    Strategy:
      1. Use the known dispatcher RVA from config (if available)
      2. Otherwise, auto-detect by finding functions with highest
         call fan-out and largest switch tables
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
    if dispatcher_rva:
        dispatcher_ea = cfg.rva_to_ea(dispatcher_rva)
    else:
        msg_info("No known dispatcher RVA configured — running auto-detection")
        dispatcher_ea = _detect_dispatcher(session)
        if not dispatcher_ea:
            return 0
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
