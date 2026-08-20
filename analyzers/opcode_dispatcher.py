"""
Opcode Dispatcher Analyzer
Automatically identifies the main CMSG dispatch switch statement,
extracts handler function addresses, and maps them to TrinityCore names.
"""

import os
import json
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, dumps_dir, current_build)
from tc_wow_analyzer.core import kv_keys


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

    # Persist the discovered RVA into the config for future runs, scoped to
    # THIS build. It used to be stored globally, so the next build resolved the
    # stale RVA against its own image base and "found" the dispatcher at
    # whatever function happened to live at that offset.
    known = dict(cfg.known_rvas or {})
    known["main_dispatcher"] = best_rva
    cfg.set_build_scoped("known_rvas", known)
    cfg.save()
    msg_info(f"Saved dispatcher RVA {best_rva:#x} to config "
             f"(build {cfg.build_number or 'unknown'})")

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
    """Locate the client's per-family dispatchers and identify each family from
    the client's OWN JAM message type names.

    REWRITTEN 2026-08-20 — the previous implementation fabricated opcodes
    ---------------------------------------------------------------------
    It collected the dispatcher's callees, sorted them by ADDRESS, and assigned

        internal_index = dispatch_start + i          # i = address rank

    Address rank has no relationship to opcode order, so every row it wrote was
    invented. It looked plausible because the values landed inside a real family
    range. Residue from that era is still visible in older databases as rows
    tagged `dispatch_switch@<ea>` that place SMSG opcodes into CMSG family 0x40
    with dozens of opcodes sharing one handler address.

    It also early-outed whenever the `opcodes` table was non-empty, which hid the
    fabrication behind "already in DB" — so on a populated database it silently
    did nothing, and on a fresh one it silently invented. Both are gone.

    WHAT IT DOES NOW
    ----------------
    Uses the shared, evidence-based identification in `core/jam_family.py`: find
    every per-family switch dispatcher, read the `WowGetRawTypeName<...>` strings
    its case bodies reference, and match those real message-type names against
    the catalog's opcode names. A family is only accepted when the winner clears
    an absolute match rate AND beats the runner-up — otherwise it is skipped, not
    guessed.

    This analyzer deliberately writes NO opcode rows: `opcode_dispatch_switch`
    owns opcode->handler, and two writers could disagree. Here we persist the
    DISPATCHER MAP, which is what this analyzer is actually good for:

      * `known_rvas.family_dispatchers` (build-scoped) — client family -> RVA
      * artifact `family_map_<build>.json` — client family, catalog family, delta,
        evidence and case count, so each build's mapping is diffable against the
        next one. Family numbers shift every build by design (JAM ids are assigned
        in metadata order), so a per-build record is the thing worth keeping.
    """
    db = session.db
    cfg = session.cfg
    build = current_build() or (cfg.build_number if cfg else 0)

    try:
        import idautils  # noqa: F401  (are we inside IDA?)
    except Exception:
        msg_warn("Opcode dispatcher: not inside IDA — skipping")
        return 0

    from tc_wow_analyzer.analyzers.opcode_dispatch_switch import load_opcode_oracle
    from tc_wow_analyzer.core.jam_family import (
        _collect_family_switches, _case_typenames, choose_catalog_family)

    known_values, _bases = load_opcode_oracle(session)
    if not known_values:
        msg_warn("Opcode dispatcher: no opcode catalog — run 'TC Opcode Xref' "
                 "first; skipping (refusing to guess)")
        return 0

    switches = _collect_family_switches()
    if not switches:
        msg_warn("Opcode dispatcher: no per-family switch dispatcher found")
        return 0

    catalog_families = sorted({v >> 16 for v in known_values})
    cache = {}
    mapping = []
    dispatchers = {}
    for client_fam, (disp_ea, cases) in sorted(switches.items()):
        dispatchers["0x%X" % client_fam] = "0x%X" % cfg.ea_to_rva(disp_ea)
        ordered = sorted(set(cases.values()))
        idx_types = {}
        for idx, tgt in cases.items():
            t = _case_typenames(tgt, ordered, disp_ea, cache)
            if t:
                idx_types[idx] = t
        pick = choose_catalog_family(idx_types, known_values, catalog_families)
        if not pick:
            continue
        mapping.append({
            "client_family": "0x%X" % client_fam,
            "catalog_family": "0x%X" % pick["family"],
            "delta": client_fam - pick["family"],
            "dispatcher_rva": "0x%X" % cfg.ea_to_rva(disp_ea),
            "cases": len(cases),
            "match_rate": round(pick["rate"], 3),
            "runner_up_rate": round(pick["runner_up_rate"], 3),
            "evidence": "client JAM type names (%d/%d indices agree)"
                        % (pick["hits"], pick["tested"]),
        })
        msg_info("  client family 0x%X -> catalog 0x%X (delta %+d, %.0f%% vs %.0f%%)"
                 % (client_fam, pick["family"], client_fam - pick["family"],
                    100.0 * pick["rate"], 100.0 * pick["runner_up_rate"]))

    # build-scoped so a later build cannot inherit this build's addresses
    try:
        known = dict(cfg.known_rvas or {})
        known["family_dispatchers"] = dispatchers
        cfg.set_build_scoped("known_rvas", known)
    except Exception as exc:
        msg_warn("Opcode dispatcher: could not persist known_rvas (%s)" % exc)

    deltas = sorted({m["delta"] for m in mapping})
    payload = {
        "type": "family_map",
        "build": build,
        "note": ("JAM protocol/message ids are assigned in metadata order (Rumsey, "
                 "GDC 2013), so family numbers shift whenever a protocol is "
                 "inserted. This records THIS build's mapping."),
        "observed_deltas": deltas,
        "client_dispatchers": dispatchers,
        "families": mapping,
    }
    try:
        out = os.path.join(dumps_dir(), "family_map_%s.json" % build)
        with open(out, "w") as fh:
            json.dump(payload, fh, indent=1)
        msg_info("Opcode dispatcher: wrote %s" % out)
    except Exception as exc:
        msg_warn("Opcode dispatcher: could not write family map (%s)" % exc)

    try:
        db.kv_set(kv_keys.AUTO_DETECTED_DISPATCHER, payload)
    except Exception:
        pass

    msg_info("Opcode dispatcher: %d dispatchers found, %d families identified "
             "from client type names (deltas %s)"
             % (len(switches), len(mapping), deltas or "n/a"))
    return len(mapping)


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
            if isinstance(rva, str):
                rva = int(rva, 16) if rva.startswith("0x") else int(rva)
            serializer_eas.add(cfg.rva_to_ea(rva))

    handlers = db.fetchall("SELECT * FROM opcodes WHERE handler_ea IS NOT NULL")
    updated = 0

    # --- Strategy 1: IDA xref-based matching (original, requires live IDA) ---
    if serializer_eas:
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
                        db.upsert_jam_type(
                            name=jam_name,
                            deserializer_ea=xref.to,
                        )
                        updated += 1
                        break

    # --- Strategy 2: DB-based name matching from functions table ---
    # Works even without serializer RVAs or live IDA
    if updated == 0:
        msg_info("No serializer RVAs or live IDA xrefs — trying DB-based JAM linking...")

        # Build a map of Handler_Jam* functions from the functions table
        handler_jam_funcs = db.fetchall(
            "SELECT ea, name FROM functions "
            "WHERE name LIKE 'Handler_Jam%' OR name LIKE 'FJam%_Deserialize' "
            "OR name LIKE 'Jam%_Serialize' OR name LIKE '%Jam%_Read' "
            "ORDER BY name"
        )

        if handler_jam_funcs:
            msg_info(f"  Found {len(handler_jam_funcs)} JAM-related functions in DB")

            # Build a map from handler_ea to handler row
            handler_by_ea = {h["handler_ea"]: h for h in handlers}

            # Build a map from function EA -> JAM type name
            jam_func_map = {}  # ea -> jam_type_name
            for func_row in handler_jam_funcs:
                fname = func_row["name"]
                # Extract JAM type name from function name patterns:
                #   Handler_JamFoo -> JamFoo
                #   FJamFoo_Deserialize -> JamFoo
                #   JamFoo_Serialize -> JamFoo
                jam_name = None
                if fname.startswith("Handler_Jam"):
                    jam_name = fname[len("Handler_"):]
                elif fname.startswith("Handler_"):
                    # Handler_SomethingJamFoo
                    jam_name = fname[len("Handler_"):]
                elif fname.startswith("FJam") and "_Deserialize" in fname:
                    jam_name = fname[1:fname.index("_Deserialize")]
                elif "Jam" in fname and "_Serialize" in fname:
                    idx = fname.index("Jam")
                    jam_name = fname[idx:fname.index("_Serialize")]
                elif "Jam" in fname and "_Read" in fname:
                    idx = fname.index("Jam")
                    jam_name = fname[idx:fname.index("_Read")]

                if jam_name:
                    jam_func_map[func_row["ea"]] = jam_name

            # Also build JAM type name set from jam_types table
            known_jam_types = set()
            jam_rows = db.fetchall("SELECT name FROM jam_types")
            for jr in jam_rows:
                if jr["name"]:
                    known_jam_types.add(jr["name"])

            # Strategy 2a: Match by xrefs in functions table
            # For each handler_ea, find functions that xref TO this handler
            # (callers that set up the JAM type before calling the handler)
            for func_row in handler_jam_funcs:
                func_ea = func_row["ea"]
                jam_name = jam_func_map.get(func_ea)
                if not jam_name:
                    continue

                # Check if this function IS a handler (direct match)
                if func_ea in handler_by_ea:
                    handler = handler_by_ea[func_ea]
                    if not handler["jam_type"] or handler["jam_type"] in ("", "none"):
                        db.upsert_opcode(
                            direction=handler["direction"],
                            internal_index=handler["internal_index"],
                            jam_type=jam_name,
                        )
                        if jam_name not in known_jam_types:
                            db.upsert_jam_type(name=jam_name, deserializer_ea=func_ea)
                            known_jam_types.add(jam_name)
                        updated += 1

            # Strategy 2b: Match JAM types to handlers by name containment
            # If opcode already has a jam_type field from import, ensure it's in jam_types table
            for handler in handlers:
                existing_jam = handler["jam_type"]
                if existing_jam and existing_jam not in ("", "none"):
                    if existing_jam not in known_jam_types:
                        db.upsert_jam_type(name=existing_jam)
                        known_jam_types.add(existing_jam)
                        updated += 1

            msg_info(f"  DB-based JAM linking: {updated} links established")
        else:
            msg_warn("No JAM-related functions found in functions table either")

    db.commit()
    # --- Strategy 3: name normalisation against the TC opcode table ---
    # Independent of IDA and of handler_ea: convert each JAM type name the same
    # way the codegen does (JamCliHouseDecorAction -> CMSG_HOUSE_DECOR_ACTION)
    # and keep only the ones that hit a REAL TrinityCore opcode.
    updated += _link_by_name_normalisation(db)

    # --- Strategy 4: handler_rva straight from the AutoDump ---
    updated += _link_by_autodump_handler_rva(session)

    if updated == 0:
        # Say WHY, with the numbers. This analyzer returning a bare 0 told
        # nobody that the input it needs is simply absent from this build.
        _explain_missing_link(db)

    msg_info(f"Linked {updated} handlers to JAM types")
    return updated


def _link_by_name_normalisation(db):
    """Link jam_types to opcodes whose tc_name matches the normalised JAM name.

    Deliberately conservative: only an EXACT hit against a tc_name already in
    the opcodes table counts. The obvious temptation is to synthesise the
    opcode name from the JAM name and insert it — that is what
    `wow_handler_stubs_<build>.cpp` does, and on build 69382 exactly 1 of its
    291 synthesised names corresponds to a real TrinityCore opcode. Inserting
    the other 290 would manufacture opcodes that do not exist.
    """
    from tc_wow_analyzer.codegen.packet_scaffolding import _jam_to_opcode_name

    try:
        tc_rows = db.fetchall(
            "SELECT direction, internal_index, tc_name FROM opcodes "
            "WHERE tc_name IS NOT NULL AND tc_name != ''")
        jam_rows = db.fetchall("SELECT name FROM jam_types")
    except Exception as exc:
        msg_warn(f"  name-normalisation linking unavailable: {exc}")
        return 0

    by_tc_name = {}
    for row in tc_rows:
        by_tc_name.setdefault(row["tc_name"], row)

    linked = 0
    for jam in jam_rows:
        name = jam["name"]
        if not name:
            continue
        for direction in ("CMSG", "SMSG"):
            hit = by_tc_name.get(_jam_to_opcode_name(name, direction))
            if not hit:
                continue
            db.upsert_opcode(direction=hit["direction"],
                             internal_index=hit["internal_index"],
                             jam_type=name)
            linked += 1
            break

    if linked:
        db.commit()
        msg_info(f"  name normalisation: {linked} JAM types matched a real "
                 f"TC opcode")
    return linked


def _link_by_autodump_handler_rva(session):
    """Link the JAM entries that carry a real handler_rva in the AutoDump."""
    from tc_wow_analyzer.core import autodump
    from tc_wow_analyzer.core.utils import dumps_build_path

    db, cfg = session.db, session.cfg
    path = dumps_build_path("wow_jam_messages")
    if not os.path.isfile(path):
        return 0

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:
        msg_warn(f"  handler_rva linking: cannot read {path}: {exc}")
        return 0

    linked = 0
    for message, _cat, implied in autodump.iter_jam_messages(data):
        handler_rva = message.get("handler_rva")
        if not handler_rva:
            continue
        if isinstance(handler_rva, str):
            try:
                handler_rva = int(handler_rva, 16)
            except ValueError:
                continue
        handler_ea = cfg.rva_to_ea(handler_rva)
        row = db.fetchone(
            "SELECT direction, internal_index FROM opcodes WHERE handler_ea = ?",
            (handler_ea,))
        if not row:
            continue
        db.upsert_opcode(direction=row["direction"],
                         internal_index=row["internal_index"],
                         jam_type=message["name"])
        linked += 1

    if linked:
        db.commit()
        msg_info(f"  autodump handler_rva: {linked} links")
    return linked


def _explain_missing_link(db):
    """Report WHY no opcode could be linked to a JAM type.

    The opcode<->JAM mapping normally comes from the dispatch table in
    `wow_opcode_dispatch_<build>.json`. On build 69382 that file contains 0
    handlers (111 bytes), so there is nothing to link against and no amount of
    analysis inside the plugin can invent it. Saying that plainly is more
    useful than returning 0.
    """
    try:
        opcodes = db.fetchone("SELECT COUNT(*) AS c FROM opcodes")["c"]
        with_handler = db.fetchone(
            "SELECT COUNT(*) AS c FROM opcodes "
            "WHERE handler_ea IS NOT NULL AND handler_ea > 0")["c"]
        jam_types = db.fetchone("SELECT COUNT(*) AS c FROM jam_types")["c"]
    except Exception:
        return

    msg_warn("No opcode could be linked to a JAM type. Inventory:")
    msg_warn(f"    opcodes in DB:            {opcodes} "
             f"(with a handler address: {with_handler})")
    msg_warn(f"    jam_types in DB:          {jam_types}")
    msg_warn("    The link normally comes from the dispatch table in "
             "wow_opcode_dispatch_<build>.json.")
    if with_handler == 0:
        msg_warn("    No opcode carries a handler address, so there is nothing "
                 "to correlate. Re-run AutoDump for this build: an empty "
                 "wow_opcode_dispatch is an extractor problem, not a plugin one.")
