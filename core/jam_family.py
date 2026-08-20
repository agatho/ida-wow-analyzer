"""
Shared JAM family identification — the client tells us which family it is.

WHY THIS IS SHARED
------------------
Blizzard assigns each JAM protocol a one-byte family id "based on the order in
which the protocols were found in the metadata", and each message an id "by the
order they appear in their .jam file" (Rumsey, GDC 2013, "Network Serialization
and Routing in World of Warcraft"). So BOTH numbers shift whenever a protocol or
message is inserted, and any catalog of numeric opcode values goes stale on the
next build. Measured 12.1.0.69382 vs the TrinityCore catalog: +3, +4, then +5.

The only stable anchor is inside the client: every handler references
    const char *__cdecl WowGetRawTypeName<struct JamGarrisonFollower>(void)
Scoring those real message-type names against the catalog's opcode NAMES
identifies each family from evidence rather than arithmetic, and keeps working
across future builds with no catalog update.

Two analyzers need this (opcode_dispatch_switch, opcode_dispatcher), so it lives
here exactly once — two implementations could drift apart and silently disagree.
"""

_MIN_MATCHED_CASES = 4
_MIN_MATCHED_FRACTION = 0.5

def _switch_api():
    gsi = csc = None
    for modname in ("ida_nalt", "idaapi"):
        try:
            mod = __import__(modname)
        except Exception:
            continue
        if gsi is None and hasattr(mod, "get_switch_info"):
            gsi = mod.get_switch_info
        if csc is None and hasattr(mod, "calc_switch_cases"):
            csc = mod.calc_switch_cases
    return gsi, csc


def _cases_of(csc, ea, si):
    """[(case_value, target_ea), ...] excluding the switch default target."""
    try:
        c = csc(ea, si)
    except Exception:
        return None
    defj = None
    for attr in ("defjump", "default_jump"):
        try:
            d = getattr(si, attr, None)
            if isinstance(d, int) and d not in (0, 0xFFFFFFFFFFFFFFFF):
                defj = d
        except Exception:
            pass
    out = []
    try:
        n = c.targets.size()
    except Exception:
        try:
            n = len(c.targets)
        except Exception:
            return None
    for i in range(n):
        try:
            tgt = int(c.targets[i])
            vlist = list(c.cases[i])
        except Exception:
            continue
        if defj is not None and tgt == defj:
            continue
        for v in vlist:
            out.append((int(v), tgt))
    return out



# Tokens too generic to carry evidence (appear in most names/types alike).
_GENERIC_TOKENS = frozenset({
    "DATA", "INFO", "ENTRY", "STRUCT", "LIST", "UPDATE", "RESULT", "MEMBER",
    "CLIENT", "JAM", "CLI", "UNSIGNED", "INT", "CHAR", "BOOL", "GUID", "RECORD",
    "SLOT", "NODE", "RESPONSE", "REQUEST", "MSG", "SMSG", "CMSG", "SET", "GET",
    "STATE", "TYPE", "ID", "THE", "AND", "FLAGS", "COUNT", "INDEX", "VALUE",
})

_TYPENAME_RE = None


def _typename_re():
    global _TYPENAME_RE
    if _TYPENAME_RE is None:
        import re
        _TYPENAME_RE = re.compile(
            r"WowGetRawTypeName<(?:struct |class |enum )?([A-Za-z0-9_:<>, \*]+)>")
    return _TYPENAME_RE


def name_tokens(opcode_name):
    """Evidence tokens of a TC opcode name: SMSG_SETUP_CURRENCY -> {SETUP,CURRENCY}."""
    out = set()
    for part in (opcode_name or "").split("_"):
        p = part.strip().upper()
        if len(p) > 2 and p not in _GENERIC_TOKENS:
            out.add(p)
    return out


def type_tokens(type_names):
    """Evidence tokens of JAM type names: ClientSetupCurrencyRecord -> {SETUP,CURRENCY,RECORD?}."""
    import re
    out = set()
    for t in type_names or ():
        t = re.sub(r"^(?:Jam|Client|Cli)+", "", t or "")
        for m in re.finditer(r"[A-Z][a-z0-9]+|[A-Z]{2,}(?![a-z])", t):
            w = m.group(0).upper()
            if len(w) > 2 and w not in _GENERIC_TOKENS:
                out.add(w)
    return out


def score_client_family(idx_types, known_values, catalog_family,
                        direction="SMSG"):
    """How well do the client's own type names match a catalog family's names?

    idx_types: {family_index: [jam type name, ...]} taken from the client.
    Returns (hits, tested) — indices where at least one evidence token agrees.

    DIRECTION FILTER (measured 2026-08-19, do not remove): these dispatchers are
    the RECEIVE path, so only SMSG entries are legitimate candidates. Without the
    filter the CMSG twin of a subsystem wins on generic tokens — client 0x4A
    (JamWhoEntry/JamClientMOTDStruct) scored CMSG_CHAT_* (catalog 0x2B) over the
    correct SMSG_WHO / SMSG_MOTD (catalog 0x47), and client 0x58 (JamCliHouse)
    scored CMSG_HOUSING_SVCS_* over SMSG_HOUSING_SVCS_*. Both wrong by one
    direction, both silently plausible.
    """
    hits = tested = 0
    base = catalog_family << 16
    for idx, types in (idx_types or {}).items():
        entry = known_values.get(base | idx)
        if not entry:
            continue
        if direction and len(entry) > 1 and entry[1] != direction:
            continue
        tested += 1
        if name_tokens(entry[0]) & type_tokens(types):
            hits += 1
    return hits, tested


def choose_catalog_family(idx_types, known_values, candidates,
                          min_tested=4, min_rate=0.25, min_margin=1.8,
                          min_hits=3, direction="SMSG"):
    """Pick the catalog family a client family really is — or None.

    Deliberately conservative: the winner must clear an absolute match rate AND
    beat the runner-up by `min_margin`x. A wrong family scores ~0 because JAM type
    names are highly specific, so a genuine winner separates sharply.
    """
    scored = []
    for fam in candidates:
        hits, tested = score_client_family(idx_types, known_values, fam,
                                           direction=direction)
        if tested >= min_tested:
            scored.append((hits / float(tested), hits, tested, fam))
    if not scored:
        return None
    scored.sort(reverse=True)
    rate, hits, tested, fam = scored[0]
    runner = scored[1][0] if len(scored) > 1 else 0.0
    if rate < min_rate or hits < min_hits:
        return None
    if runner > 0 and rate < runner * min_margin:
        return None
    return {"family": fam, "rate": rate, "hits": hits, "tested": tested,
            "runner_up_rate": runner}


def _collect_family_switches():
    """{client_family: (dispatcher_ea, {index: target_ea})} for base-0 switches.

    A base-0 switch cases on the FULL opcode value, so the family is the client's
    own — no interpretation. Requires IDA.
    """
    import idc, idaapi, idautils, ida_funcs
    get_si, calc_cases = _switch_api()
    if get_si is None:
        return {}
    ib = idaapi.get_imagebase()
    text_lo, text_hi = ib + 0x1000, ib + 0x3782000
    found = {}
    for fn in idautils.Functions(text_lo, text_hi):
        f = ida_funcs.get_func(fn)
        if not f:
            continue
        ea = f.start_ea
        while ea < f.end_ea and ea != idaapi.BADADDR:
            si = get_si(ea)
            if si:
                pairs = _cases_of(calc_cases, ea, si)
                if pairs:
                    fams = set(v >> 16 for v, _ in pairs if v >= 0x290000)
                    if len(fams) == 1:
                        fam = fams.pop()
                        sel = dict((v & 0xFFFF, t) for v, t in pairs
                                   if (v >> 16) == fam)
                        if len(sel) >= _MIN_MATCHED_CASES and \
                           len(sel) >= _MIN_MATCHED_FRACTION * len(pairs):
                            prev = found.get(fam)
                            if prev is None or len(sel) > len(prev[1]):
                                found[fam] = (f.start_ea, sel)
            nxt = idc.next_head(ea, f.end_ea)
            ea = nxt if nxt > ea else f.end_ea
    return found


def _func_typenames(func_ea, cache, max_items=400):
    import idautils, ida_bytes, ida_funcs
    if func_ea in cache:
        return cache[func_ea]
    out = []
    fn = ida_funcs.get_func(func_ea)
    if fn:
        rx = _typename_re()
        n = 0
        for head in idautils.FuncItems(fn.start_ea):
            n += 1
            if n > max_items:
                break
            for ref in idautils.DataRefsFrom(head):
                s = ida_bytes.get_strlit_contents(ref, -1, 0)
                if not s:
                    continue
                try:
                    txt = s.decode("ascii", "replace")
                except Exception:
                    continue
                m = rx.search(txt)
                if m:
                    out.append(m.group(1).strip())
    cache[func_ea] = out
    return out


def _case_typenames(target, ordered_targets, dispatcher_ea, cache, window=0x400):
    """JAM type names for one case body, following thunk -> real handler."""
    import idc, idaapi, idautils, ida_bytes, ida_funcs
    rx = _typename_re()
    nxt = None
    for x in ordered_targets:
        if x > target:
            nxt = x
            break
    end = min(nxt if nxt else target + window, target + window)
    types, callees = [], []
    ea = target
    while ea < end and ea != idaapi.BADADDR:
        for ref in idautils.DataRefsFrom(ea):
            s = ida_bytes.get_strlit_contents(ref, -1, 0)
            if s:
                try:
                    txt = s.decode("ascii", "replace")
                except Exception:
                    txt = ""
                m = rx.search(txt)
                if m:
                    types.append(m.group(1).strip())
        if idc.print_insn_mnem(ea).lower() in ("call", "jmp"):
            for ref in idautils.CodeRefsFrom(ea, 0):
                fn = ida_funcs.get_func(ref)
                if fn and fn.start_ea != dispatcher_ea:
                    callees.append(fn.start_ea)
        nxt_ea = idc.next_head(ea, end)
        if nxt_ea == idaapi.BADADDR or nxt_ea <= ea:
            break
        ea = nxt_ea
    if not types:                      # thunk: look inside the real handler
        for fs in callees[:3]:
            types.extend(_func_typenames(fs, cache))
    return types


def resolve_via_jam_typenames(known_values, hb=None):
    """opcode -> handler using the client's own JAM type names to fix the family.

    Returns (handler_targets, stats) in the same shape as resolve_dispatch():
    {handler_ea: [(opcode, name, direction), ...]}
    """
    handler_targets = {}
    stats = {"client_families": 0, "mapped_families": 0, "opcodes": 0,
             "unmapped": [], "family_map": {}}
    switches = _collect_family_switches()
    stats["client_families"] = len(switches)
    if not switches:
        return handler_targets, stats

    catalog_families = sorted(set(v >> 16 for v in known_values))
    cache = {}
    for client_fam, (disp_ea, cases) in sorted(switches.items()):
        if hb is not None:
            try:
                hb.tick("family 0x%X" % client_fam)
            except Exception:
                pass
        ordered = sorted(set(cases.values()))
        idx_types = {}
        for idx, tgt in cases.items():
            t = _case_typenames(tgt, ordered, disp_ea, cache)
            if t:
                idx_types[idx] = t
        if not idx_types:
            stats["unmapped"].append("0x%X(no typenames)" % client_fam)
            continue
        pick = choose_catalog_family(idx_types, known_values, catalog_families)
        if not pick:
            stats["unmapped"].append("0x%X(ambiguous)" % client_fam)
            continue
        stats["mapped_families"] += 1
        # catalog family -> client family, from THIS binary. The opcode value we
        # store as internal_index is the catalog one; the value on the wire uses
        # the client family, and only this loop knows the pairing.
        stats["family_map"][pick["family"]] = client_fam
        base = pick["family"] << 16
        msg_info("    client family 0x%X -> catalog 0x%X "
                 "(%.0f%% type-name match, runner-up %.0f%%, %d cases)"
                 % (client_fam, pick["family"], 100.0 * pick["rate"],
                    100.0 * pick["runner_up_rate"], len(cases)))
        for idx, tgt in cases.items():
            entry = known_values.get(base | idx)
            if not entry:
                continue
            handler_targets.setdefault(tgt, []).append(
                (base | idx, entry[0], entry[1]))
            stats["opcodes"] += 1
    return handler_targets, stats


