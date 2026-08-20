"""
Opcode dispatch recovery via IDA's switch analysis.

RELIABILITY (read this first — 2026-08-19)
------------------------------------------
Decompilation verification showed that attributing INDEX-FORM switches to an
opcode family by matching their case values (whether via the family-router tree
or via sniff/observed opcodes) is NOT trustworthy: many switches have small
integer cases that coincidentally overlap a family's index range but are
something else entirely (a `< / == / >` condition evaluator, a character state
machine, ...). Those passes are therefore GATED OFF by `_RELIABLE_ONLY` and left
only as scaffolding. Only the BASE-0 path — a switch that literally cases on the
full opcode value (`switch(opcode){ case 0x630000: ... }`) — is emitted, and even
those are labelled "base-0 candidate" (not verified as packet readers). Finding
the real per-opcode SMSG handlers reliably needs the message REGISTRATION table
or a receive-path trace, not case-value matching.

WHY THIS EXISTS
---------------
On build 12.1.0.69382 the client dispatches network opcodes through compiler
`switch` statements, not a data `{opcode, handler}` table (a full image scan
finds exactly ONE such 16-byte table). The dispatch is a TWO-LEVEL tree:

  * a top-level FAMILY ROUTER — `switch(opcode >> 16)` — whose case values are
    the family numbers 0x29..0x65 (28 of these cover every family), and
  * per-family SUB-DISPATCHERS — `switch(opcode & 0xFFFF)` or
    `switch(opcode - family_base)` — reached from the router's family case,
    often one or two calls deep.

IDA already decoded every one of these switches during auto-analysis
(`get_switch_info` / `calc_switch_cases` return the real case-value -> target
pairs, with the sparse MSVC index table already resolved). This analyzer reads
them; it does not re-implement switch decoding and needs no live client.

HOW A SUB-DISPATCHER IS ATTRIBUTED TO A FAMILY (authoritative, guarded)
----------------------------------------------------------------------
Case values alone are ambiguous: a sub-dispatcher reports 0-based indices, and
the dense families overlap (base 0x420000 and 0x400000 both "explain" ~80% of
the same indices). So we DON'T guess a family from indices. Instead:

  1. base-0: if a switch's case values ARE opcode values directly (IDA folded
     the base into `lowcase`), accept them — unambiguous.
  2. router tree: from each family router's `case F` body, walk the call/jump
     graph (depth<=3) to the sub-dispatcher switch, and attribute it to family F
     ONLY if its case values corroborate (>=50% of `(F<<16)+idx` are real
     opcodes). F comes from the router, not from guessing — authoritative.

Two noise sources are excluded so we keep only really-handled opcodes:
  * the switch DEFAULT target (`si.defjump`) — un-cased opcodes route there;
  * any single target that absorbs >40% of a switch's cases (an implicit
    default) — those opcodes are not individually handled.

Every attributed opcode is a real entry in the opcode catalog (oracle guard: no
opcode is invented), and no family ever exceeds its known opcode count.

OUTPUT
------
`opcodes` table (`handler_ea`, `tc_name`, `direction`), kv
`opcode_dispatch_switch`, artifact `wow_opcode_dispatch_switch_<build>.json`, and
— so the handlers are readable in the disassembly — a repeatable comment on every
handler site plus a function rename for each 1:1 handler that still has an
auto-generated name.
"""

import json
import os

from tc_wow_analyzer.core.utils import (
    msg_info, msg_warn, msg_error, dumps_dir, dumps_build_path, current_build)
from tc_wow_analyzer.core import kv_keys
# Shared with analyzers/opcode_dispatcher.py — one implementation only.
from tc_wow_analyzer.core.jam_family import (  # noqa: F401  (re-exported)
    _switch_api, _cases_of, name_tokens, type_tokens, score_client_family,
    choose_catalog_family, _collect_family_switches, _func_typenames,
    _case_typenames, resolve_via_jam_typenames)


# RELIABILITY GATE.
# Decompilation verification (2026-08-19) showed the index-form attribution
# (router-tree linkage AND sniff/observed matching) is NOT reliable: switches
# whose small-integer case values coincidentally overlap an opcode family's
# index range are often something else entirely — e.g. a condition evaluator
# (`case 0x103: <; 0x104: ==; 0x105: >`) or a character state machine. Only the
# BASE-0 dispatchers — a switch that literally cases on the full opcode value
# (`switch(opcode){ case 0x630000: ... }`) — are trustworthy. So by default the
# analyzer emits base-0 only. The router/sniff/default passes are kept in the
# code (guarded) as scaffolding for a future, properly reverse-engineered
# dispatch source (the message registration table / receive-path trace), but
# they do NOT write to the opcodes table or the IDB while this flag is set.
_RELIABLE_ONLY = True

_MIN_MATCHED_CASES = 4
_MIN_MATCHED_FRACTION = 0.5
_ROUTER_MIN_CASES = 6
_ROUTER_FAMILY_FRACTION = 0.6
_BFS_MAX_DEPTH = 3
_BFS_MAX_FUNCS = 60
_DOMINANT_TARGET_FRACTION = 0.4   # a target for >40% of cases == implicit default
_COMMENT_MAX_NAMES = 8


# ---------------------------------------------------------------------------
# Oracle — pure, no IDA, unit-tested offline
# ---------------------------------------------------------------------------

def build_oracle_from_union(union):
    """(known_values, family_bases) from a tc_opcodes `union` dict.

    known_values: {opcode_value: (name, direction)}
    family_bases: sorted set of (value & 0xFFFF0000) plus 0.
    """
    known = {}
    for name, info in (union or {}).items():
        if not isinstance(info, dict):
            continue
        v = info.get("value")
        if isinstance(v, str):
            try:
                v = int(v, 16)
            except ValueError:
                continue
        if not isinstance(v, int):
            continue
        known[v] = (name, info.get("direction"))
    bases = {v & 0xFFFF0000 for v in known}
    bases.add(0)
    return known, sorted(bases)


def bind_family(case_values, known_values, family_bases, base_hints=None,
                min_cases=_MIN_MATCHED_CASES,
                min_fraction=_MIN_MATCHED_FRACTION):
    """Decide whether a decoded switch is an opcode dispatcher, on base 0.

    IDA reports a real opcode switch's case labels as opcode values (base 0);
    an unrelated `switch(state)` reports small integers that are not opcodes.
    Only base 0 (case values are opcodes directly) is accepted here; family-base
    attribution for index-form switches is done authoritatively by the router
    tree in `resolve_dispatch`, never by guessing from case values.

    Kept as a pure, unit-tested function. Returns (base, matched) or (None, set()).
    """
    vals = [v for v in case_values if isinstance(v, int)]
    if not vals:
        return None, set()
    uniq = set(vals)
    known_bases = set(family_bases)

    def matches(base):
        return {v for v in uniq if (base + v) in known_values}

    m = matches(0)
    if len(m) >= min_cases and len(m) >= min_fraction * len(uniq):
        return 0, m

    hinted = [b for b in (base_hints or []) if b in known_bases and b]
    if hinted:
        scored = sorted(((len(matches(b)), b) for b in hinted), reverse=True)
        best_n, best_b = scored[0]
        if best_n and not (len(scored) > 1 and scored[1][0] == best_n):
            mm = matches(best_b)
            if len(mm) >= min_cases and len(mm) >= min_fraction * len(uniq):
                return best_b, mm
    return None, set()


def load_opcode_oracle(session):
    """(known_values, family_bases) for the active build.

    Uses `tc_opcodes_<build>.json` (the union catalog written by TC Opcode Xref)
    as the AUTHORITATIVE source: it carries the client opcode VALUES for this
    build (value = family<<16 | index), verified against the client's own base-0
    dispatchers (which report `lowcase = 0x5A0000` etc.). The `tc_opcodes` DB
    table is NOT used here — it has been observed holding a stale name->value map
    from an earlier build (e.g. ACCEPT_GUILD_INVITE = 0x3E0029 instead of
    0x400000-range), which mislabels every recovered handler. The DB table is the
    fallback only if the JSON is missing.
    """
    build = current_build() or (session.cfg.build_number if session.cfg else 0)
    path = dumps_build_path("tc_opcodes", build=build)
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            known, bases = build_oracle_from_union(data.get("union") or {})
            if known:
                return known, bases
        except Exception as exc:
            msg_warn("  dispatch(switch): cannot read %s: %s" % (path, exc))
    # Fallback: DB table (only if the JSON catalog is unavailable).
    try:
        rows = session.db.fetchall(
            "SELECT name, value, direction FROM tc_opcodes "
            "WHERE value IS NOT NULL") or []
    except Exception:
        rows = []
    if rows:
        union = {r["name"]: {"value": r["value"], "direction": r["direction"]}
                 for r in rows}
        msg_warn("  dispatch(switch): tc_opcodes_%s.json missing — falling back "
                 "to the DB tc_opcodes table (may be stale)." % build)
        return build_oracle_from_union(union)
    return {}, [0]


# ---------------------------------------------------------------------------
# IDA switch collection + router-tree resolution (needs a live IDA)
# ---------------------------------------------------------------------------

def _drop_dominant(pairs):
    """Remove any single target that absorbs >40% of the cases (implicit default)."""
    from collections import Counter
    tc = Counter(t for _v, t in pairs)
    nuniq = len({v for v, _t in pairs}) or 1
    dominant = {t for t, c in tc.items() if c > _DOMINANT_TARGET_FRACTION * nuniq}
    return [(v, t) for v, t in pairs if t not in dominant]


def load_observed_opcodes(known_values):
    """Opcode values actually seen on the wire, from `all_sniffs_catalog.json`.

    The sniff catalog lists opcodes captured across real play sessions. We map
    each by NAME to this build's catalog value (so a value that shifted between
    builds still resolves correctly). This observed set is GROUND TRUTH — an
    unrelated switch is very unlikely to match a family's observed opcodes, so it
    is a strong, low-false-positive family-attribution signal for the dense
    index-form dispatchers (e.g. 0x42) that the router walk does not reach.
    """
    path = os.path.join(dumps_dir(), "all_sniffs_catalog.json")
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            rows = json.load(handle).get("rows") or []
    except Exception:
        return set()
    name2val = {}
    for v, (n, _d) in known_values.items():
        if n:
            name2val[n] = v
    observed = set()
    for r in rows:
        nm = r.get("name")
        if nm in name2val:
            observed.add(name2val[nm])
    return observed


def resolve_dispatch(known_values, family_bases, hb=None):
    """Return (handler_targets, stats).

    handler_targets: {handler_ea: [(opcode, tc_name, direction), ...]}.
    Uses base-0 switches + the family-router tree. Needs a live IDA.
    """
    import idautils
    import idaapi
    import idc

    gsi, csc = _switch_api()
    if gsi is None or csc is None:
        msg_warn("  dispatch(switch): IDA switch API unavailable — skipping.")
        return {}, {}

    fam_highs = {b >> 16 for b in family_bases if b}

    func_sw = {}     # func_start -> [(jmp_ea, pairs)]
    routers = []     # (func_start, {family_high: case_target_ea})
    for fea in idautils.Functions():
        if hb is not None:
            hb.tick()
        f = idaapi.get_func(fea)
        if not f:
            continue
        for head in idautils.Heads(f.start_ea, f.end_ea):
            try:
                if idc.print_insn_mnem(head) != "jmp":
                    continue
            except Exception:
                pass
            try:
                si = gsi(head)
            except Exception:
                si = None
            if not si:
                continue
            pairs = _cases_of(csc, head, si)
            if not pairs:
                continue
            func_sw.setdefault(f.start_ea, []).append((head, pairs))
            uniq = {v for v, _t in pairs}
            if (len(uniq) >= _ROUTER_MIN_CASES
                    and sum(1 for v in uniq if v in fam_highs)
                    >= _ROUTER_FAMILY_FRACTION * len(uniq)):
                routers.append((f.start_ea,
                                {v: t for v, t in pairs if v in fam_highs}))

    def index_switch_match(func_start, fam_base):
        best = None
        for jmp, pairs in func_sw.get(func_start, []):
            cv = [v for v, _t in pairs]
            uniq = set(cv)
            if len(uniq) < _MIN_MATCHED_CASES or min(cv) < 0 or max(cv) > 0x4000:
                continue
            m = sum(1 for v in uniq if (fam_base + v) in known_values)
            if m >= _MIN_MATCHED_CASES and m >= _MIN_MATCHED_FRACTION * len(uniq):
                if best is None or m > best[2]:
                    best = (jmp, pairs, m)
        return best

    def callees(func_start):
        f = idaapi.get_func(func_start)
        if not f:
            return set()
        out = set()
        for head in idautils.Heads(f.start_ea, f.end_ea):
            for t in idautils.CodeRefsFrom(head, 0):   # 0 = calls/jumps only
                g = idaapi.get_func(t)
                if g:
                    out.add(g.start_ea)
        return out

    resolved = {}   # opcode -> (handler_ea, dispatcher_ea, how)
    stats = {"routers": len(routers), "router_attributed": 0, "base0_switches": 0}

    # observed-on-the-wire opcodes (ground truth for THIS build). Only used by
    # the (unreliable, gated) sniff pass — empty when _RELIABLE_ONLY.
    observed = set() if _RELIABLE_ONLY else load_observed_opcodes(known_values)
    stats["observed"] = len(observed)
    stats["sniff_attributed"] = 0
    stats["default_routed"] = 0

    from collections import Counter as _Counter

    def _emit(pairs, fam, how):
        """Emit opcode->handler for a dispatcher attributed to family `fam`.

        Distinct (explicitly-cased) opcodes are always emitted. Opcodes that
        route to the switch DEFAULT (a target absorbing >40% of cases) are
        emitted only when they were actually OBSERVED on the wire — those are
        real opcodes the client dispatches to a shared/default handler; catalog
        opcodes that merely fall through are not invented.
        """
        tc = _Counter(t for _v, t in pairs)
        nuniq = len({v for v, _t in pairs}) or 1
        dominant = {t for t, c in tc.items()
                    if c > _DOMINANT_TARGET_FRACTION * nuniq}
        for v, t in pairs:
            op = (fam + v) if fam else v
            if op not in known_values:
                continue
            if t in dominant:
                if (not _RELIABLE_ONLY) and op in observed and op not in resolved:
                    resolved[op] = (t, how[1], "default")
                    stats["default_routed"] += 1
            else:
                resolved.setdefault(op, (t, how[1], how[0]))

    # 1) router tree — UNRELIABLE (see _RELIABLE_ONLY); disabled by default.
    for _rfunc, routing in ([] if _RELIABLE_ONLY else routers):
        for fam_hi, case_t in routing.items():
            fam = fam_hi << 16
            sf = idaapi.get_func(case_t)
            if not sf:
                continue
            seen = set()
            queue = [(sf.start_ea, 0)]
            while queue:
                cur, depth = queue.pop(0)
                if cur in seen or depth > _BFS_MAX_DEPTH:
                    continue
                seen.add(cur)
                bs = index_switch_match(cur, fam)
                if bs:
                    jmp, pairs, _m = bs
                    _emit(pairs, fam, ("router>>%d" % depth, jmp))
                    stats["router_attributed"] += 1
                    break
                if depth < _BFS_MAX_DEPTH and len(seen) < _BFS_MAX_FUNCS:
                    for c in callees(cur):
                        if c not in seen:
                            queue.append((c, depth + 1))

    # 2) base-0 switches (case values are opcode values directly)
    for _fstart, sws in func_sw.items():
        for jmp, pairs in sws:
            uniq = {v for v, _t in pairs}
            if (sum(1 for v in uniq if v in fam_highs)
                    >= _ROUTER_FAMILY_FRACTION * len(uniq)):
                continue
            m0 = sum(1 for v in uniq if v in known_values)
            if m0 >= _MIN_MATCHED_CASES and m0 >= _MIN_MATCHED_FRACTION * len(uniq):
                _emit(pairs, 0, ("base0", jmp))
                stats["base0_switches"] += 1

    # 3) sniff-validated attribution — for the dense index-form dispatchers the
    #    router walk misses (e.g. 0x42). A switch is attributed to family F when
    #    its cases hit F's OBSERVED-on-the-wire opcodes strongly and uniquely
    #    (1.5x over the next family). Observed opcodes are specific, so a
    #    coincidental match is very unlikely — no mislabeling.
    if observed:
        obs_fams = sorted({v & 0xFFFF0000 for v in observed})
        for _fstart, sws in func_sw.items():
            for jmp, pairs in sws:
                uniq = {v for v, _t in pairs}
                if (sum(1 for v in uniq if v in fam_highs)
                        >= _ROUTER_FAMILY_FRACTION * len(uniq)):
                    continue
                cv = [v for v, _t in pairs]
                if not cv or min(cv) < 0 or max(cv) > 0x4000:
                    continue
                scored = sorted(
                    ((sum(1 for v in uniq if (F + v) in observed), F)
                     for F in obs_fams), reverse=True)
                if not scored:
                    continue
                s1, F1 = scored[0]
                s2 = scored[1][0] if len(scored) > 1 else 0
                if s1 >= _MIN_MATCHED_CASES and s1 >= 1.5 * max(1, s2):
                    _emit(pairs, F1, ("sniff:0x%X" % F1, jmp))
                    stats["sniff_attributed"] += 1

    # every switch case target — used to scrub stale comments from prior runs
    all_targets = set()
    for sws in func_sw.values():
        for _jmp, pairs in sws:
            for _v, t in pairs:
                all_targets.add(t)

    # invert to handler_targets
    handler_targets = {}
    for op, (handler_ea, _disp, _how) in resolved.items():
        name, direction = known_values.get(op, (None, None))
        handler_targets.setdefault(handler_ea, []).append(
            (op, name, (direction or "").upper() or "CMSG"))
    stats["opcodes"] = len(resolved)
    stats["handler_sites"] = len(handler_targets)
    stats["all_targets"] = all_targets
    return handler_targets, stats


# ---------------------------------------------------------------------------
# JAM type-name remap  (PRIMARY source — survives build family renumbering)
#
# Why this exists (verified on 12.1.0.69382, 2026-08-19):
# The client still dispatches every family through a plain `switch` on the full
# opcode value — the mechanism never changed. What DOES change between builds is
# the family NUMBERING: Blizzard inserts new families, so every later family
# shifts up (measured on 69382 vs the TC catalog: +3, then +4, then +5). Binding
# a switch to a family by its raw case values therefore attaches the WRONG NAMES
# while looking perfectly self-consistent.
#
# The client tells us the truth itself: each handler references strings like
#     const char *__cdecl WowGetRawTypeName<struct JamGarrisonFollower>(void)
# i.e. the real JAM message type names. Scoring those type names against the
# catalog's opcode names identifies each client family's catalog counterpart
# from evidence instead of arithmetic. On 69382 the winning family beat every
# other family by ~7x (0x42: 29.1% vs runner-up 3.9%), e.g.
#     SMSG_SETUP_CURRENCY  <-> ClientSetupCurrencyRecord
#     SMSG_REGIONWIDE_CHARACTER_MAIL_DATA <-> RegionwideCharacterMail
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# IDB naming
# ---------------------------------------------------------------------------

def _sanitize_ident(text):
    out = []
    for ch in text or "":
        out.append(ch if (ch.isalnum() or ch == "_") else "_")
    s = "".join(out).strip("_")
    if s and s[0].isdigit():
        s = "_" + s
    return s


_CMT_MARK = "Opcode handler"


def _apply_idb_names(handler_targets, scrub_eas=None):
    """Comment every handler site with its opcode(s); rename 1:1 handlers.

    scrub_eas: addresses to clear of any prior `Opcode handler` comment that is
    NOT in the current result (removes stale labels from an earlier run).

    Returns (named, commented). Runs on the main thread (analyzer loop).
    """
    import idaapi
    import ida_funcs

    def get_name(ea):
        try:
            return idaapi.get_name(ea) or ""
        except Exception:
            return ""

    # Scrub stale comments first.
    if scrub_eas:
        keep = set(handler_targets)
        for ea in scrub_eas:
            if ea in keep:
                continue
            try:
                cur = idaapi.get_cmt(ea, True) or ""
                if cur.startswith(_CMT_MARK):
                    idaapi.set_cmt(ea, "", 1)
            except Exception:
                pass

    def is_auto(nm):
        return (not nm) or nm.startswith(("sub_", "nullsub_", "j_", "loc_",
                                          "unknown_", "def_", "jpt_"))

    def set_cmt(ea, text):
        try:
            return bool(idaapi.set_cmt(ea, text, 1))
        except Exception:
            return False

    def set_name(ea, name):
        try:
            return bool(idaapi.set_name(ea, name,
                                        idaapi.SN_FORCE | idaapi.SN_NOWARN))
        except Exception:
            return False

    named = commented = 0
    used = set()
    for ea, entries in handler_targets.items():
        entries = sorted(entries, key=lambda e: e[0])
        labels = ["%s (0x%X, %s)" % (n or "op_%X" % op, op, d)
                  for op, n, d in entries]
        prefix = ("switch(opcode) case [base-0 candidate]"
                  if _RELIABLE_ONLY else "Opcode handler")
        if len(labels) > _COMMENT_MAX_NAMES:
            fam = entries[0][0] & 0xFFFF0000
            shown = " / ".join(labels[:_COMMENT_MAX_NAMES])
            cmt = ("%s (%d opcodes, family 0x%X): %s / +%d more"
                   % (prefix, len(entries), fam, shown,
                      len(entries) - _COMMENT_MAX_NAMES))
        else:
            cmt = prefix + ": " + " / ".join(labels)
        if set_cmt(ea, cmt):
            commented += 1

        if len(entries) != 1:
            continue
        func = ida_funcs.get_func(ea)
        if not func or func.start_ea != ea or not is_auto(get_name(ea)):
            continue
        op0, n0, _d0 = entries[0]
        base = _sanitize_ident(n0) or ("op_%X" % op0)
        cand = "Handler_%s" % base
        nm = cand
        k = 1
        while nm in used:
            k += 1
            nm = "%s_%d" % (cand, k)
        if set_name(ea, nm):
            used.add(nm)
            named += 1
    return named, commented


# ---------------------------------------------------------------------------
# Analyzer entry point
# ---------------------------------------------------------------------------

def analyze_opcode_dispatch_switch(session):
    """Recover opcode -> handler_ea from the dispatch switch tree; annotate the IDB."""
    db = session.db
    cfg = session.cfg
    build = current_build() or (cfg.build_number if cfg else 0)

    known_values, family_bases = load_opcode_oracle(session)
    if not known_values:
        msg_warn("  dispatch(switch): no opcode catalog (tc_opcodes_%s.json / "
                 "tc_opcodes table). Run 'TC Opcode Xref' first — skipping."
                 % build)
        return 0

    try:
        import idautils  # noqa: F401  (are we inside IDA?)
    except Exception:
        msg_warn("  dispatch(switch): not inside IDA; needs get_switch_info — "
                 "skipping.")
        return 0

    hb = None
    try:
        from tc_wow_analyzer.core.heartbeat import Heartbeat
        hb = Heartbeat("Opcode Dispatch (switch tree)", total=None, interval=20)
    except Exception:
        hb = None

    # PRIMARY: the client's own JAM type names decide which catalog family each
    # dispatcher really is. This is immune to the family renumbering Blizzard
    # does between builds (the reason raw case-value binding attaches wrong
    # names while looking self-consistent). Falls back to the legacy base-0
    # binding only if it yields nothing.
    handler_targets, jam_stats = resolve_via_jam_typenames(known_values, hb)
    stats = dict(jam_stats)
    stats["source"] = "jam_typenames"
    msg_info("  dispatch(switch): JAM type-name remap -> %d opcodes from %d/%d "
             "client families" % (jam_stats.get("opcodes", 0),
                                  jam_stats.get("mapped_families", 0),
                                  jam_stats.get("client_families", 0)))
    if jam_stats.get("unmapped"):
        msg_info("    unmapped client families: %s"
                 % ", ".join(jam_stats["unmapped"][:12]))
    if not handler_targets:
        msg_warn("  dispatch(switch): no family could be identified by type "
                 "names; falling back to base-0 case binding.")
        handler_targets, stats = resolve_dispatch(known_values, family_bases, hb)
        stats["source"] = "base0_fallback"
    if hb is not None:
        hb.done()

    if not handler_targets:
        msg_warn("  dispatch(switch): no opcode handlers resolved "
                 "(routers=%d). Run analyzers_only first so auto-analysis has "
                 "typed the dispatch switches." % stats.get("routers", 0))
        return 0

    # Drop any prior dispatch_switch rows (e.g. from a run with a stale oracle)
    # so wrong opcode->handler links do not linger.
    try:
        db.execute("DELETE FROM opcodes WHERE notes = 'dispatch_switch'")
        db.commit()
    except Exception:
        pass

    # write opcodes + collect artifact
    written = 0
    per_family = {}
    handlers_artifact = []
    for handler_ea, entries in handler_targets.items():
        for opcode, name, direction in entries:
            db.upsert_opcode(
                direction=direction,
                internal_index=opcode,
                handler_ea=handler_ea,
                wire_opcode=opcode,
                tc_name=name,
                status="matched",
                notes="dispatch_switch",
            )
            written += 1
            fam = per_family.setdefault(opcode & 0xFFFF0000, 0)
            per_family[opcode & 0xFFFF0000] = fam + 1
            handlers_artifact.append({
                "opcode": "0x%X" % opcode,
                "tc_name": name,
                "direction": direction,
                "handler_rva": "0x%X" % cfg.ea_to_rva(handler_ea),
            })
    db.commit()

    named = commented = 0
    try:
        named, commented = _apply_idb_names(
            handler_targets, scrub_eas=stats.get("all_targets"))
        msg_info("  dispatch(switch): IDB — renamed %d handler functions, "
                 "commented %d handler sites" % (named, commented))
    except Exception as exc:
        msg_warn("  dispatch(switch): IDB naming skipped (%s)" % exc)

    smsg = sum(1 for h in handlers_artifact if h["direction"] == "SMSG")
    artifact = os.path.join(
        dumps_dir(), "wow_opcode_dispatch_switch_%s.json" % build)
    try:
        with open(artifact, "w", encoding="utf-8") as handle:
            json.dump({
                "type": "opcode_dispatch_switch",
                "build": build,
                "source": "ida_switch_router_tree",
                "routers": stats.get("routers"),
                "router_attributed_switches": stats.get("router_attributed"),
                "base0_switches": stats.get("base0_switches"),
                "sniff_attributed_switches": stats.get("sniff_attributed"),
                "observed_opcodes": stats.get("observed"),
                "opcodes_written": written,
                "handler_sites": stats.get("handler_sites"),
                "smsg": smsg,
                "idb_handlers_renamed": named,
                "idb_handler_sites_commented": commented,
                "families": {("0x%X" % b): v for b, v in per_family.items()},
                "handlers": handlers_artifact,
            }, handle, indent=1)
        msg_info("  dispatch(switch): wrote %s" % artifact)
    except Exception as exc:
        msg_warn("  dispatch(switch): could not write artifact: %s" % exc)

    db.kv_set(kv_keys.OPCODE_DISPATCH_SWITCH, {
        "build": build,
        "routers": stats.get("routers"),
        "opcodes_written": written,
        "handler_sites": stats.get("handler_sites"),
        "smsg": smsg,
        "idb_handlers_renamed": named,
        "idb_handler_sites_commented": commented,
        "known_opcode_total": len(known_values),
        "coverage_pct": round(100.0 * written / len(known_values), 1)
        if known_values else 0.0,
        "families": {("0x%X" % b): v for b, v in per_family.items()},
    })

    fam_summary = ", ".join(
        "0x%X:%d" % (b, v)
        for b, v in sorted(per_family.items(), key=lambda kv: -kv[1])[:6])
    msg_info("  dispatch(switch): %d opcodes -> %d handler sites "
             "(%d router, %d base-0, %d sniff-validated). %.1f%% of %d known. "
             "Top families: %s"
             % (written, stats.get("handler_sites"),
                stats.get("router_attributed"), stats.get("base0_switches"),
                stats.get("sniff_attributed", 0),
                100.0 * written / len(known_values), len(known_values),
                fam_summary))
    return written
