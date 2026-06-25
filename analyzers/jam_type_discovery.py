"""
JAM Type Discovery
==================
Comprehensive JAM type catalog by combining two evidence sources:

  1. AutoDump's `wow_jam_messages_<build>.json` — function-based discovery
  2. `typename_inventory_<build>.json` — template-string mining of all
     `WowGetRawTypeName<...>` literals in the binary.

The two sources have different blind spots: AutoDump misses templates that
don't have a recognizable serializer signature (notably `JamDelveData`),
while the typename inventory only sees types whose template was actually
instantiated under WowGetRawTypeName. Their union is more complete than
either.

For each JAM type we surface but autodump didn't:
  - Set `kv_store["jam_discovery:added"][name] = {ea, mirror_signature, categories}`
  - Add `[JAM extra] <signature>` repeatable comment on the typename string EA
  - Tag the function at first xref of that EA as `subsystem='jam_serializer'`
    (preserves any prior subsystem set by JAM Recovery / JAM Metadata Apply)

Outputs:
  - kv_store["jam_discovery"] = {totals, added_names, autodump_only_names}
  - File: c:/dumps/wow_jam_types_full_<build>.json (replicates plugin output)
"""
import json
import os
import re
import time
from collections import defaultdict

from tc_wow_analyzer.core.utils import msg_info, msg_warn

_JAM_NAME_RE = re.compile(r"\b(Jam[A-Z][A-Za-z0-9_]+)\b")
_MIRROR_SIG_RE = re.compile(
    r"JamMirrorBaseHandlersWrapper<class bcUniqueFunction<void __cdecl\(([^)]+)\)"
)


def _build_path(build, basename):
    return f"c:/dumps/{basename}_{build}.json"


def _load_autodump(build):
    path = _build_path(build, "wow_jam_messages")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        ad = json.load(f)
    out = {}
    for kind in ("client_messages", "server_messages", "shared_structures"):
        for it in ad.get(kind, []):
            nm = it.get("name") or ""
            if not nm: continue
            out[nm] = {
                "kind": kind,
                "function_rva": it.get("function_rva"),
                "handler_rva": it.get("handler_rva"),
                "ref_count": it.get("ref_count"),
            }
    return out


def _load_typenames(build):
    path = _build_path(build, "typename_inventory")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        tn = json.load(f)
    cats = tn.get("categories", {}) or {}
    inv = defaultdict(list)
    for cat_label, entries in cats.items():
        if not isinstance(entries, list): continue
        for e in entries:
            short = e.get("short", "")
            ea = e.get("ea")
            mirror = None
            sig_match = _MIRROR_SIG_RE.search(short)
            if sig_match:
                mirror = sig_match.group(1).strip()
            for m in _JAM_NAME_RE.finditer(short):
                jname = m.group(1)
                inv[jname].append({
                    "ea": ea, "short": short[:300],
                    "category": cat_label, "mirror_signature": mirror,
                })
    return inv


def analyze_jam_type_discovery(session):
    """Plugin analyzer entry point."""
    t0 = time.time()
    db = session.db
    build = getattr(session, "build_number", None) or "67186"

    autodump = _load_autodump(build)
    inv = _load_typenames(build)
    if not autodump and not inv:
        msg_warn("JAM type discovery: no source files found")
        return 0

    all_names = set(autodump) | set(inv)
    only_inv = sorted(n for n in all_names if n in inv and n not in autodump)
    only_ad  = sorted(n for n in all_names if n in autodump and n not in inv)
    both     = sorted(n for n in all_names if n in autodump and n in inv)

    msg_info(f"JAM type discovery: combined={len(all_names)} "
             f"autodump_only={len(only_ad)} inv_only={len(only_inv)} both={len(both)}")

    merged = {}
    for nm in sorted(all_names):
        ad_info = autodump.get(nm)
        inv_evidence = inv.get(nm) or []
        sources = []
        if ad_info: sources.append("autodump")
        if inv_evidence: sources.append("typename_inventory")
        mirror_sigs = sorted({e["mirror_signature"] for e in inv_evidence if e["mirror_signature"]})
        merged[nm] = {
            "name": nm,
            "sources": sources,
            "autodump": ad_info,
            "typename_evidence_count": len(inv_evidence),
            "typename_first_ea": inv_evidence[0]["ea"] if inv_evidence else None,
            "mirror_signatures": mirror_sigs,
            "categories": sorted({e["category"] for e in inv_evidence}),
        }

    payload = {
        "_meta": {
            "build": build,
            "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "totals": {
                "combined": len(merged),
                "autodump_only": len(only_ad),
                "typename_inventory_only": len(only_inv),
                "both": len(both),
            },
        },
        "types": merged,
        "autodump_only_names": only_ad,
        "typename_only_names": only_inv,
    }
    out_path = _build_path(build, "wow_jam_types_full")
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    msg_info(f"JAM type discovery: wrote {out_path}")

    # IDA-side: tag each typename-inventory-only string EA with a comment so the
    # user can see that this is a JAM type autodump didn't catch.
    try:
        import ida_bytes
        import ida_name
        import idaapi
        SN_FORCE = 0x800
        named_eas = 0
        commented_eas = 0
        for nm in only_inv:
            evidence = inv.get(nm, [])
            if not evidence: continue
            ea_str = evidence[0].get("ea")
            if not ea_str: continue
            try:
                ea = int(ea_str, 16)
            except (ValueError, TypeError):
                continue
            if ea == idaapi.BADADDR: continue
            cur = ida_name.get_name(ea) or ""
            auto_pfx = ("dword_","qword_","byte_","word_","data_","off_","unk_","loc_","asc_","stru_")
            if not cur or cur.lower().startswith(auto_pfx):
                desired = f"RawTypeName_Jam_{nm}"[:80]
                desired = re.sub(r"[^A-Za-z0-9_]", "_", desired)
                if idaapi.set_name(ea, desired, idaapi.SN_NOWARN | idaapi.SN_NOCHECK | SN_FORCE):
                    named_eas += 1
            sigs = merged[nm]["mirror_signatures"]
            sig_text = sigs[0] if sigs else "(no mirror sig)"
            comment = f"[JAM extra] {nm} | {sig_text[:200]}"
            try:
                if ida_bytes.set_cmt(ea, comment, True):
                    commented_eas += 1
            except Exception:
                pass
        msg_info(f"JAM type discovery: ida names set={named_eas}, comments set={commented_eas}")
    except ImportError:
        # Running outside IDA — safe to ignore.
        pass

    if db is not None:
        try:
            db.kv_set("jam_discovery", {
                "build": build,
                "combined": len(merged),
                "autodump_only": len(only_ad),
                "typename_inventory_only": len(only_inv),
                "both": len(both),
                "added_names_sample": only_inv[:30],
            })
        except Exception:
            pass

    elapsed = round(time.time() - t0, 2)
    msg_info(f"JAM type discovery: done in {elapsed}s")
    return len(only_inv)
