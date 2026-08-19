"""
Topic Deep Extractor
====================
Generates per-topic deep extraction reports for delve / garrison / housing /
warband / neighborhood. For each topic this runs offline-style mining against
already-loaded artifacts:

  - cfunc_cache pseudocode (with 1-hop call-graph expansion)
  - typename_inventory (every WowGetRawTypeName template that mentions topic)
  - wow_jam_types_full (combined autodump + typename inventory; produced by
    JAM Type Discovery analyzer)
  - tc_opcodes (TC source xref; produced by TC Opcode Xref analyzer)
  - wow_offsets (Lua / Cbind)
  - wow_rtti, vtable_entries (SQL)
  - hash_resolution (CVar / account-data)
  - WoWDBDefs schemas (per-topic .dbd files)

Outputs per topic:
  c:/dumps/<topic>_extract_v2_<build>.json
  c:/dumps/<TOPIC>_FULL_V2_<build>.md
  c:/dumps/pipeline/output/mega_import_<topic>_v2.py

Tags found primary functions in the SQL `functions` table with system='topic'
(only when currently NULL) so that subsequent queries can find topic-related
code without re-running the regex scan.

Run order: should follow JAM Type Discovery + TC Opcode Xref so their outputs
are available to consume.
"""
import json
import os
import re
import sqlite3
import time
from collections import Counter

from tc_wow_analyzer.core.utils import (
    msg_info, msg_warn, current_build, dumps_dir)

_FN_HEADER_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_NAME_NOISE = {"void","char","short","int","long","float","double","bool","unsigned",
               "signed","static","const","extern","__int8","__int16","__int32","__int64",
               "__fastcall","__cdecl","__stdcall","__thiscall","__vectorcall","wchar_t",
               "size_t","_BYTE","_WORD","_DWORD","_QWORD","_OWORD"}
_CALL_RE = re.compile(r"\b([A-Za-z_][\w]+)\s*\(")
_SUB_RE  = re.compile(r"\bsub_([0-9A-F]+)\b")

# Wire-primitive readers. HALF of these names carry a 67186 RVA suffix
# ("..._318EF90"), so on any other build the exact-match set never hit and
# `primitives` came out empty. Matching on the stable stem keeps it working
# across builds; the literal set is kept for exact hits.
_PRIMITIVE_EXACT = {
    "ai_Read_CompressedUInt32FromPacket", "ai_Read_CompressedFloatFromPacket",
    "ai_Read_BitFieldData", "ai_Read_LuaByteValue", "ai_Read_FileDataWithTimeout",
    "ai_Read_UInt8FromPacket", "ai_Read_UInt32FromPacket",
    "ai_Read_UInt64FromPacket", "ai_Read_PackedGuidFromPacket",
}

# stem -> matches "<stem>" and "<stem>_<HEXRVA>"
_PRIMITIVE_RE = re.compile(
    r"^(ClientOpcode_helper"
    r"|ai_Read_CompressedUInt32FromPacket"
    r"|ai_Read_CompressedFloatFromPacket"
    r"|ai_Read_BitFieldData"
    r"|ai_Read_LuaByteValue"
    r"|ai_Read_FileDataWithTimeout"
    r"|ai_Read_UInt(?:8|16|32|64)FromPacket"
    r"|ai_Read_PackedGuidFromPacket"
    r")(?:_[0-9A-Fa-f]{4,})?$")


def _is_primitive(name):
    """True if *name* is a wire-serialisation primitive, on any build."""
    return name in _PRIMITIVE_EXACT or bool(_PRIMITIVE_RE.match(name or ""))

_TOPIC_RE = {
    "delve":        re.compile(r"delve", re.I),
    "garrison":     re.compile(r"garrison|gar_follower|gar_mission|gar_building", re.I),
    "housing":      re.compile(r"housing|cornerstone", re.I),
    "warband":      re.compile(r"warband|warbank", re.I),
    "neighborhood": re.compile(r"neighborhood", re.I),
}

def _dbd_dir():
    """WoWDBDefs checkout, resolved against the configured dumps dir."""
    return os.path.join(dumps_dir(), "WoWDBDefs", "definitions")


def _extract_func_name(line):
    paren = line.find("(")
    if paren < 0: return None
    prefix = line[:paren]
    idents = [i for i in re.findall(r"[A-Za-z_]\w*", prefix) if i not in _NAME_NOISE]
    return idents[-1] if idents else None


def _extract_callees(pseudocode, self_name):
    SKIP = {"if","while","for","switch","return","do","else","case","sizeof","alignof",
            "static_cast","dynamic_cast","reinterpret_cast","const_cast","operator",
            "new","delete","throw","true","false","nullptr","this"} | _NAME_NOISE
    callees = Counter()
    for m in _CALL_RE.finditer(pseudocode):
        nm = m.group(1)
        if nm in SKIP or nm == self_name: continue
        callees[nm] += 1
    return callees


def _build_paths(build):
    """Resolve every input through the configured dumps dir and the live DB.

    All eight paths were hardcoded to ``c:/dumps``, and ``cache_db`` additionally
    pointed at the build-agnostic ``wow_dump.bin.tc_wow.db`` — so on a new build
    this analyzer read the PREVIOUS build's pseudocode cache.
    """
    root = dumps_dir()

    def p(name):
        return os.path.join(root, name)

    try:
        from tc_wow_analyzer.core.config import cfg as _cfg
        cache_db = _cfg.db_path
    except Exception:
        cache_db = p("wow_dump.bin.tc_wow.db")

    return {
        "offsets":  p(f"wow_offsets_{build}.json"),
        "rtti":     p(f"wow_rtti_{build}.json"),
        "xrefs":    p(f"wow_string_xrefs_{build}.json"),
        "tn":       p(f"typename_inventory_{build}.json"),
        "jam_full": p(f"wow_jam_types_full_{build}.json"),
        "tc_ops":   p(f"tc_opcodes_{build}.json"),
        "hash_res": p(f"hash_resolution_{build}.json"),
        "cache_db": cache_db,
    }


def _load_cache(cache_path):
    """Returns ea -> (pseudocode, fn_name)."""
    if not os.path.exists(cache_path):
        return {}, {}
    conn = sqlite3.connect(cache_path)
    cur = conn.cursor()
    fn_pseudo = {}
    fn_name = {}
    for ea, ps in cur.execute("SELECT ea, pseudocode FROM cfunc_cache WHERE pseudocode IS NOT NULL"):
        if not ps: continue
        fn_pseudo[ea] = ps
        nm = None
        for ln in ps.split("\n")[:6]:
            if ln.lstrip().startswith("//"): continue
            nm = _extract_func_name(ln)
            if nm: break
        fn_name[ea] = nm or f"sub_{ea:X}"
    conn.close()
    return fn_pseudo, fn_name


def _ea_to_rva(ea):
    """RVA of *ea* against the LOADED image base.

    Was `ea - 0x7FF75BB50000`, the 12.0.5/67186 base. On 12.1.0/69382
    (0x7FF780FD0000) every exported RVA was off by 0x25480000 -- in the topic
    JSON, the _FULL_V2_ markdown and the generated mega_import script alike.
    """
    from tc_wow_analyzer.core.config import cfg
    return cfg.ea_to_rva(ea)


def _run_for_topic(topic, build, paths):
    topic_re = _TOPIC_RE[topic]
    pretty = topic.title()

    fn_pseudo, fn_name = _load_cache(paths["cache_db"])
    if not fn_pseudo:
        msg_warn(f"topic_deep_extractor[{topic}]: cfunc_cache empty")
        return 0
    name_to_ea = {}
    for ea, nm in fn_name.items():
        name_to_ea.setdefault(nm, []).append(ea)

    primary_eas = [ea for ea, ps in fn_pseudo.items() if topic_re.search(ps)]
    primary_set = set(primary_eas)

    fn_info = {}
    for ea in primary_eas:
        ps = fn_pseudo[ea]
        nm = fn_name[ea]
        strs = sorted({m.group(1) for m in re.finditer(r'"([^"\n]{4,120})"', ps) if topic_re.search(m.group(1))})
        callees = _extract_callees(ps, nm)
        prims = [c for c in callees if _is_primitive(c)]
        fn_info[ea] = {
            "ea": f"0x{ea:X}", "rva": f"0x{_ea_to_rva(ea):X}",
            "name": nm, "matching_strings": strs,
            "callees_top": dict(callees.most_common(30)),
            "callee_count": len(callees),
            "sub_callees": sorted(set(_SUB_RE.findall(ps)))[:50],
            "primitives": prims, "pseudocode_size": len(ps),
        }

    # 1-hop expansion
    callee_eas = set()
    primary_names = {fn_name[ea] for ea in primary_eas}
    for ea in primary_eas:
        info = fn_info[ea]
        for cn in info["callees_top"]:
            for c_ea in name_to_ea.get(cn, []):
                if c_ea not in primary_set:
                    callee_eas.add(c_ea)
        for hex_str in info["sub_callees"]:
            try: c_ea = int(hex_str, 16)
            except ValueError: continue
            if c_ea in fn_pseudo and c_ea not in primary_set:
                callee_eas.add(c_ea)
    primary_target_names = primary_names | {f"sub_{ea:X}" for ea in primary_eas}
    caller_eas = set()
    for ea, ps in fn_pseudo.items():
        if ea in primary_set: continue
        for m in _CALL_RE.finditer(ps):
            if m.group(1) in primary_target_names:
                caller_eas.add(ea); break

    # Cross-ref sources
    def _safe_load(path):
        try:
            with open(path) as f: return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError): return None

    typenames = []
    tn = _safe_load(paths["tn"]) or {}
    for cat, entries in (tn.get("categories", {}) or {}).items():
        if not isinstance(entries, list): continue
        for e in entries:
            if topic_re.search(e.get("short","")):
                typenames.append({"category": cat, **e})

    jam_full = _safe_load(paths["jam_full"]) or {}
    jam_types = []
    for nm, meta in (jam_full.get("types", {}) or {}).items():
        if topic_re.search(nm) or any(topic_re.search(s or "") for s in meta.get("mirror_signatures") or []):
            jam_types.append({"name": nm, **meta})

    od = _safe_load(paths["offsets"]) or {}
    lua = [it for it in od.get("lua_functions", []) if topic_re.search(it.get("name",""))]
    cbind = [it for it in od.get("c_bindings", []) if topic_re.search(it.get("name",""))]

    rtti = _safe_load(paths["rtti"]) or {"classes": []}
    rtti_classes = [c for c in rtti.get("classes", []) if topic_re.search(c.get("name",""))]

    tc_ops_d = _safe_load(paths["tc_ops"]) or {}
    tc_opcodes = (tc_ops_d.get("by_topic", {}) or {}).get(topic, {})

    hash_res = _safe_load(paths["hash_res"]) or {}
    cvars = []
    if isinstance(hash_res, dict):
        for kind, mapping in hash_res.items():
            if not isinstance(mapping, dict): continue
            for h, val in mapping.items():
                if isinstance(val, str) and topic_re.search(val):
                    cvars.append({"hash_kind": kind, "hash": h, "name": val})
                elif isinstance(val, list):
                    for v in val:
                        if isinstance(v, str) and topic_re.search(v):
                            cvars.append({"hash_kind": kind, "hash": h, "name": v})

    dbd_schemas = []
    dbd_dir = _dbd_dir()
    if os.path.isdir(dbd_dir):
        for fname in os.listdir(dbd_dir):
            if fname.endswith(".dbd") and topic_re.search(fname[:-4]):
                with open(os.path.join(dbd_dir, fname), encoding="utf-8", errors="ignore") as f:
                    dbd_schemas.append({"table": fname[:-4], "raw": f.read()[:2000]})

    payload = {
        "_meta": {
            "topic": topic, "build": build,
            "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "totals": {
                "primary_functions": len(primary_eas),
                "callee_neighbors": len(callee_eas),
                "caller_neighbors": len(caller_eas),
                "typenames": len(typenames),
                "jam_types": len(jam_types),
                "lua_functions": len(lua),
                "c_bindings": len(cbind),
                "rtti_classes": len(rtti_classes),
                "tc_opcodes": len(tc_opcodes),
                "cvars": len(cvars),
                "dbd_schemas": len(dbd_schemas),
            },
        },
        "primary_functions": list(fn_info.values()),
        "neighbor_functions": [{"ea": f"0x{ea:X}", "name": fn_name[ea],
                                  "relation": (["callee_of_topic"] if ea in callee_eas else []) +
                                              (["caller_of_topic"] if ea in caller_eas else [])}
                                 for ea in (callee_eas | caller_eas)],
        "typenames": typenames, "jam_types": jam_types,
        "lua_functions": lua, "c_bindings": cbind,
        "rtti_classes": rtti_classes, "tc_opcodes": tc_opcodes,
        "cvars": cvars, "dbd_schemas": dbd_schemas,
    }
    out_json = os.path.join(dumps_dir(), f"{topic}_extract_v2_{build}.json")
    with open(out_json, "w") as f:
        json.dump(payload, f, indent=2)

    msg_info(f"topic_deep_extractor[{topic}]: primary={len(primary_eas)} jam={len(jam_types)} "
             f"tc_ops={len(tc_opcodes)} rtti={len(rtti_classes)} dbd={len(dbd_schemas)}")
    return len(primary_eas)


def analyze_topic_deep_extractor(session):
    t0 = time.time()
    db = session.db
    # PluginSession has no `build_number` attribute (only cfg/db/hooks),
    # so this getattr ALWAYS fell through to the literal "67186" — pinning
    # the analyzer to 12.0.5 dumps no matter which build was open.
    build = current_build() or getattr(session.cfg, "build_number", 0)
    if not build:
        msg_warn("  build number unknown — refusing to guess an AutoDump build")
        return 0
    paths = _build_paths(build)

    totals = {}
    for topic in _TOPIC_RE:
        n = _run_for_topic(topic, build, paths)
        totals[topic] = n

    if db is not None:
        try:
            db.kv_set("topic_deep_extractor", {
                "build": build,
                "topic_primary_function_counts": totals,
                "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            })
        except Exception:
            pass

    elapsed = round(time.time() - t0, 2)
    msg_info(f"topic_deep_extractor: done in {elapsed}s — {totals}")
    return sum(totals.values())
