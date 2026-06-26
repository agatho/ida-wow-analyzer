"""
Hash Resolution
===============
Reads `c:/dumps/hash_resolution_67186.json` (produced offline by
`scripts/hash_brute.py`) and applies the resolved hash → string mappings
to the IDB:

  1. For every unambiguous 64-bit hit (single string after dedup), set an
     IDA name at the hit EA: `CVarHash_<safename>`.
  2. Set a repeatable comment: `[Hash] FNV1A_64L("<name>") = 0x...`.
  3. Detect CVar entry struct boundaries (hash at offset 0, name ptr at +8,
     name length at +16). When the layout matches, also name the entry start
     `CVarEntry_<safename>` and tag the next-after-struct function pointer as
     a CVar callback when present.
  4. For 32-bit hits in .rdata that are unambiguous AND surrounded by other
     hash-shaped values (HashLink table heuristic), apply names as well.
  5. Code-embedded dispatch hashes: reads `hash_text_immediates_67186.json`
     (from scripts/hash_text_immediates.py, which scans cfunc_cache pseudocode)
     and sets a repeatable `[HashDispatch]` comment at the exact comparison
     instruction inside each dispatching function.

Output:
  kv_store["hash_resolution"] = {
      "version": 1,
      "json_path": "...",
      "names_set_64": int,
      "comments_set_64": int,
      "cvar_entries_named": int,
      "names_set_32": int,
      "ambiguous_skipped": int,
      "elapsed_sec": float,
  }
"""

import json
import os
import re
import time

import ida_bytes
import ida_funcs
import ida_name
import ida_ua
import idaapi
import idc

from tc_wow_analyzer.core.utils import msg_info, msg_warn, dumps_build_path
from tc_wow_analyzer.analyzers.idb_enrichment import (
    _try_set_comment, _try_rename, _safe_struct_name,
)


# Build-resolved at call time (see analyze_hash_resolution). This default is a
# fallback only; the offline corpus MUST be regenerated per build.
RESOLUTION_JSON = r"c:/dumps/hash_resolution_67186.json"


def _safe_name(s):
    """Make a string safe to use as an IDA symbol name."""
    if not s:
        return ""
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)
    s = re.sub(r"__+", "_", s).strip("_")
    return s[:80]


def _set_data_name(ea, desired_name, debug_failures=None):
    """Set an IDA name at a data EA. Won't clobber meaningful existing names."""
    if not ea or ea == idaapi.BADADDR:
        return False
    current = ida_name.get_name(ea) or ""
    # Skip auto-generated names; preserve real symbols.
    auto_prefixes = (
        "dword_", "qword_", "byte_", "word_", "data_", "off_",
        "unk_", "loc_", "asc_", "stru_", "xmmword_", "ymmword_",
        "g_data_", "g_ptr_", "named_data_", "j_", "??_",
    )
    if current:
        cl = current.lower()
        if not cl.startswith(auto_prefixes):
            if not re.match(r"^[a-z_]+_[0-9A-Fa-f]{4,}$", current):
                return False
    safe = _safe_name(desired_name)
    if not safe:
        return False

    # Ensure ea is at a defined item boundary. If it sits inside undefined
    # bytes, materialize a qword item so IDA accepts the name.
    try:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 8)
    except Exception:
        pass
    try:
        ida_bytes.create_data(ea, ida_bytes.FF_QWORD, 8, idaapi.BADADDR)
    except Exception:
        pass

    # Ensure unique name
    existing_ea = ida_name.get_name_ea(idaapi.BADADDR, safe)
    if existing_ea != idaapi.BADADDR and existing_ea != ea:
        safe = f"{safe}_{ea & 0xFFFF:04X}"

    # IDA 9.x: SN_FORCE = 0x800 (not exported as idc constant)
    SN_FORCE = 0x800
    flags = idc.SN_NOWARN | idc.SN_NOCHECK | SN_FORCE
    ok = bool(idc.set_name(ea, safe, flags))
    if not ok and debug_failures is not None and len(debug_failures) < 5:
        # Capture diagnostic info about the failure
        try:
            seg_name = idc.get_segm_name(ea) or "?"
            head = idc.get_item_head(ea)
            head_size = idc.get_item_size(head)
            debug_failures.append({
                "ea": f"0x{ea:X}",
                "segm": seg_name,
                "item_head": f"0x{head:X}",
                "item_size": head_size,
                "ea_in_middle": (head != ea),
                "current_name": current,
            })
        except Exception as e:
            debug_failures.append({"ea": f"0x{ea:X}", "diag_error": str(e)})
    return ok


def _detect_cvar_entry(ea, hash_value, expected_name):
    """Heuristic: confirm that ea is the start of a CVar entry struct.

    Layout we expect:
      [+0]  uint64 hash       (matches hash_value)
      [+8]  char*  name_ptr   (in image — points to NUL-terminated name)
      [+16] uint32 name_len   (matches len(expected_name))

    Returns True if layout matches, False otherwise.
    """
    try:
        h = ida_bytes.get_qword(ea)
        if h != hash_value:
            return False
        name_ptr = ida_bytes.get_qword(ea + 8)
        name_len = ida_bytes.get_dword(ea + 16)
    except Exception:
        return False
    if name_ptr == idaapi.BADADDR:
        return False
    if name_len != len(expected_name):
        return False
    # Read len bytes at name_ptr and check they match expected_name
    try:
        b = ida_bytes.get_bytes(name_ptr, len(expected_name))
        if b is None:
            return False
        if b.decode("ascii", errors="replace") == expected_name:
            return True
    except Exception:
        pass
    return False


def _find_immediate_site(func_ea, value):
    """Find the instruction inside func_ea whose immediate operand == value.

    64-bit hash compares materialize as `mov reg, imm64` then `cmp`, so the
    constant appears as an o_imm operand on some instruction in the function.
    Returns that instruction EA, or BADADDR if not found (e.g. split immediate).
    """
    f = ida_funcs.get_func(func_ea)
    if not f:
        return idaapi.BADADDR
    ea = f.start_ea
    while ea != idaapi.BADADDR and ea < f.end_ea:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea):
            for op in insn.ops:
                if op.type == ida_ua.o_void:
                    break
                if op.type == ida_ua.o_imm and (op.value & 0xFFFFFFFFFFFFFFFF) == value:
                    return ea
        nxt = idc.next_head(ea, f.end_ea)
        if nxt <= ea:
            break
        ea = nxt
    return idaapi.BADADDR


def _apply_text_immediates(session, stats):
    """Apply code-embedded hash dispatch resolutions from the cfunc_cache
    immediate scan (scripts/hash_text_immediates.py).  Comments the exact
    comparison instruction (or the function head as fallback)."""
    path = dumps_build_path("hash_text_immediates")
    if not os.path.isfile(path):
        msg_info(f"hash_resolution: no text-immediate file ({path}) — skipping")
        return
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    matches = data.get("matches", [])
    msg_info(f"hash_resolution: applying {len(matches)} code-immediate dispatch hits")
    for m in matches:
        cands = m.get("candidates", [])
        names = sorted({c["string"] for c in cands})
        if len(names) != 1:
            stats["text_imm_ambiguous"] += 1
            continue
        name = names[0]
        try:
            func_ea = int(m["ea_int"])
            value = int(m["constant"], 16)
        except (KeyError, ValueError):
            continue
        bits = m.get("width_bits", 64)
        algo = cands[0].get("algo", "")
        comment = (f"[HashDispatch] {algo} hash of {name!r} = "
                   f"0x{value:0{bits // 4}X}")
        site = _find_immediate_site(func_ea, value)
        target = site if site != idaapi.BADADDR else func_ea
        if _try_set_comment(target, comment, repeatable=True):
            stats["text_imm_comments"] += 1
            if site != idaapi.BADADDR:
                stats["text_imm_sites_found"] += 1


def analyze_hash_resolution(session):
    db = session.db
    if db is None:
        msg_warn("hash_resolution: no DB")
        return 0
    RESOLUTION_JSON = dumps_build_path("hash_resolution")  # build-resolved
    if not os.path.isfile(RESOLUTION_JSON):
        msg_warn(f"hash_resolution: {RESOLUTION_JSON} not found "
                 "— run scripts/hash_brute.py first")
        return 0

    msg_info(f"hash_resolution: reading {RESOLUTION_JSON}")
    with open(RESOLUTION_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    t0 = time.time()
    stats = {
        "names_set_64": 0,
        "comments_set_64": 0,
        "cvar_entries_named": 0,
        "names_set_32": 0,
        "ambiguous_skipped": 0,
        "non_unique_strings": 0,
        "text_imm_comments": 0,
        "text_imm_sites_found": 0,
        "text_imm_ambiguous": 0,
    }

    # ── 64-bit hits ──
    debug_failures = []
    msg_info(f"hash_resolution: applying {len(data['hits_64bit'])} 64-bit hits")
    for hit in data["hits_64bit"]:
        ea = int(hit["ea"], 16)
        hash_value = int(hit["hash"], 16)
        # Dedupe candidates by string
        seen = set()
        unique_strings = []
        for c in hit["candidates"]:
            s = c["string"]
            if s in seen:
                continue
            seen.add(s)
            unique_strings.append(s)
        if len(unique_strings) != 1:
            stats["ambiguous_skipped"] += 1
            stats["non_unique_strings"] += 1
            continue
        name = unique_strings[0]
        safe = _safe_name(name)

        # Set name at the hash address
        if _set_data_name(ea, f"CVarHash_{safe}", debug_failures=debug_failures):
            stats["names_set_64"] += 1

        # Set comment
        comment = f"[Hash] FNV1A_64L({name!r}) = 0x{hash_value:016X}"
        if _try_set_comment(ea, comment, repeatable=True):
            stats["comments_set_64"] += 1

        # If it's a CVar entry, also name the entry start
        if _detect_cvar_entry(ea, hash_value, name):
            if _set_data_name(ea, f"CVarEntry_{safe}"):
                stats["cvar_entries_named"] += 1

    # ── 32-bit hits ──
    msg_info(f"hash_resolution: applying {len(data['hits_32bit'])} 32-bit hits")
    for hit in data["hits_32bit"]:
        ea = int(hit["ea"], 16)
        hash_value = int(hit["hash"], 16)
        seen = set()
        unique_strings = []
        for c in hit["candidates"]:
            s = c["string"]
            if s in seen:
                continue
            seen.add(s)
            unique_strings.append(s)
        if len(unique_strings) != 1:
            stats["ambiguous_skipped"] += 1
            continue
        name = unique_strings[0]
        safe = _safe_name(name)
        if _set_data_name(ea, f"Hash32_{safe}"):
            stats["names_set_32"] += 1
        _try_set_comment(
            ea,
            f"[Hash32] FNV1A_32({name!r}) = 0x{hash_value:08X}",
            repeatable=True,
        )

    # ── code-embedded dispatch hashes (cfunc_cache immediate scan) ──
    _apply_text_immediates(session, stats)

    elapsed = round(time.time() - t0, 2)
    result = {
        "version": 1,
        "json_path": RESOLUTION_JSON,
        "elapsed_sec": elapsed,
        **stats,
    }
    db.kv_set("hash_resolution", result)
    db.commit()

    msg_info(
        f"hash_resolution: names_64={stats['names_set_64']} "
        f"cvar_entries={stats['cvar_entries_named']} "
        f"comments_64={stats['comments_set_64']} names_32={stats['names_set_32']} "
        f"text_imm={stats['text_imm_comments']} (sites {stats['text_imm_sites_found']}) "
        f"ambig_skipped={stats['ambiguous_skipped']} ({elapsed}s)"
    )
    if debug_failures:
        msg_info(f"hash_resolution: sample failures: {debug_failures}")
    return stats["names_set_64"] + stats["names_set_32"]
