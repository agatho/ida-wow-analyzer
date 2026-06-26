"""
FileDataID Resolution
======================
Reads `c:/dumps/fdid_resolution_67186.json` (produced offline by
`scripts/fdid_scan.py`, which correlates the binary's data against a CASC
listfile) and annotates the hardcoded FileDataID *tables* it found:

  1. Name each table's start EA `FDIDTable_<dir>` (e.g. FDIDTable_sound_creature_the_jailer).
  2. Set a repeatable header comment: `[FDIDTable] <prefix>/ — N entries`.
  3. Set a per-entry repeatable comment `[FDID] <fdid> = <path>` at each dword.

FileDataIDs are plain sequential integers, so a lone valid-FDID immediate proves
nothing (~25% of large ints are valid FDIDs by chance).  Only *runs* of
consecutive valid FDIDs whose paths share a directory are trustworthy, so only
those are auto-applied here.  For ad-hoc lookup of a single constant seen in the
disassembly, use the interactive helper from the IDA console:

    from tc_wow_analyzer.analyzers.fdid_resolution import resolve_fdid
    resolve_fdid(4326187)        # -> 'sound/creature/the_jailer/vo_920_the_jailer_41.ogg'

Output:
  kv_store["fdid_resolution"] = {
      "version": 1, "json_path": str, "tables_named": int,
      "entry_comments": int, "elapsed_sec": float,
  }
"""

import json
import os
import re
import time

import ida_bytes
import ida_name
import idaapi
import idc

from tc_wow_analyzer.core.utils import msg_info, msg_warn, dumps_build_path
from tc_wow_analyzer.analyzers.idb_enrichment import _try_set_comment

# Default listfile location for the interactive resolver (lazy-loaded).
LISTFILE = r"c:/Users/daimon/Downloads/CASCExplorer/listfile.csv"
_FD2PATH = None   # lazy cache for resolve_fdid()


def _safe_name(s):
    s = re.sub(r"[^A-Za-z0-9_]", "_", s or "")
    s = re.sub(r"__+", "_", s).strip("_")
    return s[:64]


def _name_table_start(ea, desired):
    """Name a dword table start, refusing to clobber meaningful symbols."""
    if not ea or ea == idaapi.BADADDR:
        return False
    current = ida_name.get_name(ea) or ""
    if current:
        cl = current.lower()
        auto = ("dword_", "qword_", "byte_", "word_", "unk_", "off_",
                "data_", "asc_", "stru_", "loc_")
        if not cl.startswith(auto) and not re.match(r"^[a-z_]+_[0-9A-Fa-f]{4,}$", current):
            return False
    safe = _safe_name(desired)
    if not safe:
        return False
    try:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 4)
        ida_bytes.create_data(ea, ida_bytes.FF_DWORD, 4, idaapi.BADADDR)
    except Exception:
        pass
    if ida_name.get_name_ea(idaapi.BADADDR, safe) not in (idaapi.BADADDR, ea):
        safe = f"{safe}_{ea & 0xFFFF:04X}"
    SN_FORCE = 0x800
    return bool(idc.set_name(ea, safe, idc.SN_NOWARN | idc.SN_NOCHECK | SN_FORCE))


def analyze_fdid_resolution(session):
    db = session.db
    path = dumps_build_path("fdid_resolution")
    if not os.path.isfile(path):
        msg_warn(f"fdid_resolution: {path} not found — run scripts/fdid_scan.py first")
        return 0
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    tables = data.get("tables", [])
    msg_info(f"fdid_resolution: applying {len(tables)} FDID tables "
             f"({data.get('stats', {}).get('total_entries', '?')} entries)")

    t0 = time.time()
    stats = {"tables_named": 0, "header_comments": 0, "entry_comments": 0}
    for t in tables:
        try:
            start = int(t["ea_int"])
        except (KeyError, ValueError):
            try:
                start = int(t["ea"], 16)
            except Exception:
                continue
        label = t.get("common_prefix") or t.get("top_dir") or "assets"
        if _name_table_start(start, f"FDIDTable_{_safe_name(label)}"):
            stats["tables_named"] += 1
        header = (f"[FDIDTable] {label}/ — {t.get('count', 0)} FileDataIDs "
                  f"({t.get('top_dir_frac', 0) * 100:.0f}% {t.get('top_dir', '')})")
        if _try_set_comment(start, header, repeatable=True):
            stats["header_comments"] += 1
        for e in t.get("entries", []):
            try:
                eea = int(e["ea"], 16)
            except (KeyError, ValueError):
                continue
            cmt = f"[FDID] {e['fdid']} = {e['path']}"
            if _try_set_comment(eea, cmt, repeatable=True):
                stats["entry_comments"] += 1

    elapsed = round(time.time() - t0, 2)
    result = {"version": 1, "json_path": path, "elapsed_sec": elapsed, **stats}
    if db is not None:
        db.kv_set("fdid_resolution", result)
        db.commit()
    msg_info(f"fdid_resolution: tables_named={stats['tables_named']} "
             f"headers={stats['header_comments']} "
             f"entry_comments={stats['entry_comments']} ({elapsed}s)")
    return stats["tables_named"] + stats["entry_comments"]


# ── interactive helper (IDA console) ─────────────────────────────────────────
def _load_listfile(path=None):
    global _FD2PATH
    if _FD2PATH is not None:
        return _FD2PATH
    p = path or LISTFILE
    _FD2PATH = {}
    if not os.path.isfile(p):
        msg_warn(f"resolve_fdid: listfile not at {p}")
        return _FD2PATH
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            i = line.find(";")
            if i <= 0:
                continue
            try:
                _FD2PATH[int(line[:i])] = line[i + 1:].rstrip("\n")
            except ValueError:
                continue
    return _FD2PATH


def resolve_fdid(fdid, path=None):
    """Look up a single FileDataID against the listfile (lazy-loads it once).
    Returns the asset path or None.  For console use during manual analysis."""
    return _load_listfile(path).get(int(fdid))


def comment_fdid_here(fdid=None):
    """Comment the current screen address with the path for `fdid` (or the
    immediate/dword under the cursor if fdid is None)."""
    ea = idc.here()
    if fdid is None:
        fdid = idc.get_operand_value(ea, 1)
        if fdid in (idaapi.BADADDR, -1):
            fdid = idc.get_wide_dword(ea)
    p = resolve_fdid(fdid)
    if not p:
        msg_warn(f"resolve_fdid: {fdid} not in listfile")
        return None
    _try_set_comment(ea, f"[FDID] {fdid} = {p}", repeatable=True)
    msg_info(f"[FDID] {fdid} = {p}")
    return p
