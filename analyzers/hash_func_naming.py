"""
Hash Function Naming
====================
Renames the WoW client's well-identified hash functions based on:

  * Static identification via FNV-1a 64/32 magic constants in pseudocode.
  * Cross-references to known callers that demangle as
    `t2util::ConstFnvHashStringI(char const*)` (revealed by RTTI debug
    type-name strings in `sub_7FF75D97D870`).

Naming scheme (matches the de-mangled C++ symbols where known):
  * `t2util__ConstFnvHashStringI`  — workhorse 64-bit case-insensitive
                                     FNV-1a, recursive helper.
  * `wow_FNV1A_32`                 — 32-bit FNV-1a (used by hash table
                                     rebuild in `chained_hash_node`).
  * `wow_FNV1A_64`                 — explicit case-sensitive 64-bit
                                     variant.

The analyzer reads `c:/dumps/fnv_candidates_67186.json` (produced offline
by `scripts/find_fnv_functions.py`) and applies renames using the heuristic:

  * Functions ≤ 700 chars long containing both FNV1A_64_BASIS and
    FNV1A_64_PRIME, with a tolower (`+ 32`) and recursive call → likely
    `t2util__ConstFnvHashStringI` itself or a thin wrapper.
  * Functions referencing the chained_hash_node typename string → use the
    typename to derive the rename.

Output:
  kv_store["hash_func_naming"] = {
      "version": 1,
      "renamed_64bit": int,
      "renamed_32bit": int,
      "elapsed_sec": float,
  }
"""

import json
import os
import re
import time

import ida_funcs
import ida_name
import idaapi

from tc_wow_analyzer.core.utils import msg_info, msg_warn
from tc_wow_analyzer.analyzers.idb_enrichment import (
    _try_set_comment, _try_rename,
)


CANDIDATES_JSON = r"c:/dumps/fnv_candidates_67186.json"


def _classify(hit):
    """Return a desired name for the function, or None to skip."""
    ps = hit.get("pseudocode") or ""
    has_64_basis = "0xCBF29CE484222325" in ps or "0xcbf29ce484222325" in ps
    has_64_prime = "0x100000001B3" in ps or "0x100000001b3" in ps
    has_32_prime = "0x01000193" in ps or "0x1000193" in ps or "16777619" in ps
    has_32_basis = "0x811C9DC5" in ps or "0x811c9dc5" in ps or "-2128831035" in ps
    has_tolower = "+ 32" in ps and "<" in ps  # rough — tolower compares byte to 'A'..'Z'
    is_recursive = "sub_7FF75BCE2C90" in ps  # references the workhorse helper

    # Direct typename hit — the bz::chained_hash_node debug typename references
    # the actual hash function symbol.
    if "ConstFnvHashStringI" in ps:
        return "wow_t2util_ConstFnvHashStringI_caller"

    if has_32_basis and has_32_prime and len(ps) > 1500:
        # The 32-bit hash table rebuild path
        return "wow_FNV1A_32_TableRebuild"

    if has_64_basis and has_64_prime and is_recursive and has_tolower:
        # A thin caller of the recursive hash workhorse for a literal string
        return "wow_FNV1A_64L_LiteralCaller"

    if has_64_basis and has_64_prime and len(ps) < 600:
        return "wow_FNV1A_64L_Short"

    return None


def analyze_hash_func_naming(session):
    db = session.db
    if db is None:
        msg_warn("hash_func_naming: no DB")
        return 0
    if not os.path.isfile(CANDIDATES_JSON):
        msg_warn(f"hash_func_naming: {CANDIDATES_JSON} not found "
                 "— run scripts/find_fnv_functions.py first")
        return 0

    with open(CANDIDATES_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)
    hits = data.get("hits", [])
    msg_info(f"hash_func_naming: classifying {len(hits)} FNV-magic functions")

    t0 = time.time()
    renamed_64 = 0
    renamed_32 = 0
    commented = 0
    for hit in hits:
        ea = int(hit["ea"], 16) if isinstance(hit["ea"], str) else hit["ea"]
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        ea = f.start_ea
        desired = _classify(hit)
        if desired is None:
            continue
        if _try_rename(ea, desired):
            if "32" in desired:
                renamed_32 += 1
            else:
                renamed_64 += 1
        if _try_set_comment(
            ea,
            f"[Hash function] FNV-1a magic constants present: {hit['matched']}",
            repeatable=True,
        ):
            commented += 1

    db.commit()

    elapsed = round(time.time() - t0, 2)
    result = {
        "version": 1,
        "renamed_64bit": renamed_64,
        "renamed_32bit": renamed_32,
        "comments_set": commented,
        "elapsed_sec": elapsed,
    }
    db.kv_set("hash_func_naming", result)
    db.commit()

    msg_info(
        f"hash_func_naming: renamed_64={renamed_64} renamed_32={renamed_32} "
        f"comments={commented} ({elapsed}s)"
    )
    return renamed_64 + renamed_32
