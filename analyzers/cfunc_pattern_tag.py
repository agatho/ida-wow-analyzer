"""
Cfunc Pattern Tag
=================
Mass-classifies cached pseudocodes by string-pattern signatures and writes
back system/subsystem tags + repeatable comments.

Each PATTERN is a (regex, system, subsystem, comment_prefix) tuple. For every
cached pseudocode that matches the regex, we tag the function (only when
its current subsystem is NULL — preserves Subsystem Catalog and our other
domain-specific tags).

Pattern set (build 67186):
  * `MirrorVarManager`       → cvar / cvar_mgmt           (~6 funcs)
  * `chained_hash_node`      → hash / hash_consumer       (~3,653 funcs)
  * `ConstFnvHashStringI`    → hash / hash_compute        (~3 funcs)
  * `SkipExportInRetailClient` → debug / dev_only         (varies)
  * `g_LuaState`             → lua_api / lua_state_user   (varies)

Reads cfunc_cache directly; safe to run while other analyzers process the
IDB. Output: kv_store["cfunc_pattern_tag"].
"""

import os
import re
import time
from collections import defaultdict

import idaapi

from tc_wow_analyzer.core.utils import msg_info, msg_warn
from tc_wow_analyzer.analyzers.idb_enrichment import _try_set_comment


PATTERNS = [
    # (literal_substring, system, subsystem, comment_prefix)
    ("MirrorVarManager",       "cvar",     "cvar_mgmt",       "[CVar Mgmt]"),
    ("ConstFnvHashStringI",    "cvar",     "hash_compute",    "[Hash compute]"),
    ("chained_hash_node",      "cvar",     "hash_consumer",   "[Hash consumer]"),
    ("g_LuaState",             "lua_api",  "lua_state_user",  "[Lua state user]"),
    ("UnitFrame",              "ui",       "unit_frame",      "[Unit frame]"),
    ("CG_RaidFrame",           "ui",       "raid_frame",      "[Raid frame]"),
    ("WowGetRawTypeName",      "rtti",     "rtti_wrapper",    "[RTTI wrapper]"),
    ("blz::chained_hash_node", "cvar",     "hash_consumer",   "[Hash consumer]"),
    ("MakeFrame",              "ui",       "frame_factory",   "[Frame factory]"),
]


def analyze_cfunc_pattern_tag(session):
    db = session.db
    if db is None:
        msg_warn("cfunc_pattern_tag: no DB")
        return 0

    t0 = time.time()
    msg_info(f"cfunc_pattern_tag: scanning cfunc_cache for {len(PATTERNS)} patterns")

    # Gather (ea, set[matched pattern_idx]) for every matching cached function
    ea_to_patterns = defaultdict(set)
    n_processed = 0
    cur = db.execute(
        "SELECT ea, pseudocode FROM cfunc_cache WHERE pseudocode IS NOT NULL"
    )
    for row in cur:
        n_processed += 1
        ps = row["pseudocode"]
        if not ps:
            continue
        for i, (substr, *_) in enumerate(PATTERNS):
            if substr in ps:
                ea_to_patterns[row["ea"]].add(i)
    msg_info(f"cfunc_pattern_tag: scanned {n_processed} pseudocodes, "
             f"{len(ea_to_patterns)} matching functions")

    # Apply tags
    tagged_system = 0
    tagged_subsystem = 0
    commented = 0
    pattern_counts = defaultdict(int)
    for ea, idx_set in ea_to_patterns.items():
        # Apply the FIRST matching pattern (highest priority — order in list)
        idx = sorted(idx_set)[0]
        substr, system, subsystem, prefix = PATTERNS[idx]
        pattern_counts[substr] += 1

        # Bulk update: set system + subsystem only when NULL
        try:
            cur1 = db.execute(
                "UPDATE functions SET system = ? "
                "WHERE ea = ? AND system IS NULL",
                (system, ea),
            )
            tagged_system += cur1.rowcount or 0
            cur2 = db.execute(
                "UPDATE functions SET subsystem = ? "
                "WHERE ea = ? AND subsystem IS NULL",
                (subsystem, ea),
            )
            tagged_subsystem += cur2.rowcount or 0
        except Exception:
            pass

        # Comment with all matching patterns
        all_prefixes = [PATTERNS[i][3] for i in sorted(idx_set)]
        comment = " | ".join(all_prefixes)
        if _try_set_comment(ea, comment, repeatable=True):
            commented += 1
    db.commit()

    elapsed = round(time.time() - t0, 2)
    result = {
        "version": 1,
        "patterns_total": len(PATTERNS),
        "scanned": n_processed,
        "matching_functions": len(ea_to_patterns),
        "tagged_system": tagged_system,
        "tagged_subsystem": tagged_subsystem,
        "comments_set": commented,
        "pattern_counts": dict(pattern_counts),
        "elapsed_sec": elapsed,
    }
    db.kv_set("cfunc_pattern_tag", result)
    db.commit()

    msg_info(
        f"cfunc_pattern_tag: matched={len(ea_to_patterns)} "
        f"tagged_system={tagged_system} tagged_subsystem={tagged_subsystem} "
        f"comments={commented} ({elapsed}s)"
    )
    return tagged_subsystem
