"""
CVar Consumer Tag
=================
Reads `c:/dumps/cvar_callsite_map_67186.json` (produced offline by
`scripts/mine_cvar_callsites.py`) and tags every function that references a
CVar by name (string literal) or pre-hashed value.

For each unique caller function:
  1. `functions.subsystem='cvar_consumer'` (only when currently NULL).
  2. Repeatable comment `[Reads CVars] <Name1>, <Name2>, ...` listing every
     CVar the function references (truncated to 8 + "+N more").
  3. For *single-CVar* callers with auto-named functions: rename to
     `Get_<CVarName>_consumer` (avoids collisions with the CVar entries
     themselves which are named `CVarHash_<CVarName>`).

Output:
  kv_store["cvar_consumer_tag"] = {
      "version": 1,
      "callers_total": int,
      "tagged": int,
      "comments_set": int,
      "renames_applied": int,
      "elapsed_sec": float,
  }
"""

import json
import os
import time
from collections import defaultdict

import ida_funcs
import idaapi

from tc_wow_analyzer.core.utils import msg_info, msg_warn, dumps_build_path
from tc_wow_analyzer.analyzers.idb_enrichment import (
    _try_set_comment, _try_rename, _safe_struct_name,
)


# Build-resolved at call time (see analyze_cvar_consumer_tag); default fallback only.
CALLSITE_JSON = r"c:/dumps/cvar_callsite_map_67186.json"


def analyze_cvar_consumer_tag(session):
    db = session.db
    if db is None:
        msg_warn("cvar_consumer_tag: no DB")
        return 0
    CALLSITE_JSON = dumps_build_path("cvar_callsite_map")  # build-resolved
    if not os.path.isfile(CALLSITE_JSON):
        msg_warn(f"cvar_consumer_tag: {CALLSITE_JSON} not found "
                 "— run scripts/mine_cvar_callsites.py first")
        return 0

    with open(CALLSITE_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)
    callers = data.get("callers", {})
    msg_info(f"cvar_consumer_tag: {len(callers)} CVars with callers")

    t0 = time.time()
    # Invert: caller_ea -> set[cvar_name]
    caller_to_cvars = defaultdict(set)
    for cvar_name, caller_list in callers.items():
        for entry in caller_list:
            caller_to_cvars[int(entry["ea"], 16)].add(cvar_name)

    msg_info(f"cvar_consumer_tag: {len(caller_to_cvars)} unique caller functions")

    tagged = 0
    commented = 0
    renamed = 0
    chunk = 800
    caller_eas = list(caller_to_cvars.keys())

    # Bulk subsystem backfill — only set when currently NULL (preserve other tags)
    for i in range(0, len(caller_eas), chunk):
        batch = caller_eas[i:i + chunk]
        placeholders = ",".join("?" * len(batch))
        try:
            cur = db.execute(
                f"UPDATE functions SET subsystem = 'cvar_consumer' "
                f"WHERE ea IN ({placeholders}) AND subsystem IS NULL",
                batch,
            )
            tagged += cur.rowcount or 0
        except Exception as e:
            msg_warn(f"cvar_consumer_tag: bulk update failed: {e}")
    db.commit()

    # Per-caller comment + rename
    for ea, cvar_set in caller_to_cvars.items():
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        # Resolve to function start
        ea = f.start_ea
        cvars = sorted(cvar_set)
        head = ", ".join(cvars[:8])
        if len(cvars) > 8:
            head += f", +{len(cvars) - 8} more"
        comment = f"[Reads CVars] {head}"
        if _try_set_comment(ea, comment, repeatable=True):
            commented += 1

        # Single-CVar caller — try a rename for navigation
        if len(cvars) == 1:
            safe = _safe_struct_name(cvars[0])
            if safe:
                desired = f"CVarRead_{safe}"
                if _try_rename(ea, desired):
                    renamed += 1

    db.commit()

    elapsed = round(time.time() - t0, 2)
    result = {
        "version": 1,
        "callers_total": len(caller_to_cvars),
        "tagged": tagged,
        "comments_set": commented,
        "renames_applied": renamed,
        "elapsed_sec": elapsed,
    }
    db.kv_set("cvar_consumer_tag", result)
    db.commit()

    msg_info(
        f"cvar_consumer_tag: callers={len(caller_to_cvars)} tagged={tagged} "
        f"comments={commented} renamed={renamed} ({elapsed}s)"
    )
    return tagged
