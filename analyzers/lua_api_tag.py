"""
Lua API Tag
===========
Backfills system/subsystem classifications + comments for the 9,000+ unique
C functions that the WoW client exposes as Lua bindings (the `lua_api` table
has 21,750 binding rows mapped to ~9,282 unique handler EAs — many C
functions are bound to multiple Lua names).

Lua API Recovery imports the binding metadata but doesn't tag the underlying
C functions. Subsystem Catalog tagged some by string-mining (~1,386 of them
with subsystem labels like 'housing', 'item', etc.) but the bulk (~7,896)
remained NULL. This analyzer:

  1. Sets `functions.system='lua'` only where currently NULL (preserves
     Subsystem Catalog's domain tags like 'housing', 'item').
  2. Sets `functions.subsystem='lua_binding'` only where currently NULL.
  3. Adds a repeatable comment `[Lua API] <method1>, <method2>, ...` listing
     every Lua name bound to the function (compresses to "+N more" past 8).

Output:
  kv_store["lua_api_tag"] = {
      "version": 1,
      "binding_rows": int,
      "unique_handler_eas": int,
      "tagged_system": int,
      "tagged_subsystem": int,
      "comments_set": int,
      "elapsed_sec": float,
  }
"""

import time
from collections import defaultdict

import idaapi

from tc_wow_analyzer.core.utils import msg_info, msg_warn
from tc_wow_analyzer.analyzers.idb_enrichment import _try_set_comment


def analyze_lua_api_tag(session):
    db = session.db
    if db is None:
        msg_warn("Lua API tag: no DB")
        return 0

    rows = db.fetchall(
        "SELECT namespace, method, handler_ea FROM lua_api "
        "WHERE handler_ea IS NOT NULL"
    )
    if not rows:
        msg_warn("Lua API tag: lua_api table empty — run Lua API analyzer first")
        return 0

    t0 = time.time()
    msg_info(f"Lua API tag: processing {len(rows)} binding rows")

    # handler_ea -> list[(namespace, method)]
    by_ea = defaultdict(list)
    for r in rows:
        ns = r["namespace"] or ""
        method = r["method"] or ""
        if not method:
            continue
        by_ea[r["handler_ea"]].append((ns, method))

    msg_info(f"Lua API tag: {len(by_ea)} unique handler EAs")

    # Bulk system/subsystem backfill — only when current value is NULL.
    handler_eas = list(by_ea.keys())

    # SQLite has a parameter limit; chunk the IN-list.
    CHUNK = 800
    tagged_system = 0
    tagged_subsystem = 0
    for i in range(0, len(handler_eas), CHUNK):
        chunk = handler_eas[i:i + CHUNK]
        placeholders = ",".join("?" * len(chunk))
        # system backfill — use 'lua_api' to match the established label
        # from Subsystem Catalog (don't introduce a competing 'lua' label).
        cur = db.execute(
            f"UPDATE functions SET system = 'lua_api' "
            f"WHERE ea IN ({placeholders}) AND system IS NULL",
            chunk,
        )
        tagged_system += cur.rowcount or 0
        # subsystem backfill
        cur = db.execute(
            f"UPDATE functions SET subsystem = 'lua_binding' "
            f"WHERE ea IN ({placeholders}) AND subsystem IS NULL",
            chunk,
        )
        tagged_subsystem += cur.rowcount or 0

    db.commit()

    # Per-EA comments listing the Lua method names.
    comments_set = 0
    for ea, bindings in by_ea.items():
        # Format: "ns.method" if namespace non-empty, else just "method"
        formatted = []
        for ns, method in sorted(set(bindings)):
            formatted.append(f"{ns}.{method}" if ns else method)
        head = ", ".join(formatted[:8])
        if len(formatted) > 8:
            head += f", +{len(formatted) - 8} more"
        comment = f"[Lua API] {head}"
        if _try_set_comment(ea, comment, repeatable=True):
            comments_set += 1

    elapsed = round(time.time() - t0, 2)
    result = {
        "version": 1,
        "binding_rows": len(rows),
        "unique_handler_eas": len(by_ea),
        "tagged_system": tagged_system,
        "tagged_subsystem": tagged_subsystem,
        "comments_set": comments_set,
        "elapsed_sec": elapsed,
    }
    db.kv_set("lua_api_tag", result)
    db.commit()

    msg_info(
        f"Lua API tag: bindings={len(rows)} unique_eas={len(by_ea)} "
        f"system_tagged={tagged_system} subsystem_tagged={tagged_subsystem} "
        f"comments={comments_set} ({elapsed}s)"
    )
    return len(by_ea)
