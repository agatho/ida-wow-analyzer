"""
Enhanced Lua API Analyzer
Identifies FrameScript::RegisterFunction calls and extracts
Lua API functions with their handler addresses.
"""

import json

import ida_funcs
import ida_name

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn


def analyze_lua_api(session):
    """Discover Lua API functions from the binary.

    Strategy:
      1. Check if Lua API was already imported from JSON
      2. Import from existing lua_api_mapping.json if available
      3. Otherwise, scan for FrameScript::RegisterFunction pattern
    """
    db = session.db
    cfg = session.cfg

    # If lua_api was already imported, report the count
    existing = db.count("lua_api")
    if existing > 0:
        msg_info(f"Lua API: {existing} entries already in DB "
                 f"(from JSON import)")
        return existing

    import os
    # Try existing extraction — check global extraction_dir first
    ext_dir = cfg.extraction_dir
    if ext_dir:
        lua_file = os.path.join(ext_dir, "lua_api_mapping.json")
        if os.path.isfile(lua_file):
            return _import_lua_api_json(session, lua_file)

    # Fall back to per-build extraction directories
    for build_str in [str(cfg.build_number)]:
        build_info = cfg.get("builds", build_str)
        if not build_info:
            continue
        for subdir in ["enriched_dir", "extraction_dir"]:
            bd = build_info.get(subdir, "")
            if not bd:
                continue
            lua_file = os.path.join(bd, "lua_api_mapping.json")
            if os.path.isfile(lua_file):
                return _import_lua_api_json(session, lua_file)

    msg_warn("No existing Lua API extraction found")
    return 0


def _import_lua_api_json(session, lua_file):
    """Import Lua API data from existing extraction."""
    db = session.db
    cfg = session.cfg

    msg_info(f"Importing Lua API from {lua_file}")
    with open(lua_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    apis = data if isinstance(data, list) else data.get("apis", data.get("functions", []))
    count = 0

    for api in apis:
        namespace = api.get("namespace", "")
        method = api.get("method", api.get("name", ""))
        if not method:
            continue

        handler_ea = api.get("handler_ea") or api.get("address")
        if handler_ea and isinstance(handler_ea, str):
            handler_ea = int(handler_ea, 16)

        if not handler_ea:
            continue

        db.upsert_lua_api(
            namespace=namespace,
            method=method,
            handler_ea=handler_ea,
            arg_count=api.get("arg_count", -1),
        )
        count += 1

    db.commit()
    msg_info(f"Imported {count} Lua API functions")
    return count
