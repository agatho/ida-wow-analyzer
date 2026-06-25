"""
Typename Apply
==============
Applies the 5,980 `WowGetRawTypeName<...>` template typename strings
extracted from the binary into the IDB:

  1. For each typename string in `c:/dumps/typename_inventory_67186.json`,
     set an IDA name at the string's EA: `RawTypeName_<safe>`.
  2. Walk XrefsTo each string EA — every caller is a function that
     references this template instantiation. For unambiguous templates
     (e.g., `UniqueEventCallbackContainer<MyEvent>`), tag the caller
     with `subsystem='event_handler'` and a comment naming the event.
  3. Special-case three template families:
        - `UniqueEventCallbackContainer<EventType>` → event handler
        - `chained_hash_node<pair<keyhash,Value>>`  → hash table user
        - `JamMirrorBaseHandlersWrapper<bcUniqueFunction<...>>` → JAM dispatch

Output:
  kv_store["typename_apply"] = {...stats...}
"""

import json
import os
import re
import time
from collections import defaultdict

import ida_bytes
import ida_funcs
import ida_name
import idaapi
import idautils

from tc_wow_analyzer.core.utils import msg_info, msg_warn, dumps_build_path
from tc_wow_analyzer.analyzers.idb_enrichment import (
    _try_set_comment, _safe_struct_name,
)


# Build-resolved at call time (see analyze_typename_apply); default fallback only.
INVENTORY = r"c:/dumps/typename_inventory_67186.json"


def _set_data_name(ea, desired):
    """Set name at a data EA, only when currently auto-named."""
    if not ea or ea == idaapi.BADADDR:
        return False
    current = ida_name.get_name(ea) or ""
    auto_prefixes = (
        "dword_", "qword_", "byte_", "word_", "data_", "off_",
        "unk_", "loc_", "asc_", "stru_", "xmmword_", "ymmword_",
        "g_data_", "g_ptr_",
    )
    if current and not current.lower().startswith(auto_prefixes):
        return False
    safe = re.sub(r"[^A-Za-z0-9_]", "_", desired)
    safe = re.sub(r"__+", "_", safe).strip("_")[:80]
    if not safe:
        return False
    existing_ea = ida_name.get_name_ea(idaapi.BADADDR, safe)
    if existing_ea != idaapi.BADADDR and existing_ea != ea:
        safe = f"{safe}_{ea & 0xFFFF:04X}"
    SN_FORCE = 0x800
    flags = idaapi.SN_NOWARN | idaapi.SN_NOCHECK | SN_FORCE
    return bool(idaapi.set_name(ea, safe, flags))


def _classify(short):
    """Return (subsystem, comment_prefix, brief_label) for a typename."""
    if short.startswith("LanguageBinding::UniqueEventCallbackContainer<"):
        return "event_handler", "[Event handler]", _extract_event_type(short)
    if "UniqueEventCallbackContainer<" in short:
        return "event_handler", "[Event handler]", _extract_event_type(short)
    if "JamMirrorBaseHandlersWrapper<" in short:
        return "jam_dispatch", "[JAM dispatch]", "JAM packet"
    if "chained_hash_node<" in short:
        return "hash_consumer", "[Hash table]", _extract_hash_value(short)
    return None, None, None


def _extract_event_type(short):
    m = re.search(r"UniqueEventCallbackContainer<\s*(?:struct|class)?\s*([\w:]+)", short)
    return m.group(1) if m else "event"


def _extract_hash_value(short):
    m = re.search(r"chained_hash_node<\s*(?:struct|class)?\s*([\w:<>]+)", short)
    return m.group(1)[:60] if m else "hash_value"


def analyze_typename_apply(session):
    db = session.db
    if db is None:
        msg_warn("typename_apply: no DB")
        return 0
    INVENTORY = dumps_build_path("typename_inventory")  # build-resolved
    if not os.path.isfile(INVENTORY):
        msg_warn(f"typename_apply: {INVENTORY} not found")
        return 0

    with open(INVENTORY, "r", encoding="utf-8") as f:
        data = json.load(f)
    cats = data.get("categories", {})
    flat = []
    for cat, entries in cats.items():
        for e in entries:
            flat.append(e)
    msg_info(f"typename_apply: processing {len(flat)} typename strings")

    t0 = time.time()
    names_set = 0
    comments_set = 0
    callers_tagged = 0
    callers_seen = set()

    for entry in flat:
        ea = int(entry["ea"], 16)
        short = entry["short"]
        # Set name on the string itself
        safe = _safe_struct_name(short[:60])
        desired = f"RawTypeName_{safe}"
        if _set_data_name(ea, desired):
            names_set += 1
        # Comment
        if _try_set_comment(ea, f"[Typename] {short[:200]}", repeatable=True):
            comments_set += 1

        # Classify and propagate to xrefs
        subsystem, prefix, label = _classify(short)
        if subsystem is None:
            continue
        try:
            for xref in idautils.XrefsTo(ea, 0):
                caller = ida_funcs.get_func(xref.frm)
                if not caller:
                    continue
                caller_ea = caller.start_ea
                if caller_ea in callers_seen:
                    continue
                callers_seen.add(caller_ea)
                # Bulk-tag: only when subsystem is NULL
                try:
                    cur = db.execute(
                        "UPDATE functions SET subsystem = ? "
                        "WHERE ea = ? AND subsystem IS NULL",
                        (subsystem, caller_ea),
                    )
                    callers_tagged += cur.rowcount or 0
                except Exception:
                    pass
                _try_set_comment(caller_ea, f"{prefix} {label}", repeatable=True)
        except Exception:
            continue

    db.commit()

    elapsed = round(time.time() - t0, 2)
    result = {
        "version": 1,
        "typenames_total": len(flat),
        "names_set": names_set,
        "comments_set": comments_set,
        "callers_tagged": callers_tagged,
        "callers_unique": len(callers_seen),
        "elapsed_sec": elapsed,
    }
    db.kv_set("typename_apply", result)
    db.commit()

    msg_info(
        f"typename_apply: typenames={len(flat)} names_set={names_set} "
        f"comments={comments_set} callers_tagged={callers_tagged} "
        f"({elapsed}s)"
    )
    return names_set
