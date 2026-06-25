"""
CVar Callback Rename
====================
Builds on Hash Resolution: for every resolved CVar entry, walks its struct,
finds the callback function pointer at offset +0x60, and renames the
callback function as `OnCVarChange_<safename>`.

Many CVars share a single generic callback — those keep a default
`OnCVarChange_shared_<count>` name so we don't pollute the IDB with one
incorrect rename winning over N others.

CVar struct layout (verified by inspecting RenderScale, EnableBlinkApp...,
AllowWinRT in c:/dumps/wow_dump.bin):

  [+0x00] uint64  hash         (FNV1A_64L of name)
  [+0x08] char*   name         (NUL-terminated)
  [+0x10] uint32  name_len     (matches strlen(name))
  [+0x18] char*   default_val
  [+0x20] uint64  flags1
  [+0x28] char*   current_val
  [+0x30] uint64  current_len
  [+0x38] uint64  flags2
  [+0x40] uint64  misc
  [+0x60] void*   on_change    ← callback function pointer (rename target)

Output:
  kv_store["cvar_callback_rename"] = {
      "version": 1,
      "cvar_entries_detected": int,
      "callbacks_unique_renamed": int,
      "callbacks_shared_renamed": int,
      "shared_callback_groups": dict,
      "elapsed_sec": float,
  }
"""

import json
import os
import time
from collections import defaultdict

import ida_bytes
import ida_funcs
import ida_name
import idaapi
import idc

from tc_wow_analyzer.core.utils import msg_info, msg_warn, dumps_build_path
from tc_wow_analyzer.analyzers.idb_enrichment import (
    _try_set_comment, _try_rename, _safe_struct_name,
)


# Build-resolved at call time (see analyze_cvar_callback_rename); default fallback only.
RESOLUTION_JSON = r"c:/dumps/hash_resolution_67186.json"
CALLBACK_OFFSET = 0x60
NAME_PTR_OFFSET = 0x08
NAME_LEN_OFFSET = 0x10
SHARED_CALLBACK_THRESHOLD = 3   # rename uniquely only if used by ≤ N CVars
IMAGE_BASE = 0x7FF75BB50000


def _verify_cvar_entry(ea, expected_name, expected_hash):
    """Return True iff the qwords at ea look like a CVar entry whose
    name field matches `expected_name`."""
    try:
        h = ida_bytes.get_qword(ea)
        if h != expected_hash:
            return False
        name_ptr = ida_bytes.get_qword(ea + NAME_PTR_OFFSET)
        if not name_ptr or name_ptr == idaapi.BADADDR:
            return False
        # name_len is stored in the lower 32 bits of the qword at +0x10
        # (upper 32 bits are zero in observed entries).
        name_len = ida_bytes.get_dword(ea + NAME_LEN_OFFSET)
        if name_len != len(expected_name):
            return False
        raw = ida_bytes.get_bytes(name_ptr, len(expected_name))
        if raw is None:
            return False
        return raw.decode("ascii", errors="replace") == expected_name
    except Exception:
        return False


def analyze_cvar_callback_rename(session):
    db = session.db
    if db is None:
        msg_warn("cvar_callback_rename: no DB")
        return 0
    RESOLUTION_JSON = dumps_build_path("hash_resolution")  # build-resolved
    # Resolve image base from the loaded IDB, not the 67186-hardcoded constant.
    image_base = getattr(session.cfg, "image_base", 0) or IMAGE_BASE
    if not os.path.isfile(RESOLUTION_JSON):
        msg_warn(f"cvar_callback_rename: {RESOLUTION_JSON} not found")
        return 0

    with open(RESOLUTION_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)
    msg_info(f"cvar_callback_rename: scanning {len(data['hits_64bit'])} 64-bit hits")

    t0 = time.time()
    # Pass 1: collect (ea, name) for verified CVar entries + their callback targets
    entries = []  # list of (ea, name, callback_ea)
    callback_to_names = defaultdict(list)
    for hit in data["hits_64bit"]:
        ea = int(hit["ea"], 16)
        hash_value = int(hit["hash"], 16)
        seen = set()
        unique = []
        for c in hit["candidates"]:
            if c["string"] not in seen:
                seen.add(c["string"])
                unique.append(c["string"])
        if len(unique) != 1:
            continue
        name = unique[0]
        if not _verify_cvar_entry(ea, name, hash_value):
            continue
        try:
            cb_ea = ida_bytes.get_qword(ea + CALLBACK_OFFSET)
        except Exception:
            cb_ea = 0
        if not cb_ea or cb_ea == idaapi.BADADDR:
            continue
        f = ida_funcs.get_func(cb_ea)
        if not f:
            continue
        entries.append((ea, name, f.start_ea))
        callback_to_names[f.start_ea].append(name)

    msg_info(
        f"cvar_callback_rename: verified {len(entries)} CVar entries, "
        f"{len(callback_to_names)} unique callback functions"
    )

    # Pass 2: rename callbacks
    unique_renamed = 0
    shared_renamed = 0
    shared_groups = {}
    cmtd = 0
    for cb_ea, names in callback_to_names.items():
        if len(names) <= SHARED_CALLBACK_THRESHOLD:
            # Unique callback — rename specifically
            primary = names[0]
            safe = _safe_struct_name(primary)
            desired = f"OnCVarChange_{safe}"
            if _try_rename(cb_ea, desired):
                unique_renamed += 1
            # Add comment listing all CVars that use this callback
            comment = "[CVar callback] " + ", ".join(sorted(names))
            if _try_set_comment(cb_ea, comment, repeatable=True):
                cmtd += 1
        else:
            # Generic shared callback — name with count, list samples in comment
            desired = f"OnCVarChange_shared_{len(names)}"
            if _try_rename(cb_ea, desired):
                shared_renamed += 1
            head = ", ".join(sorted(names)[:8])
            if len(names) > 8:
                head += f", +{len(names) - 8} more"
            comment = f"[CVar callback shared] {head}"
            if _try_set_comment(cb_ea, comment, repeatable=True):
                cmtd += 1
            shared_groups[f"0x{cb_ea:X}"] = names

        # Tag the callback function in functions table
        try:
            db.upsert_function(
                ea=cb_ea,
                rva=cb_ea - image_base,
                system="cvar",
                subsystem="cvar_callback",
                confidence=80,
            )
        except Exception:
            pass

    db.commit()

    elapsed = round(time.time() - t0, 2)
    result = {
        "version": 1,
        "cvar_entries_detected": len(entries),
        "callbacks_unique_renamed": unique_renamed,
        "callbacks_shared_renamed": shared_renamed,
        "comments_set": cmtd,
        "shared_callback_groups": shared_groups,
        "elapsed_sec": elapsed,
    }
    db.kv_set("cvar_callback_rename", result)
    db.commit()

    msg_info(
        f"cvar_callback_rename: entries={len(entries)} "
        f"unique_renamed={unique_renamed} shared_renamed={shared_renamed} "
        f"comments={cmtd} ({elapsed}s)"
    )
    return unique_renamed + shared_renamed
