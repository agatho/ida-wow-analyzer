"""
JAM Metadata Apply
==================
Reads `wow_jam_messages_<build>.json` (already imported as `jam_types` rows by
JAM Recovery) and applies IDA-side enrichments that JAM Recovery doesn't:

  1. Sets `functions.system='network'` / `subsystem='jam_serializer'` for every
     serializer/deserializer EA we know about (so Subsystem Catalog and the
     enrichment summary classify them correctly).
  2. Adds a repeatable comment at each EA: `[JAM] <Type> | <category> | refs=<n>`.
  3. Sets the first parameter of each function to `Jam_<Type> *` when the
     synthesized struct exists in the TIL (these are created by IDB Enrichment
     Phase 2 — `_create_jam_type_structs`).
  4. For shared_structures (which carry `handler_rva`), populates
     `opcodes.jam_type` whenever a CMSG/SMSG handler EA matches the
     handler_rva — links the wire opcode to its payload struct.
  5. Renames any still-anonymous serializer/deserializer to
     `<Type>_Serialize` / `<Type>_Deserialize` (matches IDB Enrichment's
     scheme; idempotent — won't overwrite meaningful names).

Output:
  kv_store["jam_metadata_apply"] = {
      "version": 1,
      "json_path": "...",
      "client_messages": int,
      "server_messages": int,
      "shared_structures": int,
      "functions_tagged": int,
      "comments_set": int,
      "types_applied": int,
      "renames_applied": int,
      "opcodes_linked": int,
      "missing_jam_struct": int,
      "elapsed_sec": float,
  }
"""

import json
import os
import time

import ida_funcs
import ida_typeinf
import idaapi
import idc

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, ea_str
from tc_wow_analyzer.analyzers.idb_enrichment import (
    _try_set_first_param_type,
    _try_set_comment,
    _try_rename,
    _safe_struct_name,
)


def _resolve_json_path(cfg):
    """Find the wow_jam_messages_<build>.json autodump file."""
    extraction_dir = None
    try:
        extraction_dir = cfg.get("builds", str(cfg.build_number), "extraction_dir")
    except Exception:
        pass
    if not extraction_dir:
        extraction_dir = cfg.extraction_dir
    if not extraction_dir:
        return None
    path = os.path.join(extraction_dir, f"wow_jam_messages_{cfg.build_number}.json")
    return path if os.path.isfile(path) else None


def _jam_struct_in_til(jam_name):
    """True if Jam_<Name> struct exists in the IDB type library."""
    struct_name = "Jam_" + _safe_struct_name(jam_name)
    if not struct_name or struct_name == "Jam_":
        return False, None
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    return bool(tif.get_named_type(til, struct_name)), struct_name


def _apply_one(entry, category, cfg, db, stats, already_seen):
    """Apply enrichments for a single JAM JSON entry."""
    name = entry.get("name", "")
    if not name:
        return

    # function_rva is the actual serializer; handler_rva (when present) is the
    # deserializer / receive side.
    serializer_rva = entry.get("function_rva")
    handler_rva = entry.get("handler_rva")
    code_rva = entry.get("code_rva")  # call site, not the function start
    ref_count = entry.get("ref_count", 0)

    eas_to_tag = []
    if serializer_rva is not None:
        ea = cfg.rva_to_ea(serializer_rva)
        if ida_funcs.get_func(ea):
            eas_to_tag.append((ea, "Serialize"))
    if handler_rva is not None:
        ea = cfg.rva_to_ea(handler_rva)
        if ida_funcs.get_func(ea):
            eas_to_tag.append((ea, "Deserialize"))

    if not eas_to_tag:
        return

    has_struct, struct_name = _jam_struct_in_til(name)
    if not has_struct:
        stats["missing_jam_struct"] += 1

    comment_text = f"[JAM] {name} | {category} | refs={ref_count}"
    if code_rva is not None:
        try:
            code_ea = cfg.rva_to_ea(code_rva)
            comment_text += f" | call_site={ea_str(code_ea)}"
        except Exception:
            pass

    for ea, suffix in eas_to_tag:
        if ea in already_seen:
            continue
        already_seen.add(ea)

        # functions table tag
        try:
            db.upsert_function(
                ea=ea,
                rva=cfg.ea_to_rva(ea),
                system="network",
                subsystem="jam_serializer",
                confidence=85,
            )
            stats["functions_tagged"] += 1
        except Exception:
            pass

        # repeatable comment
        if _try_set_comment(ea, comment_text, repeatable=True):
            stats["comments_set"] += 1

        # rename if still anonymous
        safe = _safe_struct_name(name)
        if safe:
            desired = f"{safe}_{suffix}"
            if _try_rename(ea, desired):
                stats["renames_applied"] += 1

        # apply Jam_<Name>* to first param
        if has_struct:
            if _try_set_first_param_type(ea, struct_name):
                stats["types_applied"] += 1


def _link_opcodes_for_shared(entries, cfg, db, stats):
    """For shared_structures with handler_rva, populate opcodes.jam_type."""
    # Build handler_ea → jam_type map
    handler_to_type = {}
    for entry in entries:
        handler_rva = entry.get("handler_rva")
        if handler_rva is None:
            continue
        try:
            ea = cfg.rva_to_ea(handler_rva)
        except Exception:
            continue
        handler_to_type.setdefault(ea, []).append(entry.get("name", ""))

    if not handler_to_type:
        return

    # Pull all opcodes with handler_ea set
    try:
        rows = db.fetchall(
            "SELECT direction, internal_index, handler_ea, tc_name, jam_type "
            "FROM opcodes WHERE handler_ea IS NOT NULL"
        )
    except Exception as e:
        msg_warn(f"JAM apply: opcodes query failed: {e}")
        return

    for row in rows:
        if row["jam_type"]:
            continue  # don't overwrite an already-known mapping
        names = handler_to_type.get(row["handler_ea"])
        if not names:
            continue
        # If multiple shared_structures map to the same handler, join them
        joined = ",".join(sorted(set(n for n in names if n)))
        if not joined:
            continue
        try:
            db.execute(
                "UPDATE opcodes SET jam_type = ? "
                "WHERE direction = ? AND internal_index = ?",
                (joined, row["direction"], row["internal_index"]),
            )
            stats["opcodes_linked"] += 1
        except Exception:
            pass


def analyze_jam_metadata_apply(session):
    """Main entry point."""
    db = session.db
    cfg = session.cfg
    if db is None or cfg is None:
        msg_warn("JAM apply: no DB / cfg")
        return 0

    json_path = _resolve_json_path(cfg)
    if not json_path:
        msg_warn(f"JAM apply: wow_jam_messages_{cfg.build_number}.json not found")
        return 0

    msg_info(f"JAM apply: reading {json_path}")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    t0 = time.time()
    stats = {
        "client_messages": len(data.get("client_messages", [])),
        "server_messages": len(data.get("server_messages", [])),
        "shared_structures": len(data.get("shared_structures", [])),
        "functions_tagged": 0,
        "comments_set": 0,
        "types_applied": 0,
        "renames_applied": 0,
        "opcodes_linked": 0,
        "missing_jam_struct": 0,
    }

    already_seen = set()
    for category in ("client_messages", "server_messages", "shared_structures"):
        for entry in data.get(category, []):
            _apply_one(entry, category, cfg, db, stats, already_seen)

    # Cross-link opcode → jam_type for shared_structures with handler_rva.
    _link_opcodes_for_shared(data.get("shared_structures", []), cfg, db, stats)

    db.commit()

    stats["version"] = 1
    stats["json_path"] = json_path
    stats["elapsed_sec"] = round(time.time() - t0, 2)
    db.kv_set("jam_metadata_apply", stats)
    db.commit()

    msg_info(
        f"JAM apply: cli={stats['client_messages']} srv={stats['server_messages']} "
        f"shared={stats['shared_structures']} | tagged={stats['functions_tagged']} "
        f"renamed={stats['renames_applied']} types={stats['types_applied']} "
        f"comments={stats['comments_set']} opcode_links={stats['opcodes_linked']} "
        f"missing_struct={stats['missing_jam_struct']} ({stats['elapsed_sec']}s)"
    )
    return stats["functions_tagged"]
