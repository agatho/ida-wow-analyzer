"""
RTTI → SQL
==========
Imports `wow_rtti_<build>.json` (1,107 named classes + 1,305 anonymous
vtables in build 67186) into the SQLite `vtables` + `vtable_entries`
tables. The existing VTable Analyzer only finds 26 via binary scanning
because the WoW retail client compiles with /GR- (RTTI mostly stripped
from game classes) — the autodump's RTTI extractor finds the rest by
walking the COL/type-descriptor chains the autodump intercepted at
runtime.

For each named RTTI class:
  * Insert/update `vtables(ea, rva, class_name, entry_count, source)`.
  * Walk `num_virtuals` consecutive qwords from `vtable_rva` and insert
    each function-pointer slot into `vtable_entries(vtable_ea, slot_index,
    func_ea, func_name)`.

For each anonymous vtable: same vtable+entries import with
`class_name=NULL`, `source='rtti_anonymous'`.

Also tags the underlying functions: every vtable slot's func_ea gets
`functions.subsystem='vfunc'` (only when currently NULL — preserves
domain-specific tags).

Output:
  kv_store["rtti_to_sql"] = {
      "version": 1,
      "named_classes": int,
      "anonymous_vtables": int,
      "vtable_rows_upserted": int,
      "vtable_entries_inserted": int,
      "vfunc_tagged": int,
      "elapsed_sec": float,
  }
"""

import json
import os
import time

import ida_bytes
import ida_funcs
import ida_name
import idaapi

from tc_wow_analyzer.core.utils import msg_info, msg_warn


def _resolve_rtti_json(cfg):
    extraction_dir = None
    try:
        extraction_dir = cfg.get("builds", str(cfg.build_number), "extraction_dir")
    except Exception:
        pass
    if not extraction_dir:
        extraction_dir = cfg.extraction_dir
    if not extraction_dir:
        return None
    path = os.path.join(extraction_dir, f"wow_rtti_{cfg.build_number}.json")
    return path if os.path.isfile(path) else None


def _walk_vtable_entries(vtable_ea, num_slots, db, vfunc_tagged_set, cfg):
    """Walk num_slots qwords from vtable_ea; insert into vtable_entries."""
    inserted = 0
    for slot in range(num_slots):
        slot_ea = vtable_ea + slot * 8
        try:
            func_ea = ida_bytes.get_qword(slot_ea)
        except Exception:
            break
        if not func_ea or func_ea == idaapi.BADADDR:
            continue
        # Sanity: func_ea must point to a function start
        f = ida_funcs.get_func(func_ea)
        if not f:
            continue
        func_ea = f.start_ea
        func_name = ida_name.get_name(func_ea) or None
        try:
            db.upsert_vtable_entry(vtable_ea, slot, func_ea, func_name)
            inserted += 1
        except Exception:
            continue
        # Tag the function as a vfunc (subsystem only when currently NULL)
        if func_ea not in vfunc_tagged_set:
            try:
                db.execute(
                    "UPDATE functions SET subsystem = 'vfunc' "
                    "WHERE ea = ? AND subsystem IS NULL",
                    (func_ea,),
                )
                vfunc_tagged_set.add(func_ea)
            except Exception:
                pass
    return inserted


def analyze_rtti_to_sql(session):
    db = session.db
    cfg = session.cfg
    if db is None or cfg is None:
        msg_warn("RTTI->SQL: no DB / cfg")
        return 0

    json_path = _resolve_rtti_json(cfg)
    if not json_path:
        msg_warn(f"RTTI->SQL: wow_rtti_{cfg.build_number}.json not found")
        return 0

    msg_info(f"RTTI->SQL: reading {json_path}")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    classes = data.get("classes", [])
    anonymous = data.get("anonymous_vtables", [])
    msg_info(
        f"RTTI->SQL: importing {len(classes)} named classes + "
        f"{len(anonymous)} anonymous vtables"
    )

    t0 = time.time()
    vt_upserted = 0
    entries_inserted = 0
    vfunc_tagged_set = set()

    # Named classes
    for cls in classes:
        name = cls.get("name")
        vtable_rva = cls.get("vtable_rva")
        if not name or vtable_rva is None:
            continue
        try:
            vt_ea = cfg.rva_to_ea(vtable_rva)
        except Exception:
            continue
        num_virtuals = cls.get("num_virtuals") or 0
        try:
            db.upsert_vtable(
                ea=vt_ea,
                rva=cfg.ea_to_rva(vt_ea),
                class_name=name,
                entry_count=num_virtuals,
                source="rtti_autodump",
            )
            vt_upserted += 1
        except Exception:
            continue
        # Walk slots if num_virtuals > 0; else best-effort scan up to 64
        slot_count = num_virtuals if num_virtuals > 0 else 64
        entries_inserted += _walk_vtable_entries(
            vt_ea, slot_count, db, vfunc_tagged_set, cfg
        )

    # Anonymous vtables
    for av in anonymous:
        rva = av.get("rva")
        if rva is None:
            continue
        try:
            vt_ea = cfg.rva_to_ea(rva)
        except Exception:
            continue
        num_methods = av.get("num_methods") or 0
        try:
            db.upsert_vtable(
                ea=vt_ea,
                rva=cfg.ea_to_rva(vt_ea),
                class_name=None,
                entry_count=num_methods,
                source="rtti_anonymous",
            )
            vt_upserted += 1
        except Exception:
            continue
        slot_count = num_methods if num_methods > 0 else 16
        entries_inserted += _walk_vtable_entries(
            vt_ea, slot_count, db, vfunc_tagged_set, cfg
        )

    db.commit()

    elapsed = round(time.time() - t0, 2)
    result = {
        "version": 1,
        "named_classes": len(classes),
        "anonymous_vtables": len(anonymous),
        "vtable_rows_upserted": vt_upserted,
        "vtable_entries_inserted": entries_inserted,
        "vfunc_tagged": len(vfunc_tagged_set),
        "elapsed_sec": elapsed,
    }
    db.kv_set("rtti_to_sql", result)
    db.commit()

    msg_info(
        f"RTTI->SQL: vtables_upserted={vt_upserted} "
        f"entries={entries_inserted} vfunc_tagged={len(vfunc_tagged_set)} "
        f"({elapsed}s)"
    )
    return vt_upserted
