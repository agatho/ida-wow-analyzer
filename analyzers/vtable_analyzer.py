"""
Enhanced VTable Analyzer
Handles WoW's /GR- compilation (RTTI disabled for game classes).
Uses constructor analysis, cross-vtable inheritance, and naming propagation.
"""

import json

import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, ea_str
from tc_wow_analyzer.core import kv_keys


def _publish_vtable_kv(session):
    """Mirror the `vtables` SQL table into kv_store[vtable_analysis].

    THREE analyzers carry a kv fallback for the case where the SQL table is
    thin (`event_system_recovery`, `pe_metadata`, `alloc_class_catalog`) and
    all three read a key that nothing ever wrote -- so the fallback could never
    fire. On build 12.1.0.69382 the AutoDump ships only 47 vtable methods, which
    is exactly the situation the fallback exists for.

    Returns the number of vtables published.
    """
    db = session.db
    try:
        rows = db.fetchall(
            "SELECT ea, rva, class_name, entry_count, source, parent_class "
            "FROM vtables ORDER BY ea")
    except Exception as exc:
        msg_warn(f"  vtable kv publish skipped: {exc}")
        return 0

    entries_by_vt = {}
    try:
        for row in db.fetchall(
                "SELECT vtable_ea, slot_index, func_ea, func_name "
                "FROM vtable_entries ORDER BY vtable_ea, slot_index"):
            entries_by_vt.setdefault(row["vtable_ea"], []).append({
                "slot": row["slot_index"],
                "ea": row["func_ea"],
                "name": row["func_name"],
            })
    except Exception:
        pass  # vtable_entries may legitimately be empty

    vtables = []
    for row in rows:
        vtables.append({
            "ea": row["ea"],
            "rva": row["rva"],
            "class_name": row["class_name"],
            "entry_count": row["entry_count"],
            "source": row["source"],
            "parent_class": row["parent_class"],
            "entries": entries_by_vt.get(row["ea"], []),
        })

    db.kv_set(kv_keys.VTABLE_ANALYSIS, {
        "version": 1,
        "count": len(vtables),
        "vtables": vtables,
    })
    db.commit()
    msg_info(f"  published {len(vtables)} vtables to kv_store["
             f"'{kv_keys.VTABLE_ANALYSIS}']")
    return len(vtables)


def analyze_vtables(session):
    """Discover and analyze virtual function tables.

    Multi-strategy approach:
      1. Check if vtables were already imported from JSON
      2. Import from existing vtable_master_database.json if available
      3. Scan .rdata for pointer arrays that look like vtables
      4. Use constructor patterns to identify vtable writes
      5. Cross-reference with existing RTTI (only 6 COLs in WoW)
    """
    db = session.db
    cfg = session.cfg

    # If vtables were already imported, report the count
    existing = db.count("vtables")
    if existing > 0:
        msg_info(f"VTable analyzer: {existing} vtables already in DB "
                 f"(from JSON import)")
        _publish_vtable_kv(session)
        return existing

    import os
    # Try to import from existing extraction
    ext_dir = cfg.extraction_dir
    if ext_dir:
        vtable_file = os.path.join(ext_dir, "vtable_master_database.json")
        if os.path.isfile(vtable_file):
            count = _import_vtable_database(session, vtable_file)
            _publish_vtable_kv(session)
            return count

    for build_str in [str(cfg.build_number)]:
        build_info = cfg.get("builds", build_str)
        if not build_info:
            continue
        bd = build_info.get("extraction_dir", "")
        if bd:
            vtable_file = os.path.join(bd, "vtable_master_database.json")
            if os.path.isfile(vtable_file):
                count = _import_vtable_database(session, vtable_file)
                _publish_vtable_kv(session)
                return count

    msg_warn("No existing vtable database found — scanning binary")
    count = _scan_for_vtables(session)
    _publish_vtable_kv(session)
    return count


def _import_vtable_database(session, vtable_file):
    """Import vtable data from the existing extraction."""
    db = session.db
    cfg = session.cfg

    msg_info(f"Importing vtable database from {vtable_file}")
    with open(vtable_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    vtables = data if isinstance(data, list) else data.get("vtables", [])
    vt_count = 0
    entry_count = 0

    for vt in vtables:
        vt_ea = vt.get("address") or vt.get("ea")
        if not vt_ea:
            continue
        if isinstance(vt_ea, str):
            vt_ea = int(vt_ea, 16)

        class_name = vt.get("class_name") or vt.get("name")
        entries = vt.get("entries", [])
        source = vt.get("source", "import")

        vt_rva = cfg.ea_to_rva(vt_ea)
        db.upsert_vtable(
            ea=vt_ea,
            rva=vt_rva,
            class_name=class_name,
            entry_count=len(entries),
            source=source,
        )
        vt_count += 1

        for i, entry in enumerate(entries):
            func_ea = entry.get("address") or entry.get("ea")
            if not func_ea:
                continue
            if isinstance(func_ea, str):
                func_ea = int(func_ea, 16)
            func_name = entry.get("name") or ida_name.get_name(func_ea)
            db.upsert_vtable_entry(vt_ea, i, func_ea, func_name)
            entry_count += 1

    db.commit()
    msg_info(f"Imported {vt_count} vtables with {entry_count} entries")
    return vt_count


def _scan_for_vtables(session):
    """Scan .rdata for vtable-like pointer arrays."""
    msg_warn("VTable scanning not yet fully implemented")
    return 0
