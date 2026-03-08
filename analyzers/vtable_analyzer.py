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
        return existing

    import os
    # Try to import from existing extraction
    ext_dir = cfg.extraction_dir
    if ext_dir:
        vtable_file = os.path.join(ext_dir, "vtable_master_database.json")
        if os.path.isfile(vtable_file):
            return _import_vtable_database(session, vtable_file)

    for build_str in [str(cfg.build_number)]:
        build_info = cfg.get("builds", build_str)
        if not build_info:
            continue
        bd = build_info.get("extraction_dir", "")
        if bd:
            vtable_file = os.path.join(bd, "vtable_master_database.json")
            if os.path.isfile(vtable_file):
                return _import_vtable_database(session, vtable_file)

    msg_warn("No existing vtable database found — scanning binary")
    return _scan_for_vtables(session)


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
