"""
Batch Data Importer
Imports all existing JSON extraction files from the pipeline into
the SQLite knowledge database. This makes 500MB+ of extraction data
available for cross-referencing through the plugin's unified DB.

Supported files (where {build} is the configured build number):
  - wow_functions_{build}.json       → functions table
  - wow_opcode_dispatch_{build}.json → opcodes table
  - wow_jam_messages_{build}.json    → jam_types table
  - wow_db2_metadata_{build}.json    → db2_tables table
  - wow_vtable_methods_{build}.json  → vtables/vtable_entries tables
  - wow_lua_signatures_{build}.json  → lua_api table
  - wow_updatefields_{build}.json    → update_fields table
  - wow_string_xrefs_{build}.json    → strings table
  - wow_rtti_{build}.json            → vtables (RTTI source)
  - wow_hierarchy_{build}.json       → vtables parent_class
"""

import json
import os
import time

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


def run_import(session, dumps_dir=None):
    """Import all available extraction files into the knowledge DB.

    Args:
        session: PluginSession with cfg and db
        dumps_dir: Override path to dumps directory (default: from config)
    """
    db = session.db
    cfg = session.cfg

    if not dumps_dir:
        dumps_dir = cfg.extraction_dir
        if not dumps_dir or not os.path.isdir(dumps_dir):
            msg_error("Extraction directory not configured. Set extraction_dir in Settings.")
            return {}

    if not os.path.isdir(dumps_dir):
        msg_error(f"Dumps directory not found: {dumps_dir}")
        return {}

    build = cfg.build_number
    if not build:
        build = _detect_build_number(dumps_dir)

    # If no build-numbered files found in configured dir, check parent directory
    # (enhanced autodump puts JSONs in the dumps root, not a subdirectory)
    if build and not os.path.isfile(os.path.join(dumps_dir, f"wow_functions_{build}.json")):
        parent = os.path.dirname(dumps_dir)
        if os.path.isfile(os.path.join(parent, f"wow_functions_{build}.json")):
            msg_info(f"JSON files found in parent directory: {parent}")
            dumps_dir = parent
        elif not build:
            # Try detecting from parent
            parent_build = _detect_build_number(parent)
            if parent_build:
                build = parent_build
                dumps_dir = parent
    elif not build:
        # Try parent directory for build detection
        parent = os.path.dirname(dumps_dir)
        if os.path.isdir(parent):
            build = _detect_build_number(parent)
            if build:
                dumps_dir = parent

    if not build:
        msg_error("Cannot determine build number. Set build_number in Settings "
                  "or ensure wow_manifest_*.json exists in the dumps directory.")
        return {}
    msg_info(f"Importing from {dumps_dir} (build {build})")
    start = time.time()

    importers = [
        # Core importers (standard autodump output)
        (f"wow_functions_{build}.json", _import_functions),
        (f"wow_opcode_dispatch_{build}.json", _import_opcodes),
        (f"wow_jam_messages_{build}.json", _import_jam_types),
        (f"wow_db2_metadata_{build}.json", _import_db2_metadata),
        (f"wow_vtable_methods_{build}.json", _import_vtable_methods),
        (f"wow_lua_signatures_{build}.json", _import_lua_api),
        (f"wow_rtti_{build}.json", _import_rtti),
        (f"wow_hierarchy_{build}.json", _import_hierarchy),
        (f"wow_string_xrefs_{build}.json", _import_strings),
        (f"wow_updatefields_{build}.json", _import_update_fields),
        (f"wow_object_layouts_{build}.json", _import_object_layouts),
        # Enhanced autodump importers (optional — only present with enhanced dumper)
        (f"wow_ctor_dtor_{build}.json", _import_ctor_dtor),
        (f"wow_vcall_sites_{build}.json", _import_vcall_sites),
        (f"wow_globals_{build}.json", _import_globals),
        ("wow_tc_reference.json", _import_tc_reference),
        (f"wow_tc_compat_{build}.json", _import_tc_compat),
        (f"wow_statemachines_{build}.json", _import_statemachines),
        (f"wow_named_data_{build}.json", _import_named_data),
        (f"wow_simhash_{build}.json", _import_simhash),
        (f"wow_enums_{build}.json", _import_enums),
        (f"wow_hotfix_tables_{build}.json", _import_hotfix_tables),
        (f"wow_pdata_{build}.json", _import_pdata),
        (f"wow_crypto_{build}.json", _import_crypto),
    ]

    # Activity tracking for progress display
    try:
        from tc_wow_analyzer.core.activity import ActivityManager
        amgr = ActivityManager.get()
    except Exception:
        amgr = None

    available = [(f, fn) for f, fn in importers
                 if os.path.isfile(os.path.join(dumps_dir, f))]

    results = {}
    for idx, (filename, importer_func) in enumerate(available):
        filepath = os.path.join(dumps_dir, filename)

        msg_info(f"  Importing {filename}...")
        if amgr:
            amgr.task_progress(idx + 1, len(available), f"Importing {filename}")
        try:
            count = importer_func(session, filepath)
            results[filename] = count
            msg_info(f"    -> {count} records")
        except Exception as e:
            msg_error(f"    -> FAILED: {e}")
            results[filename] = -1

    db.commit()
    elapsed = time.time() - start
    total = sum(v for v in results.values() if v > 0)

    # Store import metadata
    db.kv_set("last_import", {
        "dumps_dir": dumps_dir,
        "build": build,
        "timestamp": time.time(),
        "results": {k: v for k, v in results.items()},
        "total_records": total,
        "elapsed_seconds": elapsed,
    })
    db.commit()

    # ── Post-import config synthesis ──────────────────────────────────
    # Populate config values that binary analyzers depend on, using the
    # data we just imported.  This bridges the gap between "data in DB"
    # and "config values the analyzers check before running".
    _synthesize_config(session, dumps_dir, build)

    msg_info(f"Import complete: {total} records from {len(results)} files "
             f"in {elapsed:.1f}s")
    return results


def _synthesize_config(session, dumps_dir, build):
    """Populate config from imported DB data so binary analyzers work."""
    db = session.db
    cfg = session.cfg

    changed = False

    # 1. Fill builds entry with image_base and extraction_dir
    build_str = str(build)
    if not cfg.get("builds", build_str):
        cfg.set("builds", build_str, {
            "image_base": cfg.image_base,
            "extraction_dir": dumps_dir,
        })
        changed = True
        msg_info(f"Config: added builds.{build_str} "
                 f"(image_base=0x{cfg.image_base:X})")
    else:
        # Ensure extraction_dir is set even if builds entry exists
        if not cfg.get("builds", build_str, "extraction_dir"):
            cfg.set("builds", build_str, "extraction_dir", dumps_dir)
            changed = True

    # 2. Set build_number if not already set
    if not cfg.get("build_number"):
        cfg.set("build_number", int(build))
        changed = True
        msg_info(f"Config: set build_number={build}")

    # 3. Extract dispatch_range from imported opcode data
    dispatch = cfg.dispatch_range
    if not dispatch or not dispatch.get("count"):
        opcode_count = db.count("opcodes")
        if opcode_count > 0:
            # Get min/max internal_index to determine range
            row = db.fetchone(
                "SELECT MIN(internal_index) as mn, MAX(internal_index) as mx "
                "FROM opcodes")
            if row:
                cfg.set("dispatch_range", "start", row["mn"])
                cfg.set("dispatch_range", "end", row["mx"])
                cfg.set("dispatch_range", "count", opcode_count)
                changed = True
                msg_info(f"Config: set dispatch_range "
                         f"(start=0x{row['mn']:X}, count={opcode_count})")

    # 4. Extract dispatch table RVA from the JSON if available
    dispatch_json = os.path.join(dumps_dir,
                                 f"wow_opcode_dispatch_{build}.json")
    if os.path.isfile(dispatch_json):
        try:
            with open(dispatch_json, "r", encoding="utf-8") as f:
                opcode_data = json.load(f)
            tables = opcode_data.get("dispatch_tables", [])
            if tables:
                table_rva = tables[0].get("table_rva")
                if table_rva:
                    if isinstance(table_rva, str):
                        table_rva = int(table_rva, 16)
                    if not cfg.known_rvas.get("main_dispatcher"):
                        cfg.set("known_rvas", "main_dispatcher", table_rva)
                        changed = True
                        msg_info(f"Config: set main_dispatcher "
                                 f"RVA=0x{table_rva:X}")
        except Exception as e:
            msg_warn(f"Config: could not extract dispatch table RVA: {e}")

    # 5. Find serializer function RVAs from imported function names
    serializer_patterns = {
        "write_uint32": ["%WriteUInt32%", "%ByteBuffer::WriteUInt32%"],
        "write_uint8": ["%WriteUInt8%", "%ByteBuffer::WriteUInt8%"],
        "write_float": ["%WriteFloat%", "%ByteBuffer::WriteFloat%"],
        "write_bits": ["%WriteBits%", "%ByteBuffer::WriteBits%"],
        "flush_bits": ["%FlushBits%", "%ByteBuffer::FlushBits%"],
        "write_object_guid": ["%WritePackedGuid%",
                              "%ObjectGuid::WriteAsPacked%"],
    }
    for key, patterns in serializer_patterns.items():
        if cfg.known_rvas.get(key):
            continue  # already set
        for pat in patterns:
            row = db.fetchone(
                "SELECT rva FROM functions WHERE name LIKE ? LIMIT 1",
                (pat,))
            if row and row["rva"]:
                cfg.set("known_rvas", key, row["rva"])
                changed = True
                msg_info(f"Config: set known_rvas.{key} = 0x{row['rva']:X}")
                break

    # 6. Set extraction_dir globally if not set
    if not cfg.get("extraction_dir"):
        cfg.set("extraction_dir", dumps_dir)
        changed = True

    if changed:
        saved = cfg.save()
        if saved:
            msg_info(f"Config: saved synthesized values to {saved}")
        else:
            msg_warn("Config: could not save (no IDB path?)")


def _import_functions(session, filepath):
    """Import wow_functions JSON → functions table."""
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    functions = data.get("functions", [])
    count = 0

    for func in functions:
        rva = func.get("rva")
        if not rva:
            continue
        if isinstance(rva, str):
            rva = int(rva, 16)

        ea = cfg.rva_to_ea(rva)
        name = func.get("name")
        source = func.get("source", "")

        # Classify by name prefix
        system = None
        if name:
            name_lower = name.lower()
            for sys_name, prefixes in _SYSTEM_PREFIXES.items():
                if any(name_lower.startswith(p) or f"::{p}" in name_lower
                       for p in prefixes):
                    system = sys_name
                    break

        db.upsert_function(ea, rva=rva, name=name, system=system)
        count += 1

        # Batch commit every 5000 records
        if count % 5000 == 0:
            db.commit()

    db.commit()
    return count


def _import_opcodes(session, filepath):
    """Import wow_opcode_dispatch JSON → opcodes table."""
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    tables = data.get("dispatch_tables", [])
    count = 0

    for table in tables:
        handlers = table.get("handlers", [])
        for h in handlers:
            opcode = h.get("opcode")
            if opcode is None:
                continue

            handler_rva = h.get("handler_rva")
            handler_ea = None
            if handler_rva:
                if isinstance(handler_rva, str):
                    handler_rva = int(handler_rva, 16)
                handler_ea = cfg.rva_to_ea(handler_rva)

            jam_name = h.get("jam_name", "")
            direction = h.get("direction", "")

            # Infer direction from JAM name patterns when not specified
            if not direction or direction == "unknown":
                if jam_name:
                    jn = jam_name.lower()
                    if "client" in jn or jn.startswith("cmsg") or "request" in jn:
                        direction = "CMSG"
                    elif "server" in jn or jn.startswith("smsg") or "response" in jn or "notify" in jn:
                        direction = "SMSG"
                    else:
                        direction = "CMSG"  # default: most dispatch tables are client→server
                else:
                    direction = "CMSG"

            # Internal index: opcode value from dispatch table
            db.upsert_opcode(
                direction=direction,
                internal_index=opcode,
                handler_ea=handler_ea,
                jam_type=jam_name if jam_name else None,
                status="imported",
            )
            count += 1

        if count % 1000 == 0:
            db.commit()

    db.commit()
    return count


def _import_jam_types(session, filepath):
    """Import wow_jam_messages JSON → jam_types table."""
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    count = 0

    for category in ("client_messages", "server_messages", "shared_structures"):
        messages = data.get(category, [])
        for m in messages:
            name = m.get("name", "")
            if not name:
                continue

            serializer_rva = m.get("function_rva") or m.get("code_rva")
            serializer_ea = None
            if serializer_rva:
                if isinstance(serializer_rva, str):
                    serializer_rva = int(serializer_rva, 16)
                serializer_ea = cfg.rva_to_ea(serializer_rva)

            handler_rva = m.get("handler_rva")
            deserializer_ea = None
            if handler_rva:
                if isinstance(handler_rva, str):
                    handler_rva = int(handler_rva, 16)
                deserializer_ea = cfg.rva_to_ea(handler_rva)

            db.upsert_jam_type(
                name=name,
                serializer_ea=serializer_ea,
                deserializer_ea=deserializer_ea,
                status="imported",
            )
            count += 1

    db.commit()
    return count


def _import_db2_metadata(session, filepath):
    """Import wow_db2_metadata JSON → db2_tables table."""
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    tables = data.get("tables", [])
    count = 0

    for table in tables:
        name = table.get("name", "")
        if not name:
            continue

        meta_rva = table.get("meta_rva")
        meta_ea = None
        if meta_rva:
            if isinstance(meta_rva, str):
                meta_rva = int(meta_rva, 16)
            meta_ea = cfg.rva_to_ea(meta_rva)

        layout_hash = table.get("layout_hash", 0)
        if isinstance(layout_hash, str):
            layout_hash = int(layout_hash, 16)

        db.upsert_db2_table(
            name=name,
            file_data_id=table.get("file_data_id"),
            layout_hash=layout_hash,
            meta_rva=meta_rva,
            meta_ea=meta_ea,
            field_count=table.get("field_count", 0),
            record_size=table.get("record_size", 0),
            index_field=table.get("index_field", -1),
        )
        count += 1

        if count % 500 == 0:
            db.commit()

    db.commit()
    return count


def _import_vtable_methods(session, filepath):
    """Import wow_vtable_methods JSON → vtables/vtable_entries.

    Supports two formats:
      - Flat: top-level "methods" is a list of {class_name, vtable_rva, slot, ...}
      - Nested: top-level "methods" is a list of {class, vtable_rva, methods: [{slot, name, rva}]}
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    methods = data.get("methods", [])
    count = 0

    for entry in methods:
        class_name = entry.get("class_name", entry.get("class", ""))
        vtable_rva = entry.get("vtable_rva")
        if not vtable_rva:
            continue
        if isinstance(vtable_rva, str):
            vtable_rva = int(vtable_rva, 16)

        vtable_ea = cfg.rva_to_ea(vtable_rva)

        db.upsert_vtable(
            ea=vtable_ea,
            rva=vtable_rva,
            class_name=class_name,
            source="vtable_methods",
        )

        # Nested format: entry has a "methods" sub-list
        sub_methods = entry.get("methods")
        if isinstance(sub_methods, list):
            for sub in sub_methods:
                slot = sub.get("slot", sub.get("index", 0))
                func_rva = sub.get("rva", sub.get("func_rva", sub.get("method_rva")))
                if func_rva:
                    if isinstance(func_rva, str):
                        func_rva = int(func_rva, 16)
                    func_ea = cfg.rva_to_ea(func_rva)
                    func_name = sub.get("name", sub.get("method_name"))
                    db.upsert_vtable_entry(vtable_ea, slot, func_ea, func_name)
                    count += 1
        else:
            # Flat format: entry itself is a single method
            slot = entry.get("slot", entry.get("index", 0))
            func_rva = entry.get("func_rva", entry.get("method_rva", entry.get("rva")))
            if func_rva:
                if isinstance(func_rva, str):
                    func_rva = int(func_rva, 16)
                func_ea = cfg.rva_to_ea(func_rva)
                func_name = entry.get("name", entry.get("method_name"))
                db.upsert_vtable_entry(vtable_ea, slot, func_ea, func_name)
                count += 1

    db.commit()
    return count


def _import_lua_api(session, filepath):
    """Import wow_lua_signatures JSON → lua_api table."""
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    functions = data.get("functions", [])
    count = 0

    for func in functions:
        namespace = func.get("namespace", "")
        method = func.get("name", func.get("method", ""))
        if not method:
            continue

        handler_rva = func.get("handler_rva", func.get("address", func.get("rva")))
        handler_ea = func.get("ea")
        if handler_ea:
            if isinstance(handler_ea, str):
                handler_ea = int(handler_ea, 16)
        elif handler_rva:
            if isinstance(handler_rva, str):
                handler_rva = int(handler_rva, 16)
            handler_ea = cfg.rva_to_ea(handler_rva)
        else:
            handler_ea = 0

        db.upsert_lua_api(
            namespace=namespace,
            method=method,
            handler_ea=handler_ea,
            arg_count=func.get("arg_count", -1),
        )
        count += 1

    db.commit()
    return count


def _import_rtti(session, filepath):
    """Import wow_rtti JSON → vtables with RTTI source."""
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    classes = data if isinstance(data, list) else data.get("classes", [])
    count = 0

    for cls in classes:
        name = cls.get("name", cls.get("class_name", ""))
        vtable_rva = cls.get("vtable_rva", cls.get("vftable_rva"))
        if not vtable_rva:
            continue
        if isinstance(vtable_rva, str):
            vtable_rva = int(vtable_rva, 16)

        vtable_ea = cfg.rva_to_ea(vtable_rva)
        parent = cls.get("parent", cls.get("base_class"))

        db.upsert_vtable(
            ea=vtable_ea,
            rva=vtable_rva,
            class_name=name,
            source="rtti",
            parent_class=parent,
        )
        count += 1

    db.commit()
    return count


def _import_hierarchy(session, filepath):
    """Import wow_hierarchy JSON → vtables parent_class."""
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    classes = data if isinstance(data, list) else data.get("classes", [])
    count = 0

    for cls in classes:
        name = cls.get("name", "")
        if not name:
            continue
        parent = cls.get("parent", cls.get("base"))
        vtable_rva = cls.get("vtable_rva")

        if vtable_rva:
            if isinstance(vtable_rva, str):
                vtable_rva = int(vtable_rva, 16)
            vtable_ea = cfg.rva_to_ea(vtable_rva)
            db.upsert_vtable(
                ea=vtable_ea,
                rva=vtable_rva,
                class_name=name,
                source="hierarchy",
                parent_class=parent,
            )
            count += 1

    db.commit()
    return count


def _import_strings(session, filepath):
    """Import wow_string_xrefs JSON → strings table.

    Enhanced autodump format: {string, string_rva, code_rva}
    Legacy format: {rva, value, xref_count}
    Both formats are supported.
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    xrefs = data.get("xrefs", data.get("strings", []))
    if isinstance(data, list):
        xrefs = data
    count = 0

    # Track unique strings by string_rva to count xrefs
    string_xref_counts = {}

    for s in xrefs:
        # Enhanced format: {string, string_rva, code_rva}
        string_rva = s.get("string_rva", s.get("rva", s.get("address")))
        if not string_rva:
            continue
        if isinstance(string_rva, str):
            string_rva = int(string_rva, 16)

        value = s.get("string", s.get("value", ""))

        # Count xrefs per unique string address
        string_xref_counts[string_rva] = string_xref_counts.get(string_rva, 0) + 1

        # Also store the code→string cross-reference in annotations
        code_rva = s.get("code_rva")
        if code_rva:
            if isinstance(code_rva, str):
                code_rva = int(code_rva, 16)
            code_ea = cfg.rva_to_ea(code_rva)
            # Store as annotation for the code site
            db.execute(
                """INSERT OR IGNORE INTO annotations
                   (ea, ann_type, value, source, confidence, created_at)
                   VALUES (?, 'string_ref', ?, 'autodump', 100, ?)""",
                (code_ea, value[:200], time.time()),
            )

        count += 1
        if count % 10000 == 0:
            db.commit()

    # Now insert/update the deduplicated string entries
    for str_rva, xref_count in string_xref_counts.items():
        ea = cfg.rva_to_ea(str_rva)
        # Get the string value (from last occurrence)
        value_for_ea = ""
        for s in xrefs:
            sr = s.get("string_rva", s.get("rva"))
            if sr and (int(sr, 16) if isinstance(sr, str) else sr) == str_rva:
                value_for_ea = s.get("string", s.get("value", ""))
                break

        system = _classify_string(value_for_ea)
        db.execute(
            """INSERT OR REPLACE INTO strings
               (ea, value, encoding, system, xref_count)
               VALUES (?, ?, 'utf-8', ?, ?)""",
            (ea, value_for_ea, system, xref_count),
        )

    db.commit()
    return count


def _import_update_fields(session, filepath):
    """Import wow_updatefields JSON → update_fields table."""
    # Delegate to the analyzer's import function
    from tc_wow_analyzer.analyzers.update_fields import _import_update_fields_json
    return _import_update_fields_json(session, filepath)


def _import_object_layouts(session, filepath):
    """Import wow_object_layouts JSON → update_fields table."""
    from tc_wow_analyzer.analyzers.update_fields import _import_object_layouts_json
    return _import_object_layouts_json(session, filepath)


# ═══════════════════════════════════════════════════════════════════
# Enhanced Autodump Importers (optional — only with enhanced dumper)
# ═══════════════════════════════════════════════════════════════════

def _import_ctor_dtor(session, filepath):
    """Import wow_ctor_dtor JSON → functions table + vtable linkage.

    Each entry: {func_rva, vtable_rva, type, class}
    type is "ctor" or "dtor".
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("entries", data.get("constructors", []))
    count = 0

    for entry in entries:
        func_rva = entry.get("func_rva")
        if not func_rva:
            continue
        if isinstance(func_rva, str):
            func_rva = int(func_rva, 16)

        func_ea = cfg.rva_to_ea(func_rva)
        kind = entry.get("type", "ctor")
        class_name = entry.get("class", "")

        # Build function name: ClassName::ClassName (ctor) or ClassName::~ClassName (dtor)
        name = None
        if class_name:
            safe_class = class_name.replace("::", "__")
            name = f"{safe_class}__{'~' if kind == 'dtor' else ''}{safe_class.split('__')[-1]}"

        db.upsert_function(
            func_ea, rva=func_rva, name=name,
            system="rtti", subsystem=kind,
            confidence=80,
        )

        # Link to vtable
        vtable_rva = entry.get("vtable_rva")
        if vtable_rva and class_name:
            if isinstance(vtable_rva, str):
                vtable_rva = int(vtable_rva, 16)
            vtable_ea = cfg.rva_to_ea(vtable_rva)
            db.upsert_vtable(
                ea=vtable_ea, rva=vtable_rva,
                class_name=class_name, source="ctor_dtor",
            )

        count += 1
        if count % 1000 == 0:
            db.commit()

    db.commit()
    return count


def _import_vcall_sites(session, filepath):
    """Import wow_vcall_sites JSON → annotations table.

    Each entry: {call_site_rva, vtable_rva, slot, target_rva, vtable_class}
    Stores as annotations on the call site address for cross-referencing.
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    sites = data.get("sites", data.get("vcall_sites", []))
    count = 0
    now = time.time()

    for site in sites:
        call_rva = site.get("call_site_rva")
        if not call_rva:
            continue
        if isinstance(call_rva, str):
            call_rva = int(call_rva, 16)

        call_ea = cfg.rva_to_ea(call_rva)
        vtable_class = site.get("vtable_class", "")
        slot = site.get("slot", 0)
        target_rva = site.get("target_rva", "")

        # Store as annotation for the call site
        comment = f"vcall {vtable_class}::vfunc{slot}"
        if target_rva:
            if isinstance(target_rva, str):
                target_rva_int = int(target_rva, 16)
            else:
                target_rva_int = target_rva
            comment += f" -> 0x{target_rva_int:X}"

        db.execute(
            """INSERT OR REPLACE INTO annotations
               (ea, ann_type, value, source, confidence, created_at)
               VALUES (?, 'vcall', ?, 'autodump', 90, ?)""",
            (call_ea, comment, now),
        )
        count += 1

        if count % 5000 == 0:
            db.commit()

    db.commit()
    return count


def _import_globals(session, filepath):
    """Import wow_globals JSON → functions table + annotations.

    Top-level keys: named_globals, code_pointers
    Named globals: {rva, name, type, value}
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    count = 0
    now = time.time()

    for glob in data.get("named_globals", []):
        rva = glob.get("rva")
        if not rva:
            continue
        if isinstance(rva, str):
            rva = int(rva, 16)

        ea = cfg.rva_to_ea(rva)
        name = glob.get("name", "")
        gtype = glob.get("type", "")

        if name:
            db.execute(
                """INSERT OR REPLACE INTO annotations
                   (ea, ann_type, value, source, confidence, created_at)
                   VALUES (?, 'global_name', ?, 'autodump', 95, ?)""",
                (ea, json.dumps({"name": name, "type": gtype}), now),
            )
            count += 1

    for ptr in data.get("code_pointers", []):
        rva = ptr.get("rva")
        if not rva:
            continue
        if isinstance(rva, str):
            rva = int(rva, 16)
        ea = cfg.rva_to_ea(rva)
        target = ptr.get("target_rva", "")

        db.execute(
            """INSERT OR REPLACE INTO annotations
               (ea, ann_type, value, source, confidence, created_at)
               VALUES (?, 'code_pointer', ?, 'autodump', 80, ?)""",
            (ea, str(target), now),
        )
        count += 1

    db.commit()
    return count


def _import_tc_reference(session, filepath):
    """Import wow_tc_reference JSON → functions table.

    Each entry: {name, rva, category}
    Categories: lua_function, handler, jam_type, db2_table, etc.
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("entries", [])
    count = 0

    # Map categories to systems
    cat_to_system = {
        "lua_function": "lua_api",
        "handler": "networking",
        "jam_type": "networking",
        "db2_table": "database",
        "opcode": "networking",
    }

    for entry in entries:
        rva = entry.get("rva")
        if not rva:
            continue
        if isinstance(rva, str):
            rva = int(rva, 16)

        ea = cfg.rva_to_ea(rva)
        name = entry.get("name", "")
        category = entry.get("category", "")
        system = cat_to_system.get(category)

        db.upsert_function(
            ea, rva=rva, name=name,
            system=system,
            confidence=70,
        )
        count += 1

        if count % 5000 == 0:
            db.commit()

    db.commit()
    return count


def _import_tc_compat(session, filepath):
    """Import wow_tc_compat JSON → annotations table.

    Each entry: {name, status, tc_file, details, cur_rva}
    Tracks which binary functions match TC source functions.
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("changes", data.get("entries", []))
    count = 0
    now = time.time()

    for entry in entries:
        rva = entry.get("cur_rva")
        if not rva:
            continue
        if isinstance(rva, str):
            rva = int(rva, 16)

        ea = cfg.rva_to_ea(rva)
        name = entry.get("name", "")
        status = entry.get("status", "")
        tc_file = entry.get("tc_file", "")

        value = json.dumps({
            "name": name, "status": status,
            "tc_file": tc_file,
            "details": entry.get("details", ""),
        })

        db.execute(
            """INSERT OR REPLACE INTO annotations
               (ea, ann_type, value, source, confidence, created_at)
               VALUES (?, 'tc_compat', ?, 'autodump', 85, ?)""",
            (ea, value, now),
        )
        count += 1

    db.commit()
    return count


def _import_statemachines(session, filepath):
    """Import wow_statemachines JSON → kv_store + function annotations.

    Each entry: {func_rva, state_count, states[{value, handler}]}
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    machines = data.get("machines", [])
    count = 0
    now = time.time()

    for machine in machines:
        func_rva = machine.get("func_rva")
        if not func_rva:
            continue
        if isinstance(func_rva, str):
            func_rva = int(func_rva, 16)

        func_ea = cfg.rva_to_ea(func_rva)
        state_count = machine.get("state_count", 0)

        # Annotate the function
        db.upsert_function(
            func_ea, rva=func_rva,
            subsystem="state_machine",
            confidence=60,
        )

        # Store state handlers
        for state in machine.get("states", []):
            handler_rva = state.get("handler")
            if handler_rva:
                if isinstance(handler_rva, str):
                    handler_rva = int(handler_rva, 16)
                handler_ea = cfg.rva_to_ea(handler_rva)
                db.execute(
                    """INSERT OR REPLACE INTO annotations
                       (ea, ann_type, value, source, confidence, created_at)
                       VALUES (?, 'state_handler', ?, 'autodump', 70, ?)""",
                    (handler_ea, json.dumps({
                        "machine_rva": f"0x{func_rva:X}",
                        "state_value": state.get("value"),
                    }), now),
                )

        count += 1

    db.commit()
    return count


def _import_named_data(session, filepath):
    """Import wow_named_data JSON → annotations table.

    Each entry: {name, rva, section, estimated_size}
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    items = data.get("items", data.get("named_data", []))
    count = 0
    now = time.time()

    for item in items:
        rva = item.get("rva")
        if not rva:
            continue
        if isinstance(rva, str):
            rva = int(rva, 16)

        ea = cfg.rva_to_ea(rva)
        name = item.get("name", "")
        section = item.get("section", "")

        db.execute(
            """INSERT OR REPLACE INTO annotations
               (ea, ann_type, value, source, confidence, created_at)
               VALUES (?, 'named_data', ?, 'autodump', 75, ?)""",
            (ea, json.dumps({"name": name, "section": section}), now),
        )
        count += 1

        if count % 5000 == 0:
            db.commit()

    db.commit()
    return count


def _import_simhash(session, filepath):
    """Import wow_simhash JSON → kv_store (function similarity hashes).

    Each entry: {rva, size, hash, blocks, calls, strrefs}
    Stored in kv_store as bulk data for the function_similarity analyzer.
    """
    db = session.db

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    functions = data.get("functions", [])
    if not functions:
        return 0

    # Store as kv blob — too large for individual rows
    db.kv_set("autodump_simhash", {
        "build": data.get("build", ""),
        "count": len(functions),
        "functions": functions,
    })
    db.commit()
    return len(functions)


def _import_enums(session, filepath):
    """Import wow_enums JSON → kv_store (recovered_enums).

    Each entry: {name, value_count, values[{value, name, handler_rva}]}
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    enums = data.get("enums", [])
    if not enums:
        return 0

    # Merge with existing recovered enums
    existing = db.kv_get("recovered_enums") or []
    existing_names = {e["name"] for e in existing if isinstance(e, dict)}

    for enum in enums:
        name = enum.get("name", "")
        if not name or name in existing_names:
            continue

        # Convert handler RVAs to EAs
        for val in enum.get("values", []):
            handler_rva = val.get("handler_rva")
            if handler_rva:
                if isinstance(handler_rva, str):
                    handler_rva = int(handler_rva, 16)
                val["handler_ea"] = cfg.rva_to_ea(handler_rva)

        existing.append(enum)
        existing_names.add(name)

    db.kv_set("recovered_enums", existing)
    db.commit()
    return len(enums)


def _import_hotfix_tables(session, filepath):
    """Import wow_hotfix_tables JSON → annotations on registration addresses.

    Each entry: {name, priority, registration_rva, has_string_fields}
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    tables = data.get("tables", [])
    count = 0
    now = time.time()

    for table in tables:
        rva = table.get("registration_rva")
        if not rva:
            continue
        if isinstance(rva, str):
            rva = int(rva, 16)

        ea = cfg.rva_to_ea(rva)
        name = table.get("name", "")

        db.execute(
            """INSERT OR REPLACE INTO annotations
               (ea, ann_type, value, source, confidence, created_at)
               VALUES (?, 'hotfix_table', ?, 'autodump', 90, ?)""",
            (ea, json.dumps({
                "name": name,
                "priority": table.get("priority", 0),
                "has_string_fields": table.get("has_string_fields", False),
            }), now),
        )
        count += 1

    db.commit()
    return count


def _import_pdata(session, filepath):
    """Import wow_pdata JSON → functions table (function boundaries).

    Each entry: {begin, end, size, prolog}
    Uses .pdata (exception handler) data to discover function boundaries.
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("functions", data.get("entries", []))
    count = 0

    for entry in entries:
        begin_rva = entry.get("begin")
        if not begin_rva:
            continue
        if isinstance(begin_rva, str):
            begin_rva = int(begin_rva, 16)

        end_rva = entry.get("end")
        size = entry.get("size", 0)
        if end_rva and not size:
            if isinstance(end_rva, str):
                end_rva = int(end_rva, 16)
            size = end_rva - begin_rva

        ea = cfg.rva_to_ea(begin_rva)
        db.upsert_function(ea, rva=begin_rva, size=size)
        count += 1

        if count % 10000 == 0:
            db.commit()

    db.commit()
    return count


def _import_crypto(session, filepath):
    """Import wow_crypto JSON → annotations table.

    Crypto constants and key material locations.
    """
    db = session.db
    cfg = session.cfg

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    count = 0
    now = time.time()

    for key, value in data.items():
        if key in ("build", "type"):
            continue
        if isinstance(value, dict) and "rva" in value:
            rva = value["rva"]
            if isinstance(rva, str):
                rva = int(rva, 16)
            ea = cfg.rva_to_ea(rva)
            db.execute(
                """INSERT OR REPLACE INTO annotations
                   (ea, ann_type, value, source, confidence, created_at)
                   VALUES (?, 'crypto', ?, 'autodump', 95, ?)""",
                (ea, json.dumps({"name": key, **{k: v for k, v in value.items() if k != "rva"}}), now),
            )
            count += 1
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "rva" in item:
                    rva = item["rva"]
                    if isinstance(rva, str):
                        rva = int(rva, 16)
                    ea = cfg.rva_to_ea(rva)
                    db.execute(
                        """INSERT OR REPLACE INTO annotations
                           (ea, ann_type, value, source, confidence, created_at)
                           VALUES (?, 'crypto', ?, 'autodump', 95, ?)""",
                        (ea, json.dumps({"category": key, **{k: v for k, v in item.items() if k != "rva"}}), now),
                    )
                    count += 1

    db.commit()
    return count


# ─── Helpers ───────────────────────────────────────────────────────

def _detect_build_number(dumps_dir):
    """Auto-detect build number from the dumps directory.

    Detection order:
      1. wow_manifest_*.json → "build_number" field
      2. Filename pattern: wow_functions_NNNNN.json → extract NNNNN
    """
    import glob
    import re

    # Try manifest first
    manifests = glob.glob(os.path.join(dumps_dir, "wow_manifest_*.json"))
    for manifest_path in manifests:
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            bn = data.get("build_number")
            if bn:
                msg_info(f"Build number {bn} detected from {os.path.basename(manifest_path)}")
                return int(bn)
        except Exception:
            pass

    # Fallback: extract from any wow_*_NNNNN.json filename
    pattern = re.compile(r'wow_\w+_(\d{4,6})\.json$')
    for fname in os.listdir(dumps_dir):
        m = pattern.match(fname)
        if m:
            bn = int(m.group(1))
            msg_info(f"Build number {bn} detected from filename {fname}")
            return bn

    return 0


_SYSTEM_PREFIXES = {
    "housing": ["housing", "house", "interior", "decor", "plot"],
    "neighborhood": ["neighborhood", "neighbour"],
    "combat": ["combat", "spell", "aura", "damage", "heal", "threat"],
    "quest": ["quest", "objective"],
    "movement": ["movement", "movegen", "pathfind", "waypoint"],
    "social": ["guild", "social", "friend", "chat", "mail"],
    "pvp": ["battleground", "arena", "pvp", "honor"],
    "crafting": ["crafting", "profession", "recipe", "trade"],
    "achievement": ["achievement", "criteria"],
    "talent": ["talent", "spec"],
    "loot": ["loot", "roll"],
    "auction": ["auctionhouse", "auction"],
    "vehicle": ["vehicle"],
    "mythic_plus": ["mythicplus", "mythic", "keystone", "affix"],
    "delves": ["delve"],
    "garrison": ["garrison"],
    "lua_api": ["framescript", "lua_"],
    "networking": ["worldsocket", "worldpacket", "battlenet"],
    "crypto": ["arc4", "srp", "hmac", "sha", "rsa", "warden"],
    "database": ["db2", "clientdb", "hotfix"],
}


def _classify_string(value):
    """Classify a string by content to a game system."""
    if not value or len(value) < 3:
        return None
    val_lower = value.lower()
    for system, keywords in _SYSTEM_PREFIXES.items():
        if any(kw in val_lower for kw in keywords):
            return system
    return None
