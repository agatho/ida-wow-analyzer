"""
DB2 LoadInfo Codegen
====================
Two-stage analyzer that finally turns the 2,649 db2_tables rows into
TrinityCore-shaped `LoadInfo` + `Entry` C++ definitions, which has been
blocked because every row's `fields_json` is NULL (the binary autodump
extracts the meta header but not field schemas).

Stage 1 — schema bridge:
  For each `db2_tables` row, look up the matching `<Name>.dbd` file in
  `c:/dumps/WoWDBDefs/definitions/`, parse it via `_dbd_parser`, find the
  layout for build (12,0,5,67186) (or the highest fallback), convert each
  Column+LayoutField pair to the type-tagged dict format `db2_stores.py`
  expects, and `UPDATE db2_tables SET fields_json = ?`.

Stage 2 — codegen sweep:
  For every table that now has `fields_json`, call:
    * `db2_stores.generate_loadinfo(...)`
    * `db2_stores.generate_entry_struct(...)`
    * `db2_stores.generate_store_declaration(...)`
  Concatenate into:
    * `c:/dumps/codegen_out/DB2LoadInfo_<build>.h`
    * `c:/dumps/codegen_out/DB2Structure_<build>.h`
    * `c:/dumps/codegen_out/DB2Stores_<build>.h`
  Set `loadinfo_generated=1` per row that produced full output.

WoWDBDefs only ships ~1,319 .dbd files vs the binary's 2,649 tables, so a
~50% coverage ceiling is expected — the rest fall back to `db2_stores`'
existing skeleton output.
"""

import json
import os
import re
import time

from tc_wow_analyzer.core.utils import msg_info, msg_warn
from tc_wow_analyzer.analyzers._dbd_parser import (
    parse_dbd_file, find_layout_for_build,
)
from tc_wow_analyzer.codegen import db2_stores


def _wowdbdefs_dir():
    """WoWDBDefs checkout under the configured dumps dir (was hardcoded)."""
    from tc_wow_analyzer.core.utils import dumps_dir
    return os.path.join(dumps_dir(), "WoWDBDefs", "definitions")


def _target_build(cfg=None):
    """DBD layout selector for the CURRENTLY loaded build.

    Was the constant ``(12, 0, 5, 67186)``, so a 12.1.0 run silently emitted
    12.0.5 field layouts into a file named ``DB2LoadInfo_69382.h``.
    """
    from tc_wow_analyzer.core.build_version import build_tuple
    from tc_wow_analyzer.core.utils import current_build
    build = current_build()
    if not build and cfg is not None:
        build = getattr(cfg, "build_number", 0)
    return build_tuple(build)


def _column_to_db2stores_type(col, layout_field):
    """Map a (Column, LayoutField) pair to the type string `db2_stores`
    expects ("int8"/"int16"/"int32"/"int64"/"float"/"string").

    Returns (type_string, is_signed, array_size).
    """
    base = (col.base_type or "int").lower()
    bits = layout_field.bit_size if layout_field else 32
    signed = layout_field.is_signed if layout_field else True
    arr = layout_field.array_size if (layout_field and layout_field.array_size) else 1

    if base == "float":
        return "float", False, arr
    if base == "double":
        # db2_stores has no double; fall through to int64
        return "int64", False, arr
    if base in ("string", "string_lang"):
        return "string", False, arr
    if base == "locstring":
        # Localized: TC treats as a string field with array
        return "string", False, max(arr, 1)

    # Integer types
    type_by_bits = {
        8: "int8", 16: "int16", 32: "int32", 64: "int64",
    }
    return type_by_bits.get(bits, "int32"), signed, arr


def _build_fields_json_for_table(name, dbd, target_build=None):
    """Return a JSON-serializable list of field dicts for `name`'s layout
    matching the CURRENT build, or None if no layout matches."""
    layout = find_layout_for_build(dbd, target_build or _target_build())
    if layout is None:
        return None
    fields = []
    index_field = -1
    for i, lf in enumerate(layout.fields):
        # The column is named the same as the LayoutField's `name`.
        col = dbd.columns.get(lf.name)
        if col is None:
            # Fallback: synthesize a minimal Column
            class _MockCol:
                base_type = "int"
            col = _MockCol()
        ftype, signed, arr = _column_to_db2stores_type(col, lf)
        if lf.tag == "id" or (index_field < 0 and lf.name.lower() == "id"):
            index_field = i
        fields.append({
            "index": i,
            "name": lf.name,
            "type": ftype,
            "is_signed": signed,
            "array_size": arr,
            "tag": lf.tag,
        })
    return fields, index_field, layout.hash


def _stage1_populate_fields_json(db):
    """Bridge WoWDBDefs into db2_tables.fields_json (and update layout_hash
    + index_field where DBD knows them)."""
    dbd_dir = _wowdbdefs_dir()
    if not os.path.isdir(dbd_dir):
        msg_warn(f"DB2 codegen: WoWDBDefs not at {dbd_dir}")
        return {"matched": 0, "no_dbd": 0, "no_layout": 0, "updated": 0}

    target = _target_build()
    msg_info(f"DB2 codegen: selecting DBD layouts for version "
             f"{'.'.join(str(p) for p in target)}")

    rows = db.fetchall(
        "SELECT name FROM db2_tables ORDER BY name"
    )
    msg_info(f"DB2 codegen: stage 1 — bridging {len(rows)} tables vs WoWDBDefs")

    matched = 0
    no_dbd = 0
    no_layout = 0
    updated = 0
    for r in rows:
        name = r["name"]
        if not name:
            continue
        dbd_path = os.path.join(dbd_dir, f"{name}.dbd")
        if not os.path.isfile(dbd_path):
            no_dbd += 1
            continue
        matched += 1
        try:
            dbd = parse_dbd_file(dbd_path)
        except Exception as e:
            msg_warn(f"  parse failed for {name}: {e}")
            continue
        result = _build_fields_json_for_table(name, dbd)
        if not result:
            no_layout += 1
            continue
        fields, index_field, layout_hash = result
        try:
            params = [
                json.dumps(fields),
            ]
            sql = "UPDATE db2_tables SET fields_json = ?"
            if index_field >= 0:
                sql += ", index_field = ?"
                params.append(index_field)
            if layout_hash:
                # layout_hash in DB is INTEGER; .dbd stores hex string
                try:
                    lh_int = int(layout_hash, 16)
                    sql += ", layout_hash = ?"
                    params.append(lh_int)
                except ValueError:
                    pass
            sql += " WHERE name = ?"
            params.append(name)
            db.execute(sql, params)
            updated += 1
        except Exception as e:
            msg_warn(f"  update failed for {name}: {e}")
    db.commit()
    msg_info(
        f"DB2 codegen: stage 1 — matched={matched} (no_dbd={no_dbd} "
        f"no_layout={no_layout}) updated={updated}"
    )
    return {
        "matched": matched, "no_dbd": no_dbd,
        "no_layout": no_layout, "updated": updated,
    }


def _stage2_emit_codegen(session, build):
    """Iterate every db2_table with fields_json and emit the three .h files."""
    db = session.db
    from tc_wow_analyzer.codegen.writer import codegen_out_dir
    out_dir = codegen_out_dir(session)
    os.makedirs(out_dir, exist_ok=True)

    rows = db.fetchall(
        "SELECT name, field_count, layout_hash, fields_json FROM db2_tables "
        "WHERE fields_json IS NOT NULL ORDER BY name"
    )
    msg_info(f"DB2 codegen: stage 2 — emitting code for {len(rows)} tables")

    li_path = os.path.join(out_dir, f"DB2LoadInfo_{build}.h")
    es_path = os.path.join(out_dir, f"DB2Structure_{build}.h")
    sd_path = os.path.join(out_dir, f"DB2Stores_{build}.h")

    li_lines = [
        f"// Auto-generated by tc_wow_analyzer — build {build}",
        "// LoadInfo definitions — paste into TC's DB2LoadInfo.h sections",
        "#pragma once",
        "",
    ]
    es_lines = [
        f"// Auto-generated by tc_wow_analyzer — build {build}",
        "// Entry struct definitions — paste into TC's DB2Structure.h",
        "#pragma once",
        "",
    ]
    sd_lines = [
        f"// Auto-generated by tc_wow_analyzer — build {build}",
        "// Storage declarations — paste into TC's DB2Stores.h",
        "#pragma once",
        "",
    ]

    full_count = 0
    skel_count = 0
    for r in rows:
        name = r["name"]
        try:
            li = db2_stores.generate_loadinfo(session, name)
            es = db2_stores.generate_entry_struct(session, name)
            sd = db2_stores.generate_store_declaration(name)
        except Exception as e:
            msg_warn(f"  codegen failed for {name}: {e}")
            continue
        # Detect skeleton vs full
        if li.startswith("// Skeleton"):
            skel_count += 1
        else:
            full_count += 1
            try:
                db.execute(
                    "UPDATE db2_tables SET loadinfo_generated = 1 WHERE name = ?",
                    (name,),
                )
            except Exception:
                pass
        li_lines.append(li)
        es_lines.append(es)
        sd_lines.append(sd)

    db.commit()

    with open(li_path, "w", encoding="utf-8") as f:
        f.write("\n".join(li_lines))
    with open(es_path, "w", encoding="utf-8") as f:
        f.write("\n".join(es_lines))
    with open(sd_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sd_lines))

    msg_info(
        f"DB2 codegen: stage 2 — wrote {full_count} full + {skel_count} skeleton "
        f"definitions to {out_dir}"
    )
    return {
        "tables_emitted": len(rows),
        "full_loadinfo": full_count,
        "skeleton_loadinfo": skel_count,
        "loadinfo_h": li_path,
        "structure_h": es_path,
        "stores_h": sd_path,
    }


def analyze_db2_loadinfo_codegen(session):
    db = session.db
    cfg = session.cfg
    if db is None:
        msg_warn("DB2 codegen: no DB")
        return 0
    from tc_wow_analyzer.core.utils import current_build
    build = current_build() or (getattr(cfg, "build_number", 0) if cfg else 0)
    if not build:
        msg_warn("DB2 codegen: build unknown — refusing to emit build-named "
                 "headers that would carry the wrong layouts")
        return 0

    t0 = time.time()
    stage1 = _stage1_populate_fields_json(db)
    stage2 = _stage2_emit_codegen(session, build)

    elapsed = round(time.time() - t0, 2)
    result = {
        "version": 1,
        "build": build,
        "stage1": stage1,
        "stage2": stage2,
        "elapsed_sec": elapsed,
    }
    db.kv_set("db2_loadinfo_codegen", result)
    db.commit()
    msg_info(
        f"DB2 codegen: done — full_loadinfo={stage2['full_loadinfo']} "
        f"({elapsed}s)"
    )
    return stage2["full_loadinfo"]
