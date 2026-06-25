"""
IDB Enrichment Feedback Loop
Applies analysis results already stored in the knowledge DB back into IDA:
auto-renaming functions, setting types, adding comments, then re-decompiling
modified functions to discover MORE information iteratively until convergence.

The enrichment loop runs in phases:
  Phase 1 — Name Recovery:   Rename sub_XXX functions using opcode handlers,
                              JAM serializers, vtable methods, DB2 loaders,
                              and function system/subsystem labels.
  Phase 2 — Type Recovery:   Apply parameter types from object layouts, add
                              field-name comments to Read/Write calls from
                              wire formats, create IDA enums from recovered
                              enum definitions.
  Phase 3 — Comment Enrichment: Add repeatable comments from conformance
                              scores, taint analysis warnings, and behavioral
                              spec execution path summaries.
  Phase 4 — Re-decompile:    Re-decompile every function that was modified in
                              this iteration.  Check if the new pseudocode
                              reveals additional patterns (e.g., a renamed
                              callee now makes a caller's purpose obvious).

Phases 1-4 repeat for up to 5 iterations (configurable).  The loop stops
early when an iteration produces no new changes (convergence).

Results are stored under kv_store key "idb_enrichment".
"""

import json
import os
import re
import time

import ida_funcs
import ida_name
import idautils
import idaapi
import idc

try:
    import ida_hexrays
    _HAS_HEXRAYS = True
except ImportError:
    _HAS_HEXRAYS = False

try:
    import ida_typeinf
    _HAS_TYPEINF = True
except ImportError:
    _HAS_TYPEINF = False

try:
    import ida_enum
    _HAS_ENUM = True
    _ENUM_VIA_TYPEINF = False
except ImportError:
    # IDA 9.x removed ida_enum; enums are now in ida_typeinf
    _HAS_ENUM = False
    try:
        import ida_typeinf
        _ENUM_VIA_TYPEINF = True
    except ImportError:
        _ENUM_VIA_TYPEINF = False

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_ITERATIONS = 5
_RENAME_FLAGS = idc.SN_NOWARN | idc.SN_NOCHECK

# Regex: recognise IDA auto-generated names so we only overwrite those
_AUTO_NAME_RE = re.compile(r'^(?:sub_|j_sub_|nullsub_|loc_|byte_|word_|dword_|qword_)')

# Regex: extract callee name from pseudocode call expressions
_CALL_RE = re.compile(r'(\w+)\s*\(')

# Regex: Read/Write calls in pseudocode for wire-format annotation
_RW_CALL_RE = re.compile(
    r'(Read|Write)\s*(?:<\s*(\w+)\s*>)?\s*\('
    r'|'
    r'(Read(?:Bit|Bits|PackedGuid128|String|Float|Double'
    r'|UInt8|UInt16|UInt32|UInt64|Int8|Int16|Int32|Int64))\s*\(',
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def enrich_idb(session) -> int:
    """Run the full IDB enrichment feedback loop.

    Args:
        session: PluginSession with .db and .cfg.

    Returns:
        Total number of items processed (renamed + retyped + commented)
        across all iterations.
    """
    db = session.db
    if db is None:
        msg_error("No knowledge DB — cannot enrich")
        return 0

    msg_info("=== IDB Enrichment Feedback Loop starting ===")
    start_time = time.time()

    # Accumulators across all iterations
    total_renamed = 0
    total_retyped = 0
    total_commented = 0
    total_enums_created = 0
    iterations_done = 0
    convergence_reached = False

    # Track which EAs were touched so we can re-decompile them
    all_modified_eas = set()

    # Per-iteration history for the report
    iteration_history = []

    for iteration in range(1, MAX_ITERATIONS + 1):
        msg_info(f"--- Iteration {iteration}/{MAX_ITERATIONS} ---")
        iter_start = time.time()

        modified_eas = set()

        # Phase 1 — Name Recovery
        p1_count = _phase1_name_recovery(db, modified_eas)

        # Phase 2 — Type Recovery
        p2_typed, p2_enums = _phase2_type_recovery(db, modified_eas)

        # Phase 3 — Comment Enrichment
        p3_count = _phase3_comment_enrichment(db, modified_eas)

        # Phase 4 — Re-decompile and discover new patterns
        p4_new = _phase4_redecompile_and_discover(db, modified_eas)

        iter_renamed = p1_count
        iter_retyped = p2_typed
        iter_commented = p3_count
        iter_enums = p2_enums
        iter_discovered = p4_new
        iter_total = iter_renamed + iter_retyped + iter_commented + iter_discovered

        iter_elapsed = time.time() - iter_start
        msg_info(
            f"  Iteration {iteration}: "
            f"renamed={iter_renamed}, retyped={iter_retyped}, "
            f"commented={iter_commented}, enums={iter_enums}, "
            f"discovered={iter_discovered}  ({iter_elapsed:.1f}s)"
        )

        iteration_history.append({
            "iteration": iteration,
            "renamed": iter_renamed,
            "retyped": iter_retyped,
            "commented": iter_commented,
            "enums_created": iter_enums,
            "discovered": iter_discovered,
            "total": iter_total,
            "elapsed_s": round(iter_elapsed, 2),
        })

        total_renamed += iter_renamed
        total_retyped += iter_retyped
        total_commented += iter_commented
        total_enums_created += iter_enums
        iterations_done = iteration
        all_modified_eas.update(modified_eas)

        # Persist IDB at iteration boundary so a Phase 4 idat crash doesn't
        # discard the renames/types/comments from Phases 1-3.
        try:
            import idc as _idc
            _idc.save_database(_idc.get_idb_path(), 0)
            msg_info(f"  IDB saved (iteration {iteration} checkpoint)")
        except Exception as _save_exc:
            msg_warn(f"  IDB save failed at iteration {iteration}: {_save_exc}")

        if iter_total == 0:
            convergence_reached = True
            msg_info(f"  Convergence reached after {iteration} iterations.")
            break

    elapsed = time.time() - start_time

    # Store results
    report = {
        "timestamp": time.time(),
        "elapsed_s": round(elapsed, 2),
        "iterations": iterations_done,
        "convergence_reached": convergence_reached,
        "total_renamed": total_renamed,
        "total_retyped": total_retyped,
        "total_commented": total_commented,
        "total_enums_created": total_enums_created,
        "total_modified_functions": len(all_modified_eas),
        "iteration_history": iteration_history,
    }
    db.kv_set("idb_enrichment", report)
    db.commit()

    grand_total = total_renamed + total_retyped + total_commented
    msg_info(
        f"=== IDB Enrichment complete: {grand_total} changes "
        f"({total_renamed} renames, {total_retyped} retypes, "
        f"{total_commented} comments, {total_enums_created} enums) "
        f"in {iterations_done} iteration(s), {elapsed:.1f}s ==="
    )
    return grand_total


def get_enrichment_report(session):
    """Return the stored enrichment report from the last run.

    Returns:
        dict with enrichment stats, or None if never run.
    """
    if session.db is None:
        return None
    return session.db.kv_get("idb_enrichment")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1 — Name Recovery
# ═══════════════════════════════════════════════════════════════════════════

def _phase1_name_recovery(db, modified_eas):
    """Pull names from DB tables and apply them in IDA.

    Sources:
      - opcodes table:       handler_ea -> "HandleXXX" from tc_name
      - jam_types table:     serializer_ea/deserializer_ea -> "JAM_XXX_Serialize" / "Deserialize"
      - db2_tables table:    meta_ea -> "DB2_XXX_LoadMeta"
      - vtables/vtable_entries: func_ea -> "ClassName::vfuncN"
      - functions table:     system/subsystem -> repeatable prefix comment
    """
    count = 0

    count += _rename_opcode_handlers(db, modified_eas)
    count += _rename_jam_functions(db, modified_eas)
    count += _rename_db2_loaders(db, modified_eas)
    count += _rename_vtable_functions(db, modified_eas)
    count += _annotate_function_systems(db, modified_eas)

    msg_info(f"  Phase 1 (Name Recovery): {count} renames applied")
    return count


def _rename_opcode_handlers(db, modified_eas):
    """Rename opcode handler functions based on tc_name."""
    rows = db.fetchall(
        "SELECT handler_ea, tc_name, direction FROM opcodes "
        "WHERE handler_ea IS NOT NULL AND tc_name IS NOT NULL"
    )
    count = 0
    for row in rows:
        ea = row["handler_ea"]
        tc_name = row["tc_name"]
        direction = row["direction"] or "CMSG"

        if not _function_exists(ea):
            continue

        # Build a suitable IDA name
        desired_name = _build_handler_name(tc_name, direction)
        if _try_rename(ea, desired_name):
            modified_eas.add(ea)
            count += 1

    return count


def _build_handler_name(tc_name, direction):
    """Convert a TrinityCore opcode name to a handler function name.

    Examples:
        CMSG_HOUSING_PLOT_BROWSE -> HandleHousingPlotBrowse
        HousingPlotBrowse        -> HandleHousingPlotBrowse
    """
    # Strip direction prefix if present
    name = tc_name
    for prefix in ("CMSG_", "SMSG_", "MSG_"):
        if name.upper().startswith(prefix):
            name = name[len(prefix):]
            break

    # Convert UPPER_SNAKE to PascalCase
    if '_' in name:
        parts = name.split('_')
        name = ''.join(p.capitalize() for p in parts if p)
    elif name == name.upper() and len(name) > 3:
        # All caps without underscores — titlecase it
        name = name.capitalize()

    # Ensure the "Handle" prefix
    if not name.startswith("Handle"):
        name = "Handle" + name

    return name


def _rename_jam_functions(db, modified_eas):
    """Rename JAM serializer/deserializer functions."""
    rows = db.fetchall(
        "SELECT name, serializer_ea, deserializer_ea FROM jam_types "
        "WHERE name IS NOT NULL"
    )
    count = 0
    for row in rows:
        jam_name = row["name"]

        # Clean the JAM name for use in IDA (no spaces, limited chars)
        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', jam_name)

        ser_ea = row["serializer_ea"]
        if ser_ea and _function_exists(ser_ea):
            desired = f"{safe_name}_Serialize"
            if _try_rename(ser_ea, desired):
                modified_eas.add(ser_ea)
                count += 1

        deser_ea = row["deserializer_ea"]
        if deser_ea and _function_exists(deser_ea):
            desired = f"{safe_name}_Deserialize"
            if _try_rename(deser_ea, desired):
                modified_eas.add(deser_ea)
                count += 1

    return count


def _rename_db2_loaders(db, modified_eas):
    """Rename DB2 metadata / loader related functions."""
    rows = db.fetchall(
        "SELECT name, meta_ea FROM db2_tables "
        "WHERE meta_ea IS NOT NULL AND name IS NOT NULL"
    )
    count = 0
    for row in rows:
        ea = row["meta_ea"]
        table_name = row["name"]

        if not ea or not _function_exists(ea):
            continue

        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', table_name)
        desired = f"DB2_{safe_name}_LoadMeta"
        if _try_rename(ea, desired):
            modified_eas.add(ea)
            count += 1

    return count


def _rename_vtable_functions(db, modified_eas):
    """Rename vtable slot functions to ClassName::vfuncN or known names."""
    # First, get all vtables with a known class name
    vtables = db.fetchall(
        "SELECT ea, class_name FROM vtables WHERE class_name IS NOT NULL"
    )
    if not vtables:
        return 0

    count = 0
    for vt in vtables:
        vt_ea = vt["ea"]
        class_name = vt["class_name"]
        safe_class = re.sub(r'[^A-Za-z0-9_]', '_', class_name)

        # Get all entries for this vtable
        entries = db.fetchall(
            "SELECT slot_index, func_ea, func_name FROM vtable_entries "
            "WHERE vtable_ea = ? ORDER BY slot_index",
            (vt_ea,)
        )

        for entry in entries:
            func_ea = entry["func_ea"]
            slot_idx = entry["slot_index"]
            known_name = entry["func_name"]

            if not func_ea or not _function_exists(func_ea):
                continue

            # If the vtable entry already has a meaningful name from the DB,
            # prefer it (e.g. "ProcessMessage", "HandleEvent")
            if known_name and not _AUTO_NAME_RE.match(known_name):
                # Use the known name qualified by class
                if "::" not in known_name:
                    desired = f"{safe_class}::{known_name}"
                else:
                    desired = known_name
            else:
                desired = f"{safe_class}::vfunc{slot_idx}"

            # IDA doesn't allow "::" in names — use double underscore
            ida_safe_name = desired.replace("::", "__")

            if _try_rename(func_ea, ida_safe_name):
                modified_eas.add(func_ea)
                count += 1

    return count


def _annotate_function_systems(db, modified_eas):
    """Add repeatable comments with system/subsystem classification."""
    rows = db.fetchall(
        "SELECT ea, system, subsystem, confidence FROM functions "
        "WHERE system IS NOT NULL AND ea IS NOT NULL"
    )
    count = 0
    for row in rows:
        ea = row["ea"]
        system = row["system"]
        subsystem = row["subsystem"] or ""
        confidence = row["confidence"] or 0

        if not _function_exists(ea):
            continue

        # Build a classification comment
        parts = [f"[System: {system}"]
        if subsystem:
            parts.append(f"/{subsystem}")
        parts.append(f"] (conf={confidence}%)")
        comment_text = "".join(parts)

        # Check existing comment to avoid duplicates
        existing = idaapi.get_cmt(ea, True) or ""
        if "[System:" in existing:
            # Already has a system comment — skip unless confidence is higher
            continue

        if _try_set_comment(ea, comment_text, repeatable=True):
            modified_eas.add(ea)
            count += 1

    return count


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2 — Type Recovery
# ═══════════════════════════════════════════════════════════════════════════

def _phase2_type_recovery(db, modified_eas):
    """Apply type information from kv_store data.

    Sources:
      - "object_layouts":    Create struct types + set first-param types
      - "wire_formats":      Create packet structs + annotate Read/Write calls
      - "recovered_enums":   Create IDA enum types
      - DB2 metadata:        Create struct per DB2 table
      - Globals:             Apply names + types to data EAs
    """
    typed_count = 0
    enum_count = 0

    # Create struct types FIRST so subsequent first-param assignment can
    # reference them by name.
    typed_count += _create_object_layout_structs(db)
    typed_count += _apply_object_layout_types(db, modified_eas)
    typed_count += _create_db2_structs(db)
    typed_count += _create_wire_format_structs(db)
    typed_count += _create_update_field_structs(db)
    typed_count += _create_jam_type_structs(db)
    typed_count += _create_packet_structs_from_autodump_json(db)
    typed_count += _create_packet_structs_from_handlers(db)
    typed_count += _create_vtable_structs(db)
    typed_count += _annotate_wire_format_fields(db, modified_eas)
    typed_count += _apply_global_names(db, modified_eas)
    enum_count += _create_ida_enums(db)

    msg_info(f"  Phase 2 (Type Recovery): {typed_count} types applied, "
             f"{enum_count} enums created")
    return typed_count, enum_count


# ───────────────────────────────────────────────────────────────────────────
# Struct creation helpers (object_layouts, DB2 metadata, wire formats, globals)
# ───────────────────────────────────────────────────────────────────────────

# Map analyzer-emitted field type names to C declarations the IDA parser accepts.
_FIELD_TYPE_MAP = {
    "uint8":   "unsigned __int8",
    "int8":    "__int8",
    "char":    "char",
    "uint16":  "unsigned __int16",
    "int16":   "__int16",
    "uint32":  "unsigned __int32",
    "int32":   "__int32",
    "uint64":  "unsigned __int64",
    "int64":   "__int64",
    "float":   "float",
    "double":  "double",
    "ptr":     "void *",
    "pointer": "void *",
    "string":  "char *",
    "guid":    "unsigned __int64",
}


def _safe_struct_name(raw):
    """Sanitize a class/table name to a valid C identifier."""
    if not raw:
        return None
    s = re.sub(r'[^A-Za-z0-9_]', '_', raw)
    if not s:
        return None
    if s[0].isdigit():
        s = "S_" + s
    return s


def _field_type_decl(t, size):
    """Render a field-type to a C declaration. Falls back to byte arrays."""
    if isinstance(t, str):
        ct = _FIELD_TYPE_MAP.get(t.lower())
        if ct:
            return ct
    # Fallback: opaque byte array sized to the field
    if size and size >= 1:
        return f"unsigned __int8[{size}]"
    return "unsigned __int8"


def _emit_struct_decl(struct_name, fields, total_size):
    """Build a C struct declaration with explicit padding for offset gaps.

    `fields` is a list of dicts with keys: offset, name, type, size.
    Returns a multi-line C declaration string.
    """
    if not struct_name:
        return None

    # Sort by offset, dedupe overlapping (keep first)
    sorted_fields = sorted(
        (f for f in fields if isinstance(f, dict) and "offset" in f),
        key=lambda f: f["offset"],
    )
    seen_offsets = set()
    unique_fields = []
    for f in sorted_fields:
        off = f.get("offset")
        if off in seen_offsets:
            continue
        seen_offsets.add(off)
        unique_fields.append(f)

    lines = [f"struct {struct_name} {{"]
    cursor = 0
    used_names = set()
    for f in unique_fields:
        off = int(f.get("offset") or 0)
        if off > cursor:
            gap = off - cursor
            pad_name = f"_pad_{cursor:X}"
            lines.append(f"  unsigned __int8 {pad_name}[{gap}];")
            cursor = off
        elif off < cursor:
            # Overlap — skip (decompiled offsets sometimes overlap with prior)
            continue

        raw_name = f.get("name") or f"field_{off:X}"
        fname = re.sub(r'[^A-Za-z0-9_]', '_', raw_name)
        if not fname or fname[0].isdigit():
            fname = f"f_{fname}"
        # Dedupe field names within struct
        if fname in used_names:
            fname = f"{fname}_{off:X}"
            if fname in used_names:
                continue
        used_names.add(fname)

        size = int(f.get("size") or 0) or 8
        ctype = _field_type_decl(f.get("type"), size)
        lines.append(f"  {ctype} {fname};")
        cursor = off + size

    if total_size and cursor < total_size:
        gap = total_size - cursor
        lines.append(f"  unsigned __int8 _tail_pad[{gap}];")

    lines.append("};")
    return "\n".join(lines)


def _register_struct_decl(decl, struct_name, debug_first_failure=None):
    """Parse + register a struct decl into the IDB type library. Returns bool.
    Tries `idc_parse_types` first (handles multi-decl files), falls back to
    `parse_decl` + `set_named_type` for single-struct cases that the first
    parser silently rejects (some void* member combos do this in IDA 9.x).
    """
    if not decl or not _HAS_TYPEINF:
        return False
    til = ida_typeinf.get_idati()
    existing = ida_typeinf.tinfo_t()
    if existing.get_named_type(til, struct_name):
        return False  # already exists

    # Try idc_parse_types first
    try:
        added = ida_typeinf.idc_parse_types(decl, 0)
    except Exception as exc:
        added = -1
        first_exc = exc
    else:
        first_exc = None
    if isinstance(added, int) and added > 0:
        return True

    # Fallback: parse_decl directly. Needs a typedef-style decl: prepend "typedef"
    # to make it a single named type? No — parse_decl wants a TYPE expression,
    # not a struct definition. Use parse_decls (with 's') which handles multiple.
    try:
        # parse_decls returns the count of types parsed/added
        if hasattr(ida_typeinf, "parse_decls"):
            added2 = ida_typeinf.parse_decls(til, decl, None, 0)
            if isinstance(added2, int) and added2 > 0:
                # Verify it's now in the TIL
                check = ida_typeinf.tinfo_t()
                if check.get_named_type(til, struct_name):
                    return True
    except Exception as exc:
        first_exc = first_exc or exc

    # Last-ditch: build via parse_decl on the trailing declaration after
    # converting the struct definition into a typedef.
    try:
        typedef_decl = decl.rstrip().rstrip(";")
        # Wrap as `typedef struct { ... } NAME;` form
        body_start = typedef_decl.find("{")
        body_end = typedef_decl.rfind("}")
        if body_start > 0 and body_end > body_start:
            body = typedef_decl[body_start:body_end + 1]
            td = f"typedef struct {body} {struct_name};"
            tif = ida_typeinf.tinfo_t()
            if hasattr(ida_typeinf, "parse_decl"):
                rc = ida_typeinf.parse_decl(tif, til, td, 0)
                if rc is not None:
                    sn_rc = tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE)
                    if sn_rc in (0, getattr(ida_typeinf, "TERR_OK", 0)):
                        return True
    except Exception as exc:
        first_exc = first_exc or exc

    if debug_first_failure is not None and len(debug_first_failure) < 3:
        debug_first_failure.append(
            (struct_name, f"all paths failed (first exc: {first_exc!r}, idc_rc={added})", decl[:200])
        )
    return False


def _create_object_layout_structs(db):
    """Create IDA struct types for every recovered class layout."""
    if not _HAS_TYPEINF:
        return 0
    layouts = db.kv_get("object_layouts")
    if not layouts:
        return 0
    if isinstance(layouts, dict):
        layouts = list(layouts.values())
    if not isinstance(layouts, list):
        return 0

    created = 0
    for layout in layouts:
        if not isinstance(layout, dict):
            continue
        struct_name = _safe_struct_name(layout.get("class_name"))
        if not struct_name:
            continue
        fields = layout.get("fields") or []
        total = layout.get("total_size") or 0
        decl = _emit_struct_decl(struct_name, fields, total)
        if decl and _register_struct_decl(decl, struct_name):
            created += 1
    if created:
        msg_info(f"  Phase 2: created {created} struct types from object_layouts")
    return created


def _create_db2_structs(db):
    """Create IDA struct types for each DB2 table.

    Source priority:
      1. WoWDBDefs at C:/dumps/WoWDBDefs/definitions/<Name>.dbd — canonical
         per-build field schema (preferred — has real types and sizes).
      2. plugin's tc_db2_struct:<Name> kv entries (only TC class name, no fields).

    Builds tuple matched against the build_number in cfg, fallback to nearest.
    """
    if not _HAS_TYPEINF:
        return 0

    # Determine which build to look up in DBD layouts. The autodump JSON has
    # the build number; we also encode it in the cfg via the active builds row.
    try:
        from tc_wow_analyzer.analyzers._dbd_parser import (
            parse_dbd_file, find_layout_for_build, column_to_ctype
        )
    except Exception as exc:
        msg_warn(f"  Phase 2: DBD parser import failed: {exc}")
        return 0

    dbd_dir = r"C:\dumps\WoWDBDefs\definitions"
    if not os.path.isdir(dbd_dir):
        msg_warn(f"  Phase 2: DBD definitions not found at {dbd_dir}")
        return 0

    # Build target build tuple. Prefer the configured build_number; the major
    # version we'll guess from the build number range.
    build_num = 67186
    try:
        from tc_wow_analyzer.core.config import cfg as _cfg
        build_num = _cfg.build_number or build_num
    except Exception:
        pass

    # Heuristic mapping build_number -> major.minor.patch:
    #   60000+: 11.x (Dragonflight-era)
    #   65000+: 11.1.x
    #   67000+: 12.0.x (Midnight beta/release)
    if build_num >= 67000:
        build_tuple = (12, 0, 5, build_num)
    elif build_num >= 65000:
        build_tuple = (11, 1, 5, build_num)
    elif build_num >= 60000:
        build_tuple = (11, 0, 5, build_num)
    else:
        build_tuple = (10, 2, 7, build_num)

    # Pull DB2 table names from the SQL table
    try:
        table_names = [r["name"] for r in db.fetchall(
            "SELECT name FROM db2_tables WHERE name IS NOT NULL"
        )]
    except Exception:
        table_names = []

    if not table_names:
        return 0

    created = 0
    skipped_no_dbd = 0
    skipped_no_layout = 0

    for table_name in table_names:
        # WoWDBDefs filename matches table name; some tables use underscores
        dbd_path = os.path.join(dbd_dir, f"{table_name}.dbd")
        if not os.path.isfile(dbd_path):
            skipped_no_dbd += 1
            continue
        try:
            dbd = parse_dbd_file(dbd_path)
        except Exception:
            continue

        layout = find_layout_for_build(dbd, build_tuple)
        if not layout or not layout.fields:
            skipped_no_layout += 1
            continue

        # Build struct fields by walking the layout in declared order
        cursor = 0
        struct_fields = []
        for lf in layout.fields:
            col = dbd.columns.get(lf.name)
            if not col:
                continue
            ctype, sz = column_to_ctype(col, lf)
            count = lf.array_size or 1
            elem_sz = sz
            if count > 1:
                ctype = ctype + f"[{count}]"
                sz = elem_sz * count
            struct_fields.append({
                "offset": cursor,
                "name":   lf.name,
                "type":   None,           # not used; we override below
                "size":   sz,
                "_ctype": ctype,
            })
            cursor += sz

        if not struct_fields:
            continue

        struct_name = "DB2_" + _safe_struct_name(table_name)
        # Custom struct decl: we already have the C type per field.
        lines = [f"struct {struct_name} {{"]
        used_names = set()
        for f in struct_fields:
            fname = re.sub(r'[^A-Za-z0-9_]', '_', f["name"])
            if not fname or fname[0].isdigit():
                fname = f"f_{fname}"
            if fname in used_names:
                fname = f"{fname}_{f['offset']:X}"
                if fname in used_names:
                    continue
            used_names.add(fname)
            lines.append(f"  {f['_ctype']} {fname};")
        lines.append("};")
        decl = "\n".join(lines)

        if _register_struct_decl(decl, struct_name):
            created += 1

    if created:
        msg_info(
            f"  Phase 2: created {created} DB2 struct types from WoWDBDefs "
            f"(skipped {skipped_no_dbd} without .dbd, "
            f"{skipped_no_layout} without matching layout)"
        )
    return created


def _create_wire_format_structs(db):
    """Create one IDA struct per CMSG/SMSG packet from `wire_formats`."""
    if not _HAS_TYPEINF:
        return 0
    formats = db.kv_get("wire_formats")
    if not formats:
        return 0
    if isinstance(formats, dict):
        format_list = list(formats.values())
    elif isinstance(formats, list):
        format_list = formats
    else:
        return 0

    created = 0
    for fmt in format_list:
        if not isinstance(fmt, dict):
            continue
        opcode_name = fmt.get("opcode") or fmt.get("opcode_name") or fmt.get("name")
        if not opcode_name:
            continue
        struct_name = _safe_struct_name(opcode_name) + "_packet"
        fields = fmt.get("fields") or []
        # Wire format fields may have read sizes; treat them as sequential
        cursor = 0
        with_offsets = []
        for f in fields:
            if not isinstance(f, dict):
                continue
            sz = int(f.get("size") or 4)
            with_offsets.append({
                "offset": cursor,
                "name":   f.get("name") or f"field_{cursor:X}",
                "type":   f.get("type") or "uint32",
                "size":   sz,
            })
            cursor += sz
        if not with_offsets:
            continue
        decl = _emit_struct_decl(struct_name, with_offsets, cursor)
        if decl and _register_struct_decl(decl, struct_name):
            created += 1

    if created:
        msg_info(f"  Phase 2: created {created} wire-format packet structs")
    return created


def _create_update_field_structs(db):
    """Create one IDA struct per object_type from the update_fields table.

    UpdateField offsets/sizes in WoW are in DWORDs (4 bytes each). Each struct
    becomes <Class>_UpdateFields with named field_NN entries at byte offsets.
    """
    if not _HAS_TYPEINF:
        return 0

    try:
        rows = db.fetchall(
            "SELECT object_type, field_name, field_offset, field_size, "
            "field_type, array_count "
            "FROM update_fields WHERE object_type IS NOT NULL "
            "ORDER BY object_type, field_offset"
        )
    except Exception:
        return 0

    if not rows:
        return 0

    # Group by object_type
    by_obj = {}
    for r in rows:
        obj = r["object_type"]
        by_obj.setdefault(obj, []).append(dict(r))

    created = 0
    for obj_type, fields in by_obj.items():
        struct_name = "UF_" + _safe_struct_name(obj_type)
        struct_fields = []
        for f in fields:
            # field_offset is stored as hex string; convert to int (dword index)
            raw_off = f["field_offset"]
            try:
                if isinstance(raw_off, str):
                    dword_off = int(raw_off, 16) if raw_off.startswith("0x") else int(raw_off)
                else:
                    dword_off = int(raw_off)
            except (TypeError, ValueError):
                continue
            byte_off = dword_off * 4
            dword_size = max(1, int(f["field_size"] or 1))
            byte_size = dword_size * 4
            arr = max(1, int(f["array_count"] or 1))
            # In C the type is the element type and array dims attach to the
            # declarator, not to the type spec.
            ctype = "unsigned __int32"
            dims = []
            if dword_size > 1:
                dims.append(dword_size)
            if arr > 1:
                dims.append(arr)
            arr_suffix = "".join(f"[{d}]" for d in dims)
            struct_fields.append({
                "offset": byte_off,
                "name":   f["field_name"] or f"field_{byte_off:X}",
                "type":   None,
                "size":   byte_size * arr,
                "_ctype": ctype,
                "_arr":   arr_suffix,
            })

        if not struct_fields:
            continue

        # Sort + dedupe by offset (keep first)
        struct_fields.sort(key=lambda x: x["offset"])
        seen_off = set()
        unique = []
        for sf in struct_fields:
            if sf["offset"] in seen_off:
                continue
            seen_off.add(sf["offset"])
            unique.append(sf)

        # Emit decl with explicit padding for gaps
        lines = [f"struct {struct_name} {{"]
        cursor = 0
        used_names = set()
        for sf in unique:
            if sf["offset"] > cursor:
                gap = sf["offset"] - cursor
                lines.append(f"  unsigned __int8 _pad_{cursor:X}[{gap}];")
                cursor = sf["offset"]
            elif sf["offset"] < cursor:
                continue  # overlap
            fname = re.sub(r'[^A-Za-z0-9_]', '_', sf["name"])
            if not fname or fname[0].isdigit():
                fname = f"f_{fname}"
            if fname in used_names:
                fname = f"{fname}_{sf['offset']:X}"
                if fname in used_names:
                    continue
            used_names.add(fname)
            arr_suffix = sf.get("_arr", "")
            lines.append(f"  {sf['_ctype']} {fname}{arr_suffix};")
            cursor = sf["offset"] + sf["size"]
        lines.append("};")
        decl = "\n".join(lines)

        if _register_struct_decl(decl, struct_name):
            created += 1

    if created:
        msg_info(f"  Phase 2: created {created} UpdateField struct types")
    return created


def _create_vtable_structs(db):
    """Create one IDA struct per RTTI class with N function-pointer slots,
    using known method names where available.

    Sources for class -> vtable_rva mapping:
      - wow_rtti_67186.json (1107 classes, but only 6 have num_virtuals)
      - wow_ctor_dtor_67186.json (2656 ctor/dtor entries → class+vtable_rva)
      - vtable_entries SQL table (when populated)

    Slot count is derived by walking the binary at vtable_rva, reading
    consecutive 8-byte function pointers until we hit a non-function value
    (most reliable method since RTTI num_virtuals is rarely populated).

    Output: Vftbl_<ClassName> struct with named or slot_N fields.
    """
    if not _HAS_TYPEINF:
        return 0

    # Build a unified {class_name: vtable_rva_int} map from all sources.
    classes_dict = {}
    for p in (r"C:\dumps\wow_rtti_67186.json", r"C:\dumps\wow_rtti.json"):
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
                for c in d.get("classes", []) or []:
                    if not isinstance(c, dict):
                        continue
                    name = c.get("name")
                    rva_raw = c.get("vtable_rva")
                    if not name or not rva_raw:
                        continue
                    try:
                        rva = int(rva_raw, 16) if isinstance(rva_raw, str) and rva_raw.startswith("0x") else int(rva_raw)
                    except (ValueError, TypeError):
                        continue
                    if rva > 0:
                        classes_dict[name] = rva
            except Exception:
                pass
            break

    for p in (r"C:\dumps\wow_ctor_dtor_67186.json", r"C:\dumps\wow_ctor_dtor.json"):
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
                for ent in d.get("entries", []) or []:
                    if not isinstance(ent, dict):
                        continue
                    name = ent.get("class")
                    rva_raw = ent.get("vtable_rva")
                    if not name or not rva_raw:
                        continue
                    if name in classes_dict:
                        continue
                    try:
                        rva = int(rva_raw, 16) if isinstance(rva_raw, str) and rva_raw.startswith("0x") else int(rva_raw)
                    except (ValueError, TypeError):
                        continue
                    if rva > 0:
                        classes_dict[name] = rva
            except Exception:
                pass
            break

    classes = [{"name": n, "vtable_rva": rva} for n, rva in classes_dict.items()]

    # Add anonymous vtables (vtables found in binary that don't link to a class
    # name in the RTTI). They still get a struct synthesized so indirect calls
    # through them resolve to typed slot accesses.
    for p in (r"C:\dumps\wow_rtti_67186.json", r"C:\dumps\wow_rtti.json"):
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
                for av in d.get("anonymous_vtables", []) or []:
                    if not isinstance(av, dict):
                        continue
                    rva_raw = av.get("rva")
                    if not rva_raw:
                        continue
                    try:
                        rva = int(rva_raw, 16) if isinstance(rva_raw, str) and rva_raw.startswith("0x") else int(rva_raw)
                    except (ValueError, TypeError):
                        continue
                    if rva > 0:
                        classes.append({
                            "name": f"Anon_{rva:X}",
                            "vtable_rva": rva,
                            "_anonymous": True,
                            "_num_methods_hint": av.get("num_methods"),
                        })
            except Exception:
                pass
            break

    if not classes:
        return 0

    # Optional named method lookup
    method_names_by_class = {}
    methods_paths = [
        r"C:\dumps\wow_vtable_methods_67186.json",
        r"C:\dumps\wow_vtable_methods.json",
    ]
    for p in methods_paths:
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as fh:
                d = json.load(fh)
            for m in d.get("methods", []) or []:
                if not isinstance(m, dict):
                    continue
                cls = m.get("class")
                idx = m.get("vtable_index")
                name = m.get("name")
                if cls and idx is not None and name:
                    method_names_by_class.setdefault(cls, {})[idx] = name
            break
        except Exception:
            continue

    # Also try DB-side vtable_entries
    try:
        for r in db.fetchall(
            "SELECT v.class_name, e.slot_index, e.func_name FROM vtable_entries e "
            "JOIN vtables v ON v.ea = e.vtable_ea "
            "WHERE e.func_name IS NOT NULL"
        ):
            method_names_by_class.setdefault(r["class_name"], {})[r["slot_index"]] = r["func_name"]
    except Exception:
        pass

    # Build a reusable uint64 tinfo for the slot type (same 8 bytes as void* on x64).
    til = ida_typeinf.get_idati()
    uint64_tif = ida_typeinf.tinfo_t()
    if hasattr(uint64_tif, "create_simple_type"):
        # IDA 9.x exposes BT_INT64 etc.
        try:
            uint64_tif.create_simple_type(ida_typeinf.BTF_UINT64)
        except Exception:
            uint64_tif = None
    if uint64_tif is None or uint64_tif.empty():
        # Fallback: parse the type spec
        uint64_tif = ida_typeinf.tinfo_t()
        try:
            ida_typeinf.parse_decl(uint64_tif, til, "unsigned __int64;", 0)
        except Exception:
            pass

    created = 0
    fail_create = 0
    fail_set_named = 0
    fail_no_uint64 = 0
    skipped_existing = 0

    if uint64_tif is None or uint64_tif.empty():
        msg_warn("  Phase 2: cannot build uint64 tinfo — vtable struct creation skipped")
        return 0

    # Helpers to walk binary memory for vtable size discovery
    try:
        import ida_bytes
        import ida_funcs as _ida_funcs
        import idaapi as _idaapi
        image_base = _idaapi.get_imagebase()
    except Exception:
        msg_warn("  Phase 2: ida_bytes unavailable — vtable struct creation skipped")
        return 0

    def _count_vtable_slots(vtable_ea, max_slots=512):
        """Walk consecutive 8-byte qwords; return how many point to functions."""
        count = 0
        ea = vtable_ea
        for _ in range(max_slots):
            try:
                ptr = ida_bytes.get_qword(ea)
            except Exception:
                break
            if not ptr:
                break
            # Must be a known function
            if not _ida_funcs.get_func(ptr):
                break
            count += 1
            ea += 8
        return count

    for cls in classes:
        if not isinstance(cls, dict):
            continue
        name = cls.get("name")
        rva = cls.get("vtable_rva")
        if not name or not rva:
            continue
        vtable_ea = image_base + int(rva)
        n_virt = _count_vtable_slots(vtable_ea)
        if n_virt == 0:
            continue
        base = _safe_struct_name(name)
        if not base:
            continue
        struct_name = "Vftbl_" + base

        # Skip if already exists in TIL
        existing = ida_typeinf.tinfo_t()
        if existing.get_named_type(til, struct_name):
            skipped_existing += 1
            continue

        named = method_names_by_class.get(name, {})
        utd = ida_typeinf.udt_type_data_t()
        used_field_names = set()
        n_virt_int = int(n_virt)
        # Cap at 256 slots to avoid pathological vtables
        if n_virt_int > 256:
            n_virt_int = 256

        for slot in range(n_virt_int):
            mname = named.get(slot)
            if mname:
                fname = re.sub(r'[^A-Za-z0-9_]', '_', mname)
                if not fname or fname[0].isdigit():
                    fname = f"m_{fname}"
                if fname in used_field_names:
                    fname = f"{fname}_s{slot}"
            else:
                fname = f"slot_{slot}"
            used_field_names.add(fname)

            udm = ida_typeinf.udt_member_t()
            udm.name = fname
            udm.offset = slot * 64       # bit offset
            udm.size = 64                # bit size
            udm.type = uint64_tif
            utd.push_back(udm)

        # Set total size of the udt: n * 64 bits
        try:
            utd.total_size = n_virt_int * 8   # bytes (some IDA versions use this)
        except Exception:
            pass
        try:
            utd.unpadded_size = n_virt_int * 8
        except Exception:
            pass

        tif = ida_typeinf.tinfo_t()
        try:
            ok = tif.create_udt(utd, ida_typeinf.BTF_STRUCT)
        except Exception:
            ok = False
        if not ok:
            fail_create += 1
            continue

        try:
            rc = tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE)
        except Exception:
            rc = -1
        if rc in (0, getattr(ida_typeinf, "TERR_OK", 0)):
            created += 1
        else:
            fail_set_named += 1

    msg_info(
        f"  Phase 2: vtable structs (Vftbl_<Class>) — "
        f"created={created}, skipped_existing={skipped_existing}, "
        f"fail_create={fail_create}, fail_set_named={fail_set_named} "
        f"(of {len(classes)} candidates)"
    )
    return created


def _create_packet_structs_from_autodump_json(db):
    """Synthesize packet structs from autodump's wow_packet_structures_*.json.

    The 67186 autodump produced an empty packet list (regression vs older
    builds). Fall back to the 66838 archive at `c:\\dumps_66838\\` where 294
    valid packet definitions exist with field types — JAM type names mostly
    didn't change build-to-build, so the schemas stay useful.
    """
    if not _HAS_TYPEINF:
        return 0

    candidate_paths = [
        r"C:\dumps\wow_packet_structures_67186.json",
        r"C:\dumps_66838\wow_packet_structures_66838.json",
        r"C:\dumps_66198\wow_packet_structures_66198.json",
    ]
    packets = None
    src_path = None
    for p in candidate_paths:
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception:
            continue
        cand = d.get("packets") or []
        if cand:
            packets = cand
            src_path = p
            break

    if not packets:
        return 0

    # Map autodump primitive type names to IDA C types
    type_map = {
        "uint8":   ("unsigned __int8", 1),
        "uint16":  ("unsigned __int16", 2),
        "uint32":  ("unsigned __int32", 4),
        "uint64":  ("unsigned __int64", 8),
        "int8":    ("__int8", 1),
        "int16":   ("__int16", 2),
        "int32":   ("__int32", 4),
        "int64":   ("__int64", 8),
        "float":   ("float", 4),
        "double":  ("double", 8),
        "bool":    ("unsigned __int8", 1),
        "string":  ("char *", 8),
        "guid":    ("unsigned __int64[2]", 16),
        "objectguid": ("unsigned __int64[2]", 16),
        "packed_guid": ("unsigned __int64[2]", 16),
    }

    created = 0
    skipped_empty = 0
    debug_failures = []
    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        name = pkt.get("name")
        fields = pkt.get("fields") or []
        if not name or not fields:
            skipped_empty += 1
            continue

        # Prefix to avoid collision with existing object_layouts class types.
        # The autodump's packet name is the JAM/class name; we want a distinct
        # struct that captures the *wire layout*, not the in-memory class.
        struct_name = "Wire_" + _safe_struct_name(name)
        if not struct_name:
            continue

        cursor = 0
        out_fields = []
        for fld in fields:
            if not isinstance(fld, dict):
                continue
            t = (fld.get("type") or "").lower()
            ctype, sz = type_map.get(t, ("unsigned __int32", 4))
            out_fields.append({
                "offset": cursor,
                "name":   fld.get("name") or f"field_{fld.get('index', cursor)}",
                "_ctype": ctype,
                "size":   sz,
            })
            cursor += sz

        if not out_fields:
            continue

        lines = [f"struct {struct_name} {{"]
        used_names = set()
        for f in out_fields:
            fname = re.sub(r'[^A-Za-z0-9_]', '_', f["name"])
            if not fname or fname[0].isdigit():
                fname = f"f_{fname}"
            if fname in used_names:
                fname = f"{fname}_{f['offset']:X}"
                if fname in used_names:
                    continue
            used_names.add(fname)
            lines.append(f"  {f['_ctype']} {fname};")
        lines.append("};")
        decl = "\n".join(lines)

        if _register_struct_decl(decl, struct_name, debug_first_failure=debug_failures):
            created += 1

    msg_info(f"  Phase 2: autodump-json packets — found {len(packets)} in "
             f"{os.path.basename(src_path) if src_path else '?'}, "
             f"skipped_empty={skipped_empty}, created={created}")
    for sn, why, dpreview in debug_failures:
        msg_info(f"    debug: {sn} -> {why}; decl: {dpreview[:120]!r}")
    return created


def _create_packet_structs_from_handlers(db):
    """Synthesize <OPCODE>_packet structs by mining each opcode handler's
    pseudocode for typed memory-offset reads.

    Wire Format Recovery's pattern matcher (ReadUint32 etc.) doesn't fire on
    WoW's actual decompiled output, which uses raw `*(_DWORD *)(buf + 0x10)`
    style. This pass extracts those offsets and types directly.

    Checkpointed via kv_store["packet_structs_checkpoint"] so a Phase 2 idat
    crash doesn't lose progress across the ~3000 handlers.
    """
    if not _HAS_TYPEINF:
        return 0

    try:
        rows = db.fetchall(
            "SELECT tc_name, handler_ea, direction FROM opcodes "
            "WHERE handler_ea IS NOT NULL AND tc_name IS NOT NULL"
        )
    except Exception:
        return 0
    if not rows:
        return 0

    checkpoint = db.kv_get("packet_structs_checkpoint") or {}
    processed = set(checkpoint.get("processed_handlers", []))
    created = checkpoint.get("created", 0)

    typed_re = re.compile(
        r'\*\s*\(\s*(_?[A-Za-z]+)\s*\*\s*\)\s*\(\s*'
        r'\b(?:[avtl][0-9]+|this|a1|a2|packet|p_packet|buf|buffer|data)'
        r'\s*\+\s*(0x[0-9A-Fa-f]+|\d+)'
    )
    ctype_map = {
        "byte":   ("unsigned __int8", 1),
        "word":   ("unsigned __int16", 2),
        "dword":  ("unsigned __int32", 4),
        "qword":  ("unsigned __int64", 8),
        "float":  ("float", 4),
        "double": ("double", 8),
        "char":   ("char", 1),
    }

    new_in_this_run = 0
    for r in rows:
        opc_name = r["tc_name"]
        ea = r["handler_ea"]
        if opc_name in processed:
            continue
        try:
            ps = get_decompiled_text(ea)
        except Exception:
            ps = None
        if not ps:
            processed.add(opc_name)
            continue

        offsets = {}
        for m in typed_re.finditer(ps):
            ctype_raw = m.group(1).strip().lower().lstrip("_")
            off_str = m.group(2)
            try:
                off = int(off_str, 16) if off_str.startswith("0x") else int(off_str)
            except ValueError:
                continue
            if off > 0xFFFF:
                continue
            ct = ctype_map.get(ctype_raw)
            if not ct:
                continue
            existing = offsets.get(off)
            if existing is None or ct[1] > existing[1]:
                offsets[off] = ct

        if not offsets:
            processed.add(opc_name)
            continue

        struct_name = _safe_struct_name(opc_name) + "_packet"
        sorted_offs = sorted(offsets.items())
        lines = [f"struct {struct_name} {{"]
        cursor = 0
        used_names = set()
        for off, (ctype, sz) in sorted_offs:
            if off > cursor:
                gap = off - cursor
                lines.append(f"  unsigned __int8 _pad_{cursor:X}[{gap}];")
                cursor = off
            elif off < cursor:
                continue
            fname = f"field_{off:X}"
            if fname in used_names:
                continue
            used_names.add(fname)
            lines.append(f"  {ctype} {fname};")
            cursor = off + sz
        lines.append("};")
        decl = "\n".join(lines)

        if _register_struct_decl(decl, struct_name):
            created += 1
            new_in_this_run += 1
        processed.add(opc_name)

        # Checkpoint every 200 handlers
        if len(processed) % 200 == 0:
            db.kv_set("packet_structs_checkpoint", {
                "processed_handlers": list(processed),
                "created": created,
            })
            db.commit()

    db.kv_set("packet_structs_checkpoint", {
        "processed_handlers": list(processed),
        "created": created,
    })
    db.commit()

    if new_in_this_run:
        msg_info(f"  Phase 2: synthesized {new_in_this_run} packet structs "
                 f"from handler pseudocode (cumulative: {created})")
    return new_in_this_run


def _create_jam_type_structs(db):
    """Create JAM message structs by decompiling each JAM serializer/deserializer
    function and extracting the byte-offset reads/writes inside.

    For each `jam_types` row with a serializer_ea or deserializer_ea, we:
      1. Decompile the serializer
      2. Find the maximum byte offset accessed (struct size estimate)
      3. Synthesize a Jam<Name> struct by inferring fields at distinct offsets

    This is a best-effort heuristic — fields default to uint32, exact types
    require deeper analysis. But even un-typed fields at right offsets give
    the decompiler symbolic names to use.
    """
    if not _HAS_TYPEINF:
        return 0

    try:
        rows = db.fetchall(
            "SELECT name, serializer_ea, deserializer_ea, fields_json "
            "FROM jam_types WHERE name IS NOT NULL"
        )
    except Exception:
        return 0
    if not rows:
        return 0

    # Decompile each serializer once and extract byte-offset reads.
    created = 0
    pat_offset = re.compile(r'\b([avt][0-9]+|this|a1)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\b')
    pat_typed_deref = re.compile(
        r'\*\s*\(\s*'
        r'(?:_?(?:BYTE|WORD|DWORD|QWORD|byte|word|dword|qword|float|double))'
        r'\s*\*\s*\)\s*\(\s*'
        r'\b(?:[avt][0-9]+|this|a1)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)'
    )

    for r in rows:
        jam_name = r["name"]
        ea = r["serializer_ea"] or r["deserializer_ea"]
        if not ea:
            continue
        try:
            ps = get_decompiled_text(ea)
        except Exception:
            continue
        if not ps:
            continue

        # Collect (offset, c_type) hints
        offsets = {}
        typed_re = re.compile(
            r'\*\s*\(\s*(_?[A-Za-z]+)\s*\*\s*\)\s*\(\s*'
            r'\b(?:[avt][0-9]+|this|a1)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)'
        )
        for m in typed_re.finditer(ps):
            ctype_raw = m.group(1).strip().lower().lstrip("_")
            off_str = m.group(2)
            try:
                off = int(off_str, 16) if off_str.startswith("0x") else int(off_str)
            except ValueError:
                continue
            if off > 0xFFFF:  # absurd, skip
                continue
            ctype_map = {
                "byte":   "unsigned __int8",
                "word":   "unsigned __int16",
                "dword":  "unsigned __int32",
                "qword":  "unsigned __int64",
                "float":  "float",
                "double": "double",
                "char":   "char",
            }
            ctype = ctype_map.get(ctype_raw, "unsigned __int32")
            sz = {"unsigned __int8": 1, "unsigned __int16": 2,
                  "unsigned __int32": 4, "unsigned __int64": 8,
                  "float": 4, "double": 8, "char": 1}[ctype]
            existing = offsets.get(off)
            if existing is None or sz > existing[1]:  # prefer larger size
                offsets[off] = (ctype, sz)

        if not offsets:
            continue

        struct_name = "Jam_" + _safe_struct_name(jam_name)
        if not struct_name:
            continue

        sorted_offs = sorted(offsets.items())
        lines = [f"struct {struct_name} {{"]
        cursor = 0
        used_names = set()
        for off, (ctype, sz) in sorted_offs:
            if off > cursor:
                gap = off - cursor
                lines.append(f"  unsigned __int8 _pad_{cursor:X}[{gap}];")
                cursor = off
            elif off < cursor:
                continue
            fname = f"field_{off:X}"
            if fname in used_names:
                continue
            used_names.add(fname)
            lines.append(f"  {ctype} {fname};")
            cursor = off + sz
        lines.append("};")
        decl = "\n".join(lines)

        if _register_struct_decl(decl, struct_name):
            created += 1

    if created:
        msg_info(f"  Phase 2: created {created} JAM type structs")
    return created


def _apply_global_names(db, modified_eas):
    """Apply names to globals from autodump JSON exports.

    The autodump emits `named_globals: [{rva, name, type, value}, ...]` where
    RVAs are hex strings relative to image base.
    """
    globals_data = None
    # Autodump JSON path is per-build; try the standard locations.
    try:
        import json as _json
        for p in (
            r"C:\dumps\wow_globals_67186.json",
            r"C:\dumps\wow_globals.json",
        ):
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8") as fh:
                    globals_data = _json.load(fh)
                break
    except Exception:
        return 0
    if not globals_data:
        return 0

    image_base = idaapi.get_imagebase() if hasattr(idaapi, "get_imagebase") else 0

    items = []
    if isinstance(globals_data, dict):
        # autodump shape: top-level meta + named_globals list
        items = globals_data.get("named_globals", []) or []
    elif isinstance(globals_data, list):
        items = globals_data

    count = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not name:
            continue

        # RVA -> EA conversion
        rva = item.get("rva") or item.get("offset")
        ea = item.get("ea") or item.get("address")
        if rva and not ea:
            if isinstance(rva, str):
                try:
                    rva_int = int(rva, 16) if rva.startswith("0x") else int(rva)
                except ValueError:
                    continue
            else:
                rva_int = rva
            ea = image_base + rva_int
        if not ea:
            continue
        if isinstance(ea, str):
            try:
                ea = int(ea, 16) if ea.startswith("0x") else int(ea)
            except ValueError:
                continue

        try:
            existing = idaapi.get_name(ea) if hasattr(idaapi, "get_name") else None
        except Exception:
            existing = None
        if existing == name:
            continue
        try:
            if hasattr(idaapi, "set_name"):
                if idaapi.set_name(ea, name, idaapi.SN_FORCE | idaapi.SN_NOWARN):
                    count += 1
                    modified_eas.add(ea)
        except Exception:
            continue

    if count:
        msg_info(f"  Phase 2: applied {count} global variable names")
    return count


def _apply_object_layout_types(db, modified_eas):
    """Set first-parameter types on functions associated with known classes.

    Object Layout's data shape is a list of {class_name, vtable_ea, fields[]}.
    Each field has an `accessors` list of function NAMES that access it. We
    map accessors -> EAs via the `functions` table and set first-param type
    to ClassName* on each.
    """
    layouts = db.kv_get("object_layouts")
    if not layouts:
        return 0
    if not _HAS_TYPEINF:
        msg_warn("ida_typeinf not available — skipping object layout type application")
        return 0

    if isinstance(layouts, dict):
        layouts = list(layouts.values())
    if not isinstance(layouts, list):
        return 0

    # Build a one-time name->ea map from the functions table to avoid 1 query
    # per accessor. functions table has 130K+ rows so this is much cheaper than
    # repeated SELECTs.
    name_to_ea = {}
    try:
        for row in db.fetchall("SELECT name, ea FROM functions WHERE name IS NOT NULL"):
            name_to_ea[row["name"]] = row["ea"]
    except Exception:
        pass

    count = 0
    for layout in layouts:
        if not isinstance(layout, dict):
            continue
        class_name = layout.get("class_name") or layout.get("name")
        if not class_name:
            continue

        # Collect every accessor name across all fields, dedupe.
        accessor_names = set()
        for field in (layout.get("fields") or []):
            if isinstance(field, dict):
                for acc in (field.get("accessors") or []):
                    if isinstance(acc, str) and acc:
                        accessor_names.add(acc)

        for acc_name in accessor_names:
            method_ea = name_to_ea.get(acc_name)
            if not method_ea or not _function_exists(method_ea):
                continue
            if _try_set_first_param_type(method_ea, class_name):
                modified_eas.add(method_ea)
                count += 1

    return count


def _try_set_first_param_type(ea, class_name):
    """Attempt to set the first parameter of a function to ClassName*.

    Uses ida_typeinf to parse and apply the type string.
    Returns True on success, False otherwise.
    """
    if not _HAS_TYPEINF:
        return False

    func = ida_funcs.get_func(ea)
    if not func:
        return False

    # Get current type info. The API moved between IDA versions:
    #   8.x:  ida_typeinf.get_tinfo
    #   9.x:  idaapi.get_tinfo  (and ida_nalt.get_tinfo)
    tinfo = ida_typeinf.tinfo_t()
    _get_tinfo = (
        getattr(ida_typeinf, "get_tinfo", None)
        or getattr(idaapi, "get_tinfo", None)
    )
    has_existing = bool(_get_tinfo) and bool(_get_tinfo(tinfo, ea))
    if not has_existing:
        # No existing type info — we can't reliably modify what isn't there.
        # Instead, add a comment noting the expected type.
        comment_text = f"this: {class_name}*"
        existing = idaapi.get_cmt(ea, True) or ""
        if comment_text in existing:
            return False
        if existing:
            comment_text = existing + " | " + comment_text
        return _try_set_comment(ea, comment_text, repeatable=True)

    # Try to parse the type declaration for the class pointer
    type_str = f"{class_name} *"
    param_tinfo = ida_typeinf.tinfo_t()

    # Attempt parsing — this may fail if the type isn't known to IDA
    til = ida_typeinf.get_idati()
    parsed = param_tinfo.get_named_type(til, class_name)
    if not parsed:
        # Type not known in IDA's type library — fall back to comment
        comment_text = f"this: {class_name}*"
        existing = idaapi.get_cmt(ea, True) or ""
        if comment_text in existing:
            return False
        if existing:
            comment_text = existing + " | " + comment_text
        return _try_set_comment(ea, comment_text, repeatable=True)

    # If we have a proper function type with parameters, try to set param 0
    if tinfo.is_func():
        funcdata = ida_typeinf.func_type_data_t()
        if tinfo.get_func_details(funcdata):
            if funcdata.size() > 0:
                ptr_tinfo = ida_typeinf.tinfo_t()
                ptr_tinfo.create_ptr(param_tinfo)
                funcdata[0].type = ptr_tinfo
                funcdata[0].name = "this"

                new_tinfo = ida_typeinf.tinfo_t()
                new_tinfo.create_func(funcdata)
                if ida_typeinf.apply_tinfo(ea, new_tinfo, ida_typeinf.TINFO_DEFINITE):
                    return True

    return False


def _annotate_wire_format_fields(db, modified_eas):
    """Add field-name comments to Read/Write calls using wire_formats data."""
    wire_formats = db.kv_get("wire_formats")
    if not wire_formats:
        return 0

    # wire_formats is expected to be a list of packet format definitions,
    # each with "handler_ea" and "fields" (ordered list of field ops)
    if isinstance(wire_formats, dict):
        # Might be keyed by opcode name or handler EA
        format_list = list(wire_formats.values())
    elif isinstance(wire_formats, list):
        format_list = wire_formats
    else:
        return 0

    count = 0

    for fmt in format_list:
        if not isinstance(fmt, dict):
            continue

        handler_ea = fmt.get("handler_ea") or fmt.get("ea")
        if not handler_ea:
            continue
        if isinstance(handler_ea, str):
            try:
                handler_ea = int(handler_ea, 16)
            except ValueError:
                continue

        fields = fmt.get("fields") or fmt.get("operations") or []
        if not fields:
            continue

        if not _function_exists(handler_ea):
            continue

        # Build a summary comment for the handler showing the wire layout
        field_lines = []
        for i, field in enumerate(fields):
            if not isinstance(field, dict):
                continue
            fname = field.get("name") or field.get("field_name") or f"field_{i}"
            ftype = field.get("type") or field.get("wire_type") or "?"
            fbits = field.get("bits") or field.get("size") or ""
            cond = field.get("condition") or ""
            line = f"  [{i}] {ftype}"
            if fbits:
                line += f"({fbits})"
            line += f" {fname}"
            if cond:
                line += f"  (if {cond})"
            field_lines.append(line)

        if not field_lines:
            continue

        comment = "Wire format:\n" + "\n".join(field_lines)

        # Set as repeatable function comment (at function start)
        func = ida_funcs.get_func(handler_ea)
        if not func:
            continue

        existing = idaapi.get_cmt(func.start_ea, True) or ""
        if "Wire format:" in existing:
            continue  # Already annotated

        if existing:
            comment = existing + "\n\n" + comment

        if _try_set_comment(func.start_ea, comment, repeatable=True):
            modified_eas.add(func.start_ea)
            count += 1

    return count


def _create_ida_enums(db):
    """Create IDA enum types from recovered enum definitions.

    Supports both IDA 8.x (ida_enum module) and IDA 9.x (ida_typeinf).
    """
    if _HAS_ENUM:
        return _create_ida_enums_legacy(db)
    elif _ENUM_VIA_TYPEINF:
        return _create_ida_enums_typeinf(db)
    else:
        msg_warn("Neither ida_enum nor ida_typeinf available — skipping enum creation")
        return 0


def _get_enum_defs(db):
    """Load recovered enum definitions from the knowledge DB."""
    recovered = db.kv_get("recovered_enums")
    if not recovered or not isinstance(recovered, list):
        return []
    return recovered


def _create_ida_enums_legacy(db):
    """Create enums using the IDA 8.x ida_enum API."""
    recovered = _get_enum_defs(db)
    if not recovered:
        return 0

    count = 0
    for enum_def in recovered:
        if not isinstance(enum_def, dict):
            continue

        enum_name = enum_def.get("suggested_name")
        if not enum_name:
            continue

        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', enum_name)
        if not safe_name or safe_name[0].isdigit():
            safe_name = "E_" + safe_name

        values = enum_def.get("values")
        if not values or not isinstance(values, list):
            continue

        is_flags = enum_def.get("is_flags", False)

        existing_id = ida_enum.get_enum(safe_name)
        if existing_id != idaapi.BADADDR:
            existing_count = ida_enum.get_enum_size(existing_id)
            if existing_count >= len(values):
                continue
            enum_id = existing_id
        else:
            enum_id = ida_enum.add_enum(idaapi.BADADDR, safe_name, 0)
            if enum_id == idaapi.BADADDR:
                msg_warn(f"Failed to create enum: {safe_name}")
                continue

        if is_flags:
            ida_enum.set_enum_bf(enum_id, True)

        members_added = 0
        for val_entry in values:
            if not isinstance(val_entry, dict):
                continue
            val = val_entry.get("value")
            if val is None:
                continue
            vname = val_entry.get("name")
            if not vname:
                vname = f"VALUE_{val}" if val < 256 else f"VALUE_0x{val:X}"
            member_name = f"{safe_name}_{vname}"
            member_name = re.sub(r'[^A-Za-z0-9_]', '_', member_name)
            if ida_enum.get_enum_member_by_name(member_name) != idaapi.BADADDR:
                continue
            bmask = idaapi.BADADDR if is_flags else 0
            err = ida_enum.add_enum_member(enum_id, member_name, val, bmask)
            if err == 0:
                members_added += 1

        if members_added > 0:
            count += 1

    return count


def _create_ida_enums_typeinf(db):
    """Create enums using the IDA 9.x ida_typeinf API.

    IDA 9.x's text parser doesn't accept either `enum X : underlying { ... }`
    (C++11 strongly-typed) OR plain `enum X { ... }` reliably for our inputs
    — both report 'Syntax error near: enum'. We instead build the type via
    `enum_type_data_t` directly and apply it via `tinfo_t.create_enum`, with
    `bte` set to encode the underlying integer size that IDA expects.
    """
    recovered = _get_enum_defs(db)
    if not recovered:
        return 0

    til = ida_typeinf.get_idati()
    count = 0
    failed = 0
    # Instrumentation: where do the 391 enums actually go?
    skip_no_name = 0
    skip_no_values = 0
    skip_existing = 0
    skip_no_members = 0
    fail_create = 0
    fail_set_named = 0
    fail_exception = 0

    # bte byte encoding (from typeinf.hpp):
    #   low 3 bits: BTE_SIZE_MASK — size code (0=undef, 1=byte, 2=word, 3=dword, 4=qword)
    #   0x10:       BTE_ALWAYS    — must be set
    #   0x20:       BTE_HEX       — display members as hex
    BTE_ALWAYS = 0x10
    BTE_HEX = 0x20

    SIZE_TO_BTE = {
        "uint8":  1, "int8":  1,
        "uint16": 2, "int16": 2,
        "uint32": 3, "int32": 3,
        "uint64": 4, "int64": 4,
    }

    for enum_def in recovered:
        if not isinstance(enum_def, dict):
            skip_no_name += 1
            continue

        enum_name = enum_def.get("suggested_name")
        if not enum_name:
            skip_no_name += 1
            continue

        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', enum_name)
        if not safe_name or safe_name[0].isdigit():
            safe_name = "E_" + safe_name

        values = enum_def.get("values")
        if not values or not isinstance(values, list):
            skip_no_values += 1
            continue

        # Skip if the enum already exists in this IDB
        existing = ida_typeinf.tinfo_t()
        if existing.get_named_type(til, safe_name):
            skip_existing += 1
            continue

        size_code = SIZE_TO_BTE.get(
            (enum_def.get("underlying_type") or "uint32").lower(), 3
        )

        # Build enum_type_data_t directly
        etd = ida_typeinf.enum_type_data_t()
        etd.bte = BTE_ALWAYS | size_code
        if enum_def.get("is_flags"):
            etd.bte |= BTE_HEX

        seen_member_names = set()
        members_added = 0
        for val_entry in values:
            if not isinstance(val_entry, dict):
                continue
            val = val_entry.get("value")
            if val is None:
                continue
            vname = val_entry.get("name") or (
                f"VALUE_{val}" if abs(val) < 256 else f"VALUE_0x{val:X}"
            )
            member_name = re.sub(r'[^A-Za-z0-9_]', '_', f"{safe_name}_{vname}")
            if not member_name or member_name[0].isdigit():
                member_name = "M_" + member_name
            if member_name in seen_member_names:
                member_name = f"{member_name}_{val:X}"
                if member_name in seen_member_names:
                    continue
            seen_member_names.add(member_name)

            em = ida_typeinf.enum_member_t()
            em.name = member_name
            em.value = val & 0xFFFFFFFFFFFFFFFF  # mask to 64-bit unsigned
            etd.push_back(em)
            members_added += 1

        if members_added == 0:
            skip_no_members += 1
            continue

        tif = ida_typeinf.tinfo_t()
        try:
            ok = tif.create_enum(etd)
        except Exception as exc:
            ok = False
            fail_exception += 1
            if fail_exception <= 3:
                msg_warn(f"Enum create exception for {safe_name}: {exc}")

        if not ok:
            fail_create += 1
            failed += 1
            if fail_create <= 3:
                msg_warn(f"create_enum returned False for {safe_name} "
                         f"(bte=0x{etd.bte:02x}, members={members_added})")
            continue

        try:
            rc = tif.set_named_type(til, safe_name, ida_typeinf.NTF_REPLACE)
        except Exception as exc:
            rc = -1
            fail_exception += 1
            if fail_exception <= 3:
                msg_warn(f"set_named_type exception for {safe_name}: {exc}")
        # set_named_type returns 0 / TERR_OK on success in IDA 9.x
        ok_codes = (0, getattr(ida_typeinf, "TERR_OK", 0))
        if rc in ok_codes:
            count += 1
        else:
            fail_set_named += 1
            failed += 1
            if fail_set_named <= 3:
                msg_warn(f"set_named_type failed for {safe_name} (rc={rc})")

    msg_info(
        f"  Enum creation breakdown: "
        f"created={count}, skip_no_name={skip_no_name}, "
        f"skip_no_values={skip_no_values}, skip_existing={skip_existing}, "
        f"skip_no_members={skip_no_members}, "
        f"fail_create={fail_create}, fail_set_named={fail_set_named}, "
        f"fail_exception={fail_exception}"
    )
    return count


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3 — Comment Enrichment
# ═══════════════════════════════════════════════════════════════════════════

def _phase3_comment_enrichment(db, modified_eas):
    """Add repeatable comments from various analysis results.

    Sources:
      - subsystem catalog:    "Subsystem: housing (conf 85%)"
      - auth lifecycle:       "Phase: handshake / world / etc."
      - conformance scores:   Quality/fidelity rating per handler
      - taint_analysis:       Security warnings for unsafe flows
      - behavioral_specs:     Execution path summaries
      - opcode handler xrefs: "Handler for CMSG_AUTH_SESSION (idx=0x123)"
    """
    count = 0

    count += _comment_subsystem_tags(db, modified_eas)
    count += _comment_auth_phases(db, modified_eas)
    count += _comment_opcode_handler(db, modified_eas)
    count += _comment_conformance_scores(db, modified_eas)
    count += _comment_taint_warnings(db, modified_eas)
    count += _comment_behavioral_specs(db, modified_eas)

    msg_info(f"  Phase 3 (Comment Enrichment): {count} comments added")
    return count


def _comment_subsystem_tags(db, modified_eas):
    """Add 'Subsystem: X (conf Y%)' comments using the Subsystem Catalog."""
    cat = db.kv_get("subsystem_catalog")
    if not cat or not isinstance(cat, dict):
        return 0
    by_function = cat.get("by_function") or {}
    if not by_function:
        return 0
    count = 0
    for ea_str_key, info in by_function.items():
        try:
            ea = int(ea_str_key) if isinstance(ea_str_key, (str, int)) else None
        except (ValueError, TypeError):
            continue
        if ea is None or not _function_exists(ea):
            continue
        sub = info.get("subsystem") if isinstance(info, dict) else None
        conf = info.get("confidence") if isinstance(info, dict) else None
        if not sub:
            continue
        comment = f"[Subsystem: {sub}"
        if conf:
            try:
                comment += f" ({int(float(conf) * 100)}%)"
            except Exception:
                pass
        comment += "]"
        existing = idaapi.get_cmt(ea, True) or ""
        if "[Subsystem:" in existing:
            continue
        if existing:
            comment = existing + "\n" + comment
        if _try_set_comment(ea, comment, repeatable=True):
            modified_eas.add(ea)
            count += 1
    if count:
        msg_info(f"    +{count} subsystem tags")
    return count


def _comment_auth_phases(db, modified_eas):
    """Add '[Phase: handshake]' style comments to opcode handlers."""
    al = db.kv_get("auth_lifecycle")
    if not al or not isinstance(al, dict):
        return 0
    phase_of_opcode = al.get("phase_of_opcode") or {}
    if not phase_of_opcode:
        return 0

    # Need opcode->handler_ea mapping. Opcodes table stores tc_name + handler_ea
    # but they are usually in disjoint rows. Build name->ea by iterating all
    # named opcodes; for those with handler_ea we tag the EA, for those without
    # we skip silently.
    try:
        opc_rows = db.fetchall(
            "SELECT tc_name, handler_ea FROM opcodes "
            "WHERE tc_name IS NOT NULL AND handler_ea IS NOT NULL"
        )
    except Exception:
        opc_rows = []

    count = 0
    for r in opc_rows:
        ea = r["handler_ea"]
        opc = r["tc_name"]
        phase = phase_of_opcode.get(opc)
        if not phase or not _function_exists(ea):
            continue
        comment = f"[Phase: {phase}]"
        existing = idaapi.get_cmt(ea, True) or ""
        if "[Phase:" in existing:
            continue
        if existing:
            comment = existing + "\n" + comment
        if _try_set_comment(ea, comment, repeatable=True):
            modified_eas.add(ea)
            count += 1
    if count:
        msg_info(f"    +{count} auth-phase tags")
    return count


def _comment_opcode_handler(db, modified_eas):
    """Mark every opcode-handler function with 'Handler for OPCODE_NAME'."""
    try:
        rows = db.fetchall(
            "SELECT tc_name, handler_ea, direction, internal_index FROM opcodes "
            "WHERE handler_ea IS NOT NULL"
        )
    except Exception:
        return 0
    count = 0
    for r in rows:
        ea = r["handler_ea"]
        if not _function_exists(ea):
            continue
        opc = r["tc_name"] or f"opcode_0x{r['internal_index']:X}"
        direction = r["direction"] or "?"
        comment = f"[Handler: {opc} ({direction})]"
        existing = idaapi.get_cmt(ea, True) or ""
        if "[Handler:" in existing:
            continue
        if existing:
            comment = existing + "\n" + comment
        if _try_set_comment(ea, comment, repeatable=True):
            modified_eas.add(ea)
            count += 1
    if count:
        msg_info(f"    +{count} handler tags")
    return count


def _comment_conformance_scores(db, modified_eas):
    """Add conformance score comments to handler functions."""
    conformance = db.kv_get("conformance")
    if not conformance:
        return 0

    # conformance may be a list of score entries or a dict keyed by handler name
    if isinstance(conformance, dict):
        scores = conformance.get("scores") or conformance.get("handlers")
        if scores is None:
            scores = list(conformance.values())
    elif isinstance(conformance, list):
        scores = conformance
    else:
        return 0

    count = 0

    for entry in scores:
        if not isinstance(entry, dict):
            continue

        ea = entry.get("handler_ea") or entry.get("ea")
        if not ea:
            continue
        if isinstance(ea, str):
            try:
                ea = int(ea, 16)
            except ValueError:
                continue

        score = entry.get("score") or entry.get("total")
        if score is None:
            continue

        tc_name = entry.get("tc_name") or entry.get("name") or ""

        if not _function_exists(ea):
            continue

        # Build conformance comment
        comment = f"[Conformance: {score}%"
        if tc_name:
            comment += f" vs TC:{tc_name}"
        comment += "]"

        # Add detail breakdown if available
        details = entry.get("details")
        if isinstance(details, dict):
            for metric, val in sorted(details.items()):
                if metric in ("total",):
                    continue
                if isinstance(val, (int, float)):
                    comment += f"\n  {metric}: {val}"

        existing = idaapi.get_cmt(ea, True) or ""
        if "[Conformance:" in existing:
            continue

        if existing:
            comment = existing + "\n" + comment

        if _try_set_comment(ea, comment, repeatable=True):
            modified_eas.add(ea)
            count += 1

    return count


def _comment_taint_warnings(db, modified_eas):
    """Add security taint warnings as comments."""
    taint = db.kv_get("taint_analysis")
    if not taint:
        return 0

    # taint is expected to be a dict with "flows" list or similar
    if isinstance(taint, dict):
        flows = taint.get("flows") or taint.get("results") or taint.get("warnings")
        if flows is None:
            flows = []
    elif isinstance(taint, list):
        flows = taint
    else:
        return 0

    count = 0

    for flow in flows:
        if not isinstance(flow, dict):
            continue

        ea = flow.get("handler_ea") or flow.get("ea") or flow.get("func_ea")
        if not ea:
            continue
        if isinstance(ea, str):
            try:
                ea = int(ea, 16)
            except ValueError:
                continue

        if not _function_exists(ea):
            continue

        sink_type = flow.get("sink_type") or flow.get("type") or "unknown"
        source_field = flow.get("source_field") or flow.get("source") or "?"
        sink_desc = flow.get("sink_desc") or flow.get("description") or ""
        validated = flow.get("validated", False)
        severity = flow.get("severity") or ("low" if validated else "high")

        # Build warning comment
        status = "VALIDATED" if validated else "UNVALIDATED"
        comment = (
            f"[TAINT {severity.upper()}] {status}: "
            f"{source_field} -> {sink_type}"
        )
        if sink_desc:
            comment += f"\n  {sink_desc}"

        # For taint warnings, we want to add to the specific instruction
        # address if available, otherwise the function start
        sink_ea = flow.get("sink_ea") or flow.get("sink_address")
        if sink_ea:
            if isinstance(sink_ea, str):
                try:
                    sink_ea = int(sink_ea, 16)
                except ValueError:
                    sink_ea = None

        target_ea = sink_ea if sink_ea else ea

        existing = idaapi.get_cmt(target_ea, True) or ""
        # Check if we already have this specific taint warning
        if f"{source_field} -> {sink_type}" in existing:
            continue

        if existing:
            comment = existing + "\n" + comment

        if _try_set_comment(target_ea, comment, repeatable=True):
            modified_eas.add(ea)  # track by function EA for re-decompilation
            count += 1

    return count


def _comment_behavioral_specs(db, modified_eas):
    """Add execution path summary comments from behavioral specs.

    Source: per-handler `behavioral_spec:<name>` kv entries (written by
    Execution Trace Simulation since the BS analyzer was merged into it).
    The summary `behavioral_specs` key only has counts, not per-handler data.
    """
    spec_list = []
    try:
        rows = db.fetchall(
            "SELECT key, value FROM kv_store WHERE key LIKE 'behavioral_spec:%'"
        )
        import json as _json
        for r in rows:
            try:
                spec = _json.loads(r["value"]) if r["value"] else None
                if isinstance(spec, dict):
                    spec_list.append(spec)
            except Exception:
                continue
    except Exception:
        return 0

    if not spec_list:
        return 0

    count = 0

    for spec in spec_list:
        if not isinstance(spec, dict):
            continue

        ea = spec.get("handler_ea") or spec.get("ea") or spec.get("func_ea")
        if not ea:
            continue
        if isinstance(ea, str):
            try:
                ea = int(ea, 16)
            except ValueError:
                continue

        if not _function_exists(ea):
            continue

        paths = spec.get("paths") or spec.get("execution_paths") or []
        path_count = len(paths) if isinstance(paths, list) else 0
        outcomes = spec.get("outcomes") or spec.get("return_values") or []

        if path_count == 0 and not outcomes:
            continue

        # Build a concise behavior summary
        lines = [f"[Behavioral: {path_count} paths"]

        if isinstance(outcomes, list) and outcomes:
            outcome_strs = []
            for o in outcomes[:5]:
                if isinstance(o, dict):
                    outcome_strs.append(
                        f"{o.get('value', '?')}: {o.get('description', '')}"
                    )
                else:
                    outcome_strs.append(str(o))
            lines[0] += f", {len(outcomes)} outcomes]"
            for os_str in outcome_strs:
                lines.append(f"  -> {os_str}")
        else:
            lines[0] += "]"

        # Include first few path conditions as examples
        if isinstance(paths, list):
            for path in paths[:3]:
                if isinstance(path, dict):
                    conds = path.get("conditions") or path.get("guard") or []
                    outcome = path.get("outcome") or path.get("return") or "?"
                    if isinstance(conds, list) and conds:
                        cond_str = " AND ".join(str(c) for c in conds[:3])
                        lines.append(f"  path: ({cond_str}) => {outcome}")
            if len(paths) > 3:
                lines.append(f"  ... +{len(paths) - 3} more paths")

        comment = "\n".join(lines)

        existing = idaapi.get_cmt(ea, True) or ""
        if "[Behavioral:" in existing:
            continue

        if existing:
            comment = existing + "\n" + comment

        if _try_set_comment(ea, comment, repeatable=True):
            modified_eas.add(ea)
            count += 1

    return count


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4 — Re-decompile and Discover
# ═══════════════════════════════════════════════════════════════════════════

def _phase4_redecompile_and_discover(db, modified_eas):
    """Re-decompile functions that were modified and look for new patterns.

    After renaming callees, the caller's pseudocode now contains the new
    names. This can reveal:
      - System classification from callee names (e.g., calls HandleHousing* -> housing system)
      - Additional handler patterns visible through renamed sub-calls
      - New vtable method assignments recognisable from named stores
    """
    if not _HAS_HEXRAYS:
        msg_warn("Hex-Rays not available — skipping re-decompile phase")
        return 0

    if not modified_eas:
        return 0

    # Collect the modified functions PLUS their callers (one level up)
    # since renaming a callee changes the caller's decompilation
    eas_to_decompile = set()

    for ea in modified_eas:
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        eas_to_decompile.add(func.start_ea)

        # Find callers of this function (one level up)
        for xref in idautils.XrefsTo(func.start_ea, 0):
            caller_func = ida_funcs.get_func(xref.frm)
            if caller_func:
                eas_to_decompile.add(caller_func.start_ea)

    # Resume across idat-crash by tracking which EAs we already re-decompiled.
    # With the MAX_REDECOMPILE cap removed, this set can be 17K+ — without
    # checkpointing, each idat crash forces a full restart and never finishes.
    checkpoint = db.kv_get("idb_enrichment_phase4_checkpoint") or {}
    processed_eas = set(checkpoint.get("processed_eas", []))
    discovered = checkpoint.get("discovered", 0)

    msg_info(f"  Phase 4: re-decompiling {len(eas_to_decompile)} functions"
             + (f" (resuming, {len(processed_eas)} already done)" if processed_eas else ""))

    decompile_failures = 0
    todo = sorted(eas_to_decompile - processed_eas)

    for idx, ea in enumerate(todo):
        pseudocode = get_decompiled_text(ea)
        if pseudocode is None:
            decompile_failures += 1
        else:
            discovered += _discover_system_from_callees(db, ea, pseudocode)
            discovered += _discover_handler_patterns(db, ea, pseudocode)
            discovered += _discover_vtable_associations(db, ea, pseudocode)
        processed_eas.add(ea)

        if (idx + 1) % 1000 == 0:
            db.kv_set("idb_enrichment_phase4_checkpoint", {
                "processed_eas": list(processed_eas),
                "discovered": discovered,
            })
            db.commit()

    # Phase complete — clear checkpoint
    db.kv_set("idb_enrichment_phase4_checkpoint", None)
    db.commit()

    if decompile_failures > 0:
        msg_info(f"  Phase 4: {decompile_failures} decompilation failures")

    msg_info(f"  Phase 4 (Re-decompile): {discovered} new items discovered")
    return discovered


def _discover_system_from_callees(db, ea, pseudocode):
    """Infer a function's system from the names of functions it calls.

    If a function calls HandleHousingXxx, HandleHousingYyy, etc.,
    it is likely part of the housing system.
    """
    # Skip functions that already have a system classification
    existing = db.get_function(ea)
    if existing and existing["system"]:
        return 0

    # Extract all callee names from the pseudocode
    callee_names = _CALL_RE.findall(pseudocode)
    if not callee_names:
        return 0

    # Count system keywords in callee names
    system_counts = {}
    system_keywords = {
        "Housing": "housing",
        "Neighborhood": "neighborhood",
        "Quest": "quest",
        "Spell": "spell",
        "Aura": "aura",
        "Combat": "combat",
        "Guild": "guild",
        "Chat": "chat",
        "Mail": "mail",
        "Party": "party",
        "Group": "group",
        "Raid": "raid",
        "Item": "item",
        "Inventory": "inventory",
        "Loot": "loot",
        "Auction": "auction",
        "Craft": "crafting",
        "Achievement": "achievement",
        "Pet": "pet",
        "Talent": "talent",
        "Mount": "mount",
        "Transmog": "transmog",
        "Battleground": "pvp",
        "Arena": "pvp",
        "Vehicle": "vehicle",
        "Garrison": "garrison",
        "Delve": "delves",
        "Calendar": "calendar",
        "MythicPlus": "mythic_plus",
    }

    for callee in callee_names:
        for keyword, system in system_keywords.items():
            if keyword.lower() in callee.lower():
                system_counts[system] = system_counts.get(system, 0) + 1

    if not system_counts:
        return 0

    # Pick the system with the most references (needs at least 2)
    best_system, best_count = max(system_counts.items(), key=lambda x: x[1])
    if best_count < 2:
        return 0

    # Determine confidence based on how dominant the best system is
    total_refs = sum(system_counts.values())
    confidence = min(95, int(best_count / total_refs * 100))

    db.upsert_function(ea, system=best_system, confidence=confidence)
    db.commit()
    return 1


def _discover_handler_patterns(db, ea, pseudocode):
    """Look for patterns in pseudocode that indicate this function is a handler.

    After renaming, if we see calls to known serializer/deserializer functions,
    we can infer this is a handler dispatching to those.
    """
    func_name = ida_name.get_name(ea) or ""

    # Already classified — skip
    if func_name and not _AUTO_NAME_RE.match(func_name):
        return 0

    # Look for patterns: calls to known JAM deserializers then calls to
    # Handle* functions suggest this is a dispatch wrapper
    callee_names = _CALL_RE.findall(pseudocode)

    has_deserialize = any("Deserialize" in c for c in callee_names)
    handle_calls = [c for c in callee_names if c.startswith("Handle")]

    if has_deserialize and handle_calls:
        # This looks like a dispatch function
        # Name it after the first Handle call it makes
        target_name = handle_calls[0]
        dispatch_name = f"Dispatch_{target_name}"
        if _try_rename(ea, dispatch_name):
            return 1

    # Look for functions that call multiple handlers of the same system
    if len(handle_calls) >= 3:
        # This might be a system dispatcher
        # Find common prefix among Handle calls
        prefix = _common_prefix(handle_calls)
        if prefix and len(prefix) > len("Handle"):
            dispatch_name = f"Dispatch_{prefix}Subsystem"
            if _try_rename(ea, dispatch_name):
                return 1

    return 0


def _discover_vtable_associations(db, ea, pseudocode):
    """Look for vtable writes that associate a function with a class.

    Pattern: *(_QWORD *)a1 = &vtable_for_ClassName
    After renaming vtables, we can recognise these patterns.
    """
    # Look for vtable assignment patterns
    # e.g.: *(_QWORD *)v1 = &ClassName__vtable;
    vtable_assign_re = re.compile(
        r'\*\s*\(\s*_?QWORD\s*\*\s*\)\s*\w+\s*=\s*'
        r'(?:&\s*)?(\w+?)(?:__vtable|__vftable|_vtbl)\b'
    )

    matches = vtable_assign_re.findall(pseudocode)
    if not matches:
        return 0

    discovered = 0
    func_name = ida_name.get_name(ea) or ""

    for class_name in matches:
        if not class_name:
            continue

        # If this function is unnamed, it might be a constructor
        if _AUTO_NAME_RE.match(func_name) or not func_name:
            ctor_name = f"{class_name}__ctor"
            if _try_rename(ea, ctor_name):
                discovered += 1
                # Also classify the function
                db.upsert_function(ea, name=ctor_name)
                db.commit()

    return discovered


def _common_prefix(strings):
    """Find the longest common prefix of a list of strings."""
    if not strings:
        return ""
    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix


# ═══════════════════════════════════════════════════════════════════════════
# IDA Manipulation Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _function_exists(ea):
    """Check that a valid function exists at the given address."""
    if not ea or ea == idaapi.BADADDR:
        return False
    return ida_funcs.get_func(ea) is not None


def _is_auto_named(ea):
    """Check if the function at ea has an IDA auto-generated name (sub_XXX etc)."""
    name = ida_name.get_name(ea)
    if not name:
        return True
    return bool(_AUTO_NAME_RE.match(name))


def _try_rename(ea, desired_name):
    """Attempt to rename the function at ea.

    Only renames if:
      - The function currently has an auto-generated name (sub_XXX)
      - The desired name is different from the current name
      - The desired name is valid

    Returns True if rename was applied.
    """
    if not desired_name or not ea or ea == idaapi.BADADDR:
        return False

    func = ida_funcs.get_func(ea)
    if not func:
        return False

    # Work with the function start address
    ea = func.start_ea

    current_name = ida_name.get_name(ea) or ""

    # Only overwrite auto-generated names — never overwrite user/meaningful names
    if current_name and not _AUTO_NAME_RE.match(current_name):
        # Current name is meaningful — don't overwrite
        # Unless desired_name is more specific (longer and contains current)
        if current_name.lower() not in desired_name.lower():
            return False

    # Check if already correctly named
    if current_name == desired_name:
        return False

    # Sanitize the desired name for IDA
    safe_name = _sanitize_ida_name(desired_name)
    if not safe_name:
        return False

    # If this name is already taken by another address, deduplicate
    existing_ea = ida_name.get_name_ea(idaapi.BADADDR, safe_name)
    if existing_ea != idaapi.BADADDR and existing_ea != ea:
        # Name collision — append address suffix
        safe_name = f"{safe_name}_{ea & 0xFFFF:04X}"

    result = idc.set_name(ea, safe_name, _RENAME_FLAGS)
    if result:
        return True

    # If the initial attempt failed, try with SN_FORCE which can handle
    # more edge cases (but we prefer SN_NOWARN|SN_NOCHECK first)
    result = idc.set_name(ea, safe_name, idc.SN_NOWARN | idc.SN_NOCHECK | 0x800)
    return bool(result)


def _sanitize_ida_name(name):
    """Sanitize a string to be a valid IDA symbol name.

    IDA names must start with a letter or underscore, and contain only
    alphanumeric characters, underscores, and dollar signs.
    """
    if not name:
        return ""

    # Replace common C++ tokens
    name = name.replace("::", "__")
    name = name.replace("<", "_")
    name = name.replace(">", "_")
    name = name.replace(",", "_")
    name = name.replace(" ", "_")
    name = name.replace("-", "_")

    # Remove any remaining invalid characters
    name = re.sub(r'[^A-Za-z0-9_$]', '', name)

    # Ensure it starts with a letter or underscore
    if name and name[0].isdigit():
        name = "_" + name

    # Collapse multiple underscores
    name = re.sub(r'__+', '__', name)

    # Strip trailing underscores
    name = name.rstrip('_')

    # IDA has a max name length (typically 511 chars but let's be safe)
    if len(name) > 200:
        name = name[:200]

    return name


def _try_set_comment(ea, comment, repeatable=True):
    """Set a comment at the given address.

    Args:
        ea: Address to comment
        comment: Comment text
        repeatable: If True, set as repeatable comment

    Returns:
        True if comment was set successfully.
    """
    if not ea or ea == idaapi.BADADDR or not comment:
        return False

    # Truncate very long comments to avoid IDA issues
    MAX_COMMENT_LEN = 4096
    if len(comment) > MAX_COMMENT_LEN:
        comment = comment[:MAX_COMMENT_LEN - 20] + "\n... (truncated)"

    result = idaapi.set_cmt(ea, comment, repeatable)
    return bool(result)


# ═══════════════════════════════════════════════════════════════════════════
# Standalone utilities
# ═══════════════════════════════════════════════════════════════════════════

def count_auto_named_functions():
    """Count how many functions in the IDB still have auto-generated names.

    Useful for measuring enrichment progress.
    Returns (auto_count, total_count, named_count).
    """
    auto_count = 0
    total_count = 0
    named_count = 0

    for ea in idautils.Functions():
        total_count += 1
        name = ida_name.get_name(ea)
        if not name or _AUTO_NAME_RE.match(name):
            auto_count += 1
        else:
            named_count += 1

    return auto_count, total_count, named_count


def enrichment_coverage_report(session):
    """Generate a detailed coverage report showing enrichment effectiveness.

    Returns:
        dict with breakdown by source (opcodes, vtables, jam, etc.)
    """
    db = session.db
    if not db:
        return {}

    auto_count, total_count, named_count = count_auto_named_functions()

    # Count contributions from each source
    opcode_handlers = db.fetchone(
        "SELECT COUNT(*) as cnt FROM opcodes WHERE handler_ea IS NOT NULL "
        "AND tc_name IS NOT NULL"
    )
    jam_functions = db.fetchone(
        "SELECT COUNT(*) as cnt FROM jam_types "
        "WHERE serializer_ea IS NOT NULL OR deserializer_ea IS NOT NULL"
    )
    vtable_entries = db.fetchone(
        "SELECT COUNT(DISTINCT func_ea) as cnt FROM vtable_entries "
        "WHERE func_ea IS NOT NULL"
    )
    classified_functions = db.fetchone(
        "SELECT COUNT(*) as cnt FROM functions WHERE system IS NOT NULL"
    )
    db2_functions = db.fetchone(
        "SELECT COUNT(*) as cnt FROM db2_tables WHERE meta_ea IS NOT NULL"
    )

    # Get last enrichment report
    last_report = db.kv_get("idb_enrichment")

    report = {
        "total_functions": total_count,
        "auto_named_remaining": auto_count,
        "named_functions": named_count,
        "coverage_pct": round(named_count / total_count * 100, 1) if total_count else 0,
        "sources": {
            "opcode_handlers": opcode_handlers["cnt"] if opcode_handlers else 0,
            "jam_serializers": (jam_functions["cnt"] * 2) if jam_functions else 0,
            "vtable_methods": vtable_entries["cnt"] if vtable_entries else 0,
            "system_classified": classified_functions["cnt"] if classified_functions else 0,
            "db2_loaders": db2_functions["cnt"] if db2_functions else 0,
        },
        "last_enrichment": last_report,
    }

    return report


def print_enrichment_summary(session):
    """Print a human-readable enrichment summary to the IDA output window."""
    report = enrichment_coverage_report(session)
    if not report:
        msg_error("No enrichment data available")
        return

    msg("=" * 60)
    msg("  IDB Enrichment Coverage Report")
    msg("=" * 60)
    msg(f"  Total functions:       {report['total_functions']:>8}")
    msg(f"  Named (meaningful):    {report['named_functions']:>8}")
    msg(f"  Auto-named (sub_XXX):  {report['auto_named_remaining']:>8}")
    msg(f"  Coverage:              {report['coverage_pct']:>7.1f}%")
    msg("-" * 60)
    msg("  Contribution by source:")
    for source, count in report["sources"].items():
        msg(f"    {source:<25} {count:>6}")

    last = report.get("last_enrichment")
    if last:
        msg("-" * 60)
        msg("  Last enrichment run:")
        msg(f"    Iterations:      {last.get('iterations', '?')}")
        msg(f"    Converged:       {last.get('convergence_reached', '?')}")
        msg(f"    Total renamed:   {last.get('total_renamed', '?')}")
        msg(f"    Total retyped:   {last.get('total_retyped', '?')}")
        msg(f"    Total commented: {last.get('total_commented', '?')}")
        msg(f"    Enums created:   {last.get('total_enums_created', '?')}")
        msg(f"    Elapsed:         {last.get('elapsed_s', '?')}s")

    msg("=" * 60)
