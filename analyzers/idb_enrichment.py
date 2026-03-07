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
except ImportError:
    _HAS_ENUM = False

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
      - "object_layouts":    Set function parameter types for known classes
      - "wire_formats":      Annotate Read/Write calls with field names
      - "recovered_enums":   Create IDA enum types

    Returns:
        (typed_count, enum_count)
    """
    typed_count = 0
    enum_count = 0

    typed_count += _apply_object_layout_types(db, modified_eas)
    typed_count += _annotate_wire_format_fields(db, modified_eas)
    enum_count += _create_ida_enums(db)

    msg_info(f"  Phase 2 (Type Recovery): {typed_count} types applied, "
             f"{enum_count} enums created")
    return typed_count, enum_count


def _apply_object_layout_types(db, modified_eas):
    """Set first-parameter types on functions associated with known classes."""
    layouts = db.kv_get("object_layouts")
    if not layouts:
        return 0
    if not _HAS_TYPEINF:
        msg_warn("ida_typeinf not available — skipping object layout type application")
        return 0

    count = 0

    # layouts is expected to be a dict of class_name -> { "fields": [...], "methods": [...] }
    # or a list of layout objects
    if isinstance(layouts, list):
        layout_list = layouts
    elif isinstance(layouts, dict):
        layout_list = list(layouts.values()) if not isinstance(
            next(iter(layouts.values()), None), dict
        ) else [{"class_name": k, **v} for k, v in layouts.items()]
    else:
        return 0

    for layout in layout_list:
        if not isinstance(layout, dict):
            continue

        class_name = layout.get("class_name") or layout.get("name")
        if not class_name:
            continue

        methods = layout.get("methods") or layout.get("functions") or []
        for method_info in methods:
            if not isinstance(method_info, dict):
                continue

            method_ea = method_info.get("ea") or method_info.get("address")
            if not method_ea:
                continue
            if isinstance(method_ea, str):
                try:
                    method_ea = int(method_ea, 16)
                except ValueError:
                    continue

            if not _function_exists(method_ea):
                continue

            # Apply the class type as the first parameter (this pointer)
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

    # Get current type info
    tinfo = ida_typeinf.tinfo_t()
    if not ida_typeinf.get_tinfo(tinfo, ea):
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
    """Create IDA enum types from recovered enum definitions."""
    if not _HAS_ENUM:
        msg_warn("ida_enum not available — skipping enum creation")
        return 0

    recovered = db.kv_get("recovered_enums")
    if not recovered or not isinstance(recovered, list):
        return 0

    count = 0

    for enum_def in recovered:
        if not isinstance(enum_def, dict):
            continue

        enum_name = enum_def.get("suggested_name")
        if not enum_name:
            continue

        # Sanitize the name for IDA
        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', enum_name)
        if not safe_name or safe_name[0].isdigit():
            safe_name = "E_" + safe_name

        values = enum_def.get("values")
        if not values or not isinstance(values, list):
            continue

        is_flags = enum_def.get("is_flags", False)

        # Check if enum already exists
        existing_id = ida_enum.get_enum(safe_name)
        if existing_id != idaapi.BADADDR:
            # Enum already exists — skip creation but count existing members
            # to decide if we need to add more
            existing_count = ida_enum.get_enum_size(existing_id)
            if existing_count >= len(values):
                continue
            enum_id = existing_id
        else:
            # Create new enum
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

            # Build full member name: EnumName_MemberName
            member_name = f"{safe_name}_{vname}"
            member_name = re.sub(r'[^A-Za-z0-9_]', '_', member_name)

            # Check if member already exists
            if ida_enum.get_enum_member_by_name(member_name) != idaapi.BADADDR:
                continue

            # Add the member
            bmask = idaapi.BADADDR if is_flags else 0
            err = ida_enum.add_enum_member(enum_id, member_name, val, bmask)
            if err == 0:
                members_added += 1

        if members_added > 0:
            count += 1

    return count


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3 — Comment Enrichment
# ═══════════════════════════════════════════════════════════════════════════

def _phase3_comment_enrichment(db, modified_eas):
    """Add repeatable comments from various analysis results.

    Sources:
      - conformance scores:   Quality/fidelity rating per handler
      - taint_analysis:       Security warnings for unsafe flows
      - behavioral_specs:     Execution path summaries
    """
    count = 0

    count += _comment_conformance_scores(db, modified_eas)
    count += _comment_taint_warnings(db, modified_eas)
    count += _comment_behavioral_specs(db, modified_eas)

    msg_info(f"  Phase 3 (Comment Enrichment): {count} comments added")
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
    """Add execution path summary comments from behavioral specs."""
    specs = db.kv_get("behavioral_specs")
    if not specs:
        return 0

    if isinstance(specs, dict):
        spec_list = specs.get("specs") or specs.get("handlers") or list(specs.values())
    elif isinstance(specs, list):
        spec_list = specs
    else:
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

    # Limit to avoid spending too long on re-decompilation
    MAX_REDECOMPILE = 2000
    if len(eas_to_decompile) > MAX_REDECOMPILE:
        msg_info(f"  Phase 4: limiting re-decompilation to {MAX_REDECOMPILE} "
                 f"of {len(eas_to_decompile)} affected functions")
        eas_to_decompile = set(sorted(eas_to_decompile)[:MAX_REDECOMPILE])

    msg_info(f"  Phase 4: re-decompiling {len(eas_to_decompile)} functions...")

    discovered = 0
    decompile_failures = 0

    for ea in sorted(eas_to_decompile):
        pseudocode = get_decompiled_text(ea)
        if pseudocode is None:
            decompile_failures += 1
            continue

        # Discover system classification from callee names
        discovered += _discover_system_from_callees(db, ea, pseudocode)

        # Discover new handler patterns from renamed callees
        discovered += _discover_handler_patterns(db, ea, pseudocode)

        # Discover vtable class associations
        discovered += _discover_vtable_associations(db, ea, pseudocode)

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
