"""
Cross-Build Delta Transpiler (Feature #9)
Performs semantic diffing of handler behavior between two WoW builds.

For each handler that changed between builds, extracts the SEMANTIC diff:
  - Wire format changes (fields added/removed/reordered/retyped)
  - Validation rule changes (new checks, removed checks, threshold changes)
  - Response packet changes (new SMSGs, changed layouts, error codes)
  - Constant changes (distances, limits, timers, error codes)
  - State transition changes (state machine behavior)
  - Call graph changes (new/removed function calls)

Generates TrinityCore source patches from the semantic diffs.

Unlike diffing/build_differ.py which matches functions by address/hash,
this module compares the *meaning* of matched handler pairs.
"""

import json
import os
import re
import sqlite3
import time
from collections import OrderedDict
from difflib import SequenceMatcher

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

SEVERITY_BREAKING = "breaking"
SEVERITY_SIGNIFICANT = "significant"
SEVERITY_MINOR = "minor"
SEVERITY_COSMETIC = "cosmetic"

# Category → default severity mapping (can be promoted based on specifics)
_CATEGORY_DEFAULT_SEVERITY = {
    "wire_format": SEVERITY_BREAKING,
    "validation": SEVERITY_SIGNIFICANT,
    "error_code": SEVERITY_SIGNIFICANT,
    "response": SEVERITY_BREAKING,
    "constant": SEVERITY_MINOR,
    "state_transition": SEVERITY_SIGNIFICANT,
    "call_graph": SEVERITY_MINOR,
}

# Change types
CHANGE_NEW = "new"
CHANGE_REMOVED = "removed"
CHANGE_MODIFIED = "modified"
CHANGE_UNCHANGED = "unchanged"


# ---------------------------------------------------------------------------
# Type metadata for wire format diffing
# ---------------------------------------------------------------------------

_TYPE_SIZES = {
    "uint8": 8, "int8": 8,
    "uint16": 16, "int16": 16,
    "uint32": 32, "int32": 32,
    "uint64": 64, "int64": 64,
    "float": 32, "double": 64,
    "bit": 1, "bits": 0,  # bits is variable
    "packed_guid": 128, "ObjectGuid": 128,
    "string": 0,  # variable
}

_SIGNED_PAIRS = {
    "uint8": "int8", "int8": "uint8",
    "uint16": "int16", "int16": "uint16",
    "uint32": "int32", "int32": "uint32",
    "uint64": "int64", "int64": "uint64",
}


def _types_compatible(t1, t2):
    """Check if two types are the same size and only differ in signedness."""
    if t1 == t2:
        return True
    return _SIGNED_PAIRS.get(t1) == t2


def _type_display(field):
    """Human-readable type string for a field."""
    ftype = field.get("type", "unknown")
    if ftype == "bits":
        return f"bits({field.get('bit_size', '?')})"
    return ftype


# ---------------------------------------------------------------------------
# Loading old build data
# ---------------------------------------------------------------------------

def _load_old_build_data(path):
    """Load previous build's analysis data from various formats.

    Supported formats:
      1. SQLite knowledge DB from a previous analysis session
      2. JSON export from export_all_formats_json()
      3. Directory containing per-handler JSON files

    Returns a normalized dict:
        {
            "build_number": int,
            "handlers": {
                handler_name: {
                    "fields": [...],
                    "validations": [...],
                    "responses": [...],
                    "constants": [...],
                    "state_transitions": [...],
                    "call_graph": [...],
                    "error_codes": [...],
                }
            }
        }
    """
    if not os.path.exists(path):
        msg_error(f"Old build path does not exist: {path}")
        return None

    if os.path.isfile(path):
        _, ext = os.path.splitext(path)
        if ext in (".db", ".sqlite", ".sqlite3"):
            return _load_from_sqlite(path)
        elif ext == ".json":
            return _load_from_json_export(path)
        else:
            msg_error(f"Unsupported file format: {ext}")
            return None
    elif os.path.isdir(path):
        return _load_from_directory(path)
    else:
        msg_error(f"Path is neither file nor directory: {path}")
        return None


def _load_from_sqlite(db_path):
    """Load handler data from a previous build's knowledge DB."""
    result = {"build_number": 0, "handlers": {}}

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
    except Exception as e:
        msg_error(f"Cannot open old build DB: {e}")
        return None

    try:
        # Get build number
        row = conn.execute(
            "SELECT build_number FROM builds ORDER BY build_number DESC LIMIT 1"
        ).fetchone()
        if row:
            result["build_number"] = row["build_number"]
        else:
            # Try to detect from kv_store
            row = conn.execute(
                "SELECT value FROM kv_store WHERE key = 'build_number'"
            ).fetchone()
            if row:
                try:
                    result["build_number"] = int(json.loads(row["value"]))
                except (ValueError, TypeError):
                    pass

        # Load opcodes with handlers
        opcodes = conn.execute(
            "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL AND tc_name IS NOT NULL"
        ).fetchall()

        for opcode in opcodes:
            handler_name = opcode["tc_name"]
            handler_data = {
                "fields": [],
                "validations": [],
                "responses": [],
                "constants": [],
                "state_transitions": [],
                "call_graph": [],
                "error_codes": [],
                "direction": opcode["direction"],
                "handler_ea": opcode["handler_ea"],
                "internal_index": opcode["internal_index"],
                "wire_opcode": opcode["wire_opcode"],
                "jam_type": opcode["jam_type"],
            }

            # Load wire format fields from kv_store
            wire_formats = None
            row = conn.execute(
                "SELECT value FROM kv_store WHERE key = 'wire_formats'"
            ).fetchone()
            if row:
                try:
                    wire_formats = json.loads(row["value"])
                except (json.JSONDecodeError, TypeError):
                    pass

            if wire_formats and handler_name in wire_formats:
                fmt = wire_formats[handler_name]
                handler_data["fields"] = fmt.get("fields", [])

            # Load from jam_types table if available
            if opcode["jam_type"]:
                jam_row = conn.execute(
                    "SELECT * FROM jam_types WHERE name = ?",
                    (opcode["jam_type"],)
                ).fetchone()
                if jam_row and jam_row["fields_json"]:
                    try:
                        jam_fields = json.loads(jam_row["fields_json"])
                        if not handler_data["fields"] and jam_fields:
                            handler_data["fields"] = jam_fields
                    except (json.JSONDecodeError, TypeError):
                        pass

            # Load validations from kv_store
            val_row = conn.execute(
                "SELECT value FROM kv_store WHERE key = ?",
                (f"validations:{handler_name}",)
            ).fetchone()
            if val_row:
                try:
                    handler_data["validations"] = json.loads(val_row["value"])
                except (json.JSONDecodeError, TypeError):
                    pass

            # Load state machines from kv_store
            sm_row = conn.execute(
                "SELECT value FROM kv_store WHERE key = ?",
                (f"state_machine:{handler_name}",)
            ).fetchone()
            if sm_row:
                try:
                    handler_data["state_transitions"] = json.loads(sm_row["value"])
                except (json.JSONDecodeError, TypeError):
                    pass

            # Load call graph from kv_store
            cg_row = conn.execute(
                "SELECT value FROM kv_store WHERE key = ?",
                (f"call_graph:{handler_name}",)
            ).fetchone()
            if cg_row:
                try:
                    handler_data["call_graph"] = json.loads(cg_row["value"])
                except (json.JSONDecodeError, TypeError):
                    pass

            # Extract error codes from validations
            for val in handler_data["validations"]:
                ec = val.get("error_code")
                if ec and ec not in handler_data["error_codes"]:
                    handler_data["error_codes"].append(ec)

            # Extract constants from validations (comparand values)
            for val in handler_data["validations"]:
                comp = val.get("comparand")
                if comp:
                    handler_data["constants"].append({
                        "value": comp,
                        "context": val.get("condition", ""),
                        "type": val.get("type", ""),
                    })

            result["handlers"][handler_name] = handler_data

        # Also load SMSG response mappings if available
        smsg_opcodes = conn.execute(
            "SELECT * FROM opcodes WHERE direction = 'SMSG' AND tc_name IS NOT NULL"
        ).fetchall()
        smsg_map = {}
        for smsg in smsg_opcodes:
            smsg_map[smsg["tc_name"]] = {
                "internal_index": smsg["internal_index"],
                "wire_opcode": smsg["wire_opcode"],
                "jam_type": smsg["jam_type"],
            }

        # Attach SMSG responses to CMSG handlers by naming convention
        for handler_name, handler_data in result["handlers"].items():
            # CMSG_HOUSING_DECOR_PLACE -> SMSG_HOUSING_DECOR_PLACE_RESULT
            if handler_name.startswith("CMSG_"):
                base = handler_name[5:]  # strip CMSG_
                for suffix in ("_RESULT", "_RESPONSE", "_STATUS", ""):
                    smsg_name = f"SMSG_{base}{suffix}"
                    if smsg_name in smsg_map:
                        handler_data["responses"].append({
                            "name": smsg_name,
                            **smsg_map[smsg_name],
                        })

    except Exception as e:
        msg_error(f"Error reading old build DB: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

    msg_info(f"Loaded {len(result['handlers'])} handlers from old build "
             f"DB (build {result['build_number']})")
    return result


def _load_from_json_export(json_path):
    """Load handler data from a JSON export file."""
    result = {"build_number": 0, "handlers": {}}

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        msg_error(f"Cannot read JSON export: {e}")
        return None

    # Detect format: export_all_formats_json() produces {"meta": ..., "formats": {...}}
    # Or it could be a full knowledge dump with multiple sections

    if "meta" in data and "formats" in data:
        # Wire format export
        result["build_number"] = data.get("meta", {}).get("build_number", 0)
        for opcode_name, fmt in data["formats"].items():
            handler_data = {
                "fields": fmt.get("fields", []),
                "validations": [],
                "responses": [],
                "constants": [],
                "state_transitions": [],
                "call_graph": [],
                "error_codes": [],
                "direction": fmt.get("direction", "CMSG"),
                "handler_ea": fmt.get("handler_ea", 0),
            }
            result["handlers"][opcode_name] = handler_data

    elif "handlers" in data:
        # Already in our normalized format
        result["build_number"] = data.get("build_number", 0)
        for handler_name, handler_info in data["handlers"].items():
            handler_data = {
                "fields": handler_info.get("fields", []),
                "validations": handler_info.get("validations", []),
                "responses": handler_info.get("responses", []),
                "constants": handler_info.get("constants", []),
                "state_transitions": handler_info.get("state_transitions", []),
                "call_graph": handler_info.get("call_graph", []),
                "error_codes": handler_info.get("error_codes", []),
                "direction": handler_info.get("direction", "CMSG"),
                "handler_ea": handler_info.get("handler_ea", 0),
            }
            result["handlers"][handler_name] = handler_data

    elif "opcodes" in data or "wire_formats" in data:
        # Legacy combined export
        build = data.get("build_number", data.get("build", 0))
        result["build_number"] = build

        wire_formats = data.get("wire_formats", data.get("formats", {}))
        validations = data.get("validations", {})
        state_machines = data.get("state_machines", {})

        opcodes = data.get("opcodes", [])
        if isinstance(opcodes, list):
            for op in opcodes:
                name = op.get("tc_name")
                if not name:
                    continue
                handler_data = {
                    "fields": [],
                    "validations": validations.get(name, []),
                    "responses": [],
                    "constants": [],
                    "state_transitions": state_machines.get(name, []),
                    "call_graph": [],
                    "error_codes": [],
                    "direction": op.get("direction", "CMSG"),
                    "handler_ea": op.get("handler_ea", 0),
                }
                if name in wire_formats:
                    handler_data["fields"] = wire_formats[name].get("fields", [])
                result["handlers"][name] = handler_data

    msg_info(f"Loaded {len(result['handlers'])} handlers from JSON export "
             f"(build {result['build_number']})")
    return result


def _load_from_directory(dir_path):
    """Load handler data from a directory of per-handler JSON files."""
    result = {"build_number": 0, "handlers": {}}

    # Detect build number from directory name or contents
    build_match = re.search(r'(\d{5,6})', os.path.basename(dir_path))
    if build_match:
        result["build_number"] = int(build_match.group(1))

    # Look for a build_info.json or meta.json
    for meta_file in ("build_info.json", "meta.json", "info.json"):
        meta_path = os.path.join(dir_path, meta_file)
        if os.path.isfile(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                result["build_number"] = meta.get("build_number",
                                                   meta.get("build",
                                                            result["build_number"]))
            except Exception:
                pass
            break

    # Load per-handler JSON files
    handler_count = 0
    for fname in os.listdir(dir_path):
        if not fname.endswith(".json"):
            continue
        if fname in ("build_info.json", "meta.json", "info.json"):
            continue

        filepath = os.path.join(dir_path, fname)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        # Handler name from filename: CMSG_HOUSING_DECOR_PLACE.json
        handler_name = os.path.splitext(fname)[0]

        # Or from the JSON content
        if "handler" in data:
            handler_name = data["handler"]
        elif "opcode_name" in data:
            handler_name = data["opcode_name"]

        handler_data = {
            "fields": data.get("fields", []),
            "validations": data.get("validations", []),
            "responses": data.get("responses", []),
            "constants": data.get("constants", []),
            "state_transitions": data.get("state_transitions", []),
            "call_graph": data.get("call_graph", []),
            "error_codes": data.get("error_codes", []),
            "direction": data.get("direction", "CMSG"),
            "handler_ea": data.get("handler_ea", 0),
        }

        # Extract error codes from validations if not provided
        if not handler_data["error_codes"]:
            for val in handler_data["validations"]:
                ec = val.get("error_code")
                if ec and ec not in handler_data["error_codes"]:
                    handler_data["error_codes"].append(ec)

        result["handlers"][handler_name] = handler_data
        handler_count += 1

    # Also check for a single combined file like "all_handlers.json"
    combined_path = os.path.join(dir_path, "all_handlers.json")
    if os.path.isfile(combined_path):
        try:
            with open(combined_path, "r", encoding="utf-8") as f:
                combined = json.load(f)
            if isinstance(combined, dict):
                for name, info in combined.items():
                    if name not in result["handlers"]:
                        result["handlers"][name] = {
                            "fields": info.get("fields", []),
                            "validations": info.get("validations", []),
                            "responses": info.get("responses", []),
                            "constants": info.get("constants", []),
                            "state_transitions": info.get("state_transitions", []),
                            "call_graph": info.get("call_graph", []),
                            "error_codes": info.get("error_codes", []),
                            "direction": info.get("direction", "CMSG"),
                            "handler_ea": info.get("handler_ea", 0),
                        }
                        handler_count += 1
        except Exception:
            pass

    msg_info(f"Loaded {handler_count} handlers from directory "
             f"(build {result['build_number']})")
    return result


def _load_current_build_data(session):
    """Load the current build's handler data from the knowledge DB.

    Returns the same normalized format as _load_old_build_data().
    """
    db = session.db
    cfg = session.cfg
    result = {"build_number": cfg.build_number, "handlers": {}}

    # Load opcodes
    opcodes = db.fetchall(
        "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL AND tc_name IS NOT NULL"
    )

    # Load wire formats
    wire_formats = db.kv_get("wire_formats") or {}

    for opcode in opcodes:
        handler_name = opcode["tc_name"]
        handler_data = {
            "fields": [],
            "validations": [],
            "responses": [],
            "constants": [],
            "state_transitions": [],
            "call_graph": [],
            "error_codes": [],
            "direction": opcode["direction"],
            "handler_ea": opcode["handler_ea"],
            "internal_index": opcode["internal_index"],
            "wire_opcode": opcode["wire_opcode"],
            "jam_type": opcode["jam_type"],
        }

        # Wire format fields
        if handler_name in wire_formats:
            handler_data["fields"] = wire_formats[handler_name].get("fields", [])

        # JAM type fields as fallback
        if not handler_data["fields"] and opcode["jam_type"]:
            jam_row = db.fetchone(
                "SELECT * FROM jam_types WHERE name = ?",
                (opcode["jam_type"],))
            if jam_row and jam_row["fields_json"]:
                try:
                    handler_data["fields"] = json.loads(jam_row["fields_json"])
                except (json.JSONDecodeError, TypeError):
                    pass

        # Validations
        val_row = db.fetchone(
            "SELECT value FROM kv_store WHERE key = ?",
            (f"validations:{handler_name}",))
        if val_row:
            try:
                handler_data["validations"] = json.loads(val_row["value"])
            except (json.JSONDecodeError, TypeError):
                pass

        # State machines
        sm_row = db.fetchone(
            "SELECT value FROM kv_store WHERE key = ?",
            (f"state_machine:{handler_name}",))
        if sm_row:
            try:
                handler_data["state_transitions"] = json.loads(sm_row["value"])
            except (json.JSONDecodeError, TypeError):
                pass

        # Call graph
        cg_row = db.fetchone(
            "SELECT value FROM kv_store WHERE key = ?",
            (f"call_graph:{handler_name}",))
        if cg_row:
            try:
                handler_data["call_graph"] = json.loads(cg_row["value"])
            except (json.JSONDecodeError, TypeError):
                pass

        # Error codes from validations
        for val in handler_data["validations"]:
            ec = val.get("error_code")
            if ec and ec not in handler_data["error_codes"]:
                handler_data["error_codes"].append(ec)

        # Constants from validations
        for val in handler_data["validations"]:
            comp = val.get("comparand")
            if comp:
                handler_data["constants"].append({
                    "value": comp,
                    "context": val.get("condition", ""),
                    "type": val.get("type", ""),
                })

        result["handlers"][handler_name] = handler_data

    # Attach SMSG responses
    smsg_opcodes = db.fetchall(
        "SELECT * FROM opcodes WHERE direction = 'SMSG' AND tc_name IS NOT NULL"
    )
    smsg_map = {}
    for smsg in smsg_opcodes:
        smsg_map[smsg["tc_name"]] = {
            "internal_index": smsg["internal_index"],
            "wire_opcode": smsg["wire_opcode"],
            "jam_type": smsg["jam_type"],
        }

    for handler_name, handler_data in result["handlers"].items():
        if handler_name.startswith("CMSG_"):
            base = handler_name[5:]
            for suffix in ("_RESULT", "_RESPONSE", "_STATUS", ""):
                smsg_name = f"SMSG_{base}{suffix}"
                if smsg_name in smsg_map:
                    handler_data["responses"].append({
                        "name": smsg_name,
                        **smsg_map[smsg_name],
                    })

    return result


# ---------------------------------------------------------------------------
# Wire format diffing
# ---------------------------------------------------------------------------

def _diff_wire_formats(old_fields, new_fields):
    """Diff two packet field layouts at the semantic level.

    Detects:
      - Field insertions (new fields shifted indices)
      - Field removals
      - Type changes (uint32 -> uint16, etc.)
      - Reordering
      - Bit-packed field changes

    Returns a list of change dicts.
    """
    changes = []

    if not old_fields and not new_fields:
        return changes

    if not old_fields and new_fields:
        changes.append({
            "category": "wire_format",
            "description": f"Entirely new wire format with {len(new_fields)} fields",
            "old": None,
            "new": ", ".join(_type_display(f) for f in new_fields),
            "action": "add_all_fields",
            "severity": SEVERITY_BREAKING,
        })
        return changes

    if old_fields and not new_fields:
        changes.append({
            "category": "wire_format",
            "description": f"Wire format removed ({len(old_fields)} fields)",
            "old": ", ".join(_type_display(f) for f in old_fields),
            "new": None,
            "action": "remove_all_fields",
            "severity": SEVERITY_BREAKING,
        })
        return changes

    # Build type signature strings for sequence matching
    old_types = [_type_display(f) for f in old_fields]
    new_types = [_type_display(f) for f in new_fields]

    old_type_str = ", ".join(old_types)
    new_type_str = ", ".join(new_types)

    if old_types == new_types:
        # Types match exactly -- check for name/detail changes only
        for i, (of, nf) in enumerate(zip(old_fields, new_fields)):
            old_name = of.get("name", f"field_{i}")
            new_name = nf.get("name", f"field_{i}")
            if old_name != new_name and not old_name.startswith("field_") and not new_name.startswith("field_"):
                changes.append({
                    "category": "wire_format",
                    "description": f"Field {i} renamed: {old_name} -> {new_name}",
                    "old": old_name,
                    "new": new_name,
                    "action": "rename_field",
                    "field_index": i,
                    "severity": SEVERITY_COSMETIC,
                })
            # Check optional flag changes
            if of.get("is_optional") != nf.get("is_optional"):
                changes.append({
                    "category": "wire_format",
                    "description": (
                        f"Field {i} ({new_name}) became "
                        f"{'optional' if nf.get('is_optional') else 'required'}"
                    ),
                    "old": "optional" if of.get("is_optional") else "required",
                    "new": "optional" if nf.get("is_optional") else "required",
                    "action": "change_optionality",
                    "field_index": i,
                    "severity": SEVERITY_BREAKING,
                })
        return changes

    # Use SequenceMatcher to align old and new field sequences
    matcher = SequenceMatcher(None, old_types, new_types)
    opcodes_list = matcher.get_opcodes()

    for tag, i1, i2, j1, j2 in opcodes_list:
        if tag == "equal":
            # Fields match -- still check details
            for oi, ni in zip(range(i1, i2), range(j1, j2)):
                of = old_fields[oi]
                nf = new_fields[ni]
                # Check bit_size changes for 'bits' type
                if of.get("type") == "bits" and nf.get("type") == "bits":
                    if of.get("bit_size") != nf.get("bit_size"):
                        changes.append({
                            "category": "wire_format",
                            "description": (
                                f"Field {ni} bit width changed: "
                                f"{of.get('bit_size')} -> {nf.get('bit_size')} bits"
                            ),
                            "old": f"bits({of.get('bit_size')})",
                            "new": f"bits({nf.get('bit_size')})",
                            "action": "change_bit_width",
                            "field_index": ni,
                            "severity": SEVERITY_BREAKING,
                        })
                # Check optional changes
                if of.get("is_optional") != nf.get("is_optional"):
                    name = nf.get("name", f"field_{ni}")
                    changes.append({
                        "category": "wire_format",
                        "description": (
                            f"Field {ni} ({name}) became "
                            f"{'optional' if nf.get('is_optional') else 'required'}"
                        ),
                        "old": "optional" if of.get("is_optional") else "required",
                        "new": "optional" if nf.get("is_optional") else "required",
                        "action": "change_optionality",
                        "field_index": ni,
                        "severity": SEVERITY_BREAKING,
                    })

        elif tag == "replace":
            # Type changed at these positions
            for oi, ni in zip(range(i1, i2), range(j1, j2)):
                of = old_fields[oi]
                nf = new_fields[ni]
                old_t = _type_display(of)
                new_t = _type_display(nf)

                if _types_compatible(of.get("type", ""), nf.get("type", "")):
                    sev = SEVERITY_MINOR
                    desc = f"Field {ni} signedness changed: {old_t} -> {new_t}"
                    action = "change_signedness"
                else:
                    sev = SEVERITY_BREAKING
                    desc = f"Field {ni} type changed: {old_t} -> {new_t}"
                    action = "change_type"

                changes.append({
                    "category": "wire_format",
                    "description": desc,
                    "old": old_t,
                    "new": new_t,
                    "action": action,
                    "field_index": ni,
                    "severity": sev,
                })

            # Handle unmatched extra fields in replace range
            if i2 - i1 < j2 - j1:
                # More new fields than old -- insertions
                for ni in range(j1 + (i2 - i1), j2):
                    nf = new_fields[ni]
                    name = nf.get("name", f"field_{ni}")
                    prev_name = new_fields[ni - 1].get("name", f"field_{ni-1}") if ni > 0 else "start"
                    changes.append({
                        "category": "wire_format",
                        "description": (
                            f"Added {_type_display(nf)} field at position {ni} "
                            f"(after {prev_name})"
                        ),
                        "old": None,
                        "new": _type_display(nf),
                        "action": "add_field",
                        "field_index": ni,
                        "severity": SEVERITY_BREAKING,
                    })
            elif i2 - i1 > j2 - j1:
                # More old fields than new -- removals
                for oi in range(i1 + (j2 - j1), i2):
                    of = old_fields[oi]
                    name = of.get("name", f"field_{oi}")
                    changes.append({
                        "category": "wire_format",
                        "description": f"Removed {_type_display(of)} field at old position {oi} ({name})",
                        "old": _type_display(of),
                        "new": None,
                        "action": "remove_field",
                        "field_index": oi,
                        "severity": SEVERITY_BREAKING,
                    })

        elif tag == "insert":
            # New fields added
            for ni in range(j1, j2):
                nf = new_fields[ni]
                name = nf.get("name", f"field_{ni}")
                if ni > 0 and ni - 1 < len(new_fields):
                    prev_name = new_fields[ni - 1].get("name", f"field_{ni-1}")
                else:
                    prev_name = "start"
                changes.append({
                    "category": "wire_format",
                    "description": (
                        f"Added {_type_display(nf)} field at position {ni} "
                        f"(after {prev_name})"
                    ),
                    "old": None,
                    "new": _type_display(nf),
                    "action": "add_field",
                    "field_index": ni,
                    "severity": SEVERITY_BREAKING,
                })

        elif tag == "delete":
            # Old fields removed
            for oi in range(i1, i2):
                of = old_fields[oi]
                name = of.get("name", f"field_{oi}")
                changes.append({
                    "category": "wire_format",
                    "description": f"Removed {_type_display(of)} field at old position {oi} ({name})",
                    "old": _type_display(of),
                    "new": None,
                    "action": "remove_field",
                    "field_index": oi,
                    "severity": SEVERITY_BREAKING,
                })

    # Overall type string change summary if there were structural changes
    structural_changes = [c for c in changes if c["action"] in
                          ("add_field", "remove_field", "change_type")]
    if structural_changes:
        changes.insert(0, {
            "category": "wire_format",
            "description": "Wire format layout changed",
            "old": old_type_str,
            "new": new_type_str,
            "action": "layout_changed",
            "severity": SEVERITY_BREAKING,
        })

    return changes


# ---------------------------------------------------------------------------
# Validation diffing
# ---------------------------------------------------------------------------

def _match_validation_key(rule):
    """Generate a matching key for a validation rule for cross-build pairing.

    Rules are matched by their type + the variable/field being checked.
    """
    rtype = rule.get("type", "unknown")
    checked = rule.get("checked_value", "")
    # Normalize: strip decompiler-specific naming artifacts
    checked = re.sub(r'v\d+', 'VAR', checked)
    checked = re.sub(r'a\d+', 'ARG', checked)
    return f"{rtype}:{checked}"


def _diff_validations(old_rules, new_rules):
    """Diff validation rules between two builds.

    Matches rules by type and checked variable, then compares thresholds.

    Returns a list of change dicts.
    """
    changes = []

    if not old_rules and not new_rules:
        return changes

    # Build lookup maps keyed by matching key
    old_map = {}
    for rule in old_rules:
        key = _match_validation_key(rule)
        old_map.setdefault(key, []).append(rule)

    new_map = {}
    for rule in new_rules:
        key = _match_validation_key(rule)
        new_map.setdefault(key, []).append(rule)

    all_keys = set(old_map.keys()) | set(new_map.keys())

    for key in sorted(all_keys):
        old_list = old_map.get(key, [])
        new_list = new_map.get(key, [])

        if not old_list and new_list:
            # New validation added
            for rule in new_list:
                condition = rule.get("condition", "")
                error_code = rule.get("error_code", "")
                error_str = f" return {error_code}" if error_code else ""
                changes.append({
                    "category": "validation",
                    "description": (
                        f"Added {rule.get('type', 'unknown')} check: "
                        f"{condition[:100]}"
                    ),
                    "old": None,
                    "new": f"{condition}{error_str}",
                    "action": "add_validation",
                    "severity": SEVERITY_SIGNIFICANT,
                })

        elif old_list and not new_list:
            # Validation removed
            for rule in old_list:
                condition = rule.get("condition", "")
                changes.append({
                    "category": "validation",
                    "description": (
                        f"Removed {rule.get('type', 'unknown')} check: "
                        f"{condition[:100]}"
                    ),
                    "old": condition,
                    "new": None,
                    "action": "remove_validation",
                    "severity": SEVERITY_SIGNIFICANT,
                })

        else:
            # Both exist -- compare thresholds and error codes
            for old_rule, new_rule in zip(old_list, new_list):
                old_comp = old_rule.get("comparand", "")
                new_comp = new_rule.get("comparand", "")
                old_ec = old_rule.get("error_code", "")
                new_ec = new_rule.get("error_code", "")

                if old_comp != new_comp and old_comp and new_comp:
                    changes.append({
                        "category": "validation",
                        "description": (
                            f"Threshold changed in {old_rule.get('type', 'unknown')} "
                            f"check: {old_comp} -> {new_comp}"
                        ),
                        "old": str(old_comp),
                        "new": str(new_comp),
                        "action": "change_threshold",
                        "severity": SEVERITY_SIGNIFICANT,
                    })

                if old_ec != new_ec and old_ec and new_ec:
                    changes.append({
                        "category": "error_code",
                        "description": (
                            f"Error code changed in "
                            f"{old_rule.get('type', 'unknown')} check: "
                            f"{old_ec} -> {new_ec}"
                        ),
                        "old": str(old_ec),
                        "new": str(new_ec),
                        "action": "update_error_code",
                        "severity": SEVERITY_SIGNIFICANT,
                    })

            # Handle unbalanced counts (new rules added under same key)
            if len(new_list) > len(old_list):
                for rule in new_list[len(old_list):]:
                    condition = rule.get("condition", "")
                    changes.append({
                        "category": "validation",
                        "description": (
                            f"Added additional {rule.get('type', 'unknown')} "
                            f"check: {condition[:100]}"
                        ),
                        "old": None,
                        "new": condition,
                        "action": "add_validation",
                        "severity": SEVERITY_SIGNIFICANT,
                    })
            elif len(old_list) > len(new_list):
                for rule in old_list[len(new_list):]:
                    condition = rule.get("condition", "")
                    changes.append({
                        "category": "validation",
                        "description": (
                            f"Removed {rule.get('type', 'unknown')} check: "
                            f"{condition[:100]}"
                        ),
                        "old": condition,
                        "new": None,
                        "action": "remove_validation",
                        "severity": SEVERITY_SIGNIFICANT,
                    })

    return changes


# ---------------------------------------------------------------------------
# Response packet diffing
# ---------------------------------------------------------------------------

def _diff_responses(old_responses, new_responses):
    """Diff SMSG response constructions between builds.

    Returns a list of change dicts.
    """
    changes = []

    if not old_responses and not new_responses:
        return changes

    old_by_name = {r.get("name", ""): r for r in old_responses if r.get("name")}
    new_by_name = {r.get("name", ""): r for r in new_responses if r.get("name")}

    all_names = set(old_by_name.keys()) | set(new_by_name.keys())

    for name in sorted(all_names):
        old_resp = old_by_name.get(name)
        new_resp = new_by_name.get(name)

        if not old_resp and new_resp:
            changes.append({
                "category": "response",
                "description": f"New response packet: {name}",
                "old": None,
                "new": name,
                "action": "add_response",
                "severity": SEVERITY_BREAKING,
            })

        elif old_resp and not new_resp:
            changes.append({
                "category": "response",
                "description": f"Removed response packet: {name}",
                "old": name,
                "new": None,
                "action": "remove_response",
                "severity": SEVERITY_BREAKING,
            })

        else:
            # Both exist -- check for wire opcode changes
            old_wire = old_resp.get("wire_opcode")
            new_wire = new_resp.get("wire_opcode")
            if old_wire is not None and new_wire is not None and old_wire != new_wire:
                changes.append({
                    "category": "response",
                    "description": (
                        f"Response {name} wire opcode changed: "
                        f"0x{old_wire:04X} -> 0x{new_wire:04X}"
                    ),
                    "old": f"0x{old_wire:04X}",
                    "new": f"0x{new_wire:04X}",
                    "action": "change_wire_opcode",
                    "severity": SEVERITY_SIGNIFICANT,
                })

            # Check JAM type changes
            old_jam = old_resp.get("jam_type", "")
            new_jam = new_resp.get("jam_type", "")
            if old_jam and new_jam and old_jam != new_jam:
                changes.append({
                    "category": "response",
                    "description": (
                        f"Response {name} JAM type changed: "
                        f"{old_jam} -> {new_jam}"
                    ),
                    "old": old_jam,
                    "new": new_jam,
                    "action": "change_jam_type",
                    "severity": SEVERITY_SIGNIFICANT,
                })

    return changes


# ---------------------------------------------------------------------------
# Constant / error code diffing
# ---------------------------------------------------------------------------

def _diff_error_codes(old_codes, new_codes):
    """Diff error code sets between builds."""
    changes = []
    old_set = set(str(c) for c in old_codes)
    new_set = set(str(c) for c in new_codes)

    for code in sorted(new_set - old_set):
        changes.append({
            "category": "error_code",
            "description": f"New error code: {code}",
            "old": None,
            "new": code,
            "action": "add_error_code",
            "severity": SEVERITY_SIGNIFICANT,
        })

    for code in sorted(old_set - new_set):
        changes.append({
            "category": "error_code",
            "description": f"Removed error code: {code}",
            "old": code,
            "new": None,
            "action": "remove_error_code",
            "severity": SEVERITY_SIGNIFICANT,
        })

    return changes


def _diff_constants(old_constants, new_constants):
    """Diff game rule constants between builds."""
    changes = []

    if not old_constants and not new_constants:
        return changes

    # Match constants by context (the condition/check they appear in)
    old_by_ctx = {}
    for c in old_constants:
        ctx = c.get("context", "")
        if ctx:
            old_by_ctx.setdefault(ctx, []).append(c)

    new_by_ctx = {}
    for c in new_constants:
        ctx = c.get("context", "")
        if ctx:
            new_by_ctx.setdefault(ctx, []).append(c)

    all_ctx = set(old_by_ctx.keys()) | set(new_by_ctx.keys())

    for ctx in sorted(all_ctx):
        old_list = old_by_ctx.get(ctx, [])
        new_list = new_by_ctx.get(ctx, [])

        for old_c, new_c in zip(old_list, new_list):
            old_val = str(old_c.get("value", ""))
            new_val = str(new_c.get("value", ""))
            if old_val != new_val:
                changes.append({
                    "category": "constant",
                    "description": f"Constant changed: {old_val} -> {new_val} in: {ctx[:80]}",
                    "old": old_val,
                    "new": new_val,
                    "action": "update_constant",
                    "severity": SEVERITY_MINOR,
                })

    return changes


# ---------------------------------------------------------------------------
# State transition diffing
# ---------------------------------------------------------------------------

def _diff_state_transitions(old_transitions, new_transitions):
    """Diff state machine transitions between builds."""
    changes = []

    if not old_transitions and not new_transitions:
        return changes

    # Normalize transitions to (from_state, to_state) edge sets
    def _edge_set(transitions):
        edges = set()
        if isinstance(transitions, dict):
            # Format: {"states": [...], "transitions": [{"from": X, "to": Y}, ...]}
            for t in transitions.get("transitions", []):
                edges.add((str(t.get("from", "")), str(t.get("to", ""))))
        elif isinstance(transitions, list):
            for t in transitions:
                if isinstance(t, dict):
                    edges.add((str(t.get("from", "")), str(t.get("to", ""))))
                elif isinstance(t, (list, tuple)) and len(t) >= 2:
                    edges.add((str(t[0]), str(t[1])))
        return edges

    old_edges = _edge_set(old_transitions)
    new_edges = _edge_set(new_transitions)

    for edge in sorted(new_edges - old_edges):
        changes.append({
            "category": "state_transition",
            "description": f"New state transition: {edge[0]} -> {edge[1]}",
            "old": None,
            "new": f"{edge[0]} -> {edge[1]}",
            "action": "add_transition",
            "severity": SEVERITY_SIGNIFICANT,
        })

    for edge in sorted(old_edges - new_edges):
        changes.append({
            "category": "state_transition",
            "description": f"Removed state transition: {edge[0]} -> {edge[1]}",
            "old": f"{edge[0]} -> {edge[1]}",
            "new": None,
            "action": "remove_transition",
            "severity": SEVERITY_SIGNIFICANT,
        })

    return changes


# ---------------------------------------------------------------------------
# Call graph diffing
# ---------------------------------------------------------------------------

def _diff_call_graphs(old_calls, new_calls):
    """Diff function call lists between builds."""
    changes = []

    if not old_calls and not new_calls:
        return changes

    # Normalize to sets of function names
    def _name_set(calls):
        names = set()
        for c in calls:
            if isinstance(c, str):
                names.add(c)
            elif isinstance(c, dict):
                name = c.get("name", c.get("func_name", ""))
                if name:
                    names.add(name)
        return names

    old_names = _name_set(old_calls)
    new_names = _name_set(new_calls)

    for name in sorted(new_names - old_names):
        # Filter out decompiler artifacts
        if name.startswith("sub_") or name.startswith("j_"):
            sev = SEVERITY_COSMETIC
        else:
            sev = SEVERITY_MINOR
        changes.append({
            "category": "call_graph",
            "description": f"New function call: {name}",
            "old": None,
            "new": name,
            "action": "add_call",
            "severity": sev,
        })

    for name in sorted(old_names - new_names):
        if name.startswith("sub_") or name.startswith("j_"):
            sev = SEVERITY_COSMETIC
        else:
            sev = SEVERITY_MINOR
        changes.append({
            "category": "call_graph",
            "description": f"Removed function call: {name}",
            "old": name,
            "new": None,
            "action": "remove_call",
            "severity": sev,
        })

    return changes


# ---------------------------------------------------------------------------
# Per-handler semantic diff
# ---------------------------------------------------------------------------

def _compute_handler_diff(old_handler, new_handler, handler_name):
    """Compute the full semantic diff for a single handler.

    Compares wire format, validations, responses, error codes, constants,
    state transitions, and call graph.

    Returns a diff result dict.
    """
    all_changes = []

    # 1. Wire format diff
    wire_changes = _diff_wire_formats(
        old_handler.get("fields", []),
        new_handler.get("fields", [])
    )
    all_changes.extend(wire_changes)

    # 2. Validation diff
    val_changes = _diff_validations(
        old_handler.get("validations", []),
        new_handler.get("validations", [])
    )
    all_changes.extend(val_changes)

    # 3. Response diff
    resp_changes = _diff_responses(
        old_handler.get("responses", []),
        new_handler.get("responses", [])
    )
    all_changes.extend(resp_changes)

    # 4. Error code diff (standalone, beyond validation-embedded ones)
    ec_changes = _diff_error_codes(
        old_handler.get("error_codes", []),
        new_handler.get("error_codes", [])
    )
    all_changes.extend(ec_changes)

    # 5. Constant diff
    const_changes = _diff_constants(
        old_handler.get("constants", []),
        new_handler.get("constants", [])
    )
    all_changes.extend(const_changes)

    # 6. State transition diff
    st_changes = _diff_state_transitions(
        old_handler.get("state_transitions", []),
        new_handler.get("state_transitions", [])
    )
    all_changes.extend(st_changes)

    # 7. Call graph diff
    cg_changes = _diff_call_graphs(
        old_handler.get("call_graph", []),
        new_handler.get("call_graph", [])
    )
    all_changes.extend(cg_changes)

    # Determine overall change type and severity
    if not all_changes:
        change_type = CHANGE_UNCHANGED
        severity = SEVERITY_COSMETIC
    else:
        change_type = CHANGE_MODIFIED
        # Overall severity is the highest severity among all changes
        severity_order = [SEVERITY_BREAKING, SEVERITY_SIGNIFICANT,
                          SEVERITY_MINOR, SEVERITY_COSMETIC]
        severity = SEVERITY_COSMETIC
        for c in all_changes:
            c_sev = c.get("severity", SEVERITY_COSMETIC)
            if severity_order.index(c_sev) < severity_order.index(severity):
                severity = c_sev

    return {
        "handler": handler_name,
        "change_type": change_type,
        "severity": severity,
        "direction": new_handler.get("direction", old_handler.get("direction", "CMSG")),
        "change_count": len(all_changes),
        "changes": all_changes,
    }


# ---------------------------------------------------------------------------
# TC patch generation
# ---------------------------------------------------------------------------

def _opcode_to_handler_func(opcode_name):
    """Convert CMSG_HOUSING_DECOR_PLACE -> HandleHousingDecorPlace."""
    if opcode_name.startswith("CMSG_") or opcode_name.startswith("SMSG_"):
        parts = opcode_name.split("_")[1:]
        return "Handle" + "".join(p.capitalize() for p in parts)
    return opcode_name


def _opcode_to_packet_class(opcode_name):
    """Convert CMSG_HOUSING_DECOR_PLACE -> HousingDecorPlace."""
    for prefix in ("CMSG_", "SMSG_", "MSG_"):
        if opcode_name.startswith(prefix):
            opcode_name = opcode_name[len(prefix):]
            break
    return "".join(p.capitalize() for p in opcode_name.split("_"))


_TYPE_TO_CPP = {
    "uint8": "uint8", "int8": "int8",
    "uint16": "uint16", "int16": "int16",
    "uint32": "uint32", "int32": "int32",
    "uint64": "uint64", "int64": "int64",
    "float": "float", "double": "double",
    "bit": "bool", "bits": "uint32",
    "packed_guid": "ObjectGuid", "ObjectGuid": "ObjectGuid",
    "string": "std::string",
}


def generate_tc_patch(session, handler_name=None):
    """Generate TrinityCore source patches from stored build delta.

    If handler_name is specified, generates patch for that handler only.
    Otherwise generates patches for all changed handlers.

    Returns the patch text as a string.
    """
    db = session.db
    delta = db.kv_get("build_delta")
    if not delta:
        msg_warn("No build delta available. Run analyze_build_delta first.")
        return ""

    old_build = delta.get("old_build", "?")
    new_build = delta.get("new_build", "?")
    handler_diffs = delta.get("handler_diffs", {})

    if handler_name:
        if handler_name not in handler_diffs:
            msg_warn(f"No diff data for handler '{handler_name}'")
            return ""
        handlers_to_patch = {handler_name: handler_diffs[handler_name]}
    else:
        # Only patch handlers that actually changed
        handlers_to_patch = {
            name: diff for name, diff in handler_diffs.items()
            if diff.get("change_type") in (CHANGE_MODIFIED, CHANGE_NEW)
        }

    if not handlers_to_patch:
        return f"// No changes to patch (build {old_build} -> {new_build})\n"

    lines = []
    lines.append(f"// ====================================================================")
    lines.append(f"// TrinityCore Patch: Build {old_build} -> {new_build}")
    lines.append(f"// Auto-generated by TC WoW Analyzer - Build Delta Transpiler")
    lines.append(f"// Handlers with changes: {len(handlers_to_patch)}")
    lines.append(f"// ====================================================================")
    lines.append(f"")

    for name, diff in sorted(handlers_to_patch.items()):
        handler_func = _opcode_to_handler_func(name)
        packet_class = _opcode_to_packet_class(name)
        change_type = diff.get("change_type", CHANGE_MODIFIED)
        severity = diff.get("severity", SEVERITY_MINOR)
        changes = diff.get("changes", [])
        direction = diff.get("direction", "CMSG")

        lines.append(f"// === PATCH for {handler_func} ===")
        lines.append(f"// Opcode: {name} ({direction})")
        lines.append(f"// Change type: {change_type}, Severity: {severity}")
        lines.append(f"// Build delta: {old_build} -> {new_build}")
        lines.append(f"//")

        if change_type == CHANGE_NEW:
            lines.append(f"// NEW HANDLER: {name} was added in build {new_build}")
            lines.append(f"// Manual implementation required.")
            lines.append(f"//")
            lines.append(f"// 1. Add opcode enum: {name}")
            lines.append(f"// 2. Create packet class: WorldPackets::{packet_class}")
            lines.append(f"// 3. Implement handler: WorldSession::{handler_func}")
            lines.append(f"// 4. Register in Opcodes.cpp")
            lines.append(f"")
            continue

        change_num = 0
        for change in changes:
            change_num += 1
            category = change.get("category", "unknown")
            action = change.get("action", "unknown")
            desc = change.get("description", "")
            old_val = change.get("old")
            new_val = change.get("new")

            lines.append(f"// CHANGE {change_num}: [{category}] {desc}")

            if action == "add_field":
                field_idx = change.get("field_index", "?")
                cpp_type = _TYPE_TO_CPP.get(new_val, "uint32") if new_val else "uint32"
                lines.append(f"//")
                lines.append(f"// In WorldPackets::{packet_class} struct:")
                lines.append(f"// ADD member:")
                lines.append(f"//     {cpp_type} NewField_{field_idx} = 0;  // {new_val}, added in build {new_build}")
                lines.append(f"//")
                lines.append(f"// In WorldPackets::{packet_class}::Read():")
                lines.append(f"// ADD after field {field_idx - 1 if isinstance(field_idx, int) and field_idx > 0 else '?'}:")
                lines.append(f"//     _worldPacket >> NewField_{field_idx};")

            elif action == "remove_field":
                field_idx = change.get("field_index", "?")
                lines.append(f"//")
                lines.append(f"// In WorldPackets::{packet_class} struct:")
                lines.append(f"// REMOVE member at old position {field_idx} ({old_val})")
                lines.append(f"//")
                lines.append(f"// In WorldPackets::{packet_class}::Read():")
                lines.append(f"// REMOVE the corresponding read call")

            elif action == "change_type":
                field_idx = change.get("field_index", "?")
                old_cpp = _TYPE_TO_CPP.get(old_val, old_val or "?")
                new_cpp = _TYPE_TO_CPP.get(new_val, new_val or "?")
                lines.append(f"//")
                lines.append(f"// In WorldPackets::{packet_class} struct:")
                lines.append(f"// CHANGE field {field_idx}:")
                lines.append(f"//     {old_cpp} -> {new_cpp}")

            elif action == "change_bit_width":
                field_idx = change.get("field_index", "?")
                lines.append(f"//")
                lines.append(f"// In WorldPackets::{packet_class}::Read():")
                lines.append(f"// CHANGE ReadBits call at field {field_idx}:")
                lines.append(f"//     ReadBits({old_val}) -> ReadBits({new_val})")

            elif action == "change_optionality":
                field_idx = change.get("field_index", "?")
                lines.append(f"//")
                lines.append(f"// In WorldPackets::{packet_class}::Read():")
                if new_val == "optional":
                    lines.append(f"// WRAP field {field_idx} read in Optional<> and add bit flag:")
                    lines.append(f"//     bool has_field_{field_idx} = _worldPacket.ReadBit();")
                    lines.append(f"//     if (has_field_{field_idx})")
                    lines.append(f"//         _worldPacket >> Field_{field_idx};")
                else:
                    lines.append(f"// UNWRAP field {field_idx} from Optional<> — now always present")

            elif action == "add_validation":
                lines.append(f"//")
                lines.append(f"// In WorldSession::{handler_func}():")
                lines.append(f"// ADD validation check:")
                if new_val:
                    # Try to format as a C++ if-statement
                    lines.append(f"//     {new_val}")
                else:
                    lines.append(f"//     // (check details not available)")

            elif action == "remove_validation":
                lines.append(f"//")
                lines.append(f"// In WorldSession::{handler_func}():")
                lines.append(f"// REMOVE validation check:")
                lines.append(f"//     // Old check: {old_val}")

            elif action == "change_threshold":
                lines.append(f"//")
                lines.append(f"// In WorldSession::{handler_func}():")
                lines.append(f"// UPDATE threshold value:")
                lines.append(f"//     REPLACE: {old_val}")
                lines.append(f"//     WITH:    {new_val}")

            elif action in ("update_error_code", "add_error_code", "remove_error_code"):
                lines.append(f"//")
                lines.append(f"// In WorldSession::{handler_func}() or result enum:")
                if old_val and new_val:
                    lines.append(f"//     REPLACE error code: {old_val} -> {new_val}")
                elif new_val:
                    lines.append(f"//     ADD error code handling for: {new_val}")
                elif old_val:
                    lines.append(f"//     REMOVE error code: {old_val}")

            elif action == "update_constant":
                lines.append(f"//")
                lines.append(f"// UPDATE game rule constant:")
                lines.append(f"//     REPLACE: {old_val}")
                lines.append(f"//     WITH:    {new_val}")

            elif action in ("add_response", "remove_response"):
                lines.append(f"//")
                if action == "add_response":
                    lines.append(f"// ADD new response packet class for: {new_val}")
                    lines.append(f"// Implement Write() method and register SMSG opcode")
                else:
                    lines.append(f"// REMOVE response packet: {old_val}")

            elif action in ("add_transition", "remove_transition"):
                lines.append(f"//")
                if action == "add_transition":
                    lines.append(f"// ADD state transition: {new_val}")
                else:
                    lines.append(f"// REMOVE state transition: {old_val}")

            elif action in ("add_call", "remove_call"):
                lines.append(f"//")
                if action == "add_call":
                    lines.append(f"// NEW function call to: {new_val}")
                    lines.append(f"// (Review binary to determine call context)")
                else:
                    lines.append(f"// REMOVED function call to: {old_val}")

            elif action == "layout_changed":
                lines.append(f"//")
                lines.append(f"// Old layout: {old_val}")
                lines.append(f"// New layout: {new_val}")

            else:
                lines.append(f"//   old: {old_val}")
                lines.append(f"//   new: {new_val}")

            lines.append(f"//")

        lines.append(f"")

    result = "\n".join(lines)

    # Store the generated patch
    db.kv_set("build_delta_patch", result)
    db.commit()

    msg_info(f"Generated TC patch for {len(handlers_to_patch)} handlers")
    return result


# ---------------------------------------------------------------------------
# Migration report
# ---------------------------------------------------------------------------

def generate_migration_report(session):
    """Generate a comprehensive migration report from the stored build delta.

    Returns a formatted report string.
    """
    db = session.db
    delta = db.kv_get("build_delta")
    if not delta:
        msg_warn("No build delta available. Run analyze_build_delta first.")
        return "No build delta data available.\n"

    old_build = delta.get("old_build", "?")
    new_build = delta.get("new_build", "?")
    handler_diffs = delta.get("handler_diffs", {})
    summary = delta.get("summary", {})

    lines = []
    lines.append(f"=" * 72)
    lines.append(f"BUILD MIGRATION REPORT: {old_build} -> {new_build}")
    lines.append(f"=" * 72)
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"")

    # --- Summary ---
    total = summary.get("total_handlers", 0)
    modified = summary.get("modified", 0)
    new_count = summary.get("new", 0)
    removed = summary.get("removed", 0)
    unchanged = summary.get("unchanged", 0)

    lines.append(f"SUMMARY")
    lines.append(f"-" * 72)
    lines.append(f"  Total handlers compared: {total}")
    lines.append(f"  Modified:   {modified}")
    lines.append(f"  New:        {new_count}")
    lines.append(f"  Removed:    {removed}")
    lines.append(f"  Unchanged:  {unchanged}")
    lines.append(f"")

    # --- Severity breakdown ---
    breaking = []
    significant = []
    minor = []
    cosmetic = []
    new_handlers = []
    removed_handlers = []

    for name, diff in sorted(handler_diffs.items()):
        ct = diff.get("change_type", CHANGE_UNCHANGED)
        sev = diff.get("severity", SEVERITY_COSMETIC)

        if ct == CHANGE_NEW:
            new_handlers.append(name)
        elif ct == CHANGE_REMOVED:
            removed_handlers.append(name)
        elif ct == CHANGE_MODIFIED:
            if sev == SEVERITY_BREAKING:
                breaking.append((name, diff))
            elif sev == SEVERITY_SIGNIFICANT:
                significant.append((name, diff))
            elif sev == SEVERITY_MINOR:
                minor.append((name, diff))
            else:
                cosmetic.append((name, diff))

    # --- Breaking changes ---
    lines.append(f"BREAKING CHANGES ({len(breaking)} handlers)")
    lines.append(f"-" * 72)
    if breaking:
        for name, diff in breaking:
            direction = diff.get("direction", "CMSG")
            change_count = diff.get("change_count", 0)
            lines.append(f"  [{direction}] {name} ({change_count} changes)")
            for change in diff.get("changes", []):
                if change.get("severity") == SEVERITY_BREAKING:
                    lines.append(f"    ! {change.get('description', '?')}")
    else:
        lines.append(f"  (none)")
    lines.append(f"")

    # --- Significant changes ---
    lines.append(f"SIGNIFICANT CHANGES ({len(significant)} handlers)")
    lines.append(f"-" * 72)
    if significant:
        for name, diff in significant:
            direction = diff.get("direction", "CMSG")
            change_count = diff.get("change_count", 0)
            lines.append(f"  [{direction}] {name} ({change_count} changes)")
            for change in diff.get("changes", []):
                if change.get("severity") in (SEVERITY_BREAKING, SEVERITY_SIGNIFICANT):
                    lines.append(f"    * {change.get('description', '?')}")
    else:
        lines.append(f"  (none)")
    lines.append(f"")

    # --- Minor changes ---
    lines.append(f"MINOR CHANGES ({len(minor)} handlers)")
    lines.append(f"-" * 72)
    if minor:
        for name, diff in minor:
            direction = diff.get("direction", "CMSG")
            change_count = diff.get("change_count", 0)
            lines.append(f"  [{direction}] {name} ({change_count} changes)")
    else:
        lines.append(f"  (none)")
    lines.append(f"")

    # --- Cosmetic changes ---
    lines.append(f"COSMETIC CHANGES ({len(cosmetic)} handlers)")
    lines.append(f"-" * 72)
    if cosmetic:
        for name, _ in cosmetic:
            lines.append(f"  {name}")
    else:
        lines.append(f"  (none)")
    lines.append(f"")

    # --- New handlers ---
    lines.append(f"NEW HANDLERS ({len(new_handlers)})")
    lines.append(f"-" * 72)
    if new_handlers:
        for name in new_handlers:
            diff = handler_diffs.get(name, {})
            direction = diff.get("direction", "CMSG")
            lines.append(f"  [{direction}] {name}")
    else:
        lines.append(f"  (none)")
    lines.append(f"")

    # --- Removed handlers ---
    lines.append(f"REMOVED HANDLERS ({len(removed_handlers)})")
    lines.append(f"-" * 72)
    if removed_handlers:
        for name in removed_handlers:
            diff = handler_diffs.get(name, {})
            direction = diff.get("direction", "CMSG")
            lines.append(f"  [{direction}] {name}")
    else:
        lines.append(f"  (none)")
    lines.append(f"")

    # --- Patchability assessment ---
    auto_patchable = 0
    manual_review = 0
    for name, diff in handler_diffs.items():
        ct = diff.get("change_type", CHANGE_UNCHANGED)
        if ct == CHANGE_UNCHANGED:
            continue
        if ct == CHANGE_NEW or ct == CHANGE_REMOVED:
            manual_review += 1
            continue

        # A handler is auto-patchable if all its changes have clear actions
        changes = diff.get("changes", [])
        patchable_actions = {
            "update_constant", "change_threshold", "update_error_code",
            "rename_field", "change_signedness", "add_error_code",
            "remove_error_code", "layout_changed",
        }
        all_patchable = all(
            c.get("action") in patchable_actions for c in changes
        ) if changes else False

        if all_patchable:
            auto_patchable += 1
        else:
            manual_review += 1

    lines.append(f"PATCHABILITY ASSESSMENT")
    lines.append(f"-" * 72)
    lines.append(f"  Auto-patchable (constant/threshold changes): {auto_patchable}")
    lines.append(f"  Requires manual review:                      {manual_review}")
    lines.append(f"")
    lines.append(f"=" * 72)

    report = "\n".join(lines)

    # Store the report
    db.kv_set("build_delta_migration_report", report)
    db.commit()

    msg_info(f"Migration report generated: {modified + new_count + removed} "
             f"total changes across {total} handlers")
    return report


# ---------------------------------------------------------------------------
# Retrieval helpers
# ---------------------------------------------------------------------------

def get_build_delta(session):
    """Retrieve the stored build delta from the knowledge DB.

    Returns the full delta dict, or None if no delta has been computed.
    """
    return session.db.kv_get("build_delta")


def get_breaking_changes(session):
    """Retrieve only breaking changes from the stored build delta.

    Returns a list of handler diff dicts with severity == 'breaking'.
    """
    delta = session.db.kv_get("build_delta")
    if not delta:
        return []

    breaking = []
    for name, diff in delta.get("handler_diffs", {}).items():
        if diff.get("severity") == SEVERITY_BREAKING:
            breaking.append(diff)

    return breaking


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _generate_baseline_report(session):
    """Generate a baseline report when there is only one build (no old DB).

    Catalogues the current build's stats: opcodes, functions, DB2 tables,
    JAM types, vtables, and detected systems. Stores the result in kv_store
    under "build_baseline" and returns the total number of items catalogued.
    """
    db = session.db
    cfg = session.cfg
    build_number = cfg.build_number

    msg_info(f"No old build data — generating baseline report for build {build_number}")

    # Count core tables
    opcode_count = db.count("opcodes")
    function_count = db.count("functions")
    db2_count = db.count("db2_tables")
    jam_count = db.count("jam_types")
    vtable_count = db.count("vtables")

    # Count opcodes by direction
    direction_counts = {}
    try:
        rows = db.fetchall(
            "SELECT direction, COUNT(*) AS cnt FROM opcodes GROUP BY direction"
        )
        for row in rows:
            direction_counts[row["direction"] or "unknown"] = row["cnt"]
    except Exception:
        pass

    # Count opcodes by status
    status_counts = {}
    try:
        rows = db.fetchall(
            "SELECT status, COUNT(*) AS cnt FROM opcodes GROUP BY status"
        )
        for row in rows:
            status_counts[row["status"] or "unknown"] = row["cnt"]
    except Exception:
        pass

    # Detect systems from functions table
    systems_detected = []
    try:
        rows = db.fetchall(
            "SELECT system, COUNT(*) AS cnt FROM functions "
            "WHERE system IS NOT NULL GROUP BY system ORDER BY cnt DESC"
        )
        systems_detected = [
            {"system": row["system"], "function_count": row["cnt"]}
            for row in rows
        ]
    except Exception:
        pass

    # Count named functions
    named_function_count = 0
    try:
        row = db.fetchone(
            "SELECT COUNT(*) AS cnt FROM functions WHERE name IS NOT NULL "
            "AND name NOT LIKE 'sub_%'"
        )
        if row:
            named_function_count = row["cnt"]
    except Exception:
        pass

    # Count opcodes with handler_ea
    handler_count = 0
    try:
        row = db.fetchone(
            "SELECT COUNT(*) AS cnt FROM opcodes WHERE handler_ea IS NOT NULL"
        )
        if row:
            handler_count = row["cnt"]
    except Exception:
        pass

    # Count opcodes with tc_name
    matched_count = 0
    try:
        row = db.fetchone(
            "SELECT COUNT(*) AS cnt FROM opcodes WHERE tc_name IS NOT NULL"
        )
        if row:
            matched_count = row["cnt"]
    except Exception:
        pass

    # Count opcodes with jam_type
    jam_linked_count = 0
    try:
        row = db.fetchone(
            "SELECT COUNT(*) AS cnt FROM opcodes "
            "WHERE jam_type IS NOT NULL AND jam_type != '' AND jam_type != 'none'"
        )
        if row:
            jam_linked_count = row["cnt"]
    except Exception:
        pass

    # Count cached pseudocode
    cached_pseudocode_count = 0
    try:
        row = db.fetchone(
            "SELECT COUNT(*) AS cnt FROM cfunc_cache WHERE pseudocode IS NOT NULL"
        )
        if row:
            cached_pseudocode_count = row["cnt"]
    except Exception:
        pass

    total_items = (opcode_count + function_count + db2_count
                   + jam_count + vtable_count)

    baseline = {
        "build_number": build_number,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_items_catalogued": total_items,
            "opcodes": opcode_count,
            "functions": function_count,
            "named_functions": named_function_count,
            "db2_tables": db2_count,
            "jam_types": jam_count,
            "vtables": vtable_count,
            "handlers_with_ea": handler_count,
            "handlers_matched": matched_count,
            "handlers_jam_linked": jam_linked_count,
            "cached_pseudocode": cached_pseudocode_count,
        },
        "direction_breakdown": direction_counts,
        "status_breakdown": status_counts,
        "systems_detected": systems_detected,
    }

    db.kv_set("build_baseline", baseline)
    db.commit()

    msg_info(f"Baseline report for build {build_number}:")
    msg_info(f"  Opcodes:        {opcode_count}")
    msg_info(f"  Functions:      {function_count} ({named_function_count} named)")
    msg_info(f"  DB2 tables:     {db2_count}")
    msg_info(f"  JAM types:      {jam_count}")
    msg_info(f"  VTables:        {vtable_count}")
    msg_info(f"  Handlers w/ EA: {handler_count}")
    msg_info(f"  JAM linked:     {jam_linked_count}")
    msg_info(f"  Cached decompilations: {cached_pseudocode_count}")
    if systems_detected:
        msg_info(f"  Systems detected: {len(systems_detected)}")
        for s in systems_detected[:10]:
            msg(f"    {s['system']}: {s['function_count']} functions")

    return total_items


def analyze_build_delta(session, old_build_data_path):
    """Main entry point: diff two builds' analysis data handler-by-handler.

    Loads the old build's knowledge DB or JSON export, compares against
    the current build's data in the session DB, computes semantic diffs
    for each handler, and stores the complete delta in kv_store.

    If old_build_data_path is None or doesn't exist, generates a baseline
    report of the current build instead of returning 0.

    Args:
        session: PluginSession with .db and .cfg
        old_build_data_path: Path to old build's .db/.json/directory

    Returns:
        Number of changes found (total change entries across all handlers),
        or total items catalogued for baseline mode.
    """
    db = session.db
    cfg = session.cfg
    start = time.time()

    # If no old build path provided, generate baseline report instead
    if not old_build_data_path or not os.path.exists(old_build_data_path):
        return _generate_baseline_report(session)

    msg_info(f"Starting cross-build delta analysis...")
    msg_info(f"Old build data: {old_build_data_path}")

    # 1. Load old build data
    old_data = _load_old_build_data(old_build_data_path)
    if not old_data:
        msg_error("Failed to load old build data")
        return _generate_baseline_report(session)

    old_build = old_data["build_number"]
    old_handlers = old_data["handlers"]

    if not old_handlers:
        msg_error("No handlers found in old build data")
        return 0

    # 2. Load current build data
    new_data = _load_current_build_data(session)
    new_build = new_data["build_number"]
    new_handlers = new_data["handlers"]

    msg_info(f"Comparing build {old_build} ({len(old_handlers)} handlers) "
             f"-> {new_build} ({len(new_handlers)} handlers)")

    # 3. Compute diffs for each handler
    all_handler_names = set(old_handlers.keys()) | set(new_handlers.keys())
    handler_diffs = {}

    total_changes = 0
    modified_count = 0
    new_count = 0
    removed_count = 0
    unchanged_count = 0

    for handler_name in sorted(all_handler_names):
        old_h = old_handlers.get(handler_name)
        new_h = new_handlers.get(handler_name)

        if old_h and new_h:
            # Present in both builds -- compute semantic diff
            diff = _compute_handler_diff(old_h, new_h, handler_name)

            if diff["change_type"] == CHANGE_UNCHANGED:
                unchanged_count += 1
            else:
                modified_count += 1
                total_changes += diff["change_count"]

        elif new_h and not old_h:
            # New handler in this build
            diff = {
                "handler": handler_name,
                "change_type": CHANGE_NEW,
                "severity": SEVERITY_BREAKING,
                "direction": new_h.get("direction", "CMSG"),
                "change_count": 1,
                "changes": [{
                    "category": "handler",
                    "description": f"New handler added in build {new_build}",
                    "old": None,
                    "new": handler_name,
                    "action": "add_handler",
                    "severity": SEVERITY_BREAKING,
                }],
            }
            new_count += 1
            total_changes += 1

        else:
            # Handler removed in new build
            diff = {
                "handler": handler_name,
                "change_type": CHANGE_REMOVED,
                "severity": SEVERITY_BREAKING,
                "direction": old_h.get("direction", "CMSG"),
                "change_count": 1,
                "changes": [{
                    "category": "handler",
                    "description": f"Handler removed in build {new_build}",
                    "old": handler_name,
                    "new": None,
                    "action": "remove_handler",
                    "severity": SEVERITY_BREAKING,
                }],
            }
            removed_count += 1
            total_changes += 1

        handler_diffs[handler_name] = diff

    # 4. Build summary
    summary = {
        "old_build": old_build,
        "new_build": new_build,
        "total_handlers": len(all_handler_names),
        "modified": modified_count,
        "new": new_count,
        "removed": removed_count,
        "unchanged": unchanged_count,
        "total_changes": total_changes,
        "elapsed_seconds": time.time() - start,
    }

    # 5. Store in kv_store
    delta = {
        "old_build": old_build,
        "new_build": new_build,
        "summary": summary,
        "handler_diffs": handler_diffs,
        "timestamp": time.time(),
    }

    db.kv_set("build_delta", delta)
    db.commit()

    elapsed = time.time() - start
    msg_info(f"Build delta analysis complete in {elapsed:.1f}s")
    msg_info(f"  Total handlers:  {len(all_handler_names)}")
    msg_info(f"  Modified:        {modified_count}")
    msg_info(f"  New:             {new_count}")
    msg_info(f"  Removed:         {removed_count}")
    msg_info(f"  Unchanged:       {unchanged_count}")
    msg_info(f"  Total changes:   {total_changes}")

    # Count breaking changes for the summary line
    breaking_count = sum(
        1 for d in handler_diffs.values()
        if d.get("severity") == SEVERITY_BREAKING
        and d.get("change_type") != CHANGE_UNCHANGED
    )
    if breaking_count > 0:
        msg_warn(f"  BREAKING changes: {breaking_count} handlers affected")

    return total_changes
