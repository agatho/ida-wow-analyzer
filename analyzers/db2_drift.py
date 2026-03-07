"""
DB2 Schema Drift Detector
Compares DB2Meta structures from the binary against TrinityCore's LoadInfo
definitions to find mismatches in field count, types, record size, and
layout hashes.

This catches cases where a WoW patch added/changed DB2 fields that TC
hasn't picked up yet — a common source of data loading bugs.
"""

import json
import os
import re

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# TrinityCore LoadInfo type char → normalized type name
TC_TYPE_CHAR_MAP = {
    "b": "int8", "h": "int16", "i": "int32", "l": "int64",
    "f": "float", "s": "string",
}


def analyze_db2_drift(session):
    """Compare binary DB2 metadata against TrinityCore LoadInfo definitions.

    Requires:
      - db2_tables populated (from binary analysis or JSON import)
      - TrinityCore source available (tc_source_dir configured)

    Stores results in kv_store under 'db2_drift_report'.
    """
    db = session.db
    cfg = session.cfg

    # Load binary-side DB2 metadata
    binary_tables = {}
    for row in db.fetchall("SELECT * FROM db2_tables"):
        binary_tables[row["name"]] = dict(row)

    if not binary_tables:
        msg_warn("No DB2 tables in knowledge DB. Run DB2 metadata import first.")
        return 0

    msg_info(f"Binary has {len(binary_tables)} DB2 tables")

    # Load TC-side LoadInfo from source
    tc_tables = _parse_tc_loadinfo(cfg)
    msg_info(f"TrinityCore defines {len(tc_tables)} DB2 LoadInfo structs")

    # Also try to parse from DB2Structure.h for entry struct field counts
    tc_structs = _parse_tc_db2_structures(cfg)
    msg_info(f"TrinityCore defines {len(tc_structs)} DB2 Entry structs")

    # Compare
    drift_items = []

    # Tables in binary but not in TC
    binary_only = set(binary_tables.keys()) - set(tc_tables.keys()) - set(tc_structs.keys())
    for name in sorted(binary_only):
        bt = binary_tables[name]
        if bt["field_count"] and bt["field_count"] > 0:
            drift_items.append({
                "table": name,
                "severity": "missing",
                "message": f"Exists in binary ({bt['field_count']} fields, "
                           f"recSize={bt['record_size']}) but NOT in TrinityCore",
                "binary_fields": bt["field_count"],
                "tc_fields": 0,
            })

    # Tables in both — compare field counts and layout hashes
    for name in sorted(set(binary_tables.keys()) & set(tc_tables.keys())):
        bt = binary_tables[name]
        tc = tc_tables[name]

        issues = []

        # Field count mismatch
        if bt["field_count"] and tc.get("field_count"):
            if bt["field_count"] != tc["field_count"]:
                diff = bt["field_count"] - tc["field_count"]
                direction = "more" if diff > 0 else "fewer"
                issues.append(
                    f"Field count: binary={bt['field_count']}, "
                    f"TC={tc['field_count']} ({abs(diff)} {direction} in binary)"
                )

        # Layout hash mismatch
        bt_hash = bt.get("layout_hash", 0)
        tc_hash = tc.get("layout_hash", 0)
        if bt_hash and tc_hash and bt_hash != tc_hash:
            issues.append(
                f"Layout hash: binary=0x{bt_hash:08X}, TC=0x{tc_hash:08X}"
            )

        # Record size mismatch
        bt_size = bt.get("record_size", 0)
        tc_size = tc.get("record_size", 0)
        if bt_size and tc_size and bt_size != tc_size:
            issues.append(
                f"Record size: binary={bt_size}, TC={tc_size} "
                f"(delta={bt_size - tc_size})"
            )

        # Type string mismatch
        bt_types = bt.get("fields_json")
        tc_types = tc.get("type_string")
        if bt_types and tc_types:
            try:
                bt_fields = json.loads(bt_types) if isinstance(bt_types, str) else bt_types
                bt_type_str = "".join(
                    TC_TYPE_CHAR_MAP.get(f.get("type", "i")[0], "?")
                    for f in bt_fields
                )
                if bt_type_str != tc_types:
                    issues.append(f"Type string: binary='{bt_type_str}', TC='{tc_types}'")
            except (json.JSONDecodeError, TypeError, KeyError):
                pass

        if issues:
            severity = "error" if any("Field count" in i for i in issues) else "warning"
            drift_items.append({
                "table": name,
                "severity": severity,
                "message": "; ".join(issues),
                "binary_fields": bt.get("field_count", 0),
                "tc_fields": tc.get("field_count", 0),
            })

    # Tables in TC but not in binary (possibly removed or renamed)
    tc_only = (set(tc_tables.keys()) | set(tc_structs.keys())) - set(binary_tables.keys())
    for name in sorted(tc_only):
        drift_items.append({
            "table": name,
            "severity": "info",
            "message": "Defined in TrinityCore but not found in binary "
                       "(possibly renamed or build-specific)",
            "binary_fields": 0,
            "tc_fields": tc_tables.get(name, {}).get("field_count", 0),
        })

    # Store results
    report = {
        "total_binary": len(binary_tables),
        "total_tc": len(tc_tables),
        "drift_items": drift_items,
        "errors": sum(1 for d in drift_items if d["severity"] == "error"),
        "warnings": sum(1 for d in drift_items if d["severity"] == "warning"),
        "missing": sum(1 for d in drift_items if d["severity"] == "missing"),
        "info": sum(1 for d in drift_items if d["severity"] == "info"),
    }

    db.kv_set("db2_drift_report", report)
    db.commit()

    msg_info(f"DB2 drift analysis: {report['errors']} errors, "
             f"{report['warnings']} warnings, {report['missing']} missing in TC")
    return len(drift_items)


def _parse_tc_loadinfo(cfg):
    """Parse TrinityCore DB2LoadInfo.h to extract LoadInfo definitions."""
    tc_dir = cfg.tc_source_dir
    if not tc_dir:
        return {}

    # Search for DB2LoadInfo files
    results = {}
    for root, dirs, files in os.walk(os.path.join(tc_dir, "src")):
        for fname in files:
            if "LoadInfo" in fname and fname.endswith(".h"):
                filepath = os.path.join(root, fname)
                results.update(_parse_loadinfo_file(filepath))
    return results


def _parse_loadinfo_file(filepath):
    """Parse a single LoadInfo header for type strings and field counts."""
    results = {}
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return results

    # Match patterns like: constexpr char const* Types = "iisfhbi";
    # or: static char const* const types = "iisfhbi";
    type_pattern = re.compile(
        r'(?:struct|namespace)\s+(\w+?)(?:LoadInfo|Meta)\b.*?'
        r'[Tt]ypes?\s*=\s*"([^"]+)"',
        re.DOTALL
    )
    for m in type_pattern.finditer(content):
        name = m.group(1)
        type_str = m.group(2)
        results[name] = {
            "field_count": len(type_str),
            "type_string": type_str,
        }

    # Also match layout hash: constexpr uint32 LayoutHash = 0xA3B7C2D1;
    hash_pattern = re.compile(
        r'(\w+?)(?:LoadInfo|Meta).*?LayoutHash\s*=\s*(0x[0-9A-Fa-f]+)',
        re.DOTALL
    )
    for m in hash_pattern.finditer(content):
        name = m.group(1)
        layout_hash = int(m.group(2), 16)
        if name in results:
            results[name]["layout_hash"] = layout_hash
        else:
            results[name] = {"layout_hash": layout_hash}

    return results


def _parse_tc_db2_structures(cfg):
    """Parse DB2Structure.h for Entry struct field counts."""
    tc_dir = cfg.tc_source_dir
    if not tc_dir:
        return {}

    struct_file = os.path.join(tc_dir, "src", "server", "game",
                               "DataStores", "DB2Structure.h")
    if not os.path.isfile(struct_file):
        return {}

    results = {}
    try:
        with open(struct_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return results

    # Match struct definitions and count members
    struct_pattern = re.compile(
        r'struct\s+(\w+)Entry\s*\{([^}]+)\}',
        re.DOTALL
    )
    for m in struct_pattern.finditer(content):
        name = m.group(1)
        body = m.group(2)
        # Count semicolons (member declarations) excluding comments
        lines = [l.strip() for l in body.split("\n")
                 if l.strip() and not l.strip().startswith("//")]
        field_count = sum(1 for l in lines if ";" in l and not l.startswith("//"))
        results[name] = {"field_count": field_count}

    return results


def get_drift_report(session):
    """Retrieve the stored drift report."""
    return session.db.kv_get("db2_drift_report") or {}
