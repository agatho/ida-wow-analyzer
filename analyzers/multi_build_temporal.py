"""
Multi-Build Temporal Evolution Analyzer

Tracks WoW binary evolution across multiple builds, identifying trends,
deprecated features, and upcoming changes.  Loads per-build analysis data
from JSON exports and/or KnowledgeDB snapshots referenced in the config
"builds" section, then constructs a timeline of opcode, JAM type, and DB2
schema changes.

Key capabilities:
  - Opcode evolution timeline with volatility scoring
  - JAM message field-level change tracking
  - DB2 schema evolution (table and field counts)
  - System-level activity trend detection
  - Deprecation candidate identification
  - Predictive scoring for opcodes likely to change next
  - CSV export for external visualization
"""

import json
import os
import re
import time
from collections import defaultdict, OrderedDict

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Opcode naming convention for system classification
_SYSTEM_PREFIXES = OrderedDict([
    ("HOUSING",       "housing"),
    ("NEIGHBORHOOD",  "neighborhood"),
    ("GARRISON",      "garrison"),
    ("QUEST",         "quest"),
    ("GUILD",         "guild"),
    ("AUCTION",       "auction"),
    ("ACHIEVEMENT",   "achievement"),
    ("PET_BATTLE",    "pet_battle"),
    ("BATTLE_PET",    "pet_battle"),
    ("BATTLEGROUND",  "pvp"),
    ("BATTLEFIELD",   "pvp"),
    ("ARENA",         "pvp"),
    ("MYTHIC_PLUS",   "mythic_plus"),
    ("CHALLENGE",     "mythic_plus"),
    ("DELVES",        "delves"),
    ("CLUB",          "social"),
    ("SOCIAL",        "social"),
    ("CHAT",          "social"),
    ("VOICE",         "social"),
    ("CALENDAR",      "calendar"),
    ("EQUIPMENT",     "inventory"),
    ("ITEM",          "inventory"),
    ("LOOT",          "loot"),
    ("SPELL",         "combat"),
    ("CAST",          "combat"),
    ("ATTACK",        "combat"),
    ("AURA",          "combat"),
    ("MOVE",          "movement"),
    ("CHARACTER",     "character"),
    ("CHAR",          "character"),
    ("TALENT",        "talent"),
    ("TRADE_SKILL",   "profession"),
    ("CRAFT",         "profession"),
    ("LFG",           "lfg"),
    ("TAXI",          "travel"),
    ("VEHICLE",       "vehicle"),
    ("PET",           "pet"),
    ("NPC",           "npc"),
    ("TRAINER",       "npc"),
    ("GOSSIP",        "npc"),
    ("MAIL",          "mail"),
    ("WARBAND",       "warband"),
    ("ACCOUNT",       "account"),
    ("TOKEN",         "token"),
    ("COLLECTION",    "collection"),
    ("TRANSMOG",      "collection"),
    ("TRANSMOGRIFY",  "collection"),
    ("TOY",           "collection"),
    ("MOUNT",         "collection"),
    ("MAP",           "world"),
    ("WORLD",         "world"),
    ("WEATHER",       "world"),
    ("WHO",           "social"),
    ("INSPECT",       "social"),
    ("DUEL",          "pvp"),
    ("SCENARIO",      "scenario"),
    ("ISLAND",        "island"),
])

# How many builds of inactivity before flagging deprecation
_DEPRECATION_INACTIVITY_THRESHOLD = 2

# Volatility classification thresholds
_VOLATILITY_LOW = 0.15
_VOLATILITY_MEDIUM = 0.40
_VOLATILITY_HIGH = 0.70

# Confidence levels for predictions
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


# ---------------------------------------------------------------------------
# System classification helper
# ---------------------------------------------------------------------------

def _classify_opcode_system(opcode_name):
    """Classify an opcode into a game system based on its name prefix."""
    if not opcode_name:
        return "unknown"
    # Strip CMSG_ / SMSG_ prefix for matching
    stripped = opcode_name
    for prefix in ("CMSG_", "SMSG_", "MSG_"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
            break

    for pattern, system in _SYSTEM_PREFIXES.items():
        if stripped.startswith(pattern):
            return system
    return "other"


# ---------------------------------------------------------------------------
# Build data loading
# ---------------------------------------------------------------------------

def _load_build_json(directory, filename):
    """Load a single JSON file from a build's export directory.

    Returns parsed data or None on failure.
    """
    path = os.path.join(directory, filename)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        msg_warn(f"Could not load {path}: {exc}")
        return None


def _normalize_opcodes_from_list(raw_list):
    """Convert a list of opcode dicts into a name-keyed dict.

    Handles various JSON export formats:
      - [{"tc_name": "CMSG_FOO", "direction": "CMSG", ...}, ...]
      - [{"name": "CMSG_FOO", ...}, ...]
      - {"CMSG_FOO": {...}, ...}  (already a dict)
    """
    if isinstance(raw_list, dict):
        return raw_list
    result = {}
    if not isinstance(raw_list, list):
        return result
    for entry in raw_list:
        if not isinstance(entry, dict):
            continue
        name = entry.get("tc_name") or entry.get("name") or entry.get("opcode_name")
        if name:
            result[name] = entry
    return result


def _normalize_jam_types(raw):
    """Normalize JAM type data into a name-keyed dict."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list):
        result = {}
        for entry in raw:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("type_name")
                if name:
                    result[name] = entry
        return result
    return {}


def _normalize_db2_tables(raw):
    """Normalize DB2 table data into a name-keyed dict."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list):
        result = {}
        for entry in raw:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("table_name")
                if name:
                    result[name] = entry
        return result
    return {}


def _load_build_from_directory(build_dir):
    """Load all analysis data from a build's export directory.

    Looks for standard JSON export filenames produced by the pipeline:
      opcodes.json / opcode_dispatch.json
      jam_types.json / jam_recovery.json
      db2_tables.json / db2_metadata.json
      functions.json
      vtables.json
      lua_api.json
      wire_formats.json
      build_info.json

    Returns a normalized dict or None.
    """
    if not os.path.isdir(build_dir):
        return None

    build_data = {
        "opcodes": {},
        "jam_types": {},
        "db2_tables": {},
        "functions": {},
        "vtables": {},
        "lua_api": {},
        "wire_formats": {},
        "build_number": 0,
        "source_dir": build_dir,
    }

    # Build info
    build_info = _load_build_json(build_dir, "build_info.json")
    if build_info and isinstance(build_info, dict):
        build_data["build_number"] = build_info.get("build_number", 0)

    # Try to extract build number from directory name if not found
    if not build_data["build_number"]:
        dirname = os.path.basename(build_dir)
        m = re.search(r"(\d{5,6})", dirname)
        if m:
            build_data["build_number"] = int(m.group(1))

    # Opcodes
    for fname in ("opcodes.json", "opcode_dispatch.json", "opcode_handlers.json"):
        raw = _load_build_json(build_dir, fname)
        if raw:
            build_data["opcodes"] = _normalize_opcodes_from_list(raw)
            break

    # JAM types
    for fname in ("jam_types.json", "jam_recovery.json", "jam_messages.json"):
        raw = _load_build_json(build_dir, fname)
        if raw:
            build_data["jam_types"] = _normalize_jam_types(raw)
            break

    # DB2 tables
    for fname in ("db2_tables.json", "db2_metadata.json", "db2_meta.json"):
        raw = _load_build_json(build_dir, fname)
        if raw:
            build_data["db2_tables"] = _normalize_db2_tables(raw)
            break

    # Wire formats
    raw = _load_build_json(build_dir, "wire_formats.json")
    if raw and isinstance(raw, dict):
        build_data["wire_formats"] = raw

    # Functions — just load the count for trend analysis
    raw = _load_build_json(build_dir, "functions.json")
    if raw:
        if isinstance(raw, list):
            build_data["functions"] = {str(i): e for i, e in enumerate(raw)}
        elif isinstance(raw, dict):
            build_data["functions"] = raw

    # Vtables
    raw = _load_build_json(build_dir, "vtables.json")
    if raw:
        if isinstance(raw, list):
            build_data["vtables"] = {str(i): e for i, e in enumerate(raw)}
        elif isinstance(raw, dict):
            build_data["vtables"] = raw

    # Lua API
    raw = _load_build_json(build_dir, "lua_api.json")
    if raw:
        if isinstance(raw, list):
            build_data["lua_api"] = {str(i): e for i, e in enumerate(raw)}
        elif isinstance(raw, dict):
            build_data["lua_api"] = raw

    return build_data


def _load_build_from_db(db_path):
    """Load build data from a previous analysis session's KnowledgeDB.

    Opens the SQLite database read-only and extracts opcodes, JAM types,
    DB2 tables, and function/vtable counts.
    """
    import sqlite3

    if not os.path.isfile(db_path):
        return None

    build_data = {
        "opcodes": {},
        "jam_types": {},
        "db2_tables": {},
        "functions": {},
        "vtables": {},
        "lua_api": {},
        "wire_formats": {},
        "build_number": 0,
        "source_db": db_path,
    }

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
    except Exception as exc:
        msg_warn(f"Could not open DB {db_path}: {exc}")
        return None

    try:
        # Build number
        try:
            row = conn.execute(
                "SELECT build_number FROM builds ORDER BY build_number DESC LIMIT 1"
            ).fetchone()
            if row:
                build_data["build_number"] = row["build_number"]
        except Exception:
            pass

        if not build_data["build_number"]:
            try:
                row = conn.execute(
                    "SELECT value FROM kv_store WHERE key = 'build_number'"
                ).fetchone()
                if row:
                    build_data["build_number"] = int(json.loads(row["value"]))
            except Exception:
                pass

        # Opcodes
        try:
            for row in conn.execute("SELECT * FROM opcodes WHERE tc_name IS NOT NULL"):
                name = row["tc_name"]
                build_data["opcodes"][name] = {
                    "tc_name": name,
                    "direction": row["direction"],
                    "internal_index": row["internal_index"],
                    "wire_opcode": row["wire_opcode"],
                    "handler_ea": row["handler_ea"],
                    "jam_type": row["jam_type"],
                    "status": row["status"],
                }
        except Exception:
            pass

        # JAM types
        try:
            for row in conn.execute("SELECT * FROM jam_types"):
                name = row["name"]
                fields = []
                if row["fields_json"]:
                    try:
                        fields = json.loads(row["fields_json"])
                    except (json.JSONDecodeError, TypeError):
                        pass
                build_data["jam_types"][name] = {
                    "name": name,
                    "field_count": row["field_count"],
                    "fields": fields,
                    "wire_size": row["wire_size"],
                    "status": row["status"],
                }
        except Exception:
            pass

        # DB2 tables
        try:
            for row in conn.execute("SELECT * FROM db2_tables"):
                name = row["name"]
                fields = []
                if row["fields_json"]:
                    try:
                        fields = json.loads(row["fields_json"])
                    except (json.JSONDecodeError, TypeError):
                        pass
                build_data["db2_tables"][name] = {
                    "name": name,
                    "field_count": row["field_count"],
                    "record_size": row["record_size"],
                    "layout_hash": row["layout_hash"],
                    "fields": fields,
                }
        except Exception:
            pass

        # Function count
        try:
            row = conn.execute("SELECT COUNT(*) as cnt FROM functions").fetchone()
            if row:
                build_data["_function_count"] = row["cnt"]
        except Exception:
            pass

        # Vtable count
        try:
            row = conn.execute("SELECT COUNT(*) as cnt FROM vtables").fetchone()
            if row:
                build_data["_vtable_count"] = row["cnt"]
        except Exception:
            pass

        # Wire formats from kv_store
        try:
            row = conn.execute(
                "SELECT value FROM kv_store WHERE key = 'wire_formats'"
            ).fetchone()
            if row:
                build_data["wire_formats"] = json.loads(row["value"])
        except Exception:
            pass

    except Exception as exc:
        msg_warn(f"Error reading DB {db_path}: {exc}")
    finally:
        conn.close()

    return build_data


def _load_all_builds(session):
    """Load data from all configured builds.

    Sources:
      1. session.cfg "builds" config section — each entry may have:
         - "extraction_dir": path to JSON export directory
         - "db_path": path to a KnowledgeDB for that build
      2. kv_store "build_delta" from the build_delta analyzer
      3. The current session's own DB as the latest build

    Returns an OrderedDict keyed by build_number, sorted ascending.
    """
    builds = {}

    # ---- Source 1: Config "builds" section ----
    builds_cfg = session.cfg.get("builds", default={})
    if isinstance(builds_cfg, dict):
        for build_str, info in builds_cfg.items():
            if not isinstance(info, dict):
                continue
            build_num = 0
            try:
                build_num = int(build_str)
            except (ValueError, TypeError):
                continue
            if build_num == 0:
                continue

            # Try extraction_dir first, then db_path
            build_data = None
            ext_dir = info.get("extraction_dir")
            if ext_dir:
                build_data = _load_build_from_directory(ext_dir)

            if not build_data:
                db_path = info.get("db_path")
                if db_path:
                    build_data = _load_build_from_db(db_path)

            # Also check for enriched_dir which may contain the exports
            if not build_data:
                enriched_dir = info.get("enriched_dir")
                if enriched_dir:
                    build_data = _load_build_from_directory(enriched_dir)

            if build_data:
                build_data["build_number"] = build_num
                builds[build_num] = build_data
                msg_info(f"Loaded build {build_num}: "
                         f"{len(build_data['opcodes'])} opcodes, "
                         f"{len(build_data['jam_types'])} JAM types, "
                         f"{len(build_data['db2_tables'])} DB2 tables")

    # ---- Source 2: kv_store "build_delta" from build_delta analyzer ----
    if session.db:
        delta_data = session.db.kv_get("build_delta")
        if delta_data and isinstance(delta_data, dict):
            old_build = delta_data.get("old_build_number", 0)
            new_build = delta_data.get("new_build_number", 0)

            # The delta contains change information we can use to enrich timeline
            if old_build and old_build not in builds:
                # We don't have full data, but we know this build existed
                old_data = delta_data.get("old_build_data")
                if old_data and isinstance(old_data, dict):
                    builds[old_build] = {
                        "opcodes": _normalize_opcodes_from_list(
                            old_data.get("opcodes", {})
                        ),
                        "jam_types": _normalize_jam_types(
                            old_data.get("jam_types", {})
                        ),
                        "db2_tables": _normalize_db2_tables(
                            old_data.get("db2_tables", {})
                        ),
                        "build_number": old_build,
                        "source": "build_delta_kv",
                    }

    # ---- Source 3: Current session's DB as the latest build ----
    current_build = 0
    if session.cfg:
        current_build = session.cfg.build_number

    if current_build and session.db:
        current_data = {
            "opcodes": {},
            "jam_types": {},
            "db2_tables": {},
            "build_number": current_build,
            "source": "current_session",
        }

        try:
            for row in session.db.fetchall(
                "SELECT * FROM opcodes WHERE tc_name IS NOT NULL"
            ):
                name = row["tc_name"]
                current_data["opcodes"][name] = {
                    "tc_name": name,
                    "direction": row["direction"],
                    "internal_index": row["internal_index"],
                    "wire_opcode": row["wire_opcode"],
                    "handler_ea": row["handler_ea"],
                    "jam_type": row["jam_type"],
                    "status": row["status"],
                }
        except Exception:
            pass

        try:
            for row in session.db.fetchall("SELECT * FROM jam_types"):
                name = row["name"]
                fields = []
                if row["fields_json"]:
                    try:
                        fields = json.loads(row["fields_json"])
                    except (json.JSONDecodeError, TypeError):
                        pass
                current_data["jam_types"][name] = {
                    "name": name,
                    "field_count": row["field_count"],
                    "fields": fields,
                    "wire_size": row["wire_size"],
                    "status": row["status"],
                }
        except Exception:
            pass

        try:
            for row in session.db.fetchall("SELECT * FROM db2_tables"):
                name = row["name"]
                fields = []
                if row["fields_json"]:
                    try:
                        fields = json.loads(row["fields_json"])
                    except (json.JSONDecodeError, TypeError):
                        pass
                current_data["db2_tables"][name] = {
                    "name": name,
                    "field_count": row["field_count"],
                    "record_size": row["record_size"],
                    "layout_hash": row["layout_hash"],
                    "fields": fields,
                }
        except Exception:
            pass

        if (current_data["opcodes"] or current_data["jam_types"]
                or current_data["db2_tables"]):
            builds[current_build] = current_data

    # Sort by build number ascending
    sorted_builds = OrderedDict()
    for bn in sorted(builds.keys()):
        sorted_builds[bn] = builds[bn]

    return sorted_builds


# ---------------------------------------------------------------------------
# Opcode evolution timeline
# ---------------------------------------------------------------------------

def _build_opcode_timeline(builds):
    """Build per-opcode timeline tracking additions, removals, and modifications.

    Returns a dict: opcode_name -> {
        "first_seen": build_number,
        "last_seen": build_number,
        "builds_present": [list of build numbers],
        "changes": [{"build": N, "action": "added"/"removed"/"modified", "detail": ...}],
        "change_count": int,
        "volatility": float,  # 0.0 (stable) to 1.0 (changes every build)
        "direction": str,
        "system": str,
    }
    """
    build_numbers = sorted(builds.keys())
    if not build_numbers:
        return {}

    # Collect all opcode names across all builds
    all_opcodes = set()
    for _bn, bdata in builds.items():
        all_opcodes.update(bdata.get("opcodes", {}).keys())

    timeline = {}

    for opcode_name in sorted(all_opcodes):
        entry = {
            "first_seen": 0,
            "last_seen": 0,
            "builds_present": [],
            "changes": [],
            "change_count": 0,
            "volatility": 0.0,
            "direction": "",
            "system": _classify_opcode_system(opcode_name),
        }

        prev_data = None
        prev_present = False

        for bn in build_numbers:
            bdata = builds[bn]
            opcodes = bdata.get("opcodes", {})
            current_present = opcode_name in opcodes
            current_data = opcodes.get(opcode_name)

            if current_present:
                entry["builds_present"].append(bn)
                if not entry["first_seen"]:
                    entry["first_seen"] = bn
                entry["last_seen"] = bn

                if current_data:
                    direction = current_data.get("direction", "")
                    if direction and not entry["direction"]:
                        entry["direction"] = direction

                if not prev_present:
                    # Appeared in this build
                    entry["changes"].append({
                        "build": bn,
                        "action": "added",
                        "detail": "First appearance" if not prev_data
                                  else "Re-added after removal",
                    })
                else:
                    # Present in both builds — check for modifications
                    if prev_data and current_data:
                        diffs = _diff_opcode_entry(prev_data, current_data)
                        if diffs:
                            entry["changes"].append({
                                "build": bn,
                                "action": "modified",
                                "detail": "; ".join(diffs),
                            })
            else:
                if prev_present:
                    # Removed in this build
                    entry["changes"].append({
                        "build": bn,
                        "action": "removed",
                        "detail": "No longer present",
                    })

            prev_present = current_present
            prev_data = current_data

        entry["change_count"] = len(entry["changes"])

        # Volatility: ratio of builds with changes to total build gaps
        num_gaps = len(build_numbers) - 1
        if num_gaps > 0:
            entry["volatility"] = round(
                entry["change_count"] / max(num_gaps, 1), 4
            )
        else:
            entry["volatility"] = 0.0

        timeline[opcode_name] = entry

    return timeline


def _diff_opcode_entry(old, new):
    """Compare two opcode entries and return a list of difference descriptions."""
    diffs = []

    # Internal index change
    old_idx = old.get("internal_index")
    new_idx = new.get("internal_index")
    if old_idx is not None and new_idx is not None and old_idx != new_idx:
        diffs.append(f"index changed 0x{old_idx:X} -> 0x{new_idx:X}")

    # Wire opcode change
    old_wire = old.get("wire_opcode")
    new_wire = new.get("wire_opcode")
    if old_wire is not None and new_wire is not None and old_wire != new_wire:
        diffs.append(f"wire opcode changed 0x{old_wire:X} -> 0x{new_wire:X}")

    # JAM type change
    old_jam = old.get("jam_type")
    new_jam = new.get("jam_type")
    if old_jam and new_jam and old_jam != new_jam:
        diffs.append(f"JAM type changed {old_jam} -> {new_jam}")

    # Handler EA change (indicates recompilation, always expected but notable)
    old_ea = old.get("handler_ea")
    new_ea = new.get("handler_ea")
    if old_ea and new_ea and old_ea != new_ea:
        diffs.append("handler address changed")

    # Status change
    old_status = old.get("status")
    new_status = new.get("status")
    if old_status and new_status and old_status != new_status:
        diffs.append(f"status {old_status} -> {new_status}")

    return diffs


# ---------------------------------------------------------------------------
# JAM type evolution
# ---------------------------------------------------------------------------

def _build_jam_evolution(builds):
    """Track per-JAM-type field changes across builds.

    Returns a dict: type_name -> {
        "first_seen": build_number,
        "last_seen": build_number,
        "field_changes": [{"build": N, "action": str, "field": str, "detail": str}],
        "field_count_history": [{"build": N, "count": int}],
        "trend": "growing" / "shrinking" / "stable",
    }
    """
    build_numbers = sorted(builds.keys())
    if not build_numbers:
        return {}

    all_types = set()
    for _bn, bdata in builds.items():
        all_types.update(bdata.get("jam_types", {}).keys())

    evolution = {}

    for type_name in sorted(all_types):
        entry = {
            "first_seen": 0,
            "last_seen": 0,
            "field_changes": [],
            "field_count_history": [],
            "trend": "stable",
        }

        prev_fields = None
        prev_count = None

        for bn in build_numbers:
            bdata = builds[bn]
            jam_types = bdata.get("jam_types", {})
            jt = jam_types.get(type_name)
            if not jt:
                continue

            if not entry["first_seen"]:
                entry["first_seen"] = bn
            entry["last_seen"] = bn

            current_fields = jt.get("fields", [])
            current_count = jt.get("field_count", len(current_fields))

            entry["field_count_history"].append({
                "build": bn,
                "count": current_count,
            })

            if prev_fields is not None:
                changes = _diff_jam_fields(prev_fields, current_fields, bn)
                entry["field_changes"].extend(changes)

            if prev_count is not None and current_count != prev_count:
                delta = current_count - prev_count
                direction = "added" if delta > 0 else "removed"
                entry["field_changes"].append({
                    "build": bn,
                    "action": f"field_count_{direction}",
                    "field": "",
                    "detail": f"Field count {prev_count} -> {current_count} "
                              f"(delta: {delta:+d})",
                })

            prev_fields = current_fields
            prev_count = current_count

        # Determine trend from field count history
        counts = [h["count"] for h in entry["field_count_history"] if h["count"]]
        if len(counts) >= 2:
            if counts[-1] > counts[0]:
                entry["trend"] = "growing"
            elif counts[-1] < counts[0]:
                entry["trend"] = "shrinking"

        evolution[type_name] = entry

    return evolution


def _diff_jam_fields(old_fields, new_fields, build_number):
    """Diff two field lists and return change records."""
    changes = []

    if not isinstance(old_fields, list) or not isinstance(new_fields, list):
        return changes

    # Build name-keyed lookups
    old_by_name = {}
    for f in old_fields:
        if isinstance(f, dict):
            fname = f.get("name") or f.get("field_name", "")
            if fname:
                old_by_name[fname] = f

    new_by_name = {}
    for f in new_fields:
        if isinstance(f, dict):
            fname = f.get("name") or f.get("field_name", "")
            if fname:
                new_by_name[fname] = f

    # Fields added
    for fname in sorted(set(new_by_name.keys()) - set(old_by_name.keys())):
        ftype = new_by_name[fname].get("type", "unknown")
        changes.append({
            "build": build_number,
            "action": "field_added",
            "field": fname,
            "detail": f"New field: {fname} ({ftype})",
        })

    # Fields removed
    for fname in sorted(set(old_by_name.keys()) - set(new_by_name.keys())):
        ftype = old_by_name[fname].get("type", "unknown")
        changes.append({
            "build": build_number,
            "action": "field_removed",
            "field": fname,
            "detail": f"Removed field: {fname} ({ftype})",
        })

    # Fields modified
    for fname in sorted(set(old_by_name.keys()) & set(new_by_name.keys())):
        old_f = old_by_name[fname]
        new_f = new_by_name[fname]
        old_type = old_f.get("type", "")
        new_type = new_f.get("type", "")
        if old_type and new_type and old_type != new_type:
            changes.append({
                "build": build_number,
                "action": "field_retyped",
                "field": fname,
                "detail": f"Type change: {old_type} -> {new_type}",
            })

        old_offset = old_f.get("offset")
        new_offset = new_f.get("offset")
        if (old_offset is not None and new_offset is not None
                and old_offset != new_offset):
            changes.append({
                "build": build_number,
                "action": "field_reordered",
                "field": fname,
                "detail": f"Offset change: {old_offset} -> {new_offset}",
            })

    # Detect reordering via positional comparison
    old_order = [
        (f.get("name") or f.get("field_name", ""))
        for f in old_fields if isinstance(f, dict)
    ]
    new_order = [
        (f.get("name") or f.get("field_name", ""))
        for f in new_fields if isinstance(f, dict)
    ]
    old_order = [n for n in old_order if n]
    new_order = [n for n in new_order if n]

    if old_order and new_order:
        common = [n for n in old_order if n in set(new_order)]
        common_new = [n for n in new_order if n in set(old_order)]
        if common != common_new and len(common) > 1:
            changes.append({
                "build": build_number,
                "action": "fields_reordered",
                "field": "",
                "detail": "Field ordering changed for common fields",
            })

    return changes


# ---------------------------------------------------------------------------
# DB2 schema evolution
# ---------------------------------------------------------------------------

def _build_db2_evolution(builds):
    """Track DB2 table additions, removals, and field count changes.

    Returns a dict: table_name -> {
        "first_seen": build_number,
        "last_seen": build_number,
        "field_count_history": [{"build": N, "count": int}],
        "record_size_history": [{"build": N, "size": int}],
        "layout_hash_history": [{"build": N, "hash": int}],
        "change_count": int,
        "trend": "growing" / "shrinking" / "stable" / "volatile",
    }
    """
    build_numbers = sorted(builds.keys())
    if not build_numbers:
        return {}

    all_tables = set()
    for _bn, bdata in builds.items():
        all_tables.update(bdata.get("db2_tables", {}).keys())

    evolution = {}

    for table_name in sorted(all_tables):
        entry = {
            "first_seen": 0,
            "last_seen": 0,
            "field_count_history": [],
            "record_size_history": [],
            "layout_hash_history": [],
            "change_count": 0,
            "trend": "stable",
        }

        prev_count = None
        prev_hash = None
        changes = 0

        for bn in build_numbers:
            bdata = builds[bn]
            db2s = bdata.get("db2_tables", {})
            table = db2s.get(table_name)
            if not table:
                continue

            if not entry["first_seen"]:
                entry["first_seen"] = bn
            entry["last_seen"] = bn

            fc = table.get("field_count", 0)
            rs = table.get("record_size", 0)
            lh = table.get("layout_hash", 0)

            entry["field_count_history"].append({"build": bn, "count": fc})
            if rs:
                entry["record_size_history"].append({"build": bn, "size": rs})
            if lh:
                entry["layout_hash_history"].append({"build": bn, "hash": lh})

            if prev_count is not None and fc != prev_count:
                changes += 1
            if prev_hash is not None and lh and prev_hash and lh != prev_hash:
                changes += 1

            prev_count = fc
            prev_hash = lh

        entry["change_count"] = changes

        # Trend from field counts
        counts = [h["count"] for h in entry["field_count_history"] if h["count"]]
        if len(counts) >= 2:
            if counts[-1] > counts[0]:
                entry["trend"] = "growing"
            elif counts[-1] < counts[0]:
                entry["trend"] = "shrinking"
            elif changes >= len(counts):
                entry["trend"] = "volatile"

        evolution[table_name] = entry

    return evolution


# ---------------------------------------------------------------------------
# System activity analysis
# ---------------------------------------------------------------------------

def _compute_system_activity(opcode_timeline):
    """Aggregate opcode changes by game system to find the most active areas.

    Returns a list of {system, total_changes, opcode_count, avg_volatility,
    trend, top_opcodes}.
    """
    system_stats = defaultdict(lambda: {
        "total_changes": 0,
        "opcode_count": 0,
        "volatility_sum": 0.0,
        "opcodes": [],
    })

    for opcode_name, entry in opcode_timeline.items():
        system = entry.get("system", "other")
        stats = system_stats[system]
        stats["total_changes"] += entry["change_count"]
        stats["opcode_count"] += 1
        stats["volatility_sum"] += entry["volatility"]
        if entry["change_count"] > 0:
            stats["opcodes"].append({
                "name": opcode_name,
                "changes": entry["change_count"],
                "volatility": entry["volatility"],
            })

    result = []
    for system, stats in sorted(system_stats.items(),
                                 key=lambda x: -x[1]["total_changes"]):
        avg_vol = (stats["volatility_sum"] / stats["opcode_count"]
                   if stats["opcode_count"] > 0 else 0.0)

        # Trend: classify based on average volatility
        if avg_vol >= _VOLATILITY_HIGH:
            trend = "very_active"
        elif avg_vol >= _VOLATILITY_MEDIUM:
            trend = "active"
        elif avg_vol >= _VOLATILITY_LOW:
            trend = "moderate"
        else:
            trend = "stable"

        # Top opcodes by change count
        top = sorted(stats["opcodes"], key=lambda x: -x["changes"])[:10]

        result.append({
            "system": system,
            "total_changes": stats["total_changes"],
            "opcode_count": stats["opcode_count"],
            "avg_volatility": round(avg_vol, 4),
            "trend": trend,
            "top_opcodes": top,
        })

    return result


# ---------------------------------------------------------------------------
# Trend detection: protocol size over builds
# ---------------------------------------------------------------------------

def _compute_protocol_trends(builds, opcode_timeline):
    """Compute per-build protocol size metrics and moving averages.

    Returns a dict with:
      - per_build: [{"build": N, "cmsg_count": ..., "smsg_count": ..., "total": ...}]
      - moving_avg: [{"build": N, "avg_total": float}]
      - overall_trend: "growing" / "shrinking" / "stable"
    """
    build_numbers = sorted(builds.keys())
    per_build = []

    for bn in build_numbers:
        bdata = builds[bn]
        opcodes = bdata.get("opcodes", {})
        cmsg_count = sum(
            1 for o in opcodes.values()
            if isinstance(o, dict) and o.get("direction") == "CMSG"
        )
        smsg_count = sum(
            1 for o in opcodes.values()
            if isinstance(o, dict) and o.get("direction") == "SMSG"
        )
        total = len(opcodes)
        per_build.append({
            "build": bn,
            "cmsg_count": cmsg_count,
            "smsg_count": smsg_count,
            "total": total,
        })

    # Moving average with window 3
    window = 3
    moving_avg = []
    for i, entry in enumerate(per_build):
        start = max(0, i - window + 1)
        window_slice = per_build[start:i + 1]
        avg = sum(e["total"] for e in window_slice) / len(window_slice)
        moving_avg.append({
            "build": entry["build"],
            "avg_total": round(avg, 2),
        })

    # Overall trend
    overall = "stable"
    if len(per_build) >= 2:
        first_total = per_build[0]["total"]
        last_total = per_build[-1]["total"]
        if first_total > 0:
            ratio = last_total / first_total
            if ratio > 1.05:
                overall = "growing"
            elif ratio < 0.95:
                overall = "shrinking"

    return {
        "per_build": per_build,
        "moving_avg": moving_avg,
        "overall_trend": overall,
    }


# ---------------------------------------------------------------------------
# Deprecation detection
# ---------------------------------------------------------------------------

def _detect_deprecation_candidates(opcode_timeline, builds):
    """Identify opcodes that may be deprecated or on their way out.

    Signals:
      - Last seen N+ builds ago (removed and not re-added)
      - Shrinking handler complexity (if wire format data available)
      - Removal of validation rules
      - Present but status changed to 'unused' or similar

    Returns a list of {opcode, reason, last_active_build, confidence}.
    """
    build_numbers = sorted(builds.keys())
    if len(build_numbers) < 2:
        return []

    latest_build = build_numbers[-1]
    candidates = []

    for opcode_name, entry in opcode_timeline.items():
        reasons = []
        confidence = CONFIDENCE_LOW

        # Not present in latest build
        if latest_build not in entry.get("builds_present", []):
            if entry["last_seen"]:
                gap = 0
                for bn in reversed(build_numbers):
                    if bn == entry["last_seen"]:
                        break
                    gap += 1

                if gap >= _DEPRECATION_INACTIVITY_THRESHOLD:
                    reasons.append(
                        f"Not present in last {gap} builds "
                        f"(last seen: {entry['last_seen']})"
                    )
                    confidence = CONFIDENCE_HIGH
                elif gap >= 1:
                    reasons.append(
                        f"Missing from latest build "
                        f"(last seen: {entry['last_seen']})"
                    )
                    confidence = CONFIDENCE_MEDIUM

        # Check for removal as last change
        changes = entry.get("changes", [])
        if changes and changes[-1].get("action") == "removed":
            reasons.append("Last observed change was removal")
            if confidence == CONFIDENCE_LOW:
                confidence = CONFIDENCE_MEDIUM

        # Check for very low presence ratio across builds
        presence_ratio = (len(entry.get("builds_present", []))
                          / max(len(build_numbers), 1))
        if presence_ratio < 0.3 and len(build_numbers) >= 3:
            reasons.append(
                f"Low presence ratio: "
                f"{len(entry.get('builds_present', []))}/{len(build_numbers)} builds"
            )

        if reasons:
            candidates.append({
                "opcode": opcode_name,
                "reason": "; ".join(reasons),
                "last_active_build": entry["last_seen"],
                "confidence": confidence,
                "system": entry.get("system", "unknown"),
            })

    # Sort by confidence (high first), then by last active build
    priority = {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_LOW: 2}
    candidates.sort(key=lambda c: (priority.get(c["confidence"], 9),
                                   c["last_active_build"]))

    return candidates


# ---------------------------------------------------------------------------
# Prediction engine
# ---------------------------------------------------------------------------

def _predict_upcoming_changes(opcode_timeline, jam_evolution, builds):
    """Predict which opcodes/types are likely to change in the next build.

    Heuristics:
      - High volatility opcodes are likely to change again
      - Opcodes in actively developed systems
      - JAM types with recent field additions (more changes coming)
      - Opcodes that changed in the last N builds (momentum)

    Returns a list of {opcode, predicted_action, confidence, reason}.
    """
    build_numbers = sorted(builds.keys())
    if len(build_numbers) < 2:
        return []

    predictions = []
    latest_build = build_numbers[-1]
    recent_builds = set(build_numbers[-min(3, len(build_numbers)):])

    # Compute system-level recent activity
    system_recent_changes = defaultdict(int)
    for opcode_name, entry in opcode_timeline.items():
        for change in entry.get("changes", []):
            if change["build"] in recent_builds:
                system_recent_changes[entry.get("system", "other")] += 1

    for opcode_name, entry in opcode_timeline.items():
        reasons = []
        predicted_action = "modified"
        confidence = CONFIDENCE_LOW
        score = 0.0

        volatility = entry.get("volatility", 0.0)
        change_count = entry.get("change_count", 0)
        system = entry.get("system", "other")

        # Factor 1: High volatility
        if volatility >= _VOLATILITY_HIGH:
            score += 3.0
            reasons.append(f"High volatility ({volatility:.2f})")
        elif volatility >= _VOLATILITY_MEDIUM:
            score += 1.5
            reasons.append(f"Medium volatility ({volatility:.2f})")

        # Factor 2: Changed in recent builds (momentum)
        recent_changes = sum(
            1 for c in entry.get("changes", [])
            if c["build"] in recent_builds
        )
        if recent_changes >= 2:
            score += 2.5
            reasons.append(f"Changed in {recent_changes} of last "
                           f"{len(recent_builds)} builds")
        elif recent_changes >= 1:
            score += 1.0
            reasons.append("Changed in latest build window")

        # Factor 3: System is active
        sys_activity = system_recent_changes.get(system, 0)
        if sys_activity >= 10:
            score += 2.0
            reasons.append(f"System '{system}' very active "
                           f"({sys_activity} recent changes)")
        elif sys_activity >= 5:
            score += 1.0
            reasons.append(f"System '{system}' active "
                           f"({sys_activity} recent changes)")

        # Factor 4: JAM type has recent changes
        for jam_name, jam_entry in jam_evolution.items():
            # Match JAM type to opcode by naming convention
            if (opcode_name.replace("CMSG_", "").replace("SMSG_", "")
                    in jam_name.upper()):
                jam_changes = [
                    c for c in jam_entry.get("field_changes", [])
                    if c["build"] in recent_builds
                ]
                if jam_changes:
                    score += 1.5
                    reasons.append(f"Associated JAM type '{jam_name}' "
                                   f"has {len(jam_changes)} recent field changes")
                break

        # Factor 5: Recently added opcodes often get refined
        if change_count == 1 and entry.get("first_seen") == latest_build:
            score += 1.5
            predicted_action = "modified"
            reasons.append("Newly added in latest build — likely to be refined")

        # Factor 6: If last change was removal, predict it stays removed
        changes = entry.get("changes", [])
        if changes and changes[-1].get("action") == "removed":
            predicted_action = "remains_removed"
            score += 0.5
            reasons.append("Currently removed — may stay removed")

        # Determine confidence from score
        if score >= 4.0:
            confidence = CONFIDENCE_HIGH
        elif score >= 2.0:
            confidence = CONFIDENCE_MEDIUM
        else:
            confidence = CONFIDENCE_LOW

        # Only include predictions with at least some signal
        if score >= 1.5 and reasons:
            predictions.append({
                "opcode": opcode_name,
                "predicted_action": predicted_action,
                "confidence": confidence,
                "reason": "; ".join(reasons),
                "score": round(score, 2),
                "system": system,
            })

    # Sort by score descending
    predictions.sort(key=lambda p: -p["score"])

    return predictions


# ---------------------------------------------------------------------------
# Opcode rename detection
# ---------------------------------------------------------------------------

def _detect_opcode_renames(builds):
    """Detect opcodes that were likely renamed between builds.

    Heuristic: if an opcode at the same internal_index disappears in build N
    and a new name appears at that same index, it's a rename.

    Returns a list of {old_name, new_name, build, internal_index, direction}.
    """
    build_numbers = sorted(builds.keys())
    if len(build_numbers) < 2:
        return []

    renames = []

    for i in range(1, len(build_numbers)):
        prev_bn = build_numbers[i - 1]
        curr_bn = build_numbers[i]
        prev_opcodes = builds[prev_bn].get("opcodes", {})
        curr_opcodes = builds[curr_bn].get("opcodes", {})

        # Build index-to-name maps for each build
        prev_by_idx = {}
        for name, data in prev_opcodes.items():
            if isinstance(data, dict):
                idx = data.get("internal_index")
                direction = data.get("direction", "")
                if idx is not None:
                    key = (direction, idx)
                    prev_by_idx[key] = name

        curr_by_idx = {}
        for name, data in curr_opcodes.items():
            if isinstance(data, dict):
                idx = data.get("internal_index")
                direction = data.get("direction", "")
                if idx is not None:
                    key = (direction, idx)
                    curr_by_idx[key] = name

        # Find index keys that exist in both but with different names
        for key in set(prev_by_idx.keys()) & set(curr_by_idx.keys()):
            old_name = prev_by_idx[key]
            new_name = curr_by_idx[key]
            if old_name != new_name:
                direction, idx = key
                renames.append({
                    "old_name": old_name,
                    "new_name": new_name,
                    "build": curr_bn,
                    "internal_index": idx,
                    "direction": direction,
                })

    return renames


# ---------------------------------------------------------------------------
# Stable vs volatile opcode classification
# ---------------------------------------------------------------------------

def _classify_stability(opcode_timeline, build_count):
    """Classify each opcode as stable, moderate, or volatile.

    Returns a dict: opcode_name -> "stable" / "moderate" / "volatile".
    """
    result = {}
    for name, entry in opcode_timeline.items():
        vol = entry.get("volatility", 0.0)
        if vol >= _VOLATILITY_HIGH:
            result[name] = "volatile"
        elif vol >= _VOLATILITY_LOW:
            result[name] = "moderate"
        else:
            result[name] = "stable"
    return result


# ---------------------------------------------------------------------------
# TC update gap detection
# ---------------------------------------------------------------------------

def _detect_tc_update_gaps(opcode_timeline, builds):
    """Find opcodes that changed in recent builds but whose TC status
    hasn't been updated (still 'matched' or 'unknown').

    This flags things TrinityCore may need to update.

    Returns a list of {opcode, last_change_build, tc_status, changes_since_match}.
    """
    build_numbers = sorted(builds.keys())
    if not build_numbers:
        return []

    latest_build = build_numbers[-1]
    latest_opcodes = builds[latest_build].get("opcodes", {})
    gaps = []

    for opcode_name, entry in opcode_timeline.items():
        changes = entry.get("changes", [])
        if not changes:
            continue

        # Check TC status in latest build
        current = latest_opcodes.get(opcode_name, {})
        tc_status = current.get("status", "unknown") if isinstance(current, dict) else "unknown"

        # Count changes after the opcode was marked as "matched" in TC
        # (any change means TC's implementation might be stale)
        recent_modifications = [
            c for c in changes
            if c["action"] == "modified" and c["build"] >= build_numbers[-1]
        ]

        if recent_modifications and tc_status in ("matched", "verified"):
            gaps.append({
                "opcode": opcode_name,
                "last_change_build": changes[-1]["build"],
                "tc_status": tc_status,
                "changes_since_match": len(recent_modifications),
                "system": entry.get("system", "unknown"),
            })

    gaps.sort(key=lambda g: -g["changes_since_match"])
    return gaps


# ---------------------------------------------------------------------------
# Single-build baseline
# ---------------------------------------------------------------------------

def _generate_single_build_baseline(builds):
    """When only one build is available, generate useful baseline data.

    Returns a summary dict with per-system breakdowns.
    """
    if not builds:
        return {"note": "No build data available"}

    bn = next(iter(builds))
    bdata = builds[bn]
    opcodes = bdata.get("opcodes", {})
    jam_types = bdata.get("jam_types", {})
    db2_tables = bdata.get("db2_tables", {})

    # System breakdown
    system_breakdown = defaultdict(lambda: {"cmsg": 0, "smsg": 0, "total": 0})
    for name, data in opcodes.items():
        system = _classify_opcode_system(name)
        direction = data.get("direction", "") if isinstance(data, dict) else ""
        sb = system_breakdown[system]
        sb["total"] += 1
        if direction == "CMSG":
            sb["cmsg"] += 1
        elif direction == "SMSG":
            sb["smsg"] += 1

    # JAM type summary
    jam_with_fields = sum(
        1 for jt in jam_types.values()
        if isinstance(jt, dict) and jt.get("field_count", 0) > 0
    )

    # DB2 summary
    db2_with_fields = sum(
        1 for t in db2_tables.values()
        if isinstance(t, dict) and t.get("field_count", 0) > 0
    )

    return {
        "note": "Single build baseline — multi-build trend analysis requires "
                "2+ builds in the 'builds' config section",
        "build_number": bn,
        "total_opcodes": len(opcodes),
        "total_jam_types": len(jam_types),
        "jam_types_with_fields": jam_with_fields,
        "total_db2_tables": len(db2_tables),
        "db2_tables_with_fields": db2_with_fields,
        "system_breakdown": dict(system_breakdown),
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_temporal_evolution(session):
    """Analyze temporal evolution of WoW protocol across multiple builds.

    Loads per-build data from config "builds" directories / DBs, constructs
    evolution timelines for opcodes, JAM types, and DB2 tables, then runs
    trend detection and predictive analysis.

    Args:
        session: PluginSession with .db (KnowledgeDB) and .cfg (PluginConfig).

    Returns:
        int: Total number of items tracked (opcodes + JAM types + DB2 tables).

    Side effect:
        Stores full results in ``session.db.kv_set("temporal_evolution", {...})``.
    """
    start_time = time.time()
    msg("=" * 70)
    msg("Multi-Build Temporal Evolution Analyzer")
    msg("=" * 70)

    if not session.db:
        msg_error("No knowledge database available.")
        return 0

    # ---- Load all builds ----
    msg_info("Loading build data from configured sources...")
    builds = _load_all_builds(session)
    build_numbers = list(builds.keys())
    num_builds = len(build_numbers)

    if num_builds == 0:
        msg_warn("No build data found. Configure 'builds' in tc_wow_config.json "
                 "with extraction_dir or db_path for each build.")
        session.db.kv_set("temporal_evolution", {
            "builds_analyzed": 0,
            "build_numbers": [],
            "error": "No build data found",
        })
        session.db.commit()
        return 0

    msg_info(f"Loaded {num_builds} build(s): {build_numbers}")

    # ---- Single-build baseline ----
    if num_builds == 1:
        msg_warn("Only one build loaded. Generating single-build baseline. "
                 "Add more builds to 'builds' config for trend analysis.")
        baseline = _generate_single_build_baseline(builds)

        # Still build a basic opcode timeline (single snapshot)
        opcode_timeline = _build_opcode_timeline(builds)
        opcode_timeline_list = [
            {
                "opcode": name,
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
                "change_count": entry["change_count"],
                "volatility": entry["volatility"],
                "direction": entry["direction"],
                "system": entry["system"],
            }
            for name, entry in sorted(opcode_timeline.items())
        ]

        result = {
            "builds_analyzed": 1,
            "build_numbers": build_numbers,
            "single_build_baseline": baseline,
            "opcode_timeline": opcode_timeline_list,
            "jam_evolution": [],
            "db2_evolution": [],
            "system_activity": [],
            "protocol_trends": {},
            "predictions": [],
            "deprecation_candidates": [],
            "renames": [],
            "tc_update_gaps": [],
            "analysis_time_s": round(time.time() - start_time, 2),
        }

        total = len(opcode_timeline)
        session.db.kv_set("temporal_evolution", result)
        session.db.commit()

        msg_info(f"Single-build baseline: {baseline['total_opcodes']} opcodes, "
                 f"{baseline['total_jam_types']} JAM types, "
                 f"{baseline['total_db2_tables']} DB2 tables")
        msg(f"Analysis complete in {result['analysis_time_s']:.1f}s")
        return total

    # ---- Multi-build analysis ----

    # 1. Opcode evolution timeline
    msg_info("Building opcode evolution timeline...")
    opcode_timeline = _build_opcode_timeline(builds)
    msg(f"  Tracked {len(opcode_timeline)} unique opcodes across {num_builds} builds")

    volatile_count = sum(
        1 for e in opcode_timeline.values()
        if e["volatility"] >= _VOLATILITY_HIGH
    )
    stable_count = sum(
        1 for e in opcode_timeline.values()
        if e["volatility"] < _VOLATILITY_LOW
    )
    msg(f"  Volatile: {volatile_count}  Stable: {stable_count}  "
        f"Moderate: {len(opcode_timeline) - volatile_count - stable_count}")

    # 2. Opcode rename detection
    msg_info("Detecting opcode renames...")
    renames = _detect_opcode_renames(builds)
    if renames:
        msg(f"  Found {len(renames)} probable renames")
        for r in renames[:5]:
            msg(f"    {r['old_name']} -> {r['new_name']} (build {r['build']})")
        if len(renames) > 5:
            msg(f"    ... and {len(renames) - 5} more")
    else:
        msg("  No renames detected")

    # 3. JAM type evolution
    msg_info("Building JAM type evolution timeline...")
    jam_evolution = _build_jam_evolution(builds)
    growing_jams = sum(
        1 for e in jam_evolution.values() if e["trend"] == "growing"
    )
    shrinking_jams = sum(
        1 for e in jam_evolution.values() if e["trend"] == "shrinking"
    )
    msg(f"  Tracked {len(jam_evolution)} JAM types: "
        f"{growing_jams} growing, {shrinking_jams} shrinking")

    # 4. DB2 schema evolution
    msg_info("Building DB2 schema evolution timeline...")
    db2_evolution = _build_db2_evolution(builds)
    active_db2 = sum(
        1 for e in db2_evolution.values() if e["change_count"] > 0
    )
    msg(f"  Tracked {len(db2_evolution)} DB2 tables, "
        f"{active_db2} with changes across builds")

    # 5. System activity
    msg_info("Computing system-level activity...")
    system_activity = _compute_system_activity(opcode_timeline)
    for sa in system_activity[:5]:
        msg(f"  {sa['system']:20s}  changes={sa['total_changes']:4d}  "
            f"opcodes={sa['opcode_count']:4d}  trend={sa['trend']}")

    # 6. Protocol trends
    msg_info("Computing protocol size trends...")
    protocol_trends = _compute_protocol_trends(builds, opcode_timeline)
    msg(f"  Overall trend: {protocol_trends['overall_trend']}")
    for entry in protocol_trends["per_build"]:
        msg(f"  Build {entry['build']}: "
            f"{entry['cmsg_count']} CMSG + {entry['smsg_count']} SMSG "
            f"= {entry['total']} total")

    # 7. Deprecation detection
    msg_info("Detecting deprecation candidates...")
    deprecation_candidates = _detect_deprecation_candidates(opcode_timeline, builds)
    if deprecation_candidates:
        msg(f"  Found {len(deprecation_candidates)} deprecation candidates")
        for dc in deprecation_candidates[:5]:
            msg(f"    [{dc['confidence']}] {dc['opcode']}: {dc['reason']}")
        if len(deprecation_candidates) > 5:
            msg(f"    ... and {len(deprecation_candidates) - 5} more")
    else:
        msg("  No deprecation candidates identified")

    # 8. Predictions
    msg_info("Running predictive analysis...")
    predictions = _predict_upcoming_changes(opcode_timeline, jam_evolution, builds)
    high_conf = [p for p in predictions if p["confidence"] == CONFIDENCE_HIGH]
    msg(f"  Generated {len(predictions)} predictions "
        f"({len(high_conf)} high confidence)")
    for p in high_conf[:5]:
        msg(f"    {p['opcode']}: {p['predicted_action']} "
            f"(score={p['score']}) — {p['reason'][:80]}")

    # 9. TC update gap detection
    msg_info("Checking for TC update gaps...")
    tc_gaps = _detect_tc_update_gaps(opcode_timeline, builds)
    if tc_gaps:
        msg(f"  Found {len(tc_gaps)} opcodes where TC may need updating")
        for gap in tc_gaps[:5]:
            msg(f"    {gap['opcode']}: status={gap['tc_status']}, "
                f"changes_since={gap['changes_since_match']}")
    else:
        msg("  No TC update gaps detected")

    # ---- Stability classification ----
    stability = _classify_stability(opcode_timeline, num_builds)

    # ---- Serialize opcode timeline for storage ----
    opcode_timeline_list = [
        {
            "opcode": name,
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
            "change_count": entry["change_count"],
            "volatility": entry["volatility"],
            "direction": entry["direction"],
            "system": entry["system"],
            "builds_present": entry["builds_present"],
            "changes": entry["changes"],
            "stability": stability.get(name, "unknown"),
        }
        for name, entry in sorted(opcode_timeline.items())
    ]

    # Serialize JAM evolution
    jam_evolution_list = [
        {
            "type_name": name,
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
            "field_changes": entry["field_changes"],
            "field_count_history": entry["field_count_history"],
            "trend": entry["trend"],
        }
        for name, entry in sorted(jam_evolution.items())
    ]

    # Serialize DB2 evolution
    db2_evolution_list = [
        {
            "table_name": name,
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
            "field_count_history": entry["field_count_history"],
            "record_size_history": entry["record_size_history"],
            "layout_hash_history": entry["layout_hash_history"],
            "change_count": entry["change_count"],
            "trend": entry["trend"],
        }
        for name, entry in sorted(db2_evolution.items())
    ]

    # ---- Build final result ----
    elapsed = round(time.time() - start_time, 2)

    result = {
        "builds_analyzed": num_builds,
        "build_numbers": build_numbers,
        "opcode_timeline": opcode_timeline_list,
        "jam_evolution": jam_evolution_list,
        "db2_evolution": db2_evolution_list,
        "system_activity": system_activity,
        "protocol_trends": protocol_trends,
        "predictions": predictions,
        "deprecation_candidates": deprecation_candidates,
        "renames": renames,
        "tc_update_gaps": tc_gaps,
        "analysis_time_s": elapsed,
    }

    session.db.kv_set("temporal_evolution", result)
    session.db.commit()

    total_tracked = (len(opcode_timeline) + len(jam_evolution)
                     + len(db2_evolution))

    msg("")
    msg("=" * 70)
    msg(f"Temporal Evolution Analysis Complete")
    msg(f"  Builds analyzed:          {num_builds}")
    msg(f"  Opcodes tracked:          {len(opcode_timeline)}")
    msg(f"  JAM types tracked:        {len(jam_evolution)}")
    msg(f"  DB2 tables tracked:       {len(db2_evolution)}")
    msg(f"  Opcode renames detected:  {len(renames)}")
    msg(f"  Deprecation candidates:   {len(deprecation_candidates)}")
    msg(f"  Predictions generated:    {len(predictions)}")
    msg(f"  TC update gaps:           {len(tc_gaps)}")
    msg(f"  Time: {elapsed:.1f}s")
    msg("=" * 70)

    return total_tracked


# ---------------------------------------------------------------------------
# Report retrieval helper
# ---------------------------------------------------------------------------

def get_temporal_report(session):
    """Retrieve the stored temporal evolution report.

    Args:
        session: PluginSession with .db (KnowledgeDB).

    Returns:
        dict: The full temporal evolution results, or None if not yet computed.
    """
    if not session.db:
        return None
    return session.db.kv_get("temporal_evolution")


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def export_timeline_csv(session):
    """Export the opcode timeline as a CSV string for external visualization.

    Columns: opcode, direction, system, first_seen, last_seen,
             builds_present, change_count, volatility, stability

    Args:
        session: PluginSession with .db (KnowledgeDB).

    Returns:
        str: CSV content, or empty string if no data available.
    """
    report = get_temporal_report(session)
    if not report:
        msg_warn("No temporal evolution data found. Run analyze_temporal_evolution first.")
        return ""

    timeline = report.get("opcode_timeline", [])
    if not timeline:
        return ""

    lines = [
        "opcode,direction,system,first_seen,last_seen,"
        "builds_present_count,change_count,volatility,stability"
    ]

    for entry in timeline:
        builds_present = entry.get("builds_present", [])
        if isinstance(builds_present, list):
            bp_count = len(builds_present)
        else:
            bp_count = 0

        line = (
            f"{_csv_escape(entry.get('opcode', ''))},"
            f"{_csv_escape(entry.get('direction', ''))},"
            f"{_csv_escape(entry.get('system', ''))},"
            f"{entry.get('first_seen', 0)},"
            f"{entry.get('last_seen', 0)},"
            f"{bp_count},"
            f"{entry.get('change_count', 0)},"
            f"{entry.get('volatility', 0.0):.4f},"
            f"{_csv_escape(entry.get('stability', 'unknown'))}"
        )
        lines.append(line)

    csv_content = "\n".join(lines)
    msg_info(f"Exported {len(timeline)} opcodes to CSV ({len(csv_content)} bytes)")
    return csv_content


def _csv_escape(value):
    """Escape a string value for CSV output."""
    s = str(value)
    if "," in s or '"' in s or "\n" in s:
        return '"' + s.replace('"', '""') + '"'
    return s


# ---------------------------------------------------------------------------
# Volatile opcode query
# ---------------------------------------------------------------------------

def get_volatile_opcodes(session, threshold=3):
    """Return opcodes that changed in N or more builds.

    Args:
        session: PluginSession with .db (KnowledgeDB).
        threshold: Minimum number of builds with changes (default: 3).

    Returns:
        list: Dicts with opcode name, change_count, volatility, system, direction.
              Empty list if no data available.
    """
    report = get_temporal_report(session)
    if not report:
        msg_warn("No temporal evolution data found. Run analyze_temporal_evolution first.")
        return []

    timeline = report.get("opcode_timeline", [])
    result = []

    for entry in timeline:
        change_count = entry.get("change_count", 0)
        if change_count >= threshold:
            result.append({
                "opcode": entry.get("opcode", ""),
                "change_count": change_count,
                "volatility": entry.get("volatility", 0.0),
                "system": entry.get("system", "unknown"),
                "direction": entry.get("direction", ""),
                "stability": entry.get("stability", "volatile"),
                "first_seen": entry.get("first_seen", 0),
                "last_seen": entry.get("last_seen", 0),
            })

    result.sort(key=lambda x: (-x["change_count"], -x["volatility"]))
    msg_info(f"Found {len(result)} volatile opcodes "
             f"(threshold: {threshold}+ build changes)")
    return result


# ---------------------------------------------------------------------------
# Additional query helpers
# ---------------------------------------------------------------------------

def get_system_summary(session):
    """Return a summary of system-level activity from the temporal report.

    Returns:
        list: System activity entries sorted by total changes descending,
              or empty list if no data.
    """
    report = get_temporal_report(session)
    if not report:
        return []
    return report.get("system_activity", [])


def get_deprecation_candidates(session):
    """Return the list of deprecation candidate opcodes.

    Returns:
        list: Deprecation candidate dicts, or empty list if no data.
    """
    report = get_temporal_report(session)
    if not report:
        return []
    return report.get("deprecation_candidates", [])


def get_predictions(session, min_confidence=None):
    """Return prediction entries, optionally filtered by minimum confidence.

    Args:
        session: PluginSession.
        min_confidence: If set, only return entries with this confidence
                        level or higher. One of "high", "medium", "low".

    Returns:
        list: Prediction dicts.
    """
    report = get_temporal_report(session)
    if not report:
        return []

    predictions = report.get("predictions", [])

    if min_confidence:
        priority = {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_LOW: 2}
        threshold = priority.get(min_confidence, 2)
        predictions = [
            p for p in predictions
            if priority.get(p.get("confidence"), 2) <= threshold
        ]

    return predictions


def get_renames(session):
    """Return detected opcode renames across builds.

    Returns:
        list: Rename dicts with old_name, new_name, build, etc.
    """
    report = get_temporal_report(session)
    if not report:
        return []
    return report.get("renames", [])


def get_build_summary(session):
    """Return a compact summary of all analyzed builds.

    Returns:
        dict with builds_analyzed, build_numbers, protocol_trends, analysis_time_s.
    """
    report = get_temporal_report(session)
    if not report:
        return {"builds_analyzed": 0}
    return {
        "builds_analyzed": report.get("builds_analyzed", 0),
        "build_numbers": report.get("build_numbers", []),
        "protocol_trends": report.get("protocol_trends", {}),
        "analysis_time_s": report.get("analysis_time_s", 0),
    }


def get_opcode_history(session, opcode_name):
    """Return the full history for a single opcode across all builds.

    Args:
        session: PluginSession.
        opcode_name: Exact opcode name (e.g. "CMSG_HOUSING_PLACE_DECOR").

    Returns:
        dict: Timeline entry for that opcode, or None.
    """
    report = get_temporal_report(session)
    if not report:
        return None

    for entry in report.get("opcode_timeline", []):
        if entry.get("opcode") == opcode_name:
            return entry
    return None


def get_jam_type_history(session, type_name):
    """Return the full field-change history for a single JAM type.

    Args:
        session: PluginSession.
        type_name: JAM type name (e.g. "ClientHousingPlaceDecor").

    Returns:
        dict: JAM evolution entry, or None.
    """
    report = get_temporal_report(session)
    if not report:
        return None

    for entry in report.get("jam_evolution", []):
        if entry.get("type_name") == type_name:
            return entry
    return None


def get_db2_table_history(session, table_name):
    """Return the full schema evolution history for a single DB2 table.

    Args:
        session: PluginSession.
        table_name: DB2 table name (e.g. "HousingPlot").

    Returns:
        dict: DB2 evolution entry, or None.
    """
    report = get_temporal_report(session)
    if not report:
        return None

    for entry in report.get("db2_evolution", []):
        if entry.get("table_name") == table_name:
            return entry
    return None
