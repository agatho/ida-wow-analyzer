"""
Cross-Analyzer Synthesis Engine

Combines outputs from ALL other analyzers into unified per-handler
specifications and coverage reports.  This is the "grand unifier" that
cross-references every piece of knowledge accumulated by the plugin:

  - Opcode dispatch info (opcodes table)
  - JAM type & field layouts (jam_types table)
  - Bit-level wire format (wire_formats kv)
  - Conformance scores (conformance_report kv)
  - Behavioral execution paths (behavioral_specs kv)
  - Data-flow taint analysis (taint_analysis kv)
  - Validation rule comparison (validation_comparison_report kv)
  - Protocol sequencing constraints (protocol_sequences kv)
  - Callee behavioral contracts (callee_contracts kv)
  - Pseudocode transpilation (transpiled_handlers kv)
  - Response packet reconstruction (response_packets kv)

Produces:
  1. Per-handler unified profile merging all analyzer outputs
  2. Coverage matrix (handler x analyzer -> has_data)
  3. Cross-analyzer consistency checks
  4. System-level aggregation (by game subsystem)
  5. Actionable priority list ranked by improvement potential
  6. Export helpers for spec documents, CSV, and priority lists
"""

import json
import re
import time
from collections import defaultdict, OrderedDict

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Canonical list of analyzer data sources we attempt to merge.
# Each tuple: (human_name, kv_key_or_table, data_kind)
# data_kind is one of: "kv", "kv_per_handler", "table"
_ANALYZER_SOURCES = [
    ("opcodes",           "opcodes",                      "table"),
    ("jam_types",         "jam_types",                     "table"),
    ("wire_format",       "wire_formats",                  "kv"),
    ("conformance",       "conformance_report",            "kv"),
    ("behavioral_spec",   "behavioral_specs",              "kv"),
    ("taint_analysis",    "taint_analysis",                "kv"),
    ("validation",        "validation_comparison_report",  "kv"),
    ("protocol_sequence", "protocol_sequences",            "kv"),
    ("callee_contracts",  "callee_contracts",              "kv"),
    ("transpiled",        "transpiled_handlers",           "kv"),
    ("response_packets",  "response_packets",              "kv"),
]

# System classification map — maps opcode name keywords to game systems.
_SYSTEM_KEYWORDS = OrderedDict([
    ("HOUSING",       "Housing"),
    ("HOUSE",         "Housing"),
    ("DECOR",         "Housing"),
    ("NEIGHBORHOOD",  "Housing"),
    ("INTERIOR",      "Housing"),
    ("QUEST",         "Quest"),
    ("SPELL",         "Combat"),
    ("AURA",          "Combat"),
    ("ATTACK",        "Combat"),
    ("CAST",          "Combat"),
    ("GUILD",         "Social"),
    ("CHAT",          "Social"),
    ("MAIL",          "Social"),
    ("FRIEND",        "Social"),
    ("WHISPER",       "Social"),
    ("CHANNEL",       "Social"),
    ("BATTLEGROUND",  "PvP"),
    ("ARENA",         "PvP"),
    ("PVP",           "PvP"),
    ("AUCTION",       "Auction"),
    ("TRADE",         "Crafting"),
    ("CRAFT",         "Crafting"),
    ("PROFESSION",    "Crafting"),
    ("RECIPE",        "Crafting"),
    ("TALENT",        "Talent"),
    ("PET",           "Pet"),
    ("BATTLE_PET",    "Pet"),
    ("ACHIEVEMENT",   "Achievement"),
    ("LOOT",          "Loot"),
    ("MOVEMENT",      "Movement"),
    ("MOVE",          "Movement"),
    ("ITEM",          "Item"),
    ("EQUIP",         "Item"),
    ("INVENTORY",     "Item"),
    ("BAG",           "Item"),
    ("CHARACTER",     "Character"),
    ("PLAYER",        "Character"),
    ("CHAR",          "Character"),
    ("LOGIN",         "Auth"),
    ("AUTH",          "Auth"),
    ("REALM",         "Auth"),
    ("LOGOUT",        "Auth"),
    ("GARRISON",      "Garrison"),
    ("MYTHIC",        "MythicPlus"),
    ("KEYSTONE",      "MythicPlus"),
    ("DELVE",         "Delves"),
    ("VEHICLE",       "Vehicle"),
    ("CALENDAR",      "Calendar"),
    ("GROUP",         "Group"),
    ("PARTY",         "Group"),
    ("LFG",           "Group"),
    ("DUNGEON",       "Group"),
    ("RAID",          "Group"),
    ("BANK",          "Bank"),
    ("VOID_STORAGE",  "Bank"),
    ("TRANSMOGRIF",   "Transmog"),
    ("WARDEN",        "AntiCheat"),
    ("GM",            "GM"),
    ("TICKET",        "GM"),
    ("NPC",           "NPC"),
    ("TRAINER",       "NPC"),
    ("GOSSIP",        "NPC"),
    ("TAXI",          "NPC"),
    ("FLIGHT",        "NPC"),
])


# ===================================================================
# Main entry point
# ===================================================================

def synthesize_all(session) -> int:
    """Run the cross-analyzer synthesis.

    Merges data from all analyzer outputs into unified per-handler profiles,
    builds a coverage matrix, runs consistency checks, aggregates by system,
    and generates a prioritised improvement list.

    Args:
        session: PluginSession with .db (KnowledgeDB)

    Returns:
        Number of handler profiles synthesised.
    """
    db = session.db
    t0 = time.time()

    msg_info("Cross-analyzer synthesis: loading all data sources...")

    # ------------------------------------------------------------------
    # Step 0: Load all raw data from the knowledge DB
    # ------------------------------------------------------------------
    raw = _load_all_sources(db)

    # ------------------------------------------------------------------
    # Step 1: Build the canonical handler list from the opcodes table
    # ------------------------------------------------------------------
    handler_index = _build_handler_index(db, raw)
    if not handler_index:
        msg_warn("No CMSG handlers found in opcodes table. "
                 "Run opcode analysis first.")
        return 0

    msg_info(f"  Found {len(handler_index)} CMSG handlers to synthesise")

    # ------------------------------------------------------------------
    # Step 2: Merge per-handler data from every analyzer
    # ------------------------------------------------------------------
    profiles = _merge_handler_profiles(handler_index, raw, db)

    # ------------------------------------------------------------------
    # Step 3: Build coverage matrix
    # ------------------------------------------------------------------
    coverage_matrix, per_handler_coverage = _build_coverage_matrix(
        profiles, handler_index
    )

    # ------------------------------------------------------------------
    # Step 4: Cross-analyzer consistency checks
    # ------------------------------------------------------------------
    consistency_issues = _run_consistency_checks(profiles, raw)

    # ------------------------------------------------------------------
    # Step 5: System-level aggregation
    # ------------------------------------------------------------------
    system_aggregates = _aggregate_by_system(profiles)

    # ------------------------------------------------------------------
    # Step 6: Priority list
    # ------------------------------------------------------------------
    priority_list = _build_priority_list(profiles, per_handler_coverage)

    # ------------------------------------------------------------------
    # Step 7: Persist
    # ------------------------------------------------------------------
    avg_coverage = 0.0
    if profiles:
        avg_coverage = sum(
            p.get("coverage_pct", 0.0) for p in profiles
        ) / len(profiles)

    report = {
        "synthesis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_seconds": round(time.time() - t0, 2),
        "handler_profiles": profiles,
        "coverage_matrix": coverage_matrix,
        "consistency_issues": consistency_issues,
        "system_aggregates": system_aggregates,
        "priority_list": priority_list,
        "total_handlers": len(profiles),
        "avg_coverage": round(avg_coverage, 1),
    }

    db.kv_set("synthesis_report", report)
    db.commit()

    # Summary output
    msg_info(f"Cross-analyzer synthesis complete in "
             f"{report['elapsed_seconds']:.1f}s")
    msg_info(f"  Handlers synthesised: {len(profiles)}")
    msg_info(f"  Average coverage: {avg_coverage:.1f}%")
    msg_info(f"  Consistency issues: {len(consistency_issues)}")
    msg_info(f"  Systems identified: {len(system_aggregates)}")
    msg_info(f"  Priority items: {len(priority_list)}")

    _print_coverage_summary(coverage_matrix)
    _print_top_priority(priority_list)
    _print_system_summary(system_aggregates)

    return len(profiles)


# ===================================================================
# Report retrieval helper
# ===================================================================

def get_synthesis_report(session):
    """Retrieve the stored synthesis report from the knowledge DB.

    Returns the full report dict, or an empty dict if synthesis has not
    been run yet.
    """
    return session.db.kv_get("synthesis_report") or {}


# ===================================================================
# Export functions
# ===================================================================

def export_handler_spec(session, handler_name) -> str:
    """Generate a complete specification document for a single handler.

    Args:
        session: PluginSession
        handler_name: The tc_name (e.g. "CMSG_HOUSING_PLACE_DECOR")

    Returns:
        A multi-section plaintext specification string.
    """
    report = get_synthesis_report(session)
    if not report:
        return f"# {handler_name}\n\nNo synthesis data available.\n"

    profile = None
    for p in report.get("handler_profiles", []):
        if p.get("handler") == handler_name:
            profile = p
            break

    if not profile:
        return (f"# {handler_name}\n\n"
                f"Handler not found in synthesis report.\n")

    lines = []
    lines.append(f"# Handler Specification: {handler_name}")
    lines.append(f"Generated: {report.get('synthesis_time', 'unknown')}")
    lines.append("")

    # --- Identity ---
    lines.append("## Identity")
    lines.append(f"  Opcode Name:      {profile.get('handler', 'N/A')}")
    lines.append(f"  Handler EA:       {profile.get('handler_ea', 'N/A')}")
    lines.append(f"  Internal Index:   {profile.get('internal_index', 'N/A')}")
    lines.append(f"  Wire Opcode:      {profile.get('wire_opcode', 'N/A')}")
    lines.append(f"  Direction:        {profile.get('direction', 'CMSG')}")
    lines.append(f"  System:           {profile.get('system', 'Unknown')}")
    lines.append(f"  Overall Coverage: {profile.get('coverage_pct', 0):.1f}%")
    lines.append("")

    # --- JAM Type ---
    lines.append("## JAM Message Type")
    jam = profile.get("jam_type_info")
    if jam:
        lines.append(f"  Type Name:    {jam.get('name', 'N/A')}")
        lines.append(f"  Field Count:  {jam.get('field_count', 0)}")
        lines.append(f"  Wire Size:    {jam.get('wire_size', 'unknown')} bytes")
        fields = jam.get("fields", [])
        if fields:
            lines.append("  Fields:")
            for f in fields:
                fname = f.get("name", "?")
                ftype = f.get("type", "?")
                lines.append(f"    - {fname}: {ftype}")
    else:
        lines.append("  (no JAM type data)")
    lines.append("")

    # --- Wire Format ---
    lines.append("## Wire Format")
    wf = profile.get("wire_format")
    if wf:
        ops = wf.get("operations", wf.get("read_sequence", []))
        if ops:
            lines.append(f"  Operations ({len(ops)}):")
            for op in ops:
                if isinstance(op, dict):
                    desc = op.get("description", op.get("op", str(op)))
                    lines.append(f"    - {desc}")
                else:
                    lines.append(f"    - {op}")
        else:
            lines.append("  (no operations recorded)")
    else:
        lines.append("  (no wire format data)")
    lines.append("")

    # --- Conformance ---
    lines.append("## Conformance")
    conf = profile.get("conformance")
    if conf:
        lines.append(f"  Total Score:      {conf.get('score', 'N/A')}")
        lines.append(f"  Call Score:        {conf.get('call_score', 'N/A')}")
        lines.append(f"  Branch Score:      {conf.get('branch_score', 'N/A')}")
        lines.append(f"  Validation Score:  {conf.get('validation_score', 'N/A')}")
        lines.append(f"  Size Score:        {conf.get('size_score', 'N/A')}")
        missing = conf.get("missing", [])
        if missing:
            lines.append("  Missing:")
            for m in missing:
                lines.append(f"    - {m}")
    else:
        lines.append("  (no conformance data)")
    lines.append("")

    # --- Behavioral Spec ---
    lines.append("## Behavioral Specification")
    bspec = profile.get("behavioral_spec")
    if bspec:
        paths = bspec.get("paths", bspec.get("path_count", 0))
        if isinstance(paths, int):
            lines.append(f"  Execution Paths: {paths}")
        elif isinstance(paths, list):
            lines.append(f"  Execution Paths: {len(paths)}")
            for i, path in enumerate(paths[:10]):
                conds = path.get("conditions", [])
                outcome = path.get("outcome", "?")
                cond_str = " AND ".join(str(c) for c in conds[:5])
                lines.append(f"    Path {i+1}: IF ({cond_str}) -> {outcome}")
            if isinstance(paths, list) and len(paths) > 10:
                lines.append(f"    ... and {len(paths) - 10} more paths")
        else:
            lines.append(f"  Paths data: {paths}")
    else:
        lines.append("  (no behavioral spec)")
    lines.append("")

    # --- Taint Analysis ---
    lines.append("## Taint Analysis")
    taint = profile.get("taint_info")
    if taint:
        lines.append(f"  Total Flows:     {taint.get('total_flows', 0)}")
        lines.append(f"  Unguarded:       {taint.get('unguarded', 0)}")
        lines.append(f"  High Severity:   {taint.get('high_severity', 0)}")
        cats = taint.get("categories", [])
        if cats:
            lines.append(f"  Categories:      {', '.join(cats)}")
    else:
        lines.append("  (no taint data)")
    lines.append("")

    # --- Validation Rules ---
    lines.append("## Validation Rules")
    val = profile.get("validation_info")
    if val:
        if isinstance(val, dict):
            lines.append(f"  Binary Checks:   {val.get('binary_count', '?')}")
            lines.append(f"  TC Checks:       {val.get('tc_count', '?')}")
            lines.append(f"  Missing in TC:   {val.get('missing_count', '?')}")
            rules = val.get("rules", [])
            for r in rules[:10]:
                lines.append(f"    - {r}")
        elif isinstance(val, list):
            lines.append(f"  Rules ({len(val)}):")
            for r in val[:10]:
                lines.append(f"    - {r}")
    else:
        lines.append("  (no validation data)")
    lines.append("")

    # --- Protocol Sequencing ---
    lines.append("## Protocol Sequencing")
    proto = profile.get("protocol_sequence")
    if proto:
        prereqs = proto.get("prerequisites", [])
        successors = proto.get("successors", [])
        phase = proto.get("phase", "unknown")
        lines.append(f"  Phase:           {phase}")
        if prereqs:
            lines.append(f"  Prerequisites:   {', '.join(str(p) for p in prereqs)}")
        if successors:
            lines.append(f"  Successors:      {', '.join(str(s) for s in successors)}")
    else:
        lines.append("  (no sequencing data)")
    lines.append("")

    # --- Callee Contracts ---
    lines.append("## Callee Contracts Used")
    callees = profile.get("callee_contracts_used")
    if callees:
        if isinstance(callees, list):
            for c in callees[:15]:
                if isinstance(c, dict):
                    lines.append(f"    - {c.get('name', '?')}: "
                                 f"{c.get('description', '')}")
                else:
                    lines.append(f"    - {c}")
        elif isinstance(callees, int):
            lines.append(f"  Count: {callees}")
    else:
        lines.append("  (no callee contract data)")
    lines.append("")

    # --- Transpiled Code ---
    lines.append("## Transpiled C++ Code")
    transpiled = profile.get("transpiled_code")
    if transpiled:
        if isinstance(transpiled, str):
            # Truncate very long code
            if len(transpiled) > 3000:
                lines.append(transpiled[:3000])
                lines.append(f"  ... ({len(transpiled) - 3000} chars truncated)")
            else:
                lines.append(transpiled)
        elif isinstance(transpiled, dict):
            code = transpiled.get("code", transpiled.get("cpp", ""))
            if code:
                if len(code) > 3000:
                    lines.append(code[:3000])
                    lines.append(
                        f"  ... ({len(code) - 3000} chars truncated)")
                else:
                    lines.append(code)
    else:
        lines.append("  (no transpiled code)")
    lines.append("")

    # --- Response Packets ---
    lines.append("## Response Packets Sent")
    resp = profile.get("response_packets")
    if resp:
        if isinstance(resp, list):
            for r in resp:
                if isinstance(r, dict):
                    opname = r.get("opcode_name", r.get("opcode", "?"))
                    cond = r.get("condition", "always")
                    fields = r.get("fields", [])
                    lines.append(f"    - {opname} ({cond})")
                    for fld in fields[:8]:
                        lines.append(f"        {fld}")
                else:
                    lines.append(f"    - {r}")
        elif isinstance(resp, dict):
            for key, val in resp.items():
                lines.append(f"    - {key}: {val}")
    else:
        lines.append("  (no response packet data)")
    lines.append("")

    return "\n".join(lines)


def export_coverage_csv(session) -> str:
    """Export the coverage matrix as a CSV string.

    Columns: handler, system, opcodes, jam_types, wire_format, conformance,
    behavioral_spec, taint_analysis, validation, protocol_sequence,
    callee_contracts, transpiled, response_packets, coverage_pct

    Returns:
        CSV text with one row per handler.
    """
    report = get_synthesis_report(session)
    if not report:
        return "handler,coverage_pct\n(no data)\n"

    analyzer_names = [src[0] for src in _ANALYZER_SOURCES]
    header = ["handler", "system"] + analyzer_names + ["coverage_pct"]

    rows = [",".join(header)]

    for profile in report.get("handler_profiles", []):
        name = profile.get("handler", "?")
        system = profile.get("system", "?")
        has_data = profile.get("analyzer_has_data", {})

        cols = [_csv_escape(name), _csv_escape(system)]
        for aname in analyzer_names:
            cols.append("1" if has_data.get(aname, False) else "0")
        cols.append(f"{profile.get('coverage_pct', 0):.1f}")

        rows.append(",".join(cols))

    return "\n".join(rows) + "\n"


def get_priority_list(session) -> list:
    """Return the sorted priority improvement list.

    Each item is a dict with keys: handler, priority_score, reasons.

    Returns:
        List sorted by descending priority_score (most urgent first).
    """
    report = get_synthesis_report(session)
    if not report:
        return []
    return report.get("priority_list", [])


# ===================================================================
# Internal: Data loading
# ===================================================================

def _load_all_sources(db):
    """Load every analyzer output from the knowledge DB into memory.

    Returns a dict keyed by source name with the loaded data.
    """
    raw = {}

    for human_name, key_or_table, kind in _ANALYZER_SOURCES:
        try:
            if kind == "table":
                rows = db.fetchall(f"SELECT * FROM {key_or_table}")
                raw[human_name] = [dict(r) for r in rows] if rows else []
            elif kind == "kv":
                data = db.kv_get(key_or_table)
                raw[human_name] = data if data else {}
            elif kind == "kv_per_handler":
                raw[human_name] = db.kv_get(key_or_table) or {}
        except Exception as e:
            msg_warn(f"  Could not load {human_name} ({key_or_table}): {e}")
            raw[human_name] = {} if kind != "table" else []

    # Also load per-handler behavioral specs keyed individually
    raw["_behavioral_spec_individual"] = {}
    try:
        kv_rows = db.fetchall(
            "SELECT key, value FROM kv_store WHERE key LIKE 'behavioral_spec:%'"
        )
        if kv_rows:
            for row in kv_rows:
                handler_key = dict(row)["key"]
                handler_name = handler_key.replace("behavioral_spec:", "", 1)
                try:
                    raw["_behavioral_spec_individual"][handler_name] = (
                        json.loads(dict(row)["value"])
                    )
                except (json.JSONDecodeError, TypeError):
                    pass
    except Exception:
        pass

    # Log what we found
    for human_name, _, _ in _ANALYZER_SOURCES:
        data = raw.get(human_name)
        if isinstance(data, list):
            count = len(data)
        elif isinstance(data, dict):
            count = len(data)
        else:
            count = 0
        if count > 0:
            msg(f"  Loaded {human_name}: {count} items")

    return raw


# ===================================================================
# Internal: Handler index
# ===================================================================

def _build_handler_index(db, raw):
    """Build a canonical handler index from the opcodes table.

    Returns a dict keyed by tc_name with opcode row data.
    Only includes CMSG handlers (client-to-server) that have a handler_ea.
    """
    opcode_rows = raw.get("opcodes", [])
    index = {}

    for row in opcode_rows:
        direction = row.get("direction", "")
        if direction != "CMSG":
            continue
        tc_name = row.get("tc_name")
        handler_ea = row.get("handler_ea")
        if not handler_ea:
            continue

        key = tc_name if tc_name else f"handler_0x{handler_ea:X}"
        index[key] = {
            "tc_name": tc_name,
            "handler_ea": handler_ea,
            "internal_index": row.get("internal_index"),
            "wire_opcode": row.get("wire_opcode"),
            "jam_type": row.get("jam_type"),
            "status": row.get("status"),
        }

    return index


# ===================================================================
# Internal: Profile merging
# ===================================================================

def _merge_handler_profiles(handler_index, raw, db):
    """For each handler, merge data from all analyzers into a unified profile.

    Returns a list of profile dicts.
    """
    # Pre-index data sources for fast lookup
    jam_index = _index_jam_types(raw.get("jam_types", []))
    wire_index = _index_wire_formats(raw.get("wire_format", {}))
    conformance_index = _index_conformance(raw.get("conformance", {}))
    behavioral_index = _index_behavioral_specs(
        raw.get("behavioral_spec", {}),
        raw.get("_behavioral_spec_individual", {})
    )
    taint_index = _index_taint(raw.get("taint_analysis", {}))
    validation_index = _index_validations(raw.get("validation", {}))
    protocol_index = _index_protocol_sequences(raw.get("protocol_sequence", {}))
    callee_index = _index_callee_contracts(raw.get("callee_contracts", {}))
    transpiled_index = _index_transpiled(raw.get("transpiled", {}))
    response_index = _index_response_packets(raw.get("response_packets", {}))

    profiles = []

    for handler_name, opcode_info in sorted(handler_index.items()):
        handler_ea = opcode_info["handler_ea"]
        handler_ea_hex = f"0x{handler_ea:X}" if isinstance(handler_ea, int) else str(handler_ea)
        jam_type_name = opcode_info.get("jam_type") or ""

        # Determine system classification
        system = _classify_system(handler_name)

        # Build the analyzer_has_data flags
        has_data = {}

        # 1. Opcodes — always True since we got handler from opcodes table
        has_data["opcodes"] = True

        # 2. JAM type
        jam_info = jam_index.get(jam_type_name)
        has_data["jam_types"] = jam_info is not None

        # 3. Wire format
        wf = wire_index.get(handler_name) or wire_index.get(handler_ea_hex)
        has_data["wire_format"] = wf is not None

        # 4. Conformance
        conf = conformance_index.get(handler_name)
        has_data["conformance"] = conf is not None

        # 5. Behavioral spec
        bspec = behavioral_index.get(handler_name)
        has_data["behavioral_spec"] = bspec is not None

        # 6. Taint analysis
        taint = taint_index.get(handler_name)
        has_data["taint_analysis"] = taint is not None

        # 7. Validation rules
        val = validation_index.get(handler_name)
        has_data["validation"] = val is not None

        # 8. Protocol sequence
        proto = protocol_index.get(handler_name)
        has_data["protocol_sequence"] = proto is not None

        # 9. Callee contracts
        callees = callee_index.get(handler_name)
        has_data["callee_contracts"] = callees is not None

        # 10. Transpiled code
        transpiled = transpiled_index.get(handler_name)
        has_data["transpiled"] = transpiled is not None

        # 11. Response packets
        resp = response_index.get(handler_name)
        has_data["response_packets"] = resp is not None

        # Compute coverage percentage
        total_sources = len(_ANALYZER_SOURCES)
        covered = sum(1 for v in has_data.values() if v)
        coverage_pct = (covered / total_sources * 100) if total_sources > 0 else 0

        # Conformance score extraction
        conformance_score = None
        if conf:
            conformance_score = conf.get("score", conf.get("total"))

        # Taint count extraction
        taint_count = 0
        taint_unguarded = 0
        taint_high = 0
        if taint:
            taint_count = taint.get("total_flows", 0)
            taint_unguarded = taint.get("unguarded", 0)
            taint_high = taint.get("high_severity", 0)

        profile = {
            "handler": handler_name,
            "handler_ea": handler_ea_hex,
            "internal_index": opcode_info.get("internal_index"),
            "wire_opcode": opcode_info.get("wire_opcode"),
            "direction": "CMSG",
            "system": system,
            "status": opcode_info.get("status", "unknown"),

            # Merged data
            "jam_type_name": jam_type_name if jam_type_name else None,
            "jam_type_info": jam_info,
            "wire_format": wf,
            "conformance": conf,
            "conformance_score": conformance_score,
            "behavioral_spec": bspec,
            "taint_info": taint,
            "taint_count": taint_count,
            "taint_unguarded": taint_unguarded,
            "taint_high": taint_high,
            "validation_info": val,
            "protocol_sequence": proto,
            "callee_contracts_used": callees,
            "transpiled_code": transpiled,
            "response_packets": resp,

            # Coverage
            "analyzer_has_data": has_data,
            "coverage_pct": round(coverage_pct, 1),
            "analyzers_covered": covered,
            "analyzers_total": total_sources,
        }

        profiles.append(profile)

    return profiles


# ===================================================================
# Internal: Index builders for each data source
# ===================================================================

def _index_jam_types(jam_rows):
    """Index JAM type rows by name."""
    index = {}
    for row in jam_rows:
        name = row.get("name")
        if not name:
            continue
        fields = []
        fields_json = row.get("fields_json")
        if fields_json:
            try:
                fields = json.loads(fields_json) if isinstance(fields_json, str) else fields_json
            except (json.JSONDecodeError, TypeError):
                fields = []
        index[name] = {
            "name": name,
            "field_count": row.get("field_count", len(fields)),
            "wire_size": row.get("wire_size"),
            "status": row.get("status", "discovered"),
            "fields": fields,
        }
    return index


def _index_wire_formats(wire_data):
    """Index wire format data by handler name or EA.

    The wire_formats kv store can have various shapes depending on the
    analyzer version. We handle both list-of-dicts and dict-of-dicts.
    """
    index = {}
    if not wire_data:
        return index

    if isinstance(wire_data, list):
        for entry in wire_data:
            if not isinstance(entry, dict):
                continue
            key = (entry.get("handler") or entry.get("tc_name") or
                   entry.get("handler_ea") or "")
            if key:
                index[key] = entry
    elif isinstance(wire_data, dict):
        # Could be keyed by handler name or contain a "formats" list
        formats = wire_data.get("formats", wire_data.get("handlers", []))
        if isinstance(formats, list):
            for entry in formats:
                if not isinstance(entry, dict):
                    continue
                key = (entry.get("handler") or entry.get("tc_name") or
                       entry.get("handler_ea") or "")
                if key:
                    index[key] = entry
        else:
            # Assume the dict is itself keyed by handler name
            for key, val in wire_data.items():
                if isinstance(val, dict):
                    index[key] = val

    return index


def _index_conformance(conf_data):
    """Index conformance scores by handler tc_name."""
    index = {}
    if not conf_data:
        return index

    handlers = conf_data.get("handlers", [])
    if isinstance(handlers, list):
        for entry in handlers:
            if not isinstance(entry, dict):
                continue
            tc_name = entry.get("tc_name")
            if tc_name:
                index[tc_name] = entry
    return index


def _index_behavioral_specs(specs_summary, individual_specs):
    """Index behavioral specs by handler name.

    Merges the summary (from "behavioral_specs" kv) with individual
    per-handler specs (from "behavioral_spec:<name>" kv entries).
    """
    index = {}

    # From summary
    if isinstance(specs_summary, dict):
        handlers = specs_summary.get("handlers", specs_summary.get("specs", []))
        if isinstance(handlers, list):
            for entry in handlers:
                if isinstance(entry, dict):
                    name = entry.get("handler") or entry.get("tc_name", "")
                    if name:
                        index[name] = entry
        elif isinstance(handlers, dict):
            for name, data in handlers.items():
                index[name] = data

    # Merge individual specs (higher priority — more detailed)
    for name, spec in individual_specs.items():
        if name in index:
            # Merge: keep individual spec data, supplement with summary
            merged = dict(index[name])
            merged.update(spec)
            index[name] = merged
        else:
            index[name] = spec

    return index


def _index_taint(taint_data):
    """Index taint analysis per-handler summaries by handler name."""
    index = {}
    if not taint_data:
        return index

    # The taint_analysis kv has handler_summaries
    summaries = taint_data.get("handler_summaries", [])
    if isinstance(summaries, list):
        for entry in summaries:
            if not isinstance(entry, dict):
                continue
            handler = entry.get("handler")
            if handler:
                index[handler] = entry
    return index


def _index_validations(val_data):
    """Index validation comparison data by handler name."""
    index = {}
    if not val_data:
        return index

    # The validation_comparison_report kv may have various shapes
    handlers = val_data.get("handlers", val_data.get("comparisons", []))
    if isinstance(handlers, list):
        for entry in handlers:
            if not isinstance(entry, dict):
                continue
            name = entry.get("handler") or entry.get("tc_name", "")
            if name:
                index[name] = entry
    elif isinstance(handlers, dict):
        for name, data in handlers.items():
            index[name] = data

    return index


def _index_protocol_sequences(proto_data):
    """Index protocol sequence data by handler name."""
    index = {}
    if not proto_data:
        return index

    # The protocol_sequences kv has various shapes
    handlers = proto_data.get("handlers", proto_data.get("nodes", []))
    if isinstance(handlers, list):
        for entry in handlers:
            if not isinstance(entry, dict):
                continue
            name = entry.get("handler") or entry.get("tc_name") or entry.get("opcode", "")
            if name:
                index[name] = entry
    elif isinstance(handlers, dict):
        for name, data in handlers.items():
            if isinstance(data, dict):
                index[name] = data

    # Also check edges to build predecessor/successor info
    edges = proto_data.get("edges", proto_data.get("dependencies", []))
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            src = edge.get("from") or edge.get("source", "")
            dst = edge.get("to") or edge.get("target", "")
            reason = edge.get("reason", edge.get("type", ""))

            if src and src in index:
                succs = index[src].setdefault("successors", [])
                succs.append({"target": dst, "reason": reason})
            if dst and dst in index:
                prereqs = index[dst].setdefault("prerequisites", [])
                prereqs.append({"source": src, "reason": reason})

    # Check phases
    phases = proto_data.get("phases", [])
    if isinstance(phases, list):
        for phase_info in phases:
            if not isinstance(phase_info, dict):
                continue
            phase_name = phase_info.get("name", phase_info.get("phase", ""))
            members = phase_info.get("members", phase_info.get("handlers", []))
            for member in members:
                if isinstance(member, str) and member in index:
                    index[member]["phase"] = phase_name
                elif isinstance(member, dict):
                    mname = member.get("handler", member.get("name", ""))
                    if mname in index:
                        index[mname]["phase"] = phase_name

    return index


def _index_callee_contracts(callee_data):
    """Index callee contracts usage by handler.

    The callee_contracts kv stores contracts for utility functions.
    We need to invert this: for each handler, which contracts does it use?
    """
    index = {}
    if not callee_data:
        return index

    # callee_contracts kv_store may be a list (flat) or dict with "contracts" key
    if isinstance(callee_data, list):
        contracts = callee_data
    elif isinstance(callee_data, dict):
        contracts = callee_data.get("contracts", [])
    else:
        contracts = []
    if isinstance(contracts, list):
        for contract in contracts:
            if not isinstance(contract, dict):
                continue
            callers = contract.get("callers", contract.get("call_sites", []))
            contract_name = contract.get("name", contract.get("function", "?"))
            contract_desc = contract.get("description", contract.get("summary", ""))

            for caller in callers:
                caller_name = ""
                if isinstance(caller, str):
                    caller_name = caller
                elif isinstance(caller, dict):
                    caller_name = caller.get("handler", caller.get("caller", ""))

                if caller_name:
                    if caller_name not in index:
                        index[caller_name] = []
                    index[caller_name].append({
                        "name": contract_name,
                        "description": contract_desc,
                    })
    elif isinstance(callee_data, dict) and "contracts" not in callee_data:
        # Might be directly keyed by function name
        for func_name, contract in callee_data.items():
            if not isinstance(contract, dict):
                continue
            callers = contract.get("callers", [])
            for caller in callers:
                caller_name = ""
                if isinstance(caller, str):
                    caller_name = caller
                elif isinstance(caller, dict):
                    caller_name = caller.get("handler", caller.get("caller", ""))
                if caller_name:
                    if caller_name not in index:
                        index[caller_name] = []
                    index[caller_name].append({
                        "name": func_name,
                        "description": contract.get("description", ""),
                    })

    return index


def _index_transpiled(transpiled_data):
    """Index transpiled handler code by handler name."""
    index = {}
    if not transpiled_data:
        return index

    if isinstance(transpiled_data, list):
        for entry in transpiled_data:
            if not isinstance(entry, dict):
                continue
            name = entry.get("handler") or entry.get("tc_name", "")
            if name:
                index[name] = entry
    elif isinstance(transpiled_data, dict):
        handlers = transpiled_data.get("handlers", [])
        if isinstance(handlers, list):
            for entry in handlers:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("handler") or entry.get("tc_name", "")
                if name:
                    index[name] = entry
        else:
            # Might be keyed by handler name directly
            for name, data in transpiled_data.items():
                if isinstance(data, (dict, str)):
                    index[name] = data

    return index


def _index_response_packets(response_data):
    """Index response packet data by handler name."""
    index = {}
    if not response_data:
        return index

    if isinstance(response_data, list):
        for entry in response_data:
            if not isinstance(entry, dict):
                continue
            handler = entry.get("handler") or entry.get("tc_name", "")
            if handler:
                responses = entry.get("responses", entry.get("packets", []))
                index[handler] = responses if responses else [entry]
    elif isinstance(response_data, dict):
        handlers = response_data.get("handlers", response_data.get("results", []))
        if isinstance(handlers, list):
            for entry in handlers:
                if not isinstance(entry, dict):
                    continue
                handler = entry.get("handler") or entry.get("tc_name", "")
                if handler:
                    responses = entry.get("responses", entry.get("packets", []))
                    index[handler] = responses if responses else [entry]
        elif isinstance(handlers, dict):
            for name, data in handlers.items():
                index[name] = data

    return index


# ===================================================================
# Internal: Coverage matrix
# ===================================================================

def _build_coverage_matrix(profiles, handler_index):
    """Build the coverage matrix: per-analyzer coverage stats.

    Returns:
        coverage_matrix: {analyzer_name: {total, covered, pct}}
        per_handler_coverage: {handler_name: coverage_pct}
    """
    analyzer_names = [src[0] for src in _ANALYZER_SOURCES]
    total_handlers = len(profiles)

    # Per-analyzer counts
    coverage_matrix = {}
    for aname in analyzer_names:
        covered = sum(
            1 for p in profiles
            if p.get("analyzer_has_data", {}).get(aname, False)
        )
        pct = (covered / total_handlers * 100) if total_handlers > 0 else 0
        coverage_matrix[aname] = {
            "total": total_handlers,
            "covered": covered,
            "pct": round(pct, 1),
        }

    # Per-handler coverage
    per_handler_coverage = {}
    for p in profiles:
        per_handler_coverage[p["handler"]] = p.get("coverage_pct", 0)

    return coverage_matrix, per_handler_coverage


# ===================================================================
# Internal: Consistency checks
# ===================================================================

def _run_consistency_checks(profiles, raw):
    """Run cross-analyzer consistency checks.

    Identifies discrepancies between data from different analyzers.
    Returns a list of issue dicts.
    """
    issues = []

    for profile in profiles:
        handler = profile["handler"]

        # Check 1: Wire format field count vs JAM field count
        jam_info = profile.get("jam_type_info")
        wf = profile.get("wire_format")
        if jam_info and wf:
            jam_field_count = jam_info.get("field_count", 0)
            wf_ops = wf.get("operations", wf.get("read_sequence", []))
            wf_field_count = len(wf_ops) if isinstance(wf_ops, list) else 0

            # Wire format may have more ops than fields (bits, flushes, etc.)
            # but should not have fewer than the JAM field count
            if wf_field_count > 0 and jam_field_count > 0:
                if wf_field_count < jam_field_count * 0.5:
                    issues.append({
                        "handler": handler,
                        "issue_type": "wire_jam_field_mismatch",
                        "details": (
                            f"Wire format has {wf_field_count} operations but "
                            f"JAM type has {jam_field_count} fields "
                            f"(expected wire >= JAM)"
                        ),
                        "severity": "medium",
                    })
                elif wf_field_count > jam_field_count * 4:
                    issues.append({
                        "handler": handler,
                        "issue_type": "wire_jam_field_mismatch",
                        "details": (
                            f"Wire format has {wf_field_count} operations but "
                            f"JAM type has {jam_field_count} fields "
                            f"(wire format may include sub-message ops)"
                        ),
                        "severity": "low",
                    })

        # Check 2: Behavioral spec paths vs conformance branch count
        bspec = profile.get("behavioral_spec")
        conf = profile.get("conformance")
        if bspec and conf:
            path_count = 0
            paths = bspec.get("paths", bspec.get("path_count", 0))
            if isinstance(paths, int):
                path_count = paths
            elif isinstance(paths, list):
                path_count = len(paths)

            branch_score = conf.get("branch_score")
            if (branch_score is not None and
                    isinstance(branch_score, (int, float)) and
                    branch_score < 40 and path_count > 10):
                issues.append({
                    "handler": handler,
                    "issue_type": "spec_conformance_branch_divergence",
                    "details": (
                        f"Behavioral spec found {path_count} paths but "
                        f"conformance branch score is only {branch_score}% "
                        f"— TC implementation may be missing branches"
                    ),
                    "severity": "high",
                })

        # Check 3: Taint sources vs wire format reads
        taint = profile.get("taint_info")
        if taint and wf:
            taint_total = taint.get("total_flows", 0)
            wf_ops = wf.get("operations", wf.get("read_sequence", []))
            wf_read_count = 0
            if isinstance(wf_ops, list):
                for op in wf_ops:
                    if isinstance(op, dict):
                        op_type = op.get("type", op.get("op", ""))
                        if "read" in str(op_type).lower():
                            wf_read_count += 1
                    elif isinstance(op, str) and "read" in op.lower():
                        wf_read_count += 1

            if (wf_read_count > 0 and taint_total == 0):
                issues.append({
                    "handler": handler,
                    "issue_type": "taint_wire_read_gap",
                    "details": (
                        f"Wire format has {wf_read_count} read operations "
                        f"but taint analysis found 0 flows — taint analysis "
                        f"may have failed to parse this handler"
                    ),
                    "severity": "low",
                })

        # Check 4: Protocol prerequisites consistency
        proto = profile.get("protocol_sequence")
        if proto:
            prereqs = proto.get("prerequisites", [])
            for prereq in prereqs:
                prereq_name = ""
                if isinstance(prereq, str):
                    prereq_name = prereq
                elif isinstance(prereq, dict):
                    prereq_name = prereq.get("source", prereq.get("handler", ""))

                if prereq_name:
                    # Check that the prerequisite handler actually exists
                    prereq_found = any(
                        p["handler"] == prereq_name for p in profiles
                    )
                    if not prereq_found:
                        issues.append({
                            "handler": handler,
                            "issue_type": "protocol_prereq_missing",
                            "details": (
                                f"Protocol prerequisite '{prereq_name}' not "
                                f"found in handler index — may be an SMSG or "
                                f"misidentified handler"
                            ),
                            "severity": "low",
                        })

        # Check 5: Response packets should exist if conformance shows callees
        if conf and not profile.get("response_packets"):
            callees = conf.get("callees", [])
            send_indicators = [c for c in callees
                               if isinstance(c, str) and
                               ("Send" in c or "WorldPacket" in c)]
            if len(send_indicators) >= 2:
                issues.append({
                    "handler": handler,
                    "issue_type": "missing_response_reconstruction",
                    "details": (
                        f"Conformance shows {len(send_indicators)} send-related "
                        f"callees but no response packet data was reconstructed"
                    ),
                    "severity": "medium",
                })

    # Sort issues by severity (high first) then by handler name
    severity_order = {"high": 0, "medium": 1, "low": 2}
    issues.sort(key=lambda i: (
        severity_order.get(i.get("severity", "low"), 3),
        i.get("handler", "")
    ))

    return issues


# ===================================================================
# Internal: System aggregation
# ===================================================================

def _aggregate_by_system(profiles):
    """Group handlers by game system and compute aggregated statistics.

    Returns a list of system aggregate dicts sorted by coverage (ascending).
    """
    system_data = defaultdict(lambda: {
        "handlers": [],
        "conformance_scores": [],
        "taint_totals": 0,
        "taint_unguarded": 0,
        "coverage_values": [],
    })

    for p in profiles:
        system = p.get("system", "Other")
        data = system_data[system]
        data["handlers"].append(p["handler"])

        cs = p.get("conformance_score")
        if cs is not None and isinstance(cs, (int, float)):
            data["conformance_scores"].append(cs)

        data["taint_totals"] += p.get("taint_count", 0)
        data["taint_unguarded"] += p.get("taint_unguarded", 0)
        data["coverage_values"].append(p.get("coverage_pct", 0))

    aggregates = []
    for system, data in sorted(system_data.items()):
        handler_count = len(data["handlers"])
        conf_scores = data["conformance_scores"]
        cov_values = data["coverage_values"]

        avg_conformance = 0
        if conf_scores:
            avg_conformance = sum(conf_scores) / len(conf_scores)

        avg_coverage = 0
        if cov_values:
            avg_coverage = sum(cov_values) / len(cov_values)

        aggregates.append({
            "system": system,
            "handler_count": handler_count,
            "avg_conformance": round(avg_conformance, 1),
            "min_conformance": round(min(conf_scores), 1) if conf_scores else None,
            "max_conformance": round(max(conf_scores), 1) if conf_scores else None,
            "conformance_rated_count": len(conf_scores),
            "taint_total": data["taint_totals"],
            "taint_unguarded": data["taint_unguarded"],
            "coverage_pct": round(avg_coverage, 1),
            "handlers": data["handlers"],
        })

    # Sort by coverage ascending (least-covered first = most attention needed)
    aggregates.sort(key=lambda a: a["coverage_pct"])

    return aggregates


# ===================================================================
# Internal: Priority list
# ===================================================================

def _build_priority_list(profiles, per_handler_coverage):
    """Rank handlers by improvement potential.

    Higher priority score = more urgently needs developer attention.

    Factors:
      - Low conformance score (weight: 30)
      - High unguarded taint flows (weight: 40)
      - Low analysis coverage (weight: 15)
      - High taint severity (weight: 15)

    Returns a list of {handler, priority_score, reasons} sorted descending.
    """
    items = []

    for p in profiles:
        handler = p["handler"]
        reasons = []
        score = 0.0

        # Factor 1: Conformance (inverted — lower conformance = higher priority)
        conf_score = p.get("conformance_score")
        if conf_score is not None and isinstance(conf_score, (int, float)):
            conf_deficit = max(0, 100 - conf_score)
            contribution = (conf_deficit / 100.0) * 30
            score += contribution
            if conf_score < 50:
                reasons.append(f"Low conformance: {conf_score}%")
            elif conf_score < 70:
                reasons.append(f"Moderate conformance: {conf_score}%")
        else:
            # No conformance data — contributes a baseline
            score += 10
            reasons.append("No conformance data available")

        # Factor 2: Unguarded taint flows
        taint_unguarded = p.get("taint_unguarded", 0)
        taint_high = p.get("taint_high", 0)

        if taint_unguarded > 0:
            # Scale: 1 unguarded = 5 pts, capped at 40
            taint_contribution = min(40, taint_unguarded * 5)
            score += taint_contribution
            reasons.append(f"{taint_unguarded} unguarded taint flows")

        if taint_high > 0:
            # Additional weight for high-severity
            high_contribution = min(15, taint_high * 5)
            score += high_contribution
            reasons.append(f"{taint_high} HIGH severity taint flows")

        # Factor 3: Low coverage
        coverage = p.get("coverage_pct", 0)
        coverage_deficit = max(0, 100 - coverage)
        coverage_contribution = (coverage_deficit / 100.0) * 15
        score += coverage_contribution
        if coverage < 30:
            reasons.append(f"Very low analysis coverage: {coverage}%")
        elif coverage < 50:
            reasons.append(f"Low analysis coverage: {coverage}%")

        # Factor 4: Missing validations
        val = p.get("validation_info")
        if val and isinstance(val, dict):
            missing = val.get("missing_count", val.get("missing", 0))
            if isinstance(missing, int) and missing > 0:
                val_contribution = min(10, missing * 2)
                score += val_contribution
                reasons.append(f"{missing} missing validation checks")

        # Only include handlers that actually need attention
        if score > 5 and reasons:
            items.append({
                "handler": handler,
                "system": p.get("system", "Other"),
                "priority_score": round(score, 1),
                "conformance_score": conf_score,
                "taint_unguarded": taint_unguarded,
                "coverage_pct": coverage,
                "reasons": reasons,
            })

    # Sort by priority score descending (most urgent first)
    items.sort(key=lambda x: -x["priority_score"])

    return items


# ===================================================================
# Internal: System classification
# ===================================================================

def _classify_system(handler_name):
    """Classify a handler into a game system based on its opcode name.

    Uses keyword matching against the opcode name to determine the
    system.  Falls back to "Other" if no keyword matches.
    """
    if not handler_name:
        return "Other"

    name_upper = handler_name.upper()

    # Remove CMSG_/SMSG_ prefix for cleaner matching
    for prefix in ("CMSG_", "SMSG_"):
        if name_upper.startswith(prefix):
            name_upper = name_upper[len(prefix):]
            break

    for keyword, system in _SYSTEM_KEYWORDS.items():
        if keyword in name_upper:
            return system

    return "Other"


# ===================================================================
# Internal: Output helpers
# ===================================================================

def _print_coverage_summary(coverage_matrix):
    """Print a compact coverage summary to the IDA output window."""
    msg("")
    msg("  Coverage Matrix:")
    msg("  " + "-" * 50)
    for aname, data in sorted(coverage_matrix.items(),
                               key=lambda x: x[1]["pct"]):
        bar_len = int(data["pct"] / 5)
        bar = "#" * bar_len + "." * (20 - bar_len)
        msg(f"    {aname:25s} [{bar}] "
            f"{data['covered']:4d}/{data['total']:4d} "
            f"({data['pct']:5.1f}%)")
    msg("")


def _print_top_priority(priority_list):
    """Print top-10 priority items to the IDA output window."""
    if not priority_list:
        msg("  Priority List: (empty)")
        return

    msg("  Top Priority Handlers (need most attention):")
    msg("  " + "-" * 60)
    for item in priority_list[:10]:
        reasons_str = "; ".join(item["reasons"][:3])
        msg(f"    [{item['priority_score']:5.1f}] {item['handler']}")
        msg(f"           System: {item.get('system', '?')}  |  {reasons_str}")
    if len(priority_list) > 10:
        msg(f"    ... and {len(priority_list) - 10} more handlers")
    msg("")


def _print_system_summary(system_aggregates):
    """Print system-level summary to the IDA output window."""
    if not system_aggregates:
        return

    msg("  System Summary (sorted by coverage, lowest first):")
    msg("  " + "-" * 70)
    msg(f"    {'System':15s} {'Handlers':>8s} {'Conformance':>12s} "
        f"{'Taint':>6s} {'Coverage':>9s}")
    msg("  " + "-" * 70)
    for sa in system_aggregates:
        conf_str = f"{sa['avg_conformance']:.0f}%" if sa['conformance_rated_count'] > 0 else "N/A"
        msg(f"    {sa['system']:15s} {sa['handler_count']:>8d} "
            f"{conf_str:>12s} {sa['taint_total']:>6d} "
            f"{sa['coverage_pct']:>8.1f}%")
    msg("")


# ===================================================================
# Internal: CSV helper
# ===================================================================

def _csv_escape(value):
    """Escape a value for CSV output."""
    s = str(value) if value is not None else ""
    if "," in s or '"' in s or "\n" in s:
        s = '"' + s.replace('"', '""') + '"'
    return s


# ===================================================================
# Convenience: Dark handler finder
# ===================================================================

def get_dark_handlers(session, threshold=20.0):
    """Return handlers with coverage below the given threshold.

    These are handlers that have very little analysis data — "dark spots"
    in the knowledge base.

    Args:
        session: PluginSession
        threshold: Coverage percentage below which a handler is "dark"

    Returns:
        List of (handler_name, coverage_pct, system) tuples.
    """
    report = get_synthesis_report(session)
    if not report:
        return []

    dark = []
    for p in report.get("handler_profiles", []):
        cov = p.get("coverage_pct", 0)
        if cov < threshold:
            dark.append((
                p.get("handler", "?"),
                cov,
                p.get("system", "Other"),
            ))

    dark.sort(key=lambda x: x[1])
    return dark


def get_system_report(session, system_name):
    """Return all handler profiles belonging to a given system.

    Args:
        session: PluginSession
        system_name: System name (e.g. "Housing", "Combat")

    Returns:
        List of handler profile dicts for that system.
    """
    report = get_synthesis_report(session)
    if not report:
        return []

    return [
        p for p in report.get("handler_profiles", [])
        if p.get("system", "").lower() == system_name.lower()
    ]


def get_consistency_issues_by_type(session, issue_type=None):
    """Filter consistency issues, optionally by issue_type.

    Args:
        session: PluginSession
        issue_type: If given, only return issues of this type

    Returns:
        List of issue dicts.
    """
    report = get_synthesis_report(session)
    if not report:
        return []

    issues = report.get("consistency_issues", [])
    if issue_type:
        issues = [i for i in issues if i.get("issue_type") == issue_type]
    return issues


def export_system_comparison(session) -> str:
    """Export a system-level comparison table as formatted text.

    Returns a multi-line string with one row per system, showing
    key metrics for quick comparison.
    """
    report = get_synthesis_report(session)
    if not report:
        return "No synthesis data available.\n"

    aggregates = report.get("system_aggregates", [])
    if not aggregates:
        return "No system aggregates available.\n"

    lines = []
    lines.append("System Comparison Report")
    lines.append(f"Generated: {report.get('synthesis_time', 'unknown')}")
    lines.append("")

    # Header
    header = (f"{'System':<18} {'Count':>6} {'Avg Conf':>9} "
              f"{'Min Conf':>9} {'Max Conf':>9} "
              f"{'Taint':>6} {'Unguard':>8} {'Coverage':>9}")
    lines.append(header)
    lines.append("-" * len(header))

    for sa in aggregates:
        conf_avg = f"{sa['avg_conformance']:.1f}%" if sa.get('conformance_rated_count', 0) > 0 else "N/A"
        conf_min = f"{sa['min_conformance']:.1f}%" if sa.get('min_conformance') is not None else "N/A"
        conf_max = f"{sa['max_conformance']:.1f}%" if sa.get('max_conformance') is not None else "N/A"

        lines.append(
            f"{sa['system']:<18} {sa['handler_count']:>6} "
            f"{conf_avg:>9} {conf_min:>9} {conf_max:>9} "
            f"{sa['taint_total']:>6} {sa['taint_unguarded']:>8} "
            f"{sa['coverage_pct']:>8.1f}%"
        )

    lines.append("")
    lines.append(f"Total handlers: {report.get('total_handlers', 0)}")
    lines.append(f"Average coverage: {report.get('avg_coverage', 0):.1f}%")
    lines.append("")

    return "\n".join(lines)


def export_full_report(session) -> str:
    """Export the complete synthesis report as formatted text.

    Combines all sections: coverage, systems, consistency issues,
    and priority list into a single document.
    """
    report = get_synthesis_report(session)
    if not report:
        return "No synthesis data available.\n"

    lines = []
    lines.append("=" * 72)
    lines.append("  CROSS-ANALYZER SYNTHESIS REPORT")
    lines.append("=" * 72)
    lines.append(f"  Generated: {report.get('synthesis_time', 'unknown')}")
    lines.append(f"  Elapsed:   {report.get('elapsed_seconds', '?')}s")
    lines.append(f"  Handlers:  {report.get('total_handlers', 0)}")
    lines.append(f"  Avg Coverage: {report.get('avg_coverage', 0):.1f}%")
    lines.append("")

    # Section 1: Coverage Matrix
    lines.append("-" * 72)
    lines.append("  SECTION 1: ANALYZER COVERAGE MATRIX")
    lines.append("-" * 72)
    lines.append("")

    coverage = report.get("coverage_matrix", {})
    if coverage:
        lines.append(f"  {'Analyzer':<30} {'Covered':>8} {'Total':>8} {'Pct':>8}")
        lines.append("  " + "-" * 56)
        for aname in sorted(coverage.keys(), key=lambda k: coverage[k]["pct"]):
            data = coverage[aname]
            lines.append(
                f"  {aname:<30} {data['covered']:>8} "
                f"{data['total']:>8} {data['pct']:>7.1f}%"
            )
    lines.append("")

    # Section 2: System Aggregation
    lines.append("-" * 72)
    lines.append("  SECTION 2: SYSTEM-LEVEL AGGREGATION")
    lines.append("-" * 72)
    lines.append("")
    lines.append(export_system_comparison(session))

    # Section 3: Consistency Issues
    issues = report.get("consistency_issues", [])
    lines.append("-" * 72)
    lines.append(f"  SECTION 3: CONSISTENCY ISSUES ({len(issues)} found)")
    lines.append("-" * 72)
    lines.append("")

    if issues:
        for issue in issues[:30]:
            sev = issue.get("severity", "?").upper()
            lines.append(f"  [{sev:6s}] {issue.get('handler', '?')}")
            lines.append(f"           Type: {issue.get('issue_type', '?')}")
            lines.append(f"           {issue.get('details', '')}")
            lines.append("")
        if len(issues) > 30:
            lines.append(f"  ... and {len(issues) - 30} more issues")
    else:
        lines.append("  No consistency issues found.")
    lines.append("")

    # Section 4: Priority List
    priority = report.get("priority_list", [])
    lines.append("-" * 72)
    lines.append(f"  SECTION 4: PRIORITY IMPROVEMENT LIST ({len(priority)} items)")
    lines.append("-" * 72)
    lines.append("")

    if priority:
        lines.append(f"  {'Rank':>4} {'Score':>6} {'Handler':<40} {'System':<15}")
        lines.append("  " + "-" * 67)
        for i, item in enumerate(priority[:50], 1):
            lines.append(
                f"  {i:>4} {item['priority_score']:>6.1f} "
                f"{item['handler']:<40} {item.get('system', '?'):<15}"
            )
            for reason in item.get("reasons", []):
                lines.append(f"  {'':>12} - {reason}")
        if len(priority) > 50:
            lines.append(f"  ... and {len(priority) - 50} more items")
    else:
        lines.append("  No priority items.")
    lines.append("")

    lines.append("=" * 72)
    lines.append("  END OF REPORT")
    lines.append("=" * 72)

    return "\n".join(lines)
