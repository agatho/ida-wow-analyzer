"""
Automated TrinityCore Handler C++ Scaffolding Generator

Combines results from ALL other analyzers to emit compilable TrinityCore-style
handler implementations.  For each CMSG handler, the generator gathers wire
format, JAM types, symbolic constraints, behavioral specs, response packets,
validation rules, conformance data, taint analysis, enum recovery, game
constants, binary-TC alignment, return value semantics, and LLM decompilation
results, then selects a template and emits a complete C++ handler scaffold
with validation, core logic skeleton, response packets, and gap annotations.

Entry points:
    generate_all_scaffolds(session) -> int    — all handlers
    generate_handler_scaffold(session, name)  — single handler -> str

Export functions:
    get_scaffolding_report(session)           — retrieve stored results
    export_handler_file(session, name)        — single handler C++ code
    export_all_handlers(session, output_dir)  — write all to .cpp files
    get_best_scaffolds(session, min_compl)    — handlers above threshold
    get_gap_summary(session)                  — aggregate gap analysis
"""

import json
import re
import time
import os

import ida_funcs
import ida_name
import idautils

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text


# =========================================================================
# Constants
# =========================================================================

KV_KEY = "handler_scaffolding"

# JAM / wire type -> TrinityCore C++ type
_TYPE_MAP = {
    "uint8":        "uint8",
    "uint16":       "uint16",
    "uint32":       "uint32",
    "uint64":       "uint64",
    "int8":         "int8",
    "int16":        "int16",
    "int32":        "int32",
    "int64":        "int64",
    "float":        "float",
    "double":       "double",
    "ObjectGuid":   "ObjectGuid",
    "PackedGuid":   "ObjectGuid",
    "string":       "std::string",
    "bits":         "uint32",
    "bool":         "bool",
    "bit":          "bool",
}

# C++ default initialiser per type
_DEFAULTS = {
    "uint8": " = 0", "uint16": " = 0", "uint32": " = 0", "uint64": " = 0",
    "int8": " = 0", "int16": " = 0", "int32": " = 0", "int64": " = 0",
    "float": " = 0.0f", "double": " = 0.0",
    "bool": " = false",
}

# Opcode name -> handler category (used for template selection)
_CATEGORY_PATTERNS = [
    (re.compile(r"CMSG_MOVE_"),               "movement"),
    (re.compile(r"CMSG_CAST_SPELL"),          "spell"),
    (re.compile(r"CMSG_.*_QUERY"),            "query"),
    (re.compile(r"CMSG_CHAT_"),               "chat"),
    (re.compile(r"CMSG_GUILD_"),              "guild"),
    (re.compile(r"CMSG_AUCTION_"),            "auction"),
    (re.compile(r"CMSG_HOUSING_"),            "housing"),
    (re.compile(r"CMSG_HOUSE_"),              "housing"),
    (re.compile(r"CMSG_NEIGHBORHOOD_"),       "housing"),
    (re.compile(r"CMSG_DECOR_"),              "housing"),
    (re.compile(r"CMSG_ITEM_"),               "item"),
    (re.compile(r"CMSG_EQUIP_"),              "item"),
    (re.compile(r"CMSG_LOOT_"),               "loot"),
    (re.compile(r"CMSG_QUEST_"),              "quest"),
    (re.compile(r"CMSG_QUESTGIVER_"),         "quest"),
    (re.compile(r"CMSG_PET_"),               "pet"),
    (re.compile(r"CMSG_BATTLE_PET_"),         "pet"),
    (re.compile(r"CMSG_BATTLEGROUND_"),       "pvp"),
    (re.compile(r"CMSG_ARENA_"),              "pvp"),
    (re.compile(r"CMSG_GARRISON_"),           "garrison"),
    (re.compile(r"CMSG_TALENT_"),             "talent"),
    (re.compile(r"CMSG_TRADE_"),              "crafting"),
    (re.compile(r"CMSG_CRAFT_"),              "crafting"),
    (re.compile(r"CMSG_TRANSMOGRIFY_"),       "transmog"),
    (re.compile(r"CMSG_CALENDAR_"),           "calendar"),
    (re.compile(r"CMSG_GROUP_"),              "group"),
    (re.compile(r"CMSG_PARTY_"),              "group"),
    (re.compile(r"CMSG_LFG_"),               "group"),
    (re.compile(r"CMSG_MAIL_"),              "social"),
    (re.compile(r"CMSG_FRIEND_"),             "social"),
    (re.compile(r"CMSG_WHO"),                 "social"),
    (re.compile(r"CMSG_MYTHIC_PLUS_"),        "mythicplus"),
    (re.compile(r"CMSG_KEYSTONE_"),           "mythicplus"),
    (re.compile(r"CMSG_DELVE_"),              "delves"),
    (re.compile(r"CMSG_VEHICLE_"),            "vehicle"),
    (re.compile(r"CMSG_ACHIEVEMENT_"),        "achievement"),
    (re.compile(r"CMSG_BANK_"),              "bank"),
    (re.compile(r"CMSG_NPC_"),               "npc"),
    (re.compile(r"CMSG_GOSSIP_"),             "npc"),
    (re.compile(r"CMSG_TRAINER_"),            "npc"),
]

# System keyword -> game system classification
_SYSTEM_KEYWORDS = {
    "housing": "Housing", "movement": "Movement", "spell": "Combat",
    "query": "Query", "chat": "Social", "guild": "Social",
    "auction": "Auction", "item": "Item", "loot": "Loot",
    "quest": "Quest", "pet": "Pet", "pvp": "PvP",
    "garrison": "Garrison", "talent": "Talent", "crafting": "Crafting",
    "transmog": "Transmog", "calendar": "Calendar", "group": "Group",
    "social": "Social", "mythicplus": "MythicPlus", "delves": "Delves",
    "vehicle": "Vehicle", "achievement": "Achievement", "bank": "Bank",
    "npc": "NPC", "generic": "Misc",
}

# Include header guesses per category
_CATEGORY_INCLUDES = {
    "housing":      ["HousingPackets.h", "Player.h", "Housing.h", "WorldSession.h"],
    "movement":     ["MovementPackets.h", "Player.h", "WorldSession.h"],
    "spell":        ["SpellPackets.h", "Player.h", "Spell.h", "WorldSession.h"],
    "query":        ["QueryPackets.h", "Player.h", "WorldSession.h"],
    "chat":         ["ChatPackets.h", "Player.h", "WorldSession.h"],
    "guild":        ["GuildPackets.h", "Player.h", "Guild.h", "WorldSession.h"],
    "auction":      ["AuctionHousePackets.h", "Player.h", "AuctionHouseMgr.h", "WorldSession.h"],
    "item":         ["ItemPackets.h", "Player.h", "Item.h", "WorldSession.h"],
    "loot":         ["LootPackets.h", "Player.h", "Loot.h", "WorldSession.h"],
    "quest":        ["QuestPackets.h", "Player.h", "QuestDef.h", "WorldSession.h"],
    "pet":          ["PetPackets.h", "Player.h", "Pet.h", "WorldSession.h"],
    "pvp":          ["BattlegroundPackets.h", "Player.h", "Battleground.h", "WorldSession.h"],
    "garrison":     ["GarrisonPackets.h", "Player.h", "Garrison.h", "WorldSession.h"],
    "talent":       ["TalentPackets.h", "Player.h", "WorldSession.h"],
    "crafting":     ["TradePackets.h", "Player.h", "WorldSession.h"],
    "transmog":     ["TransmogrificationPackets.h", "Player.h", "WorldSession.h"],
    "calendar":     ["CalendarPackets.h", "Player.h", "CalendarMgr.h", "WorldSession.h"],
    "group":        ["PartyPackets.h", "Player.h", "Group.h", "WorldSession.h"],
    "social":       ["SocialPackets.h", "Player.h", "WorldSession.h"],
    "mythicplus":   ["MythicPlusPackets.h", "Player.h", "WorldSession.h"],
    "delves":       ["DelvesPackets.h", "Player.h", "WorldSession.h"],
    "vehicle":      ["VehiclePackets.h", "Player.h", "Vehicle.h", "WorldSession.h"],
    "achievement":  ["AchievementPackets.h", "Player.h", "AchievementMgr.h", "WorldSession.h"],
    "bank":         ["BankPackets.h", "Player.h", "WorldSession.h"],
    "npc":          ["NPCPackets.h", "Player.h", "Creature.h", "WorldSession.h"],
    "generic":      ["WorldPacket.h", "Player.h", "WorldSession.h"],
}

# Namespace guesses per category
_CATEGORY_NAMESPACE = {
    "housing": "Housing", "movement": "Movement", "spell": "Spells",
    "query": "Query", "chat": "Chat", "guild": "Guild",
    "auction": "AuctionHouse", "item": "Item", "loot": "Loot",
    "quest": "Quest", "pet": "Pet", "pvp": "Battleground",
    "garrison": "Garrison", "talent": "Talent", "crafting": "Trade",
    "transmog": "Transmogrification", "calendar": "Calendar",
    "group": "Party", "social": "Social", "mythicplus": "MythicPlus",
    "delves": "Delves", "vehicle": "Vehicle",
    "achievement": "Achievement", "bank": "Bank", "npc": "NPC",
    "generic": "Misc",
}


# =========================================================================
# Data Collection — Phase 1
# =========================================================================

class HandlerData:
    """Aggregated data for a single CMSG handler from all analyzers."""

    __slots__ = (
        "tc_name", "handler_ea", "jam_type", "category",
        "wire_format", "jam_fields", "constraints",
        "behavioral_spec", "response_packets", "validations",
        "conformance", "alignment", "taint", "game_constants",
        "enum_defs", "return_semantics", "llm_decompilation",
        "decompiled_text",
    )

    def __init__(self, tc_name, handler_ea, jam_type=None):
        self.tc_name = tc_name
        self.handler_ea = handler_ea
        self.jam_type = jam_type
        self.category = _classify_handler(tc_name)
        self.wire_format = None
        self.jam_fields = None
        self.constraints = None
        self.behavioral_spec = None
        self.response_packets = None
        self.validations = None
        self.conformance = None
        self.alignment = None
        self.taint = None
        self.game_constants = None
        self.enum_defs = None
        self.return_semantics = None
        self.llm_decompilation = None
        self.decompiled_text = None


def _classify_handler(tc_name):
    """Classify a handler by opcode name into a category string."""
    if not tc_name:
        return "generic"
    upper = tc_name.upper()
    for pattern, category in _CATEGORY_PATTERNS:
        if pattern.search(upper):
            return category
    return "generic"


def _collect_handler_data(session, handler_row):
    """Gather ALL analyzer results for a single handler into HandlerData."""
    db = session.db
    tc_name = handler_row["tc_name"] or handler_row.get("jam_type") or f"handler_{handler_row['internal_index']}"
    handler_ea = handler_row["handler_ea"]
    jam_type = handler_row["jam_type"]

    hd = HandlerData(tc_name, handler_ea, jam_type)

    # --- Wire format ---
    wire_data = db.kv_get("wire_formats")
    if wire_data and isinstance(wire_data, dict):
        formats = wire_data.get("formats", wire_data)
        # Try by tc_name, handler_ea hex, or jam_type
        hd.wire_format = (
            formats.get(tc_name)
            or formats.get(ea_str(handler_ea))
            or formats.get(str(handler_ea))
        )
        if not hd.wire_format and jam_type:
            hd.wire_format = formats.get(jam_type)

    # --- JAM type fields ---
    if jam_type:
        jam_row = db.fetchone(
            "SELECT * FROM jam_types WHERE name = ?", (jam_type,))
        if jam_row and jam_row["fields_json"]:
            try:
                hd.jam_fields = json.loads(jam_row["fields_json"])
            except (json.JSONDecodeError, TypeError):
                pass

    # --- Symbolic constraints ---
    constraint_data = db.kv_get("symbolic_constraints")
    if constraint_data and isinstance(constraint_data, dict):
        constraints = constraint_data.get("handlers", constraint_data)
        hd.constraints = (
            constraints.get(tc_name)
            or constraints.get(ea_str(handler_ea))
            or constraints.get(str(handler_ea))
        )

    # --- Behavioral spec ---
    spec_data = db.kv_get("behavioral_specs")
    if spec_data and isinstance(spec_data, dict):
        specs = spec_data.get("handlers", spec_data)
        hd.behavioral_spec = (
            specs.get(tc_name)
            or specs.get(ea_str(handler_ea))
            or specs.get(str(handler_ea))
        )

    # --- Response reconstruction ---
    resp_data = db.kv_get("response_packets")
    if resp_data and isinstance(resp_data, dict):
        packets = resp_data.get("handlers", resp_data)
        hd.response_packets = (
            packets.get(tc_name)
            or packets.get(ea_str(handler_ea))
            or packets.get(str(handler_ea))
        )

    # --- Validation extractor ---
    val_data = db.kv_get("validation_comparison_report")
    if val_data and isinstance(val_data, dict):
        validations = val_data.get("handlers", val_data)
        hd.validations = (
            validations.get(tc_name)
            or validations.get(ea_str(handler_ea))
            or validations.get(str(handler_ea))
        )

    # --- Conformance ---
    conf_data = db.kv_get("conformance_report")
    if conf_data and isinstance(conf_data, dict):
        scores = conf_data.get("handlers", conf_data.get("scores", conf_data))
        if isinstance(scores, list):
            for entry in scores:
                if isinstance(entry, dict):
                    if entry.get("tc_name") == tc_name:
                        hd.conformance = entry
                        break
        elif isinstance(scores, dict):
            hd.conformance = (
                scores.get(tc_name)
                or scores.get(ea_str(handler_ea))
                or scores.get(str(handler_ea))
            )

    # --- Binary-TC alignment ---
    align_data = db.kv_get("binary_tc_alignment")
    if align_data and isinstance(align_data, dict):
        alignments = align_data.get("handlers", align_data)
        hd.alignment = (
            alignments.get(tc_name)
            or alignments.get(ea_str(handler_ea))
            or alignments.get(str(handler_ea))
        )

    # --- Taint analysis ---
    taint_data = db.kv_get("taint_analysis")
    if taint_data and isinstance(taint_data, dict):
        taints = taint_data.get("handlers", taint_data)
        hd.taint = (
            taints.get(tc_name)
            or taints.get(ea_str(handler_ea))
            or taints.get(str(handler_ea))
        )

    # --- Game constants ---
    const_data = db.kv_get("game_constants")
    if const_data and isinstance(const_data, dict):
        constants = const_data.get("handlers", const_data)
        hd.game_constants = (
            constants.get(tc_name)
            or constants.get(ea_str(handler_ea))
            or constants.get(str(handler_ea))
        )

    # --- Enum recovery ---
    enum_data = db.kv_get("enum_recovery")
    if enum_data and isinstance(enum_data, dict):
        enums = enum_data.get("enums", enum_data)
        if isinstance(enums, dict):
            hd.enum_defs = enums
        elif isinstance(enums, list):
            hd.enum_defs = {e.get("name", f"Enum{i}"): e for i, e in enumerate(enums) if isinstance(e, dict)}

    # --- Return value semantics ---
    ret_data = db.kv_get("return_value_semantics")
    if ret_data and isinstance(ret_data, dict):
        rets = ret_data.get("handlers", ret_data)
        hd.return_semantics = (
            rets.get(tc_name)
            or rets.get(ea_str(handler_ea))
            or rets.get(str(handler_ea))
        )

    # --- LLM decompilation ---
    llm_data = db.kv_get("llm_semantic_decompilation")
    if llm_data and isinstance(llm_data, dict):
        llm = llm_data.get("handlers", llm_data)
        hd.llm_decompilation = (
            llm.get(tc_name)
            or llm.get(ea_str(handler_ea))
            or llm.get(str(handler_ea))
        )

    # --- Raw decompiled text (fallback for gap annotations) ---
    if handler_ea:
        try:
            hd.decompiled_text = get_decompiled_text(handler_ea, db=db)
        except Exception:
            pass

    return hd


# =========================================================================
# Field Resolution — merge wire_format + jam_fields into canonical list
# =========================================================================

class ResolvedField:
    """A single packet field with merged information from wire + JAM."""

    __slots__ = (
        "name", "cpp_type", "wire_type", "bit_count",
        "is_optional", "is_array", "array_size_field",
        "constraint", "comment",
    )

    def __init__(self, name="Field0", cpp_type="uint32", wire_type="uint32"):
        self.name = name
        self.cpp_type = cpp_type
        self.wire_type = wire_type
        self.bit_count = 0
        self.is_optional = False
        self.is_array = False
        self.array_size_field = None
        self.constraint = None
        self.comment = None


def _resolve_fields(hd):
    """Merge wire format and JAM fields into a list of ResolvedField objects.

    Priority: wire_format fields take precedence for read order and types;
    JAM fields provide names and structural metadata.
    """
    fields = []

    # Build a JAM field lookup by index
    jam_by_index = {}
    if hd.jam_fields:
        for i, jf in enumerate(hd.jam_fields):
            if isinstance(jf, dict):
                jam_by_index[i] = jf

    # Primary source: wire format (has correct read order)
    if hd.wire_format:
        wire_fields = None
        if isinstance(hd.wire_format, dict):
            wire_fields = hd.wire_format.get("fields", [])
        elif isinstance(hd.wire_format, list):
            wire_fields = hd.wire_format

        if wire_fields:
            for i, wf in enumerate(wire_fields):
                if not isinstance(wf, dict):
                    continue
                rf = ResolvedField()
                wire_type = wf.get("type", "uint32")
                rf.wire_type = wire_type
                rf.cpp_type = _TYPE_MAP.get(wire_type, "uint32")

                # Prefer JAM name, fall back to wire name or generic
                jam_f = jam_by_index.get(i, {})
                rf.name = (
                    wf.get("name")
                    or jam_f.get("name")
                    or f"Field{i}"
                )
                rf.name = _sanitise_field_name(rf.name)

                rf.bit_count = wf.get("bit_count", 0)
                rf.is_optional = wf.get("optional", False) or wf.get("is_optional", False)
                rf.is_array = wf.get("is_array", False)
                rf.array_size_field = wf.get("array_size_field")

                # Attach constraint if available
                if hd.constraints and isinstance(hd.constraints, dict):
                    param_constraints = hd.constraints.get("parameters", hd.constraints)
                    if isinstance(param_constraints, dict):
                        rf.constraint = param_constraints.get(rf.name)
                    elif isinstance(param_constraints, list):
                        if i < len(param_constraints):
                            rf.constraint = param_constraints[i]

                fields.append(rf)
            return fields

    # Fallback: JAM fields only
    if hd.jam_fields:
        for i, jf in enumerate(hd.jam_fields):
            if not isinstance(jf, dict):
                continue
            rf = ResolvedField()
            jtype = jf.get("type", "uint32")
            rf.wire_type = jtype
            rf.cpp_type = _TYPE_MAP.get(jtype, "uint32")
            rf.name = _sanitise_field_name(jf.get("name", f"Field{i}"))
            rf.bit_count = jf.get("bit_count", 0)
            rf.is_optional = jf.get("optional", False)
            rf.is_array = jf.get("is_array", False)
            rf.array_size_field = jf.get("array_size_field")
            fields.append(rf)

    return fields


def _sanitise_field_name(name):
    """Ensure a field name is a valid C++ identifier in PascalCase."""
    if not name:
        return "UnknownField"
    # Strip leading underscores/digits
    name = re.sub(r'^[^A-Za-z]+', '', name)
    if not name:
        return "UnknownField"
    # PascalCase: capitalise first letter
    return name[0].upper() + name[1:] if len(name) > 1 else name.upper()


# =========================================================================
# C++ Code Generation — Phases 3-8
# =========================================================================

def _derive_handler_name(tc_name):
    """CMSG_HOUSING_PLACE_DECOR -> HandleHousingPlaceDecor"""
    if not tc_name:
        return "HandleUnknown"
    # Strip CMSG_ prefix
    body = tc_name
    for prefix in ("CMSG_", "SMSG_"):
        if body.upper().startswith(prefix):
            body = body[len(prefix):]
            break
    # UPPER_SNAKE -> PascalCase
    parts = body.split("_")
    pascal = "".join(p.capitalize() for p in parts if p)
    return f"Handle{pascal}"


def _derive_class_name(tc_name):
    """CMSG_HOUSING_PLACE_DECOR -> HousingPlaceDecor"""
    if not tc_name:
        return "Unknown"
    body = tc_name
    for prefix in ("CMSG_", "SMSG_"):
        if body.upper().startswith(prefix):
            body = body[len(prefix):]
            break
    parts = body.split("_")
    return "".join(p.capitalize() for p in parts if p)


def _derive_class_name_from_jam(jam_type):
    """JamCliHouseDecorAction -> HouseDecorAction"""
    if not jam_type:
        return None
    for prefix in ("JamCli", "JamSvcs", "JamSrv", "Jam"):
        if jam_type.startswith(prefix):
            return jam_type[len(prefix):]
    return jam_type


def _get_default_init(cpp_type):
    """Get C++ default initialiser string."""
    return _DEFAULTS.get(cpp_type, "")


# -------------------------------------------------------------------------
# Phase 3: Packet reading code
# -------------------------------------------------------------------------

def _gen_packet_field_extraction(fields, hd):
    """Generate local variable declarations from packet fields.

    Returns list of C++ lines (no leading indent).
    """
    lines = []
    if not fields:
        lines.append("// No wire format data available for this handler")
        lines.append("// GAP: Wire format unknown — run wire_format_recovery analyzer")
        return lines

    lines.append("// --- Packet fields (auto-generated from wire format) ---")
    for rf in fields:
        if rf.is_array:
            size_expr = rf.array_size_field or "arraySize"
            lines.append(f"// Array field: {rf.name} (size from {size_expr})")
            lines.append(f"for (uint32 i = 0; i < packet.{rf.name}.size(); ++i)")
            lines.append("{")
            lines.append(f"    auto const& entry = packet.{rf.name}[i];")
            lines.append(f"    // TODO: process entry")
            lines.append("}")
        elif rf.wire_type == "bits" and rf.bit_count == 1:
            lines.append(f"bool {_to_local(rf.name)} = packet.{rf.name};")
        elif rf.wire_type in ("PackedGuid", "ObjectGuid"):
            lines.append(f"ObjectGuid {_to_local(rf.name)} = packet.{rf.name};")
        elif rf.wire_type == "string":
            lines.append(f"std::string const& {_to_local(rf.name)} = packet.{rf.name};")
        else:
            lines.append(f"{rf.cpp_type} {_to_local(rf.name)} = packet.{rf.name};")

        # Add constraint comment
        if rf.constraint:
            constraint_str = _format_constraint(rf.constraint)
            if constraint_str:
                lines[-1] += f"  // {constraint_str}"

    return lines


def _to_local(pascal_name):
    """PascalCase -> camelCase for local variable name."""
    if not pascal_name or len(pascal_name) < 2:
        return pascal_name.lower() if pascal_name else "val"
    return pascal_name[0].lower() + pascal_name[1:]


def _format_constraint(constraint):
    """Format a constraint dict/string into a human-readable comment."""
    if isinstance(constraint, str):
        return constraint
    if not isinstance(constraint, dict):
        return None
    ctype = constraint.get("type", constraint.get("ctype", ""))
    if ctype == "range":
        lo = constraint.get("min_val", constraint.get("min", "?"))
        hi = constraint.get("max_val", constraint.get("max", "?"))
        return f"Valid range: [{lo}, {hi}]"
    if ctype == "set":
        vals = constraint.get("values", [])
        if len(vals) <= 8:
            return f"Valid values: {{{', '.join(str(v) for v in vals)}}}"
        return f"Valid set ({len(vals)} values)"
    if ctype == "bitmask":
        mask = constraint.get("mask", "?")
        expected = constraint.get("expected", "?")
        return f"Bitmask: value & {mask} == {expected}"
    if ctype == "boolean":
        return "Boolean (0 or 1)"
    if ctype == "null_check":
        return "Must be non-null"
    parts = []
    for k, v in constraint.items():
        if k not in ("type", "ctype"):
            parts.append(f"{k}={v}")
    return "; ".join(parts) if parts else None


# -------------------------------------------------------------------------
# Phase 4: Validation code
# -------------------------------------------------------------------------

def _gen_validation_code(fields, hd):
    """Generate validation blocks from constraints + validation extractor.

    Returns list of C++ lines.
    """
    lines = []
    has_validations = False

    # From resolved field constraints
    for rf in fields:
        if not rf.constraint:
            continue
        block = _gen_single_validation(rf)
        if block:
            if not has_validations:
                lines.append("")
                lines.append("// --- Validations (auto-generated from binary constraints) ---")
                has_validations = True
            lines.extend(block)

    # From validation extractor results
    if hd.validations:
        extracted = None
        if isinstance(hd.validations, dict):
            extracted = hd.validations.get("binary_validations",
                        hd.validations.get("validations",
                        hd.validations.get("checks")))
        elif isinstance(hd.validations, list):
            extracted = hd.validations

        if extracted and isinstance(extracted, list):
            if not has_validations:
                lines.append("")
                lines.append("// --- Validations (from validation extractor) ---")
                has_validations = True
            for val in extracted:
                if not isinstance(val, dict):
                    continue
                vtype = val.get("type", val.get("name", "unknown"))
                desc = val.get("description", val.get("desc", ""))
                condition = val.get("condition", val.get("check", ""))
                error_code = val.get("error_code", val.get("return_value", ""))

                if condition:
                    lines.append(f"")
                    lines.append(f"    // Validation: {vtype} — {desc}")
                    lines.append(f"    // Binary check: {condition}")
                    if error_code:
                        lines.append(f"    // Error code: {error_code}")

    return lines


def _gen_single_validation(rf):
    """Generate a validation if-block for a single field's constraint."""
    c = rf.constraint
    if not isinstance(c, dict):
        return None

    lines = []
    local = _to_local(rf.name)
    ctype = c.get("type", c.get("ctype", ""))

    if ctype == "range":
        lo = c.get("min_val", c.get("min"))
        hi = c.get("max_val", c.get("max"))
        if lo is not None and hi is not None:
            lines.append(f"    if ({local} < {lo} || {local} > {hi})")
            lines.append(f"    {{")
            lines.append(f"        // Binary rejects values outside [{lo}, {hi}]")
            lines.append(f"        TC_LOG_DEBUG(\"network\", \"Invalid {rf.name}: {{}}\", {local});")
            lines.append(f"        return;")
            lines.append(f"    }}")
        elif lo is not None:
            lines.append(f"    if ({local} < {lo})")
            lines.append(f"    {{")
            lines.append(f"        TC_LOG_DEBUG(\"network\", \"Invalid {rf.name}: {{}}\", {local});")
            lines.append(f"        return;")
            lines.append(f"    }}")
        elif hi is not None:
            lines.append(f"    if ({local} > {hi})")
            lines.append(f"    {{")
            lines.append(f"        TC_LOG_DEBUG(\"network\", \"Invalid {rf.name}: {{}}\", {local});")
            lines.append(f"        return;")
            lines.append(f"    }}")

    elif ctype == "set":
        vals = c.get("values", [])
        if vals and len(vals) <= 16:
            checks = " && ".join(f"{local} != {v}" for v in vals)
            lines.append(f"    if ({checks})")
            lines.append(f"    {{")
            lines.append(f"        TC_LOG_DEBUG(\"network\", \"Invalid {rf.name}: {{}}\", {local});")
            lines.append(f"        return;")
            lines.append(f"    }}")

    elif ctype == "bitmask":
        mask = c.get("mask", 0)
        expected = c.get("expected", 0)
        lines.append(f"    if (({local} & {mask}) != {expected})")
        lines.append(f"    {{")
        lines.append(f"        TC_LOG_DEBUG(\"network\", \"Invalid {rf.name} bitmask\");")
        lines.append(f"        return;")
        lines.append(f"    }}")

    elif ctype == "null_check":
        lines.append(f"    if (!{local})")
        lines.append(f"    {{")
        lines.append(f"        TC_LOG_DEBUG(\"network\", \"{rf.name} is null\");")
        lines.append(f"        return;")
        lines.append(f"    }}")

    return lines if lines else None


# -------------------------------------------------------------------------
# Phase 5: Core logic skeleton
# -------------------------------------------------------------------------

def _gen_core_logic(hd, fields):
    """Generate core logic skeleton from behavioral spec + conformance.

    Returns list of C++ lines.
    """
    lines = []
    lines.append("")
    lines.append("    // --- Core logic (skeleton from behavioral analysis) ---")

    # If we have behavioral spec, extract execution paths
    if hd.behavioral_spec and isinstance(hd.behavioral_spec, dict):
        paths = hd.behavioral_spec.get("paths",
                hd.behavioral_spec.get("execution_paths", []))
        side_effects = hd.behavioral_spec.get("side_effects", [])
        callees = hd.behavioral_spec.get("callees",
                  hd.behavioral_spec.get("called_functions", []))

        if callees and isinstance(callees, list):
            lines.append("")
            lines.append("    // Called functions (from behavioral analysis):")
            for callee in callees[:20]:
                if isinstance(callee, dict):
                    cname = callee.get("name", callee.get("function", "unknown"))
                    cclass = callee.get("classification", callee.get("category", ""))
                    lines.append(f"    // -> {cname}" + (f" ({cclass})" if cclass else ""))
                elif isinstance(callee, str):
                    lines.append(f"    // -> {callee}")

        if side_effects and isinstance(side_effects, list):
            lines.append("")
            for se in side_effects[:15]:
                if isinstance(se, dict):
                    effect = se.get("effect", se.get("description", str(se)))
                    lines.append(f"    // Effect: {effect}")
                elif isinstance(se, str):
                    lines.append(f"    // Effect: {se}")

        if isinstance(paths, list) and paths:
            lines.append("")
            lines.append(f"    // Execution paths: {len(paths)} identified")
            for i, path in enumerate(paths[:5]):
                if isinstance(path, dict):
                    cond = path.get("conditions", path.get("condition", ""))
                    outcome = path.get("outcome", path.get("result", ""))
                    if cond or outcome:
                        lines.append(f"    // Path {i+1}: {cond} -> {outcome}")

    # LLM decompilation hints
    elif hd.llm_decompilation and isinstance(hd.llm_decompilation, dict):
        llm_code = hd.llm_decompilation.get("code",
                   hd.llm_decompilation.get("decompiled", ""))
        if llm_code and isinstance(llm_code, str):
            lines.append("")
            lines.append("    // LLM-assisted decompilation available:")
            for llm_line in llm_code.split("\n")[:30]:
                lines.append(f"    // {llm_line}")

    # Alignment-based hints
    if hd.alignment and isinstance(hd.alignment, dict):
        divergences = hd.alignment.get("divergences", [])
        if divergences and isinstance(divergences, list):
            lines.append("")
            lines.append(f"    // Binary-TC alignment: {len(divergences)} divergence(s)")
            for div in divergences[:10]:
                if isinstance(div, dict):
                    dtype = div.get("type", "unknown")
                    severity = div.get("severity", "UNKNOWN")
                    desc = div.get("description", div.get("desc", ""))
                    lines.append(f"    // [{severity}] {dtype}: {desc}")

    # Category-specific skeleton code
    skeleton = _gen_category_skeleton(hd, fields)
    if skeleton:
        lines.append("")
        lines.extend(skeleton)

    # If no data at all, generate minimal skeleton
    if len(lines) <= 2:
        lines.append("")
        lines.append(f"    // TODO: Implement {hd.tc_name} handler logic")
        lines.append(f"    // No behavioral analysis data available")
        if hd.decompiled_text:
            linecount = hd.decompiled_text.count("\n") + 1
            lines.append(f"    // Binary handler is ~{linecount} lines of pseudocode")

    return lines


def _gen_category_skeleton(hd, fields):
    """Generate category-specific skeleton code."""
    cat = hd.category
    lines = []

    if cat == "housing":
        lines.append("    Housing* housing = player->GetHousing();")
        lines.append("    if (!housing)")
        lines.append("    {")
        lines.append("        TC_LOG_DEBUG(\"network\", \"Player {} has no housing\", player->GetGUID().ToString());")
        lines.append("        return;")
        lines.append("    }")
        lines.append("")
        lines.append("    // TODO: Housing-specific logic")

    elif cat == "movement":
        lines.append("    // Movement handlers typically validate then broadcast")
        lines.append("    MovementInfo& movementInfo = player->m_movementInfo;")
        lines.append("")
        lines.append("    // TODO: Validate movement flags and position")
        lines.append("    // TODO: Broadcast to nearby players")

    elif cat == "spell":
        lines.append("    // Spell cast handlers validate target, spell id, reagents")
        lines.append("    // TODO: Validate spell exists and player can cast it")
        lines.append("    // TODO: Check cooldown, resources, range")
        lines.append("    // TODO: Create Spell object and prepare cast")

    elif cat == "query":
        lines.append("    // Query handlers look up data and send response")
        lines.append("    // TODO: Look up requested data from world/DB")
        lines.append("    // TODO: Build and send response packet")

    elif cat == "chat":
        lines.append("    // Chat handlers validate message, check mute, then broadcast")
        lines.append("    // TODO: Validate message content and length")
        lines.append("    // TODO: Check chat restrictions (mute, level, etc.)")
        lines.append("    // TODO: Route message to appropriate channel/target")

    elif cat == "guild":
        lines.append("    Guild* guild = player->GetGuild();")
        lines.append("    if (!guild)")
        lines.append("    {")
        lines.append("        // Player must be in a guild")
        lines.append("        return;")
        lines.append("    }")
        lines.append("")
        lines.append("    // TODO: Guild-specific logic")

    elif cat == "auction":
        lines.append("    // Auction handlers require proximity to auctioneer")
        lines.append("    // TODO: Validate auctioneer creature proximity")
        lines.append("    // TODO: Validate item/bid/buyout parameters")
        lines.append("    // TODO: Interact with AuctionHouseMgr")

    elif cat == "item":
        lines.append("    // Item handlers validate bag/slot, item existence, permissions")
        lines.append("    // TODO: Validate bag and slot indices")
        lines.append("    // TODO: Check item exists and player can modify it")

    elif cat == "loot":
        lines.append("    Loot* loot = player->GetLootByWorldObjectGUID(/* lootGuid */);")
        lines.append("    if (!loot)")
        lines.append("    {")
        lines.append("        // No active loot")
        lines.append("        return;")
        lines.append("    }")
        lines.append("")
        lines.append("    // TODO: Loot-specific logic")

    elif cat == "quest":
        lines.append("    // Quest handlers validate quest state and prerequisites")
        lines.append("    // TODO: Validate quest ID exists")
        lines.append("    // TODO: Check quest status and prerequisites")
        lines.append("    // TODO: Process quest action (accept/complete/abandon)")

    elif cat == "pvp":
        lines.append("    // PvP handlers interact with BattlegroundMgr")
        lines.append("    // TODO: Validate battleground context")
        lines.append("    // TODO: Process PvP action")

    elif cat == "npc":
        lines.append("    // NPC interaction handlers validate creature proximity")
        lines.append("    // TODO: Find and validate target creature")
        lines.append("    // TODO: Check interaction distance and flags")

    return lines


# -------------------------------------------------------------------------
# Phase 6: Response packet generation
# -------------------------------------------------------------------------

def _gen_response_code(hd):
    """Generate response packet code from response_reconstruction data.

    Returns list of C++ lines.
    """
    lines = []

    if not hd.response_packets:
        lines.append("")
        lines.append("    // GAP: No response packet data available")
        lines.append("    // Run response_reconstruction analyzer for this handler")
        return lines

    resp_list = None
    if isinstance(hd.response_packets, dict):
        resp_list = hd.response_packets.get("responses",
                    hd.response_packets.get("packets", []))
        if not resp_list:
            # Maybe the dict itself is a single response
            if "opcode" in hd.response_packets or "smsg_name" in hd.response_packets:
                resp_list = [hd.response_packets]
    elif isinstance(hd.response_packets, list):
        resp_list = hd.response_packets

    if not resp_list:
        lines.append("")
        lines.append("    // No response packets identified for this handler")
        return lines

    lines.append("")
    lines.append("    // --- Response (auto-generated from SMSG analysis) ---")

    for resp in resp_list:
        if not isinstance(resp, dict):
            continue

        smsg_name = resp.get("smsg_name",
                    resp.get("opcode_name",
                    resp.get("name", "UnknownResponse")))
        condition = resp.get("condition", resp.get("path", ""))
        resp_fields = resp.get("fields", resp.get("writes", []))

        # Derive response packet class name
        resp_class = _derive_smsg_class(smsg_name)

        if condition:
            lines.append(f"    // Sent when: {condition}")

        lines.append(f"    WorldPackets::{_CATEGORY_NAMESPACE.get(hd.category, 'Misc')}::{resp_class} response;")

        if resp_fields and isinstance(resp_fields, list):
            for rf in resp_fields:
                if isinstance(rf, dict):
                    fname = rf.get("name", rf.get("field", "UnknownField"))
                    fval = rf.get("value", rf.get("source", "/* TODO */"))
                    lines.append(f"    response.{_sanitise_field_name(fname)} = {fval};")
                elif isinstance(rf, str):
                    lines.append(f"    // response field: {rf}")
        else:
            lines.append(f"    // TODO: populate response fields")

        lines.append(f"    SendPacket(response.Write());")
        lines.append("")

    return lines


def _derive_smsg_class(smsg_name):
    """SMSG_HOUSING_PLACE_DECOR_RESULT -> HousingPlaceDecorResult"""
    if not smsg_name:
        return "UnknownResponse"
    body = smsg_name
    for prefix in ("SMSG_", "CMSG_"):
        if body.upper().startswith(prefix):
            body = body[len(prefix):]
            break
    parts = body.split("_")
    return "".join(p.capitalize() for p in parts if p)


# -------------------------------------------------------------------------
# Phase 7: Gap annotations
# -------------------------------------------------------------------------

def _gen_gap_annotations(hd, fields):
    """Generate GAP annotations for unresolved logic.

    Returns (list_of_lines, gap_count).
    """
    lines = []
    gap_count = 0

    # Check for missing wire format
    if not fields:
        lines.append("")
        lines.append("    // GAP: No wire format data — packet fields unknown")
        lines.append("    // Action: Run wire_format_recovery and/or jam_recovery analyzers")
        gap_count += 1

    # Check for unresolved behavioral spec sections
    if hd.behavioral_spec and isinstance(hd.behavioral_spec, dict):
        unresolved = hd.behavioral_spec.get("unresolved_blocks",
                     hd.behavioral_spec.get("unknown_calls", []))
        if unresolved and isinstance(unresolved, list):
            for block in unresolved[:10]:
                lines.append("")
                if isinstance(block, dict):
                    ea = block.get("ea", block.get("address", "unknown"))
                    desc = block.get("description", block.get("desc", ""))
                    line_count = block.get("line_count", block.get("lines", "?"))
                    lines.append(f"    // GAP: Binary contains {line_count} lines of logic at {ea}")
                    if desc:
                        lines.append(f"    //   {desc}")
                elif isinstance(block, str):
                    lines.append(f"    // GAP: {block}")
                gap_count += 1

    # Check alignment divergences that indicate missing logic
    if hd.alignment and isinstance(hd.alignment, dict):
        divs = hd.alignment.get("divergences", [])
        for div in divs:
            if not isinstance(div, dict):
                continue
            dtype = div.get("type", "")
            if dtype in ("MISSING_VALIDATION", "MISSING_LOGIC", "MISSING_NOTIFICATION"):
                lines.append("")
                desc = div.get("description", div.get("desc", ""))
                binary_code = div.get("binary_code", div.get("binary_snippet", ""))
                lines.append(f"    // GAP: {dtype} — {desc}")
                if binary_code:
                    for bline in str(binary_code).split("\n")[:5]:
                        lines.append(f"    //   Decompiled: {bline.strip()}")
                gap_count += 1

    # Taint-based security gaps
    if hd.taint and isinstance(hd.taint, dict):
        sensitive = hd.taint.get("sensitive_flows",
                   hd.taint.get("tainted_sinks", []))
        if sensitive and isinstance(sensitive, list):
            for flow in sensitive[:5]:
                lines.append("")
                if isinstance(flow, dict):
                    source = flow.get("source", "user_input")
                    sink = flow.get("sink", "unknown")
                    sanitised = flow.get("sanitised", flow.get("sanitized", False))
                    lines.append(f"    // SECURITY: Tainted flow from {source} -> {sink}")
                    if not sanitised:
                        lines.append(f"    // WARNING: Flow appears unsanitised in binary")
                        gap_count += 1
                elif isinstance(flow, str):
                    lines.append(f"    // SECURITY: {flow}")
                    gap_count += 1

    # Estimate coverage from decompiled text
    if hd.decompiled_text and not hd.behavioral_spec:
        linecount = hd.decompiled_text.count("\n") + 1
        if linecount > 10:
            lines.append("")
            lines.append(f"    // GAP: Binary handler is ~{linecount} lines of pseudocode")
            lines.append(f"    //   but no behavioral analysis data available")
            lines.append(f"    //   Run behavioral_spec analyzer for this handler")
            gap_count += 1

    return lines, gap_count


# -------------------------------------------------------------------------
# Phase 8: Header / include generation
# -------------------------------------------------------------------------

def _gen_includes(hd):
    """Generate #include lines for this handler.

    Returns list of include strings.
    """
    cat = hd.category
    base_includes = list(_CATEGORY_INCLUDES.get(cat, _CATEGORY_INCLUDES["generic"]))

    # Add includes from response packets
    if hd.response_packets:
        resp_list = None
        if isinstance(hd.response_packets, dict):
            resp_list = hd.response_packets.get("responses",
                        hd.response_packets.get("packets", []))
        elif isinstance(hd.response_packets, list):
            resp_list = hd.response_packets

        if resp_list:
            for resp in resp_list:
                if isinstance(resp, dict):
                    inc = resp.get("include", resp.get("header", ""))
                    if inc and inc not in base_includes:
                        base_includes.append(inc)

    # Behavioural spec might reference additional systems
    if hd.behavioral_spec and isinstance(hd.behavioral_spec, dict):
        deps = hd.behavioral_spec.get("dependencies",
               hd.behavioral_spec.get("required_includes", []))
        if isinstance(deps, list):
            for dep in deps:
                if isinstance(dep, str) and dep.endswith(".h") and dep not in base_includes:
                    base_includes.append(dep)

    # De-duplicate preserving order
    seen = set()
    result = []
    for inc in base_includes:
        if inc not in seen:
            seen.add(inc)
            result.append(inc)

    return result


# =========================================================================
# Phase 9: Completeness & Confidence Scoring
# =========================================================================

def _compute_scores(hd, fields, gap_count):
    """Compute completeness, confidence, validation_coverage, response_coverage.

    Returns dict with score fields.
    """
    scores = {
        "completeness_score": 0,
        "confidence_score": 0,
        "gap_count": gap_count,
        "validation_coverage": 0,
        "response_coverage": 0,
    }

    # --- Completeness: how much logic is filled vs TODO/GAP ---
    # Start at 10 (we always generate the handler signature)
    completeness = 10

    # Wire format / fields known?
    if fields:
        completeness += 20
    # Validations generated?
    if hd.constraints or hd.validations:
        completeness += 15
    # Behavioral spec available?
    if hd.behavioral_spec:
        completeness += 20
    # Response packets known?
    if hd.response_packets:
        completeness += 15
    # Conformance data available?
    if hd.conformance:
        completeness += 5
    # Alignment data available?
    if hd.alignment:
        completeness += 5
    # LLM decompilation?
    if hd.llm_decompilation:
        completeness += 10

    # Penalise for gaps
    completeness = max(0, completeness - gap_count * 5)
    scores["completeness_score"] = min(100, completeness)

    # --- Confidence: how confident in the generated code ---
    confidence = 0

    # Wire format confidence
    if hd.wire_format:
        wf_conf = 0
        if isinstance(hd.wire_format, dict):
            wf_conf = hd.wire_format.get("confidence", 70)
        confidence += min(30, wf_conf * 0.3)
    elif hd.jam_fields:
        confidence += 15  # JAM fields are less precise

    # Constraint confidence
    if hd.constraints:
        confidence += 15

    # Conformance score contribution
    if hd.conformance:
        conf_score = 0
        if isinstance(hd.conformance, dict):
            conf_score = hd.conformance.get("score",
                         hd.conformance.get("total", 0))
        confidence += min(20, conf_score * 0.2)

    # Behavioral spec adds confidence
    if hd.behavioral_spec:
        confidence += 15

    # Response packet adds confidence
    if hd.response_packets:
        confidence += 10

    # Deduct for gaps
    confidence = max(0, confidence - gap_count * 3)
    scores["confidence_score"] = min(100, int(confidence))

    # --- Validation coverage ---
    if hd.validations and isinstance(hd.validations, dict):
        binary_count = 0
        reproduced = 0
        binary_vals = hd.validations.get("binary_validations",
                      hd.validations.get("binary_checks", []))
        if isinstance(binary_vals, list):
            binary_count = len(binary_vals)
        tc_vals = hd.validations.get("tc_validations",
                  hd.validations.get("tc_checks", []))
        if isinstance(tc_vals, list):
            reproduced = len(tc_vals)
        missing = hd.validations.get("missing_count",
                  hd.validations.get("missing", 0))
        if binary_count > 0:
            scores["validation_coverage"] = int(
                (binary_count - missing) / binary_count * 100
            ) if isinstance(missing, int) else int(reproduced / binary_count * 100)

    # --- Response coverage ---
    if hd.response_packets:
        resp_list = None
        if isinstance(hd.response_packets, dict):
            resp_list = hd.response_packets.get("responses",
                        hd.response_packets.get("packets", []))
        elif isinstance(hd.response_packets, list):
            resp_list = hd.response_packets
        if resp_list:
            total_fields = 0
            known_fields = 0
            for resp in resp_list:
                if isinstance(resp, dict):
                    rf = resp.get("fields", resp.get("writes", []))
                    if isinstance(rf, list):
                        total_fields += max(1, len(rf))
                        known_fields += len(rf)
            if total_fields > 0:
                scores["response_coverage"] = min(100, int(known_fields / total_fields * 100))
            else:
                scores["response_coverage"] = 50  # We know the SMSG exists

    return scores


# =========================================================================
# Full Scaffold Assembly
# =========================================================================

def _assemble_scaffold(hd):
    """Assemble a complete C++ handler scaffold from HandlerData.

    Returns (cpp_code: str, metadata: dict).
    """
    handler_name = _derive_handler_name(hd.tc_name)
    class_name = _derive_class_name_from_jam(hd.jam_type) or _derive_class_name(hd.tc_name)
    namespace = _CATEGORY_NAMESPACE.get(hd.category, "Misc")
    includes = _gen_includes(hd)
    fields = _resolve_fields(hd)

    # Game constants comment block
    const_lines = _gen_constant_comments(hd)

    # Enum definition comment block
    enum_lines = _gen_enum_comments(hd)

    # Build C++ code
    code_lines = []

    # File header
    code_lines.append("/*")
    code_lines.append(f" * Handler: {handler_name}")
    code_lines.append(f" * Opcode:  {hd.tc_name}")
    if hd.jam_type:
        code_lines.append(f" * JAM:     {hd.jam_type}")
    code_lines.append(f" * Category: {hd.category}")
    code_lines.append(f" *")
    code_lines.append(f" * AUTO-GENERATED by TC WoW Analyzer — handler_scaffolding")
    code_lines.append(f" * Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    code_lines.append(f" */")
    code_lines.append("")

    # Includes
    for inc in includes:
        code_lines.append(f"#include \"{inc}\"")
    code_lines.append("")

    # Enum/constant comments if present
    if enum_lines:
        code_lines.extend(enum_lines)
        code_lines.append("")
    if const_lines:
        code_lines.extend(const_lines)
        code_lines.append("")

    # Handler function signature
    code_lines.append(
        f"void WorldSession::{handler_name}"
        f"(WorldPackets::{namespace}::{class_name}& packet)"
    )
    code_lines.append("{")

    # Player pointer check
    code_lines.append("    Player* player = GetPlayer();")
    code_lines.append("    if (!player)")
    code_lines.append("        return;")
    code_lines.append("")

    # Log line
    code_lines.append(
        f"    TC_LOG_DEBUG(\"network\", \"WORLD: Received {hd.tc_name}\");"
    )

    # Phase 3: packet fields
    field_lines = _gen_packet_field_extraction(fields, hd)
    if field_lines:
        code_lines.append("")
        for fl in field_lines:
            code_lines.append(f"    {fl}")

    # Phase 4: validations
    val_lines = _gen_validation_code(fields, hd)
    if val_lines:
        code_lines.extend(val_lines)

    # Phase 5: core logic
    logic_lines = _gen_core_logic(hd, fields)
    code_lines.extend(logic_lines)

    # Phase 6: response packets
    resp_lines = _gen_response_code(hd)
    code_lines.extend(resp_lines)

    # Phase 7: gap annotations
    gap_lines, gap_count = _gen_gap_annotations(hd, fields)
    code_lines.extend(gap_lines)

    # Close function
    code_lines.append("}")
    code_lines.append("")

    cpp_code = "\n".join(code_lines)

    # Phase 9: scoring
    scores = _compute_scores(hd, fields, gap_count)

    metadata = {
        "cpp_code": cpp_code,
        "header_includes": includes,
        "category": hd.category,
        "handler_name": handler_name,
        "class_name": class_name,
        "namespace": namespace,
        "tc_name": hd.tc_name,
        "handler_ea": hd.handler_ea,
        "jam_type": hd.jam_type,
        "field_count": len(fields),
    }
    metadata.update(scores)

    return cpp_code, metadata


def _gen_constant_comments(hd):
    """Generate comment block listing relevant game constants."""
    if not hd.game_constants:
        return []
    lines = []
    consts = None
    if isinstance(hd.game_constants, dict):
        consts = hd.game_constants.get("constants",
                 hd.game_constants.get("values", []))
    elif isinstance(hd.game_constants, list):
        consts = hd.game_constants

    if not consts:
        return []

    lines.append("// --- Game constants used by this handler ---")
    for c in consts[:20]:
        if isinstance(c, dict):
            cname = c.get("name", c.get("symbol", "UNKNOWN"))
            cval = c.get("value", "?")
            cdesc = c.get("description", c.get("context", ""))
            if cdesc:
                lines.append(f"// {cname} = {cval}  // {cdesc}")
            else:
                lines.append(f"// {cname} = {cval}")
        elif isinstance(c, str):
            lines.append(f"// {c}")

    return lines


def _gen_enum_comments(hd):
    """Generate comment block with relevant enum definitions."""
    if not hd.enum_defs:
        return []

    # Only include enums referenced by this handler's constraints/spec
    relevant_enums = _find_relevant_enums(hd)
    if not relevant_enums:
        return []

    lines = []
    lines.append("// --- Relevant enum definitions (from binary) ---")
    for ename, edata in list(relevant_enums.items())[:5]:
        lines.append(f"// enum {ename}")
        lines.append("// {")
        members = []
        if isinstance(edata, dict):
            members = edata.get("members", edata.get("values", []))
        elif isinstance(edata, list):
            members = edata
        for m in members[:20]:
            if isinstance(m, dict):
                mname = m.get("name", m.get("symbol", "?"))
                mval = m.get("value", "?")
                lines.append(f"//     {mname} = {mval},")
            elif isinstance(m, (list, tuple)) and len(m) >= 2:
                lines.append(f"//     {m[0]} = {m[1]},")
        if len(members) > 20:
            lines.append(f"//     ... ({len(members) - 20} more)")
        lines.append("// };")

    return lines


def _find_relevant_enums(hd):
    """Filter enum_defs to only those potentially referenced by this handler."""
    if not hd.enum_defs or not isinstance(hd.enum_defs, dict):
        return {}

    # Keywords from the handler's opcode name
    keywords = set()
    if hd.tc_name:
        parts = hd.tc_name.replace("CMSG_", "").replace("SMSG_", "").split("_")
        keywords.update(p.lower() for p in parts if len(p) > 2)

    # Keywords from field names
    if hd.wire_format:
        wf_fields = None
        if isinstance(hd.wire_format, dict):
            wf_fields = hd.wire_format.get("fields", [])
        elif isinstance(hd.wire_format, list):
            wf_fields = hd.wire_format
        if wf_fields:
            for f in wf_fields:
                if isinstance(f, dict):
                    fname = f.get("name", "")
                    if fname:
                        keywords.update(
                            p.lower() for p in re.split(r'[_\s]+|(?<=[a-z])(?=[A-Z])', fname)
                            if len(p) > 2
                        )

    if not keywords:
        # Return first few enums as fallback
        return dict(list(hd.enum_defs.items())[:3])

    relevant = {}
    for ename, edata in hd.enum_defs.items():
        ename_lower = ename.lower()
        for kw in keywords:
            if kw in ename_lower:
                relevant[ename] = edata
                break

    return relevant


# =========================================================================
# Public Entry Points
# =========================================================================

def generate_all_scaffolds(session):
    """Generate scaffolds for all CMSG handlers with known TC names.

    Stores results in kv_store under "handler_scaffolding".

    Args:
        session: PluginSession

    Returns:
        int: number of handlers scaffolded
    """
    db = session.db
    if not db:
        msg_error("No database loaded")
        return 0

    start_time = time.time()

    # Get all CMSG handlers that have both a handler_ea and a tc_name.
    # Also accept direction='unknown' (imported opcodes not yet classified)
    # and handlers without tc_name (use jam_type or index as fallback).
    handlers = db.fetchall(
        "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL "
        "AND (direction = 'CMSG' OR direction = 'unknown') "
        "AND (tc_name IS NOT NULL OR jam_type IS NOT NULL) "
        "ORDER BY COALESCE(tc_name, jam_type, internal_index)"
    )

    if not handlers:
        msg_warn("No matched CMSG handlers found. Run opcode analysis first.")
        return 0

    msg_info(f"Generating scaffolds for {len(handlers)} CMSG handlers...")

    scaffolds = {}
    total_completeness = 0
    total_confidence = 0
    category_counts = {}
    error_count = 0

    for i, handler_row in enumerate(handlers):
        tc_name = handler_row["tc_name"] or handler_row.get("jam_type") or f"handler_{handler_row['internal_index']}"
        try:
            hd = _collect_handler_data(session, handler_row)
            cpp_code, metadata = _assemble_scaffold(hd)

            handler_name = metadata["handler_name"]
            scaffolds[handler_name] = metadata

            total_completeness += metadata["completeness_score"]
            total_confidence += metadata["confidence_score"]

            cat = metadata["category"]
            if cat not in category_counts:
                category_counts[cat] = {"count": 0, "completeness": 0, "confidence": 0}
            category_counts[cat]["count"] += 1
            category_counts[cat]["completeness"] += metadata["completeness_score"]
            category_counts[cat]["confidence"] += metadata["confidence_score"]

            if (i + 1) % 50 == 0:
                msg(f"  [{i+1}/{len(handlers)}] scaffolds generated...")

        except Exception as e:
            msg_warn(f"Failed to scaffold {tc_name}: {e}")
            error_count += 1

    n = len(scaffolds)
    elapsed = time.time() - start_time

    # Compute category averages
    category_summary = {}
    for cat, data in category_counts.items():
        cnt = data["count"]
        category_summary[cat] = {
            "count": cnt,
            "avg_completeness": round(data["completeness"] / cnt, 1) if cnt else 0,
            "avg_confidence": round(data["confidence"] / cnt, 1) if cnt else 0,
            "system": _SYSTEM_KEYWORDS.get(cat, cat),
        }

    result = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_seconds": round(elapsed, 1),
        "handlers_generated": n,
        "handlers_errored": error_count,
        "avg_completeness": round(total_completeness / n, 1) if n else 0,
        "avg_confidence": round(total_confidence / n, 1) if n else 0,
        "categories": category_summary,
        "scaffolds": scaffolds,
    }

    db.kv_set(KV_KEY, result)
    db.commit()

    msg_info(f"Scaffolding complete: {n} handlers in {elapsed:.1f}s")
    msg_info(f"  Average completeness: {result['avg_completeness']}%")
    msg_info(f"  Average confidence:   {result['avg_confidence']}%")
    if error_count:
        msg_warn(f"  Errors: {error_count}")

    for cat, data in sorted(category_summary.items()):
        msg(f"  {data['system']:15s}: {data['count']:3d} handlers, "
            f"completeness={data['avg_completeness']:.0f}%, "
            f"confidence={data['avg_confidence']:.0f}%")

    return n


def generate_handler_scaffold(session, handler_name):
    """Generate a scaffold for a single handler by TC name or handler name.

    Args:
        session: PluginSession
        handler_name: TC opcode name (e.g. "CMSG_HOUSING_PLACE_DECOR")
                      or handler function name (e.g. "HandleHousingPlaceDecor")

    Returns:
        str: generated C++ code, or empty string on failure
    """
    db = session.db
    if not db:
        msg_error("No database loaded")
        return ""

    # Try to find by tc_name
    handler_row = db.fetchone(
        "SELECT * FROM opcodes WHERE tc_name = ? AND direction = 'CMSG'",
        (handler_name,)
    )

    # Try CMSG_ prefix
    if not handler_row and not handler_name.startswith("CMSG_"):
        handler_row = db.fetchone(
            "SELECT * FROM opcodes WHERE tc_name = ? AND direction = 'CMSG'",
            (f"CMSG_{handler_name}",)
        )

    # Try by handler function name -> derive tc_name
    if not handler_row:
        # HandleHousingPlaceDecor -> HOUSING_PLACE_DECOR
        stripped = handler_name
        if stripped.startswith("Handle"):
            stripped = stripped[6:]
        snake = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', stripped).upper()
        handler_row = db.fetchone(
            "SELECT * FROM opcodes WHERE tc_name = ? AND direction = 'CMSG'",
            (f"CMSG_{snake}",)
        )

    # Try LIKE search
    if not handler_row:
        handler_row = db.fetchone(
            "SELECT * FROM opcodes WHERE tc_name LIKE ? AND direction = 'CMSG'",
            (f"%{handler_name}%",)
        )

    if not handler_row:
        msg_error(f"Handler '{handler_name}' not found in opcode database")
        return ""

    if not handler_row["handler_ea"]:
        msg_error(f"Handler '{handler_name}' has no binary address")
        return ""

    hd = _collect_handler_data(session, handler_row)
    cpp_code, metadata = _assemble_scaffold(hd)

    msg_info(f"Generated scaffold for {metadata['handler_name']}")
    msg_info(f"  Completeness: {metadata['completeness_score']}%")
    msg_info(f"  Confidence:   {metadata['confidence_score']}%")
    msg_info(f"  Gaps:         {metadata['gap_count']}")
    msg_info(f"  Fields:       {metadata['field_count']}")

    return cpp_code


# =========================================================================
# Export Functions
# =========================================================================

def get_scaffolding_report(session):
    """Retrieve the stored scaffolding report from the knowledge DB.

    Returns:
        dict or None: the full scaffolding report
    """
    if not session.db:
        return None
    return session.db.kv_get(KV_KEY)


def export_handler_file(session, handler_name):
    """Export a single handler's C++ scaffold code.

    Looks up from stored results first; generates fresh if not found.

    Args:
        session: PluginSession
        handler_name: handler name (e.g. "HandleHousingPlaceDecor")

    Returns:
        str: C++ code
    """
    report = get_scaffolding_report(session)
    if report:
        scaffolds = report.get("scaffolds", {})
        if handler_name in scaffolds:
            return scaffolds[handler_name].get("cpp_code", "")
        # Try by tc_name
        for hname, data in scaffolds.items():
            if data.get("tc_name") == handler_name:
                return data.get("cpp_code", "")

    # Not in store — generate fresh
    return generate_handler_scaffold(session, handler_name)


def export_all_handlers(session, output_dir):
    """Export all scaffolded handlers to .cpp files organized by category.

    Creates subdirectories per category under output_dir.

    Args:
        session: PluginSession
        output_dir: base output directory path

    Returns:
        int: number of files written
    """
    report = get_scaffolding_report(session)
    if not report:
        msg_warn("No scaffolding data found. Run generate_all_scaffolds first.")
        return 0

    scaffolds = report.get("scaffolds", {})
    if not scaffolds:
        msg_warn("No scaffolds in report")
        return 0

    os.makedirs(output_dir, exist_ok=True)
    written = 0

    # Group by category
    by_category = {}
    for hname, data in scaffolds.items():
        cat = data.get("category", "generic")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append((hname, data))

    for cat, handlers in sorted(by_category.items()):
        cat_dir = os.path.join(output_dir, cat)
        os.makedirs(cat_dir, exist_ok=True)

        for hname, data in handlers:
            cpp_code = data.get("cpp_code", "")
            if not cpp_code:
                continue

            filename = f"{hname}.cpp"
            filepath = os.path.join(cat_dir, filename)

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(cpp_code)
                written += 1
            except OSError as e:
                msg_warn(f"Failed to write {filepath}: {e}")

    msg_info(f"Exported {written} handler files to {output_dir}")
    for cat, handlers in sorted(by_category.items()):
        system = _SYSTEM_KEYWORDS.get(cat, cat)
        msg(f"  {system}: {len(handlers)} files")

    return written


def get_best_scaffolds(session, min_completeness=70):
    """Get handlers with completeness score at or above threshold.

    Args:
        session: PluginSession
        min_completeness: minimum completeness score (0-100)

    Returns:
        list of (handler_name, metadata) tuples sorted by score descending
    """
    report = get_scaffolding_report(session)
    if not report:
        return []

    scaffolds = report.get("scaffolds", {})
    results = []

    for hname, data in scaffolds.items():
        score = data.get("completeness_score", 0)
        if score >= min_completeness:
            results.append((hname, data))

    results.sort(key=lambda x: x[1].get("completeness_score", 0), reverse=True)
    return results


def get_gap_summary(session):
    """Aggregate gap analysis across all scaffolded handlers.

    Returns:
        dict with gap statistics:
        {
            "total_handlers": int,
            "total_gaps": int,
            "handlers_with_gaps": int,
            "handlers_gap_free": int,
            "avg_gaps_per_handler": float,
            "by_category": {
                "housing": {"handlers": int, "total_gaps": int, "avg_gaps": float},
                ...
            },
            "worst_handlers": [(name, gap_count, completeness), ...],
            "best_handlers": [(name, gap_count, completeness), ...],
            "missing_wire_format": int,
            "missing_behavioral": int,
            "missing_response": int,
            "security_concerns": int,
        }
    """
    report = get_scaffolding_report(session)
    if not report:
        return {"total_handlers": 0, "total_gaps": 0}

    scaffolds = report.get("scaffolds", {})
    if not scaffolds:
        return {"total_handlers": 0, "total_gaps": 0}

    total_gaps = 0
    handlers_with_gaps = 0
    by_category = {}
    handler_gaps = []  # (name, gap_count, completeness)
    missing_wire = 0
    missing_behavioral = 0
    missing_response = 0
    security_concerns = 0

    for hname, data in scaffolds.items():
        gc = data.get("gap_count", 0)
        compl = data.get("completeness_score", 0)
        cat = data.get("category", "generic")

        total_gaps += gc
        if gc > 0:
            handlers_with_gaps += 1
        handler_gaps.append((hname, gc, compl))

        if cat not in by_category:
            by_category[cat] = {"handlers": 0, "total_gaps": 0}
        by_category[cat]["handlers"] += 1
        by_category[cat]["total_gaps"] += gc

        # Check for specific missing data
        cpp_code = data.get("cpp_code", "")
        if "Wire format unknown" in cpp_code or "No wire format" in cpp_code:
            missing_wire += 1
        if "No behavioral analysis" in cpp_code:
            missing_behavioral += 1
        if "No response packet data" in cpp_code:
            missing_response += 1
        if "SECURITY:" in cpp_code:
            security_concerns += 1

    n = len(scaffolds)
    handler_gaps.sort(key=lambda x: x[1], reverse=True)

    # Compute per-category averages
    cat_summary = {}
    for cat, cdata in by_category.items():
        cnt = cdata["handlers"]
        cat_summary[cat] = {
            "handlers": cnt,
            "total_gaps": cdata["total_gaps"],
            "avg_gaps": round(cdata["total_gaps"] / cnt, 1) if cnt else 0,
            "system": _SYSTEM_KEYWORDS.get(cat, cat),
        }

    return {
        "total_handlers": n,
        "total_gaps": total_gaps,
        "handlers_with_gaps": handlers_with_gaps,
        "handlers_gap_free": n - handlers_with_gaps,
        "avg_gaps_per_handler": round(total_gaps / n, 2) if n else 0,
        "by_category": cat_summary,
        "worst_handlers": handler_gaps[:20],
        "best_handlers": handler_gaps[-20:] if len(handler_gaps) > 20 else [],
        "missing_wire_format": missing_wire,
        "missing_behavioral": missing_behavioral,
        "missing_response": missing_response,
        "security_concerns": security_concerns,
    }


# =========================================================================
# Header Declaration Generation
# =========================================================================

def generate_handler_header_decl(session, handler_name):
    """Generate the WorldSession.h declaration for a handler.

    Args:
        session: PluginSession
        handler_name: TC opcode name or handler function name

    Returns:
        str: header declaration line (e.g. "void HandleFoo(WorldPackets::Ns::Foo& packet);")
    """
    report = get_scaffolding_report(session)
    if report:
        scaffolds = report.get("scaffolds", {})
        meta = scaffolds.get(handler_name)
        if not meta:
            for hname, data in scaffolds.items():
                if data.get("tc_name") == handler_name:
                    meta = data
                    break
        if meta:
            hname = meta.get("handler_name", handler_name)
            ns = meta.get("namespace", "Misc")
            cname = meta.get("class_name", "Unknown")
            return f"void {hname}(WorldPackets::{ns}::{cname}& packet);"

    # Fallback: derive from name
    hfunc = _derive_handler_name(handler_name)
    cname = _derive_class_name(handler_name)
    return f"void {hfunc}(WorldPackets::Misc::{cname}& packet);"


def generate_opcode_registration(session, handler_name):
    """Generate the Opcodes.cpp registration line for a handler.

    Args:
        session: PluginSession
        handler_name: TC opcode name

    Returns:
        str: opcode registration macro/line
    """
    report = get_scaffolding_report(session)
    meta = None
    if report:
        scaffolds = report.get("scaffolds", {})
        for hname, data in scaffolds.items():
            if data.get("tc_name") == handler_name or hname == handler_name:
                meta = data
                break

    if meta:
        tc_name = meta.get("tc_name", handler_name)
        hfunc = meta.get("handler_name", _derive_handler_name(handler_name))
        ns = meta.get("namespace", "Misc")
        cname = meta.get("class_name", "Unknown")
        return (
            f"DEFINE_HANDLER({tc_name}, STATUS_LOGGEDIN, PROCESS_THREADUNSAFE, "
            f"WorldPackets::{ns}::{cname}, &WorldSession::{hfunc});"
        )

    # Fallback
    hfunc = _derive_handler_name(handler_name)
    cname = _derive_class_name(handler_name)
    tc_name = handler_name if handler_name.startswith("CMSG_") else f"CMSG_{handler_name}"
    return (
        f"DEFINE_HANDLER({tc_name}, STATUS_LOGGEDIN, PROCESS_THREADUNSAFE, "
        f"WorldPackets::Misc::{cname}, &WorldSession::{hfunc});"
    )


# =========================================================================
# Batch Export Helpers
# =========================================================================

def export_category_file(session, category, output_path=None):
    """Export all handlers of a given category into a single .cpp file.

    Useful for generating e.g. HousingHandler.cpp with all housing handlers.

    Args:
        session: PluginSession
        category: handler category (e.g. "housing", "movement")
        output_path: optional output file path; if None returns string

    Returns:
        str: combined C++ code (also written to file if output_path given)
    """
    report = get_scaffolding_report(session)
    if not report:
        msg_warn("No scaffolding data. Run generate_all_scaffolds first.")
        return ""

    scaffolds = report.get("scaffolds", {})

    # Collect all handlers in this category
    category_handlers = []
    all_includes = set()
    for hname, data in scaffolds.items():
        if data.get("category") == category:
            category_handlers.append((hname, data))
            for inc in data.get("header_includes", []):
                all_includes.add(inc)

    if not category_handlers:
        msg_warn(f"No handlers found for category '{category}'")
        return ""

    # Sort by handler name for stable output
    category_handlers.sort(key=lambda x: x[0])

    system_name = _SYSTEM_KEYWORDS.get(category, category.capitalize())

    lines = []
    lines.append("/*")
    lines.append(f" * {system_name} Handlers")
    lines.append(f" * Category: {category}")
    lines.append(f" * Handler count: {len(category_handlers)}")
    lines.append(f" *")
    lines.append(f" * AUTO-GENERATED by TC WoW Analyzer — handler_scaffolding")
    lines.append(f" * Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f" */")
    lines.append("")

    # Includes (sorted, deduplicated)
    for inc in sorted(all_includes):
        lines.append(f"#include \"{inc}\"")
    lines.append("")

    # Each handler
    for hname, data in category_handlers:
        cpp = data.get("cpp_code", "")
        if not cpp:
            continue
        # Strip per-handler includes (already in file header)
        filtered_lines = []
        past_includes = False
        for cline in cpp.split("\n"):
            if cline.startswith("#include"):
                continue
            if cline.startswith("/*") or cline.startswith(" *"):
                # Keep handler-level comment block
                filtered_lines.append(cline)
                continue
            filtered_lines.append(cline)
        lines.extend(filtered_lines)
        lines.append("")

    result = "\n".join(lines)

    if output_path:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result)
            msg_info(f"Exported {len(category_handlers)} {system_name} handlers to {output_path}")
        except OSError as e:
            msg_error(f"Failed to write {output_path}: {e}")

    return result


def export_header_declarations(session, output_path=None):
    """Export all handler declarations for WorldSession.h.

    Args:
        session: PluginSession
        output_path: optional output file path; if None returns string

    Returns:
        str: block of handler declarations
    """
    report = get_scaffolding_report(session)
    if not report:
        return ""

    scaffolds = report.get("scaffolds", {})
    if not scaffolds:
        return ""

    # Group by category
    by_category = {}
    for hname, data in scaffolds.items():
        cat = data.get("category", "generic")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append((hname, data))

    lines = []
    lines.append("    // ---- Auto-generated handler declarations ----")
    lines.append(f"    // Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"    // Total handlers: {len(scaffolds)}")
    lines.append("")

    for cat in sorted(by_category.keys()):
        handlers = by_category[cat]
        handlers.sort(key=lambda x: x[0])
        system = _SYSTEM_KEYWORDS.get(cat, cat.capitalize())
        lines.append(f"    // {system} handlers ({len(handlers)})")
        for hname, data in handlers:
            ns = data.get("namespace", "Misc")
            cname = data.get("class_name", "Unknown")
            lines.append(f"    void {hname}(WorldPackets::{ns}::{cname}& packet);")
        lines.append("")

    result = "\n".join(lines)

    if output_path:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result)
            msg_info(f"Exported {len(scaffolds)} header declarations to {output_path}")
        except OSError as e:
            msg_error(f"Failed to write {output_path}: {e}")

    return result


def export_opcode_registrations(session, output_path=None):
    """Export DEFINE_HANDLER lines for all scaffolded opcodes.

    Args:
        session: PluginSession
        output_path: optional output file path; if None returns string

    Returns:
        str: block of DEFINE_HANDLER lines
    """
    report = get_scaffolding_report(session)
    if not report:
        return ""

    scaffolds = report.get("scaffolds", {})
    if not scaffolds:
        return ""

    # Group by category
    by_category = {}
    for hname, data in scaffolds.items():
        cat = data.get("category", "generic")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append((hname, data))

    lines = []
    lines.append("    // ---- Auto-generated opcode registrations ----")
    lines.append(f"    // Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    for cat in sorted(by_category.keys()):
        handlers = by_category[cat]
        handlers.sort(key=lambda x: x[1].get("tc_name", ""))
        system = _SYSTEM_KEYWORDS.get(cat, cat.capitalize())
        lines.append(f"    // {system}")
        for hname, data in handlers:
            tc_name = data.get("tc_name", "CMSG_UNKNOWN")
            ns = data.get("namespace", "Misc")
            cname = data.get("class_name", "Unknown")
            lines.append(
                f"    DEFINE_HANDLER({tc_name}, STATUS_LOGGEDIN, "
                f"PROCESS_THREADUNSAFE, WorldPackets::{ns}::{cname}, "
                f"&WorldSession::{hname});"
            )
        lines.append("")

    result = "\n".join(lines)

    if output_path:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result)
            msg_info(f"Exported {len(scaffolds)} opcode registrations to {output_path}")
        except OSError as e:
            msg_error(f"Failed to write {output_path}: {e}")

    return result


# =========================================================================
# Decompiled Text Gap Mining
# =========================================================================

_RE_DECOMPILED_IF = re.compile(
    r'if\s*\(\s*(.+?)\s*\)', re.MULTILINE
)

_RE_DECOMPILED_CALL = re.compile(
    r'\b([A-Za-z_]\w*)\s*\([^)]*\)\s*;', re.MULTILINE
)

_RE_DECOMPILED_OFFSET = re.compile(
    r'\*\s*\(\s*(?:_DWORD|_QWORD|_WORD|_BYTE|'
    r'unsigned\s+(?:int|__int64|__int16|__int8)|'
    r'int|__int64|float|double)\s*\*?\s*\)'
    r'\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)',
    re.MULTILINE,
)

_RE_DECOMPILED_RETURN = re.compile(
    r'return\s+(.*?)\s*;', re.MULTILINE
)


def _mine_decompiled_gaps(decompiled_text):
    """Extract structural hints from raw decompiled pseudocode.

    Used when no behavioral spec is available to provide basic gap info.

    Returns dict with:
        condition_count, call_count, offset_accesses, return_values
    """
    if not decompiled_text:
        return None

    conditions = _RE_DECOMPILED_IF.findall(decompiled_text)
    calls = _RE_DECOMPILED_CALL.findall(decompiled_text)
    offsets = _RE_DECOMPILED_OFFSET.findall(decompiled_text)
    returns = _RE_DECOMPILED_RETURN.findall(decompiled_text)

    # Deduplicate calls
    unique_calls = list(dict.fromkeys(calls))
    # Filter out common noise
    noise = {"if", "else", "while", "for", "switch", "case", "return",
             "break", "continue", "goto", "sizeof", "LODWORD", "HIDWORD",
             "LOBYTE", "HIBYTE", "LOWORD", "HIWORD", "COERCE_FLOAT",
             "COERCE_DOUBLE", "BYTE1", "BYTE2", "BYTE3"}
    unique_calls = [c for c in unique_calls if c not in noise and not c.startswith("_")]

    return {
        "condition_count": len(conditions),
        "call_count": len(unique_calls),
        "unique_calls": unique_calls[:30],
        "offset_access_count": len(offsets),
        "offset_accesses": [(v, int(o, 0) if isinstance(o, str) else o)
                           for v, o in offsets[:20]],
        "return_values": list(dict.fromkeys(returns))[:10],
        "line_count": decompiled_text.count("\n") + 1,
    }


# =========================================================================
# Comparison Helpers — diff stored scaffolds against current TC source
# =========================================================================

def compare_scaffold_to_tc(session, handler_name, tc_source_code):
    """Compare a generated scaffold against actual TC handler source.

    Useful for measuring how close the scaffold is to existing TC code.

    Args:
        session: PluginSession
        handler_name: handler name
        tc_source_code: string of the current TC handler source

    Returns:
        dict with comparison metrics
    """
    scaffold_code = export_handler_file(session, handler_name)
    if not scaffold_code:
        return {"error": f"No scaffold found for {handler_name}"}
    if not tc_source_code:
        return {"error": "No TC source provided"}

    # Normalise both for comparison
    scaffold_norm = _normalise_code(scaffold_code)
    tc_norm = _normalise_code(tc_source_code)

    scaffold_lines = scaffold_norm.split("\n")
    tc_lines = tc_norm.split("\n")

    # Count matching structural elements
    scaffold_calls = set(_RE_DECOMPILED_CALL.findall(scaffold_code))
    tc_calls = set(_RE_DECOMPILED_CALL.findall(tc_source_code))
    common_calls = scaffold_calls & tc_calls

    scaffold_conditions = set(_RE_DECOMPILED_IF.findall(scaffold_code))
    tc_conditions = set(_RE_DECOMPILED_IF.findall(tc_source_code))
    common_conditions = scaffold_conditions & tc_conditions

    # Line-level similarity
    import difflib
    sm = difflib.SequenceMatcher(None, scaffold_lines, tc_lines)
    similarity = sm.ratio()

    return {
        "similarity_ratio": round(similarity, 3),
        "scaffold_lines": len(scaffold_lines),
        "tc_lines": len(tc_lines),
        "common_calls": len(common_calls),
        "scaffold_only_calls": len(scaffold_calls - tc_calls),
        "tc_only_calls": len(tc_calls - scaffold_calls),
        "common_conditions": len(common_conditions),
        "scaffold_only_conditions": len(scaffold_conditions - tc_conditions),
        "tc_only_conditions": len(tc_conditions - scaffold_conditions),
    }


def _normalise_code(code):
    """Normalise C++ code for comparison: strip comments, whitespace, blank lines."""
    lines = []
    in_block_comment = False
    for line in code.split("\n"):
        stripped = line.strip()
        # Block comments
        if "/*" in stripped:
            in_block_comment = True
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        # Line comments
        if stripped.startswith("//"):
            continue
        # Strip inline comments
        comment_pos = stripped.find("//")
        if comment_pos > 0:
            stripped = stripped[:comment_pos].rstrip()
        # Skip blank lines
        if not stripped:
            continue
        # Normalise whitespace
        stripped = re.sub(r'\s+', ' ', stripped)
        lines.append(stripped)
    return "\n".join(lines)


# =========================================================================
# Statistics & Reporting
# =========================================================================

def print_scaffolding_summary(session):
    """Print a human-readable summary of scaffolding results to IDA output.

    Args:
        session: PluginSession
    """
    report = get_scaffolding_report(session)
    if not report:
        msg_warn("No scaffolding data found. Run generate_all_scaffolds first.")
        return

    msg("=" * 70)
    msg("  HANDLER SCAFFOLDING SUMMARY")
    msg("=" * 70)
    msg(f"  Generated:          {report.get('timestamp', 'unknown')}")
    msg(f"  Handlers:           {report.get('handlers_generated', 0)}")
    msg(f"  Errors:             {report.get('handlers_errored', 0)}")
    msg(f"  Avg completeness:   {report.get('avg_completeness', 0)}%")
    msg(f"  Avg confidence:     {report.get('avg_confidence', 0)}%")
    msg(f"  Elapsed:            {report.get('elapsed_seconds', 0)}s")
    msg("")

    categories = report.get("categories", {})
    if categories:
        msg("  CATEGORY BREAKDOWN:")
        msg(f"  {'System':<18s} {'Count':>6s} {'Compl%':>8s} {'Conf%':>8s}")
        msg(f"  {'-'*18} {'-'*6} {'-'*8} {'-'*8}")
        for cat, data in sorted(categories.items(),
                                key=lambda x: x[1].get("count", 0),
                                reverse=True):
            system = data.get("system", cat)
            msg(f"  {system:<18s} {data['count']:>6d} "
                f"{data.get('avg_completeness', 0):>7.1f}% "
                f"{data.get('avg_confidence', 0):>7.1f}%")
        msg("")

    # Gap summary
    gaps = get_gap_summary(session)
    if gaps.get("total_handlers", 0) > 0:
        msg("  GAP ANALYSIS:")
        msg(f"  Total gaps:         {gaps.get('total_gaps', 0)}")
        msg(f"  Handlers with gaps: {gaps.get('handlers_with_gaps', 0)}")
        msg(f"  Gap-free handlers:  {gaps.get('handlers_gap_free', 0)}")
        msg(f"  Avg gaps/handler:   {gaps.get('avg_gaps_per_handler', 0)}")
        msg(f"  Missing wire fmt:   {gaps.get('missing_wire_format', 0)}")
        msg(f"  Missing behavioral: {gaps.get('missing_behavioral', 0)}")
        msg(f"  Missing response:   {gaps.get('missing_response', 0)}")
        msg(f"  Security concerns:  {gaps.get('security_concerns', 0)}")
        msg("")

        worst = gaps.get("worst_handlers", [])
        if worst:
            msg("  WORST HANDLERS (most gaps):")
            for hname, gc, compl in worst[:10]:
                msg(f"    {hname:<45s} gaps={gc:>3d}  compl={compl:>3d}%")
            msg("")

    # Best scaffolds
    best = get_best_scaffolds(session, min_completeness=80)
    if best:
        msg(f"  BEST SCAFFOLDS (>= 80% completeness): {len(best)}")
        for hname, data in best[:15]:
            msg(f"    {hname:<45s} compl={data.get('completeness_score', 0):>3d}%  "
                f"conf={data.get('confidence_score', 0):>3d}%  "
                f"gaps={data.get('gap_count', 0):>2d}")
        msg("")

    msg("=" * 70)


def get_category_list(session):
    """Get list of all categories with handler counts.

    Returns:
        list of (category, system_name, count) tuples
    """
    report = get_scaffolding_report(session)
    if not report:
        return []
    categories = report.get("categories", {})
    result = []
    for cat, data in categories.items():
        system = data.get("system", cat)
        count = data.get("count", 0)
        result.append((cat, system, count))
    result.sort(key=lambda x: x[2], reverse=True)
    return result


def get_handlers_by_category(session, category):
    """Get all handler names for a given category.

    Args:
        session: PluginSession
        category: category string (e.g. "housing")

    Returns:
        list of handler names
    """
    report = get_scaffolding_report(session)
    if not report:
        return []
    scaffolds = report.get("scaffolds", {})
    result = []
    for hname, data in scaffolds.items():
        if data.get("category") == category:
            result.append(hname)
    result.sort()
    return result


def get_handlers_needing_work(session, max_completeness=50):
    """Get handlers below a completeness threshold — candidates for manual work.

    Args:
        session: PluginSession
        max_completeness: maximum completeness to include (exclusive)

    Returns:
        list of (handler_name, metadata) tuples sorted by completeness ascending
    """
    report = get_scaffolding_report(session)
    if not report:
        return []

    scaffolds = report.get("scaffolds", {})
    results = []

    for hname, data in scaffolds.items():
        score = data.get("completeness_score", 0)
        if score < max_completeness:
            results.append((hname, data))

    results.sort(key=lambda x: x[1].get("completeness_score", 0))
    return results


def get_security_sensitive_handlers(session):
    """Get handlers that have security-sensitive taint flows.

    Returns:
        list of (handler_name, metadata) tuples
    """
    report = get_scaffolding_report(session)
    if not report:
        return []

    scaffolds = report.get("scaffolds", {})
    results = []

    for hname, data in scaffolds.items():
        cpp_code = data.get("cpp_code", "")
        if "SECURITY:" in cpp_code:
            results.append((hname, data))

    results.sort(key=lambda x: x[0])
    return results
