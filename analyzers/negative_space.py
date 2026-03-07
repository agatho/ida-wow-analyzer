"""
Negative Space Analyzer for CMSG Handlers

Identifies what CMSG handlers explicitly DON'T do -- missing validations,
unchecked permissions, skipped updates, absent notifications.  The "negative
space" is often where server bugs hide.

Approach:
  1. Build a statistical catalog of what the MAJORITY of handlers do
     (common validation patterns, response patterns, permission checks).
  2. For each handler, compare its behavior against the catalog.
  3. Flag anything the handler OMITS that the majority of similar handlers
     perform -- missing validations, silent mutations, permission gaps,
     notification gaps, rate-limiting absences, and asymmetric pairs.
  4. Score each gap by severity: CRITICAL (security), HIGH (exploit risk),
     MEDIUM (bug risk), LOW (polish).
"""

import json
import re
import time
from collections import defaultdict

import ida_funcs
import ida_name
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Validation pattern catalog -- what handlers SHOULD be doing
# ---------------------------------------------------------------------------

# Each entry: (pattern_name, regex_or_callable, description, category)
# category: "player_state", "input_validation", "permission", "notification",
#           "rate_limit", "error_handling"

_VALIDATION_REGEXES = {
    # --- Player state checks ---
    "is_alive_check": {
        "regex": re.compile(
            r'(?:IsAlive|isAlive|is_alive|!.*(?:IsDead|isDead))\s*\(',
            re.IGNORECASE
        ),
        "description": "Checks whether the player is alive before proceeding",
        "category": "player_state",
        "severity_if_missing": "HIGH",
    },
    "is_in_world_check": {
        "regex": re.compile(
            r'(?:IsInWorld|isInWorld|is_in_world|InWorld)\s*\(',
            re.IGNORECASE
        ),
        "description": "Checks whether the player is in the world",
        "category": "player_state",
        "severity_if_missing": "MEDIUM",
    },
    "in_combat_check": {
        "regex": re.compile(
            r'(?:IsInCombat|isInCombat|InCombat|in_combat)\s*\(',
            re.IGNORECASE
        ),
        "description": "Checks or blocks during combat",
        "category": "player_state",
        "severity_if_missing": "MEDIUM",
    },
    "is_mounted_check": {
        "regex": re.compile(
            r'(?:IsMounted|isMounted|is_mounted|HasUnitState.*UNIT_STATE_ON_VEHICLE)\s*\(',
            re.IGNORECASE
        ),
        "description": "Checks mount or vehicle state",
        "category": "player_state",
        "severity_if_missing": "LOW",
    },
    "is_in_flight_check": {
        "regex": re.compile(
            r'(?:IsInFlight|isInFlight|in_flight|HasUnitState.*UNIT_STATE_IN_FLIGHT)\s*\(',
            re.IGNORECASE
        ),
        "description": "Checks whether the player is on a flight path",
        "category": "player_state",
        "severity_if_missing": "LOW",
    },
    "is_charmed_check": {
        "regex": re.compile(
            r'(?:IsCharmed|isCharmed|HasUnitState.*UNIT_STATE_CHARMED)\s*\(',
            re.IGNORECASE
        ),
        "description": "Checks whether the player is mind-controlled/charmed",
        "category": "player_state",
        "severity_if_missing": "HIGH",
    },
    "is_dead_check": {
        "regex": re.compile(
            r'(?:IsDead|isDead|is_dead|HasFlag.*PLAYER_FLAGS_GHOST)\s*\(',
            re.IGNORECASE
        ),
        "description": "Checks whether the player is dead/ghost",
        "category": "player_state",
        "severity_if_missing": "MEDIUM",
    },
    "has_aura_check": {
        "regex": re.compile(
            r'(?:HasAura|hasAura|has_aura|HasAuraType)\s*\(',
            re.IGNORECASE
        ),
        "description": "Checks for specific aura presence",
        "category": "player_state",
        "severity_if_missing": "LOW",
    },

    # --- Input validation ---
    "guid_validation": {
        "regex": re.compile(
            r'(?:IsEmpty|isEmpty|!.*GetGUID|IsPlayer|IsCreature|'
            r'IsGameObject|GetTypeId|IsUnit)\s*\(',
            re.IGNORECASE
        ),
        "description": "Validates GUID input before use",
        "category": "input_validation",
        "severity_if_missing": "CRITICAL",
    },
    "null_pointer_check": {
        "regex": re.compile(
            r'if\s*\(\s*!\s*\w+\s*\).*?return',
            re.DOTALL
        ),
        "description": "Null pointer guard before dereference",
        "category": "input_validation",
        "severity_if_missing": "CRITICAL",
    },
    "range_check": {
        "regex": re.compile(
            r'(?:>=?\s*(?:MAX_|0x[0-9A-Fa-f]+|\d{2,})|'
            r'<\s*0\s*[|&]|'
            r'>\s*(?:MAX_|LIMIT_|0x[0-9A-Fa-f]+))',
            re.IGNORECASE
        ),
        "description": "Range/bounds check on numeric input",
        "category": "input_validation",
        "severity_if_missing": "HIGH",
    },
    "string_length_check": {
        "regex": re.compile(
            r'(?:\.size\(\)\s*[><=!]+|\.length\(\)\s*[><=!]+|'
            r'strlen\s*\([^)]+\)\s*[><=!]+|MAX_.*LEN)',
            re.IGNORECASE
        ),
        "description": "String length validation",
        "category": "input_validation",
        "severity_if_missing": "HIGH",
    },
    "bag_space_check": {
        "regex": re.compile(
            r'(?:HasItem|CanStore|CanAddItem|GetFreeSlot|'
            r'GetItemCount|CanStoreNewItem|HasInventorySpace)\s*\(',
            re.IGNORECASE
        ),
        "description": "Inventory/bag space check before modification",
        "category": "input_validation",
        "severity_if_missing": "HIGH",
    },

    # --- Permission checks ---
    "gm_check": {
        "regex": re.compile(
            r'(?:IsGameMaster|isGameMaster|HasPermission|GetSecurity|'
            r'IsGMCommand|GetSession.*GetSecurity|SEC_GAMEMASTER|SEC_ADMINISTRATOR)\s*[(\s]',
            re.IGNORECASE
        ),
        "description": "GM/admin permission check",
        "category": "permission",
        "severity_if_missing": "LOW",
    },
    "level_check": {
        "regex": re.compile(
            r'(?:GetLevel|getLevel|get_level)\s*\(\s*\)\s*[<>=!]+',
            re.IGNORECASE
        ),
        "description": "Player level requirement check",
        "category": "permission",
        "severity_if_missing": "MEDIUM",
    },
    "faction_check": {
        "regex": re.compile(
            r'(?:GetTeam|getTeam|GetFaction|GetReputationRank|IsFriendlyTo|IsHostileTo)\s*\(',
            re.IGNORECASE
        ),
        "description": "Faction/reputation check",
        "category": "permission",
        "severity_if_missing": "LOW",
    },

    # --- Distance / spatial checks ---
    "distance_check": {
        "regex": re.compile(
            r'(?:GetDistance|IsWithinDist|IsWithinLOS|GetExactDist|'
            r'IsWithinDistInMap|MAX_INTERACT_DISTANCE|INTERACTION_DISTANCE)\s*[(\s]',
            re.IGNORECASE
        ),
        "description": "Distance/range check for interaction",
        "category": "input_validation",
        "severity_if_missing": "HIGH",
    },
    "map_validity_check": {
        "regex": re.compile(
            r'(?:GetMap\(\)|FindMap|IsInMap|GetMapId|'
            r'GetInstanceScript|sMapMgr|sMapStore)\s*[(\s]',
            re.IGNORECASE
        ),
        "description": "Map/instance validity check",
        "category": "input_validation",
        "severity_if_missing": "MEDIUM",
    },

    # --- Response / notification patterns ---
    "sends_response_packet": {
        "regex": re.compile(
            r'(?:SendPacket|Send\s*\(|WritePacket|operator<<)',
            re.IGNORECASE
        ),
        "description": "Sends a response packet to the client",
        "category": "notification",
        "severity_if_missing": "MEDIUM",
    },
    "broadcasts_update": {
        "regex": re.compile(
            r'(?:SendMessageToSet|BroadcastPacket|SendToAll|'
            r'SendPacketToAll|SendUpdateToAll|SendDirectMessage)\s*\(',
            re.IGNORECASE
        ),
        "description": "Broadcasts state update to nearby players",
        "category": "notification",
        "severity_if_missing": "MEDIUM",
    },
    "sends_error_response": {
        "regex": re.compile(
            r'(?:SendEquipError|SendBuyError|SendSellError|'
            r'SendNotification|SendSysMessage|ChatHandler|'
            r'ERR_|EQUIP_ERR_|AUCTION_ERR_)',
            re.IGNORECASE
        ),
        "description": "Sends error response on failure path",
        "category": "error_handling",
        "severity_if_missing": "MEDIUM",
    },

    # --- Rate limiting ---
    "cooldown_check": {
        "regex": re.compile(
            r'(?:HasCooldown|GetCooldown|HasSpellCooldown|'
            r'HasGlobalCooldown|AddCooldown|GetLastTime|'
            r'time.*diff|GetMSTimeDiff|m_lastAction|_cooldown)',
            re.IGNORECASE
        ),
        "description": "Cooldown or rate-limiting check",
        "category": "rate_limit",
        "severity_if_missing": "LOW",
    },
    "anti_flood_check": {
        "regex": re.compile(
            r'(?:m_muteTime|GetTotalPlayedTime|m_.*Count|_spamCount|'
            r'FLOOD|SPAM|throttle|rateLimit|m_last.*Time)',
            re.IGNORECASE
        ),
        "description": "Anti-flood / anti-spam mechanism",
        "category": "rate_limit",
        "severity_if_missing": "LOW",
    },
}


# ---------------------------------------------------------------------------
# Handler system classification
# ---------------------------------------------------------------------------

_SYSTEM_KEYWORDS = {
    "housing":      ["HOUSING", "HOUSE", "DECOR", "INTERIOR", "STEWARD"],
    "neighborhood": ["NEIGHBORHOOD", "NEIGHBOUR"],
    "quest":        ["QUEST"],
    "combat":       ["SPELL", "AURA", "ATTACK", "CAST", "DAMAGE"],
    "social":       ["GUILD", "CHAT", "MAIL", "FRIEND", "WHISPER", "CHANNEL", "WHO",
                     "PARTY", "GROUP", "RAID", "INVITE"],
    "pvp":          ["BATTLEGROUND", "ARENA", "PVP", "WARGAME", "DUEL"],
    "auction":      ["AUCTION"],
    "trade":        ["TRADE", "CRAFT", "PROFESSION"],
    "talent":       ["TALENT", "SPEC"],
    "pet":          ["PET", "COMPANION", "BATTLE_PET", "STABLE"],
    "achievement":  ["ACHIEVEMENT"],
    "loot":         ["LOOT"],
    "movement":     ["MOVE", "MOVEMENT", "TELEPORT", "TRANSPORT"],
    "item":         ["ITEM", "EQUIP", "USE_ITEM", "DESTROY", "SPLIT", "SWAP",
                     "AUTOEQUIP", "SELL", "BUY", "REPAIR"],
    "character":    ["CHARACTER", "PLAYER", "LOGOUT", "LOGIN", "RELOG",
                     "NAME_QUERY", "CHAR_CREATE", "CHAR_DELETE"],
    "npc":          ["NPC", "CREATURE", "VENDOR", "TRAINER", "GOSSIP",
                     "BANKER", "TABARD", "BINDER", "PETITION"],
    "vehicle":      ["VEHICLE"],
    "garrison":     ["GARRISON", "MISSION"],
    "mythic_plus":  ["MYTHIC", "CHALLENGE_MODE", "KEYSTONE"],
    "calendar":     ["CALENDAR"],
    "lfg":          ["LFG", "LFD", "LFR", "DUNGEON_FINDER"],
    "ticket":       ["TICKET", "SUPPORT", "BUG", "SUGGESTION"],
    "toy":          ["TOY"],
    "transmog":     ["TRANSMOG", "TRANSMOGRIF"],
    "collection":   ["COLLECTION", "APPEARANCE", "MOUNT", "TITLE"],
    "warband":      ["WARBAND", "ACCOUNT_DATA"],
}


def _classify_handler_system(tc_name):
    """Return the game system for a given opcode name."""
    if not tc_name:
        return "unknown"
    upper = tc_name.upper()
    for system, keywords in _SYSTEM_KEYWORDS.items():
        for kw in keywords:
            if kw in upper:
                return system
    return "other"


# ---------------------------------------------------------------------------
# Symmetric pair definitions
# ---------------------------------------------------------------------------

_SYMMETRIC_PAIRS = [
    # (pattern_A_regex, pattern_B_regex, description)
    (r"BUY",       r"SELL",       "Buy/Sell symmetry"),
    (r"ADD",       r"REMOVE",     "Add/Remove symmetry"),
    (r"JOIN",      r"LEAVE",      "Join/Leave symmetry"),
    (r"CREATE",    r"DELETE",     "Create/Delete symmetry"),
    (r"ACCEPT",    r"DECLINE",    "Accept/Decline symmetry"),
    (r"ENABLE",    r"DISABLE",    "Enable/Disable symmetry"),
    (r"OPEN",      r"CLOSE",      "Open/Close symmetry"),
    (r"LEARN",     r"UNLEARN",    "Learn/Unlearn symmetry"),
    (r"EQUIP",     r"UNEQUIP",    "Equip/Unequip symmetry"),
    (r"LOCK",      r"UNLOCK",     "Lock/Unlock symmetry"),
    (r"SUBSCRIBE", r"UNSUBSCRIBE","Subscribe/Unsubscribe symmetry"),
    (r"START",     r"STOP",       "Start/Stop symmetry"),
    (r"SET",       r"CLEAR",      "Set/Clear symmetry"),
    (r"INVITE",    r"UNINVITE",   "Invite/Uninvite symmetry"),
    (r"DEPOSIT",   r"WITHDRAW",   "Deposit/Withdraw symmetry"),
    (r"PLACE",     r"PICKUP",     "Place/Pickup symmetry"),
    (r"ACTIVATE",  r"DEACTIVATE", "Activate/Deactivate symmetry"),
]


# ---------------------------------------------------------------------------
# Pseudocode feature extraction
# ---------------------------------------------------------------------------

def _extract_handler_features(pseudocode):
    """Extract a feature vector from handler pseudocode.

    Returns a dict mapping pattern_name -> bool (present or not),
    plus additional metadata.
    """
    features = {}
    for pattern_name, pattern_info in _VALIDATION_REGEXES.items():
        regex = pattern_info["regex"]
        features[pattern_name] = bool(regex.search(pseudocode))

    # Additional structural features
    features["_branch_count"] = pseudocode.count("if (")
    features["_return_count"] = pseudocode.count("return")
    features["_line_count"] = pseudocode.count("\n") + 1
    features["_has_early_return"] = bool(re.search(
        r'if\s*\([^)]*\)\s*\n?\s*return', pseudocode))

    # Count GUID reads (potential untrusted input)
    features["_guid_read_count"] = len(re.findall(
        r'(?:ReadPackedGuid|ReadGuid|ReadObjectGuid|ObjectGuid)',
        pseudocode, re.IGNORECASE))

    # Count numeric reads
    features["_numeric_read_count"] = len(re.findall(
        r'(?:Read\s*<\s*\w+\s*>|ReadBit|ReadBits|Read(?:UInt|Int)\d+)',
        pseudocode, re.IGNORECASE))

    # Detects whether handler modifies persistent state
    features["_modifies_state"] = bool(re.search(
        r'(?:SetFlag|SetUInt|SetInt|SetFloat|ModifyMoney|AddItem|RemoveItem|'
        r'DestroyItem|SaveToDB|CharacterDatabase|LoginDatabase|WorldDatabase|'
        r'PreparedStatement|SetQuestStatus|CompleteQuest|AddQuest|'
        r'SendNewItem|EquipItem|SwapItem)',
        pseudocode, re.IGNORECASE))

    # Detects whether handler reads from a GUID parameter
    features["_reads_guid_input"] = features["_guid_read_count"] > 0

    # Detects whether handler sends any packet at all
    features["_sends_any_packet"] = bool(re.search(
        r'(?:SendPacket|Send\s*\(|WritePacket|operator<<|'
        r'SendMessageToSet|BroadcastPacket)',
        pseudocode, re.IGNORECASE))

    # Detects NPC interaction pattern
    features["_npc_interaction"] = bool(re.search(
        r'(?:GetNPCIfCanInteractWith|GetCreature|FindNearestCreature|'
        r'npcGuid|npc_guid|vendorGuid|trainerGuid)',
        pseudocode, re.IGNORECASE))

    # Detects item/inventory operations
    features["_item_operation"] = bool(re.search(
        r'(?:GetItemByPos|HasItemCount|AddItem|RemoveItem|DestroyItem|'
        r'SwapItem|EquipItem|CanStoreNewItem|AutoStoreLoot)',
        pseudocode, re.IGNORECASE))

    # Detects teleport / positional operations
    features["_teleport_operation"] = bool(re.search(
        r'(?:TeleportTo|Relocate|NearTeleportTo|GetMotionMaster|'
        r'SendTransferAborted|GetPosition)',
        pseudocode, re.IGNORECASE))

    return features


# ---------------------------------------------------------------------------
# Pattern frequency computation
# ---------------------------------------------------------------------------

def _build_common_pattern_catalog(handler_features):
    """Given a dict of {handler_name: features_dict}, compute frequency of
    each validation pattern across all handlers.

    Returns:
        catalog: dict of pattern_name -> {
            frequency: float (0..1),
            handlers_with: [handler_name, ...],
            handlers_without: [handler_name, ...],
        }
    """
    catalog = {}
    handler_names = list(handler_features.keys())
    total = len(handler_names)

    if total == 0:
        return catalog

    for pattern_name in _VALIDATION_REGEXES:
        with_list = []
        without_list = []
        for hname in handler_names:
            feats = handler_features[hname]
            if feats.get(pattern_name, False):
                with_list.append(hname)
            else:
                without_list.append(hname)

        freq = len(with_list) / total if total > 0 else 0.0
        catalog[pattern_name] = {
            "frequency": round(freq, 4),
            "count_with": len(with_list),
            "count_without": len(without_list),
            "handlers_with": with_list,
            "handlers_without": without_list,
        }

    return catalog


# ---------------------------------------------------------------------------
# System-level pattern frequency (what do handlers IN THIS SYSTEM do?)
# ---------------------------------------------------------------------------

def _build_system_catalogs(handler_features, handler_systems):
    """Build per-system pattern frequency catalogs.

    This is more useful than the global catalog: if 95% of ITEM handlers
    check bag space but this one doesn't, it's a stronger signal than
    comparing against ALL handlers.
    """
    # Group handlers by system
    system_handlers = defaultdict(list)
    for hname, system in handler_systems.items():
        system_handlers[system].append(hname)

    system_catalogs = {}
    for system, handlers in system_handlers.items():
        if len(handlers) < 3:
            continue  # too few to make statistical claims

        sub_features = {h: handler_features[h] for h in handlers
                        if h in handler_features}
        system_catalogs[system] = _build_common_pattern_catalog(sub_features)

    return system_catalogs


# ---------------------------------------------------------------------------
# Absence detection
# ---------------------------------------------------------------------------

def _detect_missing_validations(handler_name, features, global_catalog,
                                system_catalog, system, threshold=0.5):
    """For a handler, identify which common patterns it is missing.

    A pattern is considered "missing" if:
      - Its system-level frequency >= threshold (i.e. most in this system do it)
      - OR its global frequency >= 0.8 AND the handler context suggests it should
      - AND this handler does NOT have the pattern

    Returns list of gap dicts.
    """
    gaps = []

    for pattern_name, pattern_info in _VALIDATION_REGEXES.items():
        if features.get(pattern_name, False):
            continue  # handler already does it

        # Determine effective frequency
        sys_freq = 0.0
        global_freq = 0.0

        if pattern_name in global_catalog:
            global_freq = global_catalog[pattern_name]["frequency"]

        if system_catalog and pattern_name in system_catalog:
            sys_freq = system_catalog[pattern_name]["frequency"]

        effective_freq = max(sys_freq, global_freq)

        # Contextual boosting: some patterns are more relevant given handler content
        context_boost = 0.0
        if pattern_name == "guid_validation" and features.get("_reads_guid_input"):
            context_boost = 0.3
        elif pattern_name == "bag_space_check" and features.get("_item_operation"):
            context_boost = 0.3
        elif pattern_name == "distance_check" and features.get("_npc_interaction"):
            context_boost = 0.3
        elif pattern_name == "map_validity_check" and features.get("_teleport_operation"):
            context_boost = 0.3
        elif pattern_name == "null_pointer_check" and features.get("_reads_guid_input"):
            context_boost = 0.2
        elif pattern_name == "is_alive_check" and features.get("_modifies_state"):
            context_boost = 0.15
        elif pattern_name == "in_combat_check" and features.get("_item_operation"):
            context_boost = 0.1
        elif pattern_name == "sends_response_packet" and features.get("_modifies_state"):
            context_boost = 0.2

        boosted_freq = min(1.0, effective_freq + context_boost)

        if boosted_freq < threshold:
            continue

        # Determine severity
        base_severity = pattern_info["severity_if_missing"]

        # Elevate severity if context makes it particularly dangerous
        severity = base_severity
        if pattern_name == "guid_validation" and features.get("_reads_guid_input"):
            severity = "CRITICAL"
        elif pattern_name == "null_pointer_check" and features.get("_guid_read_count", 0) > 0:
            severity = "CRITICAL"
        elif pattern_name == "distance_check" and features.get("_npc_interaction"):
            severity = "HIGH"
        elif pattern_name == "bag_space_check" and features.get("_item_operation"):
            severity = "HIGH"

        # Collect similar handlers that DO have this check
        similar_with = []
        if system_catalog and pattern_name in system_catalog:
            similar_with = system_catalog[pattern_name].get("handlers_with", [])[:5]
        elif pattern_name in global_catalog:
            similar_with = global_catalog[pattern_name].get("handlers_with", [])[:5]

        gaps.append({
            "handler": handler_name,
            "missing_pattern": pattern_name,
            "description": pattern_info["description"],
            "category": pattern_info["category"],
            "severity": severity,
            "system_frequency": round(sys_freq, 3),
            "global_frequency": round(global_freq, 3),
            "boosted_frequency": round(boosted_freq, 3),
            "similar_handlers_with": similar_with,
        })

    return gaps


# ---------------------------------------------------------------------------
# Permission gap analysis
# ---------------------------------------------------------------------------

def _analyze_permission_gaps(handler_name, features, system, global_catalog):
    """Identify permission-related gaps for a handler.

    Returns list of permission gap dicts.
    """
    gaps = []

    # Handler accepts operations during combat when similar handlers don't
    if (features.get("_modifies_state") and
            not features.get("in_combat_check") and
            global_catalog.get("in_combat_check", {}).get("frequency", 0) > 0.3):
        gaps.append({
            "handler": handler_name,
            "gap_type": "allows_during_combat",
            "details": ("Handler modifies persistent state but does not block "
                        "during combat. {:.0%} of other handlers check combat state.".format(
                            global_catalog["in_combat_check"]["frequency"])),
            "severity": "MEDIUM",
        })

    # Handler has no GM check but interacts with privileged operations
    if (features.get("_modifies_state") and
            not features.get("gm_check") and
            any(kw in handler_name.upper() for kw in
                ["DELETE", "DESTROY", "BAN", "KICK", "MUTE", "FORCE",
                 "ADMIN", "GM", "SET_LEVEL", "ADD_ITEM"])):
        gaps.append({
            "handler": handler_name,
            "gap_type": "missing_gm_check",
            "details": ("Handler name suggests privileged operation but "
                        "no GM/permission check detected"),
            "severity": "CRITICAL",
        })

    # Handler reads GUID but never checks if the referenced object is valid
    if (features.get("_reads_guid_input") and
            not features.get("guid_validation") and
            not features.get("null_pointer_check")):
        gaps.append({
            "handler": handler_name,
            "gap_type": "unchecked_guid_input",
            "details": ("Handler reads GUID from packet but never validates "
                        "the referenced object exists or is accessible"),
            "severity": "CRITICAL",
        })

    # NPC interaction without distance check
    if (features.get("_npc_interaction") and
            not features.get("distance_check")):
        gaps.append({
            "handler": handler_name,
            "gap_type": "npc_no_distance_check",
            "details": ("Handler interacts with an NPC but never checks "
                        "interaction distance -- exploitable from anywhere on map"),
            "severity": "HIGH",
        })

    # Teleport without map validity
    if (features.get("_teleport_operation") and
            not features.get("map_validity_check")):
        gaps.append({
            "handler": handler_name,
            "gap_type": "teleport_no_map_check",
            "details": ("Handler performs teleportation but does not validate "
                        "the target map/instance"),
            "severity": "HIGH",
        })

    # Level-gated content without level check
    if (not features.get("level_check") and
            any(kw in handler_name.upper() for kw in
                ["HEROIC", "MYTHIC", "RAID", "ARENA", "RATED", "EPIC"])):
        gaps.append({
            "handler": handler_name,
            "gap_type": "missing_level_check",
            "details": ("Handler name suggests level-gated content but "
                        "no level check detected"),
            "severity": "MEDIUM",
        })

    return gaps


# ---------------------------------------------------------------------------
# Notification gap analysis
# ---------------------------------------------------------------------------

def _analyze_notification_gaps(handler_name, features, system,
                                response_data):
    """Identify notification-related gaps.

    Args:
        response_data: response_packets data from the kv_store (or None).

    Returns list of notification gap dicts.
    """
    gaps = []

    # Handler modifies state but sends no packet
    if features.get("_modifies_state") and not features.get("_sends_any_packet"):
        gaps.append({
            "handler": handler_name,
            "state_modified": True,
            "notification_missing": "no_response_at_all",
            "details": ("Handler modifies persistent state (DB write, item change, "
                        "flag set) but sends NO packet response -- client may be "
                        "out of sync"),
            "severity": "HIGH",
        })

    # Handler modifies shared state (group/guild) but no broadcast
    social_systems = {"social", "pvp", "guild", "party", "group", "raid"}
    if (system in social_systems and
            features.get("_modifies_state") and
            not features.get("broadcasts_update")):
        gaps.append({
            "handler": handler_name,
            "state_modified": True,
            "notification_missing": "no_broadcast_for_shared_state",
            "details": ("Handler in '{}' system modifies state but never "
                        "broadcasts to other group/guild members".format(system)),
            "severity": "MEDIUM",
        })

    # Handler sends success response but no error response on failure paths
    if (features.get("sends_response_packet") and
            not features.get("sends_error_response") and
            features.get("_branch_count", 0) > 3 and
            features.get("_has_early_return")):
        gaps.append({
            "handler": handler_name,
            "state_modified": features.get("_modifies_state", False),
            "notification_missing": "no_error_response_on_failure",
            "details": ("Handler sends success response but has early-return "
                        "failure paths with no error response -- client hangs "
                        "or gets no feedback"),
            "severity": "MEDIUM",
        })

    # Cross-reference with response_packets data if available
    if response_data:
        handler_responses = None
        for entry in response_data:
            if (entry.get("cmsg_opcode", "").upper() == handler_name.upper() or
                    handler_name.upper() in entry.get("cmsg_opcode", "").upper()):
                handler_responses = entry
                break

        if handler_responses:
            responses = handler_responses.get("responses", [])
            path_types = [r.get("path_type") for r in responses]

            # Has success but no error path
            if "success_response" in path_types and "error_response" not in path_types:
                if features.get("_branch_count", 0) > 2:
                    gaps.append({
                        "handler": handler_name,
                        "state_modified": features.get("_modifies_state", False),
                        "notification_missing": "success_only_no_error_smsg",
                        "details": ("Response reconstruction found success SMSG "
                                    "path but no error SMSG -- failure paths are silent"),
                        "severity": "MEDIUM",
                    })
        else:
            # Handler has no response data at all and modifies state
            if features.get("_modifies_state"):
                gaps.append({
                    "handler": handler_name,
                    "state_modified": True,
                    "notification_missing": "no_smsg_reconstructed",
                    "details": ("No SMSG response packets were reconstructed for "
                                "this handler despite modifying state"),
                    "severity": "MEDIUM",
                })

    return gaps


# ---------------------------------------------------------------------------
# Error handling gap analysis
# ---------------------------------------------------------------------------

def _analyze_error_handling_gaps(handler_name, pseudocode, features):
    """Identify error handling deficiencies.

    Returns list of error handling gap dicts.
    """
    gaps = []
    lines = pseudocode.split("\n")

    # Track paths: if blocks that return vs those that silently fall through
    responding_paths = 0
    silent_paths = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("if"):
            continue

        # Look ahead for what happens in this if block
        block = _get_if_block(lines, i)

        has_send = bool(re.search(
            r'(?:SendPacket|Send\(|WritePacket|SendEquipError|'
            r'SendNotification|ChatHandler)',
            block, re.IGNORECASE))
        has_return = "return" in block

        if has_return and has_send:
            responding_paths += 1
        elif has_return and not has_send:
            silent_paths += 1

    if responding_paths > 0 and silent_paths > 0:
        gaps.append({
            "handler": handler_name,
            "path_description": (
                f"{responding_paths} paths send error responses but "
                f"{silent_paths} paths return silently"),
            "gap_type": "inconsistent_error_responses",
            "severity": "MEDIUM",
        })

    # Check for function calls whose return values are ignored
    # Pattern: functionCall(...); on its own line (not in if, not assigned)
    ignored_returns = 0
    important_funcs = re.compile(
        r'^\s*(?:AddItem|RemoveItem|EquipItem|CreateItem|DestroyItem|'
        r'AddQuest|TeleportTo|SetPosition|ModifyMoney|'
        r'SendMailTo|AddToGroup|RemoveFromGroup|'
        r'LearnSpell|CastSpell)\s*\(',
        re.IGNORECASE
    )
    for line in lines:
        if important_funcs.match(line.strip()):
            # Check if the result is captured
            if "=" not in line and "if" not in line:
                ignored_returns += 1

    if ignored_returns > 0:
        gaps.append({
            "handler": handler_name,
            "path_description": (
                f"{ignored_returns} important function call(s) with ignored "
                f"return values -- error conditions may be silently lost"),
            "gap_type": "ignored_return_values",
            "severity": "HIGH",
        })

    # Handler with no early returns despite reading user input
    if (features.get("_numeric_read_count", 0) > 0 and
            not features.get("_has_early_return") and
            features.get("_branch_count", 0) == 0):
        gaps.append({
            "handler": handler_name,
            "path_description": (
                "Handler reads user-controlled input but has no branching "
                "or early returns -- all input values accepted unconditionally"),
            "gap_type": "no_input_validation",
            "severity": "HIGH",
        })

    return gaps


# ---------------------------------------------------------------------------
# Rate limiting gap analysis
# ---------------------------------------------------------------------------

def _analyze_rate_limiting_gaps(handler_name, features, system,
                                 rate_limited_handlers):
    """Identify handlers that should have rate limiting but don't.

    Args:
        rate_limited_handlers: set of handler names that DO have rate limiting

    Returns list of rate limiting gap dicts.
    """
    gaps = []

    has_rate_limit = (features.get("cooldown_check") or
                      features.get("anti_flood_check"))

    if has_rate_limit:
        return gaps

    # Systems where rate limiting is particularly important
    high_risk_systems = {"social", "auction", "trade", "ticket", "calendar",
                         "lfg", "mail"}
    spammable_keywords = ["CHAT", "MAIL", "WHISPER", "CHANNEL", "EMOTE",
                          "COMPLAIN", "REPORT", "AUCTION", "PETITION",
                          "CALENDAR", "INVITE"]

    is_high_risk = system in high_risk_systems
    is_spammable = any(kw in handler_name.upper() for kw in spammable_keywords)

    if is_high_risk or is_spammable:
        # Check if similar handlers (same system) have rate limiting
        same_system_rate_limited = [h for h in rate_limited_handlers
                                    if h != handler_name]
        risk = "HIGH" if is_spammable else "MEDIUM"

        gaps.append({
            "handler": handler_name,
            "risk_level": risk,
            "details": (
                f"Handler in '{system}' system has no rate limiting. "
                f"{'Name suggests spammable operation. ' if is_spammable else ''}"
                f"{len(same_system_rate_limited)} handlers in the codebase "
                f"do have rate limiting."),
        })

    # Any handler that modifies state and is callable at will
    elif (features.get("_modifies_state") and
          features.get("_numeric_read_count", 0) == 0 and
          features.get("_guid_read_count", 0) == 0):
        # Simple fire-and-forget handler with state modification
        gaps.append({
            "handler": handler_name,
            "risk_level": "LOW",
            "details": (
                "Handler modifies server state with no input parameters "
                "and no rate limiting -- can be spammed to cause load"),
        })

    return gaps


# ---------------------------------------------------------------------------
# Cross-handler consistency (symmetric pair detection)
# ---------------------------------------------------------------------------

def _find_asymmetric_pairs(handler_features, handler_systems):
    """Find pairs of handlers that should be symmetric but have
    different validation patterns.

    Returns list of asymmetric pair dicts.
    """
    pairs = []
    handler_names = sorted(handler_features.keys())

    for pattern_a_re, pattern_b_re, description in _SYMMETRIC_PAIRS:
        # Find handlers matching each side of the pair
        re_a = re.compile(pattern_a_re, re.IGNORECASE)
        re_b = re.compile(pattern_b_re, re.IGNORECASE)

        handlers_a = [h for h in handler_names if re_a.search(h)]
        handlers_b = [h for h in handler_names if re_b.search(h)]

        # Try to match specific pairs by replacing the keyword
        for ha in handlers_a:
            ha_upper = ha.upper()
            # Construct what the partner name should look like
            candidate_b = re_a.sub(pattern_b_re, ha_upper)

            best_match = None
            best_score = 0
            for hb in handlers_b:
                if hb.upper() == candidate_b:
                    best_match = hb
                    best_score = 100
                    break
                # Partial match: same system prefix
                ha_parts = set(ha_upper.split("_"))
                hb_parts = set(hb.upper().split("_"))
                overlap = len(ha_parts & hb_parts)
                if overlap > best_score:
                    best_score = overlap
                    best_match = hb

            if not best_match or best_score < 2:
                continue

            feats_a = handler_features[ha]
            feats_b = handler_features[best_match]

            # Compare validation patterns
            diffs = []
            for pname in _VALIDATION_REGEXES:
                a_has = feats_a.get(pname, False)
                b_has = feats_b.get(pname, False)
                if a_has != b_has:
                    who_has = ha if a_has else best_match
                    who_lacks = best_match if a_has else ha
                    diffs.append({
                        "pattern": pname,
                        "present_in": who_has,
                        "missing_from": who_lacks,
                        "description": _VALIDATION_REGEXES[pname]["description"],
                    })

            if diffs:
                severity = "HIGH" if any(
                    _VALIDATION_REGEXES[d["pattern"]]["severity_if_missing"]
                    in ("CRITICAL", "HIGH") for d in diffs
                ) else "MEDIUM"

                pairs.append({
                    "handler_a": ha,
                    "handler_b": best_match,
                    "pair_type": description,
                    "validation_diff": diffs,
                    "diff_count": len(diffs),
                    "severity": severity,
                })

    return pairs


# ---------------------------------------------------------------------------
# Helper: extract if-block
# ---------------------------------------------------------------------------

def _get_if_block(lines, start_idx):
    """Extract the if-block starting at line index."""
    block_lines = [lines[start_idx]]
    brace_depth = lines[start_idx].count("{") - lines[start_idx].count("}")

    for j in range(start_idx + 1, min(start_idx + 15, len(lines))):
        block_lines.append(lines[j])
        brace_depth += lines[j].count("{") - lines[j].count("}")
        if brace_depth <= 0 and ("return" in lines[j] or "}" in lines[j]):
            break

    return "\n".join(block_lines)


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _compute_handler_risk_score(gaps):
    """Compute a numeric risk score for a handler based on its gaps.

    Score range: 0 (no issues) to 100+ (many critical gaps).
    """
    score = 0
    for gap in gaps:
        sev = gap.get("severity", "LOW")
        score += _SEVERITY_ORDER.get(sev, 1) * 10
    return score


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_negative_space(session):
    """Analyze all CMSG handlers for negative-space gaps.

    Builds a statistical catalog of what handlers commonly do, then
    flags each handler's omissions against that catalog.

    Args:
        session: PluginSession with a valid .db

    Returns:
        Total number of gaps identified.
    """
    db = session.db
    t0 = time.time()

    # Step 1: Load all CMSG handlers
    handlers = db.fetchall(
        "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL "
        "AND direction = 'CMSG'"
    )
    if not handlers:
        msg_warn("No CMSG handlers found. Run opcode analysis first.")
        return 0

    msg_info(f"Negative space analysis: scanning {len(handlers)} CMSG handlers...")

    # Step 2: Load response_packets data for notification gap cross-reference
    response_data = db.kv_get("response_packets") or []

    # Step 3: Decompile and extract features for every handler
    handler_features = {}   # tc_name -> features dict
    handler_systems = {}    # tc_name -> system string
    handler_pseudocode = {} # tc_name -> raw pseudocode (for error gap analysis)
    handler_eas = {}        # tc_name -> ea

    decompile_count = 0
    decompile_failures = 0

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"CMSG_UNKNOWN_0x{ea:X}"
        system = _classify_handler_system(tc_name)

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            decompile_failures += 1
            continue

        features = _extract_handler_features(pseudocode)
        handler_features[tc_name] = features
        handler_systems[tc_name] = system
        handler_pseudocode[tc_name] = pseudocode
        handler_eas[tc_name] = ea
        decompile_count += 1

        if decompile_count % 100 == 0:
            msg_info(f"  Decompiled {decompile_count}/{len(handlers)} handlers...")

    msg_info(f"  Decompiled {decompile_count} handlers "
             f"({decompile_failures} failures)")

    if decompile_count == 0:
        msg_error("No handlers could be decompiled")
        return 0

    # Step 4: Build pattern catalogs
    msg_info("  Building pattern catalogs...")
    global_catalog = _build_common_pattern_catalog(handler_features)
    system_catalogs = _build_system_catalogs(handler_features, handler_systems)

    # Identify handlers with rate limiting for comparison
    rate_limited_handlers = set()
    for hname, feats in handler_features.items():
        if feats.get("cooldown_check") or feats.get("anti_flood_check"):
            rate_limited_handlers.add(hname)

    # Step 5: Analyze each handler for gaps
    msg_info("  Detecting negative space gaps...")

    all_missing_validations = []
    all_permission_gaps = []
    all_notification_gaps = []
    all_error_handling_gaps = []
    all_rate_limiting_gaps = []

    for hname in sorted(handler_features.keys()):
        feats = handler_features[hname]
        system = handler_systems[hname]
        sys_catalog = system_catalogs.get(system)
        pseudocode = handler_pseudocode.get(hname, "")

        # 5a: Missing validations
        missing = _detect_missing_validations(
            hname, feats, global_catalog, sys_catalog, system,
            threshold=0.4)
        all_missing_validations.extend(missing)

        # 5b: Permission gaps
        perm_gaps = _analyze_permission_gaps(
            hname, feats, system, global_catalog)
        all_permission_gaps.extend(perm_gaps)

        # 5c: Notification gaps
        notif_gaps = _analyze_notification_gaps(
            hname, feats, system, response_data)
        all_notification_gaps.extend(notif_gaps)

        # 5d: Error handling gaps
        err_gaps = _analyze_error_handling_gaps(
            hname, pseudocode, feats)
        all_error_handling_gaps.extend(err_gaps)

        # 5e: Rate limiting gaps
        rate_gaps = _analyze_rate_limiting_gaps(
            hname, feats, system, rate_limited_handlers)
        all_rate_limiting_gaps.extend(rate_gaps)

    # Step 6: Cross-handler consistency (symmetric pairs)
    msg_info("  Checking cross-handler consistency...")
    asymmetric_pairs = _find_asymmetric_pairs(
        handler_features, handler_systems)

    # Step 7: Compute summary statistics
    all_gaps = (all_missing_validations + all_permission_gaps +
                all_notification_gaps + all_error_handling_gaps +
                all_rate_limiting_gaps)

    # Add asymmetric pair gaps to total
    for pair in asymmetric_pairs:
        all_gaps.append({
            "handler": pair["handler_a"],
            "severity": pair["severity"],
        })

    severity_counts = defaultdict(int)
    for gap in all_gaps:
        sev = gap.get("severity", gap.get("risk_level", "LOW"))
        severity_counts[sev] += 1

    # Build per-handler risk scores
    handler_gaps = defaultdict(list)
    for gap in all_gaps:
        hname = gap.get("handler", "unknown")
        handler_gaps[hname].append(gap)

    handler_risk_scores = {}
    for hname, gaps_list in handler_gaps.items():
        handler_risk_scores[hname] = {
            "score": _compute_handler_risk_score(gaps_list),
            "gap_count": len(gaps_list),
            "system": handler_systems.get(hname, "unknown"),
            "ea": hex(handler_eas.get(hname, 0)),
        }

    # Sort by risk score descending
    top_risky = sorted(
        handler_risk_scores.items(),
        key=lambda x: x[1]["score"],
        reverse=True
    )[:50]

    # Step 8: Build compact common_patterns for storage
    common_patterns_compact = []
    for pname, cat_data in sorted(global_catalog.items(),
                                   key=lambda x: x[1]["frequency"],
                                   reverse=True):
        common_patterns_compact.append({
            "pattern_name": pname,
            "description": _VALIDATION_REGEXES.get(pname, {}).get(
                "description", ""),
            "category": _VALIDATION_REGEXES.get(pname, {}).get(
                "category", "unknown"),
            "frequency": cat_data["frequency"],
            "count_with": cat_data["count_with"],
            "count_without": cat_data["count_without"],
        })

    # System-level pattern summary
    system_pattern_summary = {}
    for system, catalog in system_catalogs.items():
        top_patterns = sorted(
            catalog.items(), key=lambda x: x[1]["frequency"], reverse=True
        )[:10]
        system_pattern_summary[system] = [
            {
                "pattern_name": pn,
                "frequency": cd["frequency"],
                "count_with": cd["count_with"],
                "count_without": cd["count_without"],
            }
            for pn, cd in top_patterns
        ]

    # Trim large lists for storage (keep full detail for top items, counts
    # for the rest)
    def _trim_gaps(gap_list, max_full=200):
        """Sort by severity, keep max_full with full detail."""
        sorted_gaps = sorted(
            gap_list,
            key=lambda g: _SEVERITY_ORDER.get(
                g.get("severity", g.get("risk_level", "LOW")), 0),
            reverse=True)
        trimmed = []
        for g in sorted_gaps[:max_full]:
            # Remove the similar_handlers_with list if too long
            entry = dict(g)
            if "similar_handlers_with" in entry:
                entry["similar_handlers_with"] = entry["similar_handlers_with"][:3]
            trimmed.append(entry)
        return trimmed

    # Step 9: Store results
    elapsed = time.time() - t0
    total_gaps = len(all_gaps)
    critical_count = severity_counts.get("CRITICAL", 0)
    high_count = severity_counts.get("HIGH", 0)

    result = {
        "analysis_time_seconds": round(elapsed, 1),
        "handlers_analyzed": decompile_count,
        "handlers_failed": decompile_failures,
        "total_gaps": total_gaps,
        "critical_gaps": critical_count,
        "high_gaps": high_count,
        "medium_gaps": severity_counts.get("MEDIUM", 0),
        "low_gaps": severity_counts.get("LOW", 0),
        "common_patterns": common_patterns_compact,
        "system_patterns": system_pattern_summary,
        "missing_validations": _trim_gaps(all_missing_validations),
        "permission_gaps": _trim_gaps(all_permission_gaps),
        "notification_gaps": _trim_gaps(all_notification_gaps, max_full=150),
        "error_handling_gaps": _trim_gaps(all_error_handling_gaps),
        "rate_limiting_gaps": _trim_gaps(all_rate_limiting_gaps),
        "asymmetric_pairs": asymmetric_pairs[:100],
        "top_risky_handlers": [
            {"handler": h, **data} for h, data in top_risky
        ],
        "severity_distribution": dict(severity_counts),
    }

    db.kv_set("negative_space", result)
    db.commit()

    # Step 10: Print summary
    msg_info(f"Negative space analysis complete in {elapsed:.1f}s")
    msg_info(f"  Handlers analyzed: {decompile_count}")
    msg_info(f"  Total gaps found: {total_gaps}")
    msg_info(f"    CRITICAL: {critical_count}")
    msg_info(f"    HIGH:     {high_count}")
    msg_info(f"    MEDIUM:   {severity_counts.get('MEDIUM', 0)}")
    msg_info(f"    LOW:      {severity_counts.get('LOW', 0)}")
    msg_info(f"  Asymmetric pairs: {len(asymmetric_pairs)}")
    msg("")

    if top_risky:
        msg("  Top risky handlers:")
        for hname, data in top_risky[:15]:
            msg(f"    [{data['score']:3d}] {hname} "
                f"({data['gap_count']} gaps, {data['system']})")
    msg("")

    # Log the most frequent pattern gaps
    if all_missing_validations:
        gap_freq = defaultdict(int)
        for mv in all_missing_validations:
            gap_freq[mv["missing_pattern"]] += 1
        msg("  Most commonly missing patterns:")
        for pname, cnt in sorted(gap_freq.items(), key=lambda x: -x[1])[:10]:
            desc = _VALIDATION_REGEXES.get(pname, {}).get("description", "")
            msg(f"    {pname}: {cnt} handlers ({desc})")

    return total_gaps


# ---------------------------------------------------------------------------
# Report retrieval
# ---------------------------------------------------------------------------

def get_negative_space_report(session):
    """Retrieve stored negative space analysis results.

    Returns:
        dict with all analysis data, or None if not yet run.
    """
    return session.db.kv_get("negative_space")


# ---------------------------------------------------------------------------
# Focused queries (convenience wrappers)
# ---------------------------------------------------------------------------

def get_critical_gaps(session):
    """Return only CRITICAL severity gaps."""
    report = get_negative_space_report(session)
    if not report:
        return []

    critical = []
    for section in ("missing_validations", "permission_gaps",
                    "notification_gaps", "error_handling_gaps"):
        for gap in report.get(section, []):
            if gap.get("severity") == "CRITICAL":
                critical.append(gap)
    return critical


def get_gaps_for_handler(session, handler_name):
    """Return all gaps for a specific handler."""
    report = get_negative_space_report(session)
    if not report:
        return []

    handler_upper = handler_name.upper()
    gaps = []

    for section in ("missing_validations", "permission_gaps",
                    "notification_gaps", "error_handling_gaps",
                    "rate_limiting_gaps"):
        for gap in report.get(section, []):
            if gap.get("handler", "").upper() == handler_upper:
                gaps.append(gap)

    # Check asymmetric pairs too
    for pair in report.get("asymmetric_pairs", []):
        if (pair.get("handler_a", "").upper() == handler_upper or
                pair.get("handler_b", "").upper() == handler_upper):
            gaps.append({
                "type": "asymmetric_pair",
                "pair": pair,
                "severity": pair.get("severity", "MEDIUM"),
            })

    return gaps


def get_gaps_for_system(session, system_name):
    """Return all gaps for a specific game system."""
    report = get_negative_space_report(session)
    if not report:
        return []

    # Use the top_risky_handlers to find handlers in this system
    system_lower = system_name.lower()
    system_handlers = set()
    for entry in report.get("top_risky_handlers", []):
        if entry.get("system", "").lower() == system_lower:
            system_handlers.add(entry.get("handler", "").upper())

    # Also scan gaps directly: handler names containing system keywords
    keywords = _SYSTEM_KEYWORDS.get(system_lower, [system_name.upper()])

    gaps = []
    for section in ("missing_validations", "permission_gaps",
                    "notification_gaps", "error_handling_gaps",
                    "rate_limiting_gaps"):
        for gap in report.get(section, []):
            hname = gap.get("handler", "").upper()
            if hname in system_handlers:
                gaps.append(gap)
            elif any(kw in hname for kw in keywords):
                gaps.append(gap)

    return gaps


def get_pattern_statistics(session):
    """Return the common pattern frequency catalog."""
    report = get_negative_space_report(session)
    if not report:
        return []
    return report.get("common_patterns", [])


def get_asymmetric_pairs(session):
    """Return all detected asymmetric handler pairs."""
    report = get_negative_space_report(session)
    if not report:
        return []
    return report.get("asymmetric_pairs", [])
