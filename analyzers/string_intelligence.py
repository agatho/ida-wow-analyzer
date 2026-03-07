"""
String Intelligence Analyzer
Mines error, debug, assert, and diagnostic strings from the WoW x64 binary
to recover function names, variable names, system boundaries, and original
source file paths.

The key insight: Blizzard leaves thousands of strings embedded in the binary
-- assert messages, debug logs, error descriptions, file paths from __FILE__
macros -- each carrying precious metadata about the function that references
it.  By systematically scanning, classifying, and cross-referencing these
strings, we recover:

  - Direct function names from "CClassName::MethodName" assert patterns
  - System boundaries from shared string prefix groups
  - Variable names from format-string parameter analysis
  - Original source directory tree from __FILE__ macro paths
  - Function neighborhoods from shared string references

Produces a comprehensive string intelligence database that enriches every
other analyzer's output.
"""

import json
import re
import time
from collections import defaultdict

import ida_funcs
import ida_name
import ida_bytes
import ida_nalt
import idautils
import idaapi
import idc

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Regex patterns for string classification and name recovery
# ---------------------------------------------------------------------------

# Direct class::method patterns (highest confidence)
# Matches: "CSpellHistory::AddCooldown", "CGUnit_C::UpdateDisplayPower"
_RE_CLASS_METHOD = re.compile(
    r'\b(C?[A-Z][A-Za-z0-9_]+(?:_C)?)::'
    r'([A-Z][A-Za-z0-9_]+)\b'
)

# Dotted class.method patterns (Lua/script style)
# Matches: "SpellBook.LearnSpell", "Container.GetSlotCount"
_RE_DOT_METHOD = re.compile(
    r'\b([A-Z][A-Za-z0-9_]+)\.([A-Z][A-Za-z0-9_]+)\b'
)

# Assert patterns: ASSERT(condition), WoWAssert(...), BLIZZARD_ASSERT(...)
_RE_ASSERT = re.compile(
    r'(?:ASSERT|WoWAssert|BLIZZARD_ASSERT|SAssert|FATAL)\s*\(\s*(.+?)\s*\)',
    re.DOTALL
)

# WoW error/warning calls with string parameter
_RE_ERROR_CALL = re.compile(
    r'(?:WoWError|WoWWarning|SysMsgf?|OutputDebugString[AW]?|'
    r'ConsoleWrite|LogMessage|DebugPrint)\s*\(\s*"([^"]+)"',
    re.DOTALL
)

# Format string with %s placeholders
_RE_FORMAT_PARAM = re.compile(r'%[-+0 #]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[diouxXeEfFgGaAcspn%]')

# Bracketed system prefix: [System] message
_RE_BRACKET_PREFIX = re.compile(r'^\[([A-Za-z][A-Za-z0-9_]+)\]\s')

# Colon-delimited system prefix: "System: message"
_RE_COLON_PREFIX = re.compile(r'^([A-Z][A-Za-z0-9_]+):\s')

# File path patterns from __FILE__ macros
# Windows: "c:\build\wow\Source\Game\Spell\SpellHistory.cpp"
_RE_WINDOWS_PATH = re.compile(
    r'[A-Za-z]:\\(?:[A-Za-z0-9_.\-]+\\)+[A-Za-z0-9_.\-]+\.\w{1,4}'
)
# Unix: "/build/wow/Source/Game/Spell/SpellHistory.cpp"
_RE_UNIX_PATH = re.compile(
    r'/(?:[A-Za-z0-9_.\-]+/)+[A-Za-z0-9_.\-]+\.\w{1,4}'
)

# "Invalid X" / "Unknown X" / "Bad X" patterns for variable inference
_RE_INVALID_PARAM = re.compile(
    r'(?:Invalid|Unknown|Bad|Missing|NULL|Null|nil)\s+([A-Za-z][A-Za-z0-9_]*)',
    re.IGNORECASE
)

# "X not found" / "X is null" patterns
_RE_NOT_FOUND = re.compile(
    r'([A-Za-z][A-Za-z0-9_]*)\s+(?:not\s+found|is\s+null|is\s+NULL|'
    r'is\s+nil|doesn\'t\s+exist|does\s+not\s+exist)',
    re.IGNORECASE
)

# "Failed to X" patterns for function purpose
_RE_FAILED_TO = re.compile(
    r'[Ff]ailed\s+to\s+([A-Za-z][A-Za-z0-9_ ]{2,40})'
)

# "Cannot X" / "Could not X" patterns
_RE_CANNOT = re.compile(
    r'(?:Cannot|Could\s+not|Can\'t|Unable\s+to)\s+([A-Za-z][A-Za-z0-9_ ]{2,40})',
    re.IGNORECASE
)

# Numeric ID pattern: "... ID %d" or "... ID: %d"
_RE_ID_PARAM = re.compile(
    r'([A-Za-z][A-Za-z0-9_]*)\s+ID\s*[:=]?\s*%',
    re.IGNORECASE
)

# Enumeration-like patterns: "type = %d", "state = %d"
_RE_ENUM_PARAM = re.compile(
    r'([A-Za-z][A-Za-z0-9_]*)\s*[:=]\s*%[diu]'
)

# Source line patterns: "file.cpp(123)" or "file.cpp:123"
_RE_SOURCE_LINE = re.compile(
    r'([A-Za-z0-9_]+\.\w{1,4})\s*[:(]\s*(\d+)\s*\)?'
)


# ---------------------------------------------------------------------------
# System prefix mapping: string prefixes → TrinityCore system names
# ---------------------------------------------------------------------------

SYSTEM_PREFIX_MAP = {
    # Core systems
    "Spell":        "Spell",
    "Aura":         "Spell",
    "Cast":         "Spell",
    "SpellHistory": "Spell",
    "Quest":        "Quest",
    "QuestGiver":   "Quest",
    "Item":         "Item",
    "Equip":        "Item",
    "Inventory":    "Item",
    "Bag":          "Item",
    "Loot":         "Loot",
    "Guild":        "Guild",
    "Chat":         "Chat",
    "Channel":      "Chat",
    "Mail":         "Mail",
    "Auction":      "Auction",
    "AuctionHouse": "Auction",
    "Party":        "Group",
    "Group":        "Group",
    "Raid":         "Group",
    "Player":       "Player",
    "Character":    "Player",
    "Unit":         "Unit",
    "Creature":     "Creature",
    "NPC":          "Creature",
    "Pet":          "Pet",
    "BattlePet":    "BattlePet",
    "Gossip":       "Gossip",
    "Vehicle":      "Vehicle",
    "Transport":    "Transport",
    "Movement":     "Movement",
    "Move":         "Movement",
    "Path":         "Movement",
    "Map":          "Map",
    "Zone":         "Map",
    "Area":         "Map",
    "Instance":     "Instance",
    "Scenario":     "Scenario",
    "Phase":        "Phase",
    "Talent":       "Talent",
    "Spec":         "Talent",
    "Glyph":        "Talent",
    "Achievement":  "Achievement",
    "Criteria":     "Achievement",
    "PvP":          "PvP",
    "Arena":        "PvP",
    "BG":           "PvP",
    "Battleground": "PvP",
    "Honor":        "PvP",
    "Garrison":     "Garrison",
    "Follower":     "Garrison",
    "Mission":      "Garrison",
    "Shipment":     "Garrison",
    "Calendar":     "Calendar",
    "Transmog":     "Transmog",
    "Appearance":   "Transmog",
    "Wardrobe":     "Transmog",
    "Collection":   "Collection",
    "Mount":        "Collection",
    "Toy":          "Collection",
    "Heirloom":     "Collection",
    "Trade":        "Profession",
    "Profession":   "Profession",
    "Craft":        "Profession",
    "Recipe":       "Profession",
    "Trainer":      "Profession",
    "Bank":         "Bank",
    "Void":         "VoidStorage",
    "VoidStorage":  "VoidStorage",
    "World":        "World",
    "Obj":          "ObjectMgr",
    "Object":       "ObjectMgr",
    "DB":           "Database",
    "Script":       "Scripting",
    "Event":        "Event",
    "Timer":        "Timer",
    "Network":      "Network",
    "Packet":       "Network",
    "Opcode":       "Network",
    "Auth":         "Auth",
    "Login":        "Auth",
    "Account":      "Auth",
    "Housing":      "Housing",
    "House":        "Housing",
    "Decor":        "Housing",
    "Neighborhood": "Housing",
    "Plot":         "Housing",
    "Steward":      "Housing",
    "Warband":      "Warband",
    "Delve":        "Delve",
    "Delves":       "Delve",
    "Flight":       "Flight",
    "Taxi":         "Flight",
    "Skill":        "Skill",
    "Social":       "Social",
    "Friend":       "Social",
    "Ignore":       "Social",
    "Warden":       "AntiCheat",
    "Hack":         "AntiCheat",
    "Cheat":        "AntiCheat",
    "Debug":        "Debug",
    "Console":      "Debug",
    "Test":         "Debug",
    "Memory":       "Memory",
    "Alloc":        "Memory",
    "Pool":         "Memory",
    "Thread":       "Threading",
    "Lock":         "Threading",
    "Mutex":        "Threading",
    "Render":       "Rendering",
    "Gx":           "Rendering",
    "GxApi":        "Rendering",
    "Texture":      "Rendering",
    "Model":        "Rendering",
    "Sound":        "Sound",
    "Audio":        "Sound",
    "Animation":    "Animation",
    "Anim":         "Animation",
    "UI":           "UI",
    "Frame":        "UI",
    "Widget":       "UI",
    "Layout":       "UI",
    "Lua":          "Lua",
    "Script":       "Lua",
    "FrameScript":  "Lua",
    "Battle.net":   "BattleNet",
    "Bnet":         "BattleNet",
    "Store":        "Store",
    "Shop":         "Store",
    "Cinematic":    "Cinematic",
    "Movie":        "Cinematic",
    "Camera":       "Camera",
    "Weather":      "Weather",
    "AI":           "AI",
    "Pathfind":     "AI",
    "Waypoint":     "AI",
}


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

CONFIDENCE_DIRECT_NAME = 95      # "CClassName::MethodName" in string
CONFIDENCE_ASSERT_CLASS = 90     # Assert with class::method context
CONFIDENCE_FILE_PATH = 85        # __FILE__ macro with path
CONFIDENCE_ERROR_CONTEXT = 70    # "Error in CClassName::Method"
CONFIDENCE_BRACKET_PREFIX = 65   # "[System] error message"
CONFIDENCE_COLON_PREFIX = 60     # "System: error message"
CONFIDENCE_FORMAT_INFERRED = 50  # Inferred from format string analysis
CONFIDENCE_FAILED_TO = 45       # "Failed to do something"
CONFIDENCE_VARIABLE_HINT = 40   # "Invalid paramName"
CONFIDENCE_NEIGHBORHOOD = 35    # Inferred from string co-reference


# ---------------------------------------------------------------------------
# Core analysis functions
# ---------------------------------------------------------------------------

def analyze_string_intelligence(session):
    """Main entry point: mine strings from the binary for intelligence.

    Scans all referenced strings, extracts naming information from assert/error
    patterns, detects system boundaries, recovers variable names, and builds
    function neighborhoods from shared string references.

    Args:
        session: PluginSession with db and cfg attributes.

    Returns:
        int: Total number of name recoveries made.
    """
    db = session.db
    start_time = time.time()

    msg_info("Starting string intelligence analysis...")

    # Phase 1: Scan all strings and build xref map
    msg_info("Phase 1: Scanning binary strings...")
    string_catalog, xref_map = _scan_all_strings()

    total_strings = len(string_catalog)
    total_xrefs = sum(len(v) for v in xref_map.values())
    msg_info(f"  Found {total_strings} strings with {total_xrefs} cross-references")

    # Phase 2: Mine assert/error strings for direct name recovery
    msg_info("Phase 2: Mining assert/error strings for names...")
    recovered_names = _mine_name_patterns(string_catalog, xref_map)
    msg_info(f"  Recovered {len(recovered_names)} function/method names")

    # Phase 3: Detect system boundaries from string prefixes
    msg_info("Phase 3: Detecting system boundaries...")
    system_boundaries = _detect_system_boundaries(string_catalog, xref_map)
    msg_info(f"  Identified {len(system_boundaries)} system groups")

    # Phase 4: Recover variable names from format strings
    msg_info("Phase 4: Recovering variable names...")
    variable_hints = _recover_variable_names(string_catalog, xref_map)
    msg_info(f"  Found {len(variable_hints)} variable name hints")

    # Phase 5: Extract source file paths
    msg_info("Phase 5: Extracting source file paths...")
    source_paths = _extract_source_paths(string_catalog, xref_map)
    msg_info(f"  Extracted {len(source_paths)} source file paths")

    # Phase 6: Build string neighborhoods (co-reference clusters)
    msg_info("Phase 6: Building string neighborhoods...")
    neighborhoods = _build_string_neighborhoods(xref_map, string_catalog)
    msg_info(f"  Found {len(neighborhoods)} function clusters")

    # Phase 7: Merge variable hints into recovered names
    for vh in variable_hints:
        recovered_names.append({
            "ea": vh["ea"],
            "suggested_name": vh.get("suggested_name", ""),
            "source_string": vh["source_string"],
            "confidence": vh["confidence"],
            "category": "variable_hint",
            "variable_name": vh.get("variable_name", ""),
            "variable_role": vh.get("variable_role", ""),
        })

    # Compile final results
    results = {
        "recovered_names": recovered_names,
        "system_boundaries": system_boundaries,
        "source_paths": source_paths,
        "string_neighborhoods": neighborhoods,
        "total_strings_scanned": total_strings,
        "total_names_recovered": len(recovered_names),
        "total_systems_identified": len(system_boundaries),
        "analysis_time_seconds": round(time.time() - start_time, 2),
    }

    # Store in KV database
    db.kv_set("string_intelligence", results)
    db.commit()

    elapsed = time.time() - start_time
    msg_info(f"String intelligence analysis complete in {elapsed:.1f}s")
    msg_info(f"  Strings scanned:    {total_strings}")
    msg_info(f"  Names recovered:    {len(recovered_names)}")
    msg_info(f"  Systems identified: {len(system_boundaries)}")
    msg_info(f"  Source paths:       {len(source_paths)}")
    msg_info(f"  Neighborhoods:      {len(neighborhoods)}")

    # Log top systems by function count
    if system_boundaries:
        top_systems = sorted(system_boundaries,
                             key=lambda s: s["function_count"], reverse=True)[:15]
        msg_info("  Top systems by function coverage:")
        for sb in top_systems:
            msg(f"    {sb['system_name']:20s}  {sb['function_count']:5d} functions  "
                f"({sb['prefix']})")

    return len(recovered_names)


def get_string_intelligence(session):
    """Retrieve previously computed string intelligence data.

    Args:
        session: PluginSession with db attribute.

    Returns:
        dict: The stored string intelligence results, or empty dict.
    """
    return session.db.kv_get("string_intelligence") or {}


# ---------------------------------------------------------------------------
# Phase 1: String scanning
# ---------------------------------------------------------------------------

def _scan_all_strings():
    """Scan the binary for all strings and build a cross-reference map.

    Returns:
        tuple: (string_catalog, xref_map)
            string_catalog: dict mapping string_ea → string_value
            xref_map: dict mapping string_ea → list of referring function EAs
    """
    string_catalog = {}
    xref_map = defaultdict(list)

    sc = idautils.Strings()
    sc.setup(strtypes=[
        ida_nalt.STRTYPE_C,
        ida_nalt.STRTYPE_C_16,
    ], minlen=4)

    for s in sc:
        str_ea = s.ea
        str_val = str(s)

        if not str_val or len(str_val) < 4:
            continue

        # Skip strings that are purely numeric or whitespace
        stripped = str_val.strip()
        if not stripped:
            continue

        # Skip strings that look like pure data (all hex, all digits)
        if re.match(r'^[0-9A-Fa-f\s]+$', stripped) and len(stripped) < 20:
            continue

        string_catalog[str_ea] = str_val

        # Find all code references to this string
        for xref_ea in idautils.DataRefsTo(str_ea):
            func = ida_funcs.get_func(xref_ea)
            if func:
                func_ea = func.start_ea
                if func_ea not in xref_map[str_ea]:
                    xref_map[str_ea].append(func_ea)
            else:
                # The xref might be from a data segment (e.g., a pointer table)
                # Follow one more level of indirection
                for xref2_ea in idautils.DataRefsTo(xref_ea):
                    func2 = ida_funcs.get_func(xref2_ea)
                    if func2:
                        func_ea2 = func2.start_ea
                        if func_ea2 not in xref_map[str_ea]:
                            xref_map[str_ea].append(func_ea2)

    return string_catalog, dict(xref_map)


# ---------------------------------------------------------------------------
# Phase 2: Name recovery from assert/error patterns
# ---------------------------------------------------------------------------

def _mine_name_patterns(string_catalog, xref_map):
    """Extract function and class names from strings.

    Scans for patterns like:
      - "CClassName::MethodName" → direct name
      - ASSERT(...) with class context
      - "Error in X::Y" patterns
      - WoWAssert / WoWError calls

    Returns:
        list: Recovery records with ea, suggested_name, confidence, etc.
    """
    recovered = []
    seen_ea_name = set()  # (ea, name) to deduplicate

    for str_ea, str_val in string_catalog.items():
        referring_funcs = xref_map.get(str_ea, [])
        if not referring_funcs:
            continue

        # Strategy 1: Direct CClassName::MethodName patterns
        for m in _RE_CLASS_METHOD.finditer(str_val):
            class_name = m.group(1)
            method_name = m.group(2)
            full_name = f"{class_name}::{method_name}"

            # Determine confidence based on context
            confidence = CONFIDENCE_DIRECT_NAME
            category = "direct_name"

            # If the string is inside an assert, boost confidence
            if _RE_ASSERT.search(str_val):
                confidence = CONFIDENCE_ASSERT_CLASS
                category = "assert_name"

            for func_ea in referring_funcs:
                key = (func_ea, full_name)
                if key in seen_ea_name:
                    continue
                seen_ea_name.add(key)

                current_name = ida_name.get_name(func_ea)
                # Only suggest if function is unnamed or auto-named
                if current_name and not current_name.startswith("sub_"):
                    # Still record but lower confidence (name already set)
                    confidence = min(confidence, 50)

                recovered.append({
                    "ea": func_ea,
                    "suggested_name": full_name,
                    "source_string": str_val[:200],
                    "confidence": confidence,
                    "category": category,
                    "class_name": class_name,
                    "method_name": method_name,
                })

        # Strategy 2: Dotted class.method patterns (Lua-style)
        for m in _RE_DOT_METHOD.finditer(str_val):
            class_name = m.group(1)
            method_name = m.group(2)
            full_name = f"{class_name}_{method_name}"

            # Lower confidence for dot notation (could be Lua API, not C++)
            confidence = CONFIDENCE_FORMAT_INFERRED

            for func_ea in referring_funcs:
                key = (func_ea, full_name)
                if key in seen_ea_name:
                    continue
                seen_ea_name.add(key)

                recovered.append({
                    "ea": func_ea,
                    "suggested_name": full_name,
                    "source_string": str_val[:200],
                    "confidence": confidence,
                    "category": "dot_method",
                    "class_name": class_name,
                    "method_name": method_name,
                })

        # Strategy 3: Error/warning call patterns
        err_match = _RE_ERROR_CALL.search(str_val)
        if err_match:
            err_msg = err_match.group(1)
            names_from_err = _extract_names_from_error_msg(err_msg)
            for name_info in names_from_err:
                for func_ea in referring_funcs:
                    key = (func_ea, name_info["name"])
                    if key in seen_ea_name:
                        continue
                    seen_ea_name.add(key)

                    recovered.append({
                        "ea": func_ea,
                        "suggested_name": name_info["name"],
                        "source_string": str_val[:200],
                        "confidence": name_info["confidence"],
                        "category": "error_context",
                    })

        # Strategy 4: "Failed to X" / "Cannot X" → function purpose
        for pattern, conf in [(_RE_FAILED_TO, CONFIDENCE_FAILED_TO),
                              (_RE_CANNOT, CONFIDENCE_FAILED_TO)]:
            m = pattern.search(str_val)
            if m:
                action = m.group(1).strip()
                # Convert "load player data" → "LoadPlayerData"
                suggested = _action_to_func_name(action)
                if suggested and len(suggested) >= 6:
                    for func_ea in referring_funcs:
                        key = (func_ea, suggested)
                        if key in seen_ea_name:
                            continue
                        seen_ea_name.add(key)

                        recovered.append({
                            "ea": func_ea,
                            "suggested_name": suggested,
                            "source_string": str_val[:200],
                            "confidence": conf,
                            "category": "action_inference",
                        })

        # Strategy 5: Assert condition analysis
        assert_match = _RE_ASSERT.search(str_val)
        if assert_match:
            condition = assert_match.group(1)
            # Look for class::method in the condition or surrounding text
            cm_in_assert = _RE_CLASS_METHOD.search(condition)
            if cm_in_assert:
                full_name = f"{cm_in_assert.group(1)}::{cm_in_assert.group(2)}"
                for func_ea in referring_funcs:
                    key = (func_ea, full_name)
                    if key in seen_ea_name:
                        continue
                    seen_ea_name.add(key)

                    recovered.append({
                        "ea": func_ea,
                        "suggested_name": full_name,
                        "source_string": str_val[:200],
                        "confidence": CONFIDENCE_ASSERT_CLASS,
                        "category": "assert_condition",
                        "assert_condition": condition[:120],
                    })

    return recovered


def _extract_names_from_error_msg(error_msg):
    """Parse an error message string for embedded class/method names.

    Handles patterns like:
      "Error in CSpellBook::LearnSpell"
      "CUnit::Attack failed"
      "CPlayer::LoadFromDB: invalid data"

    Returns:
        list of dict: [{name, confidence}, ...]
    """
    results = []

    # Direct class::method in error
    for m in _RE_CLASS_METHOD.finditer(error_msg):
        results.append({
            "name": f"{m.group(1)}::{m.group(2)}",
            "confidence": CONFIDENCE_ERROR_CONTEXT,
        })

    return results


def _action_to_func_name(action):
    """Convert an action phrase to a PascalCase function name.

    "load player data" → "LoadPlayerData"
    "create guild bank tab" → "CreateGuildBankTab"
    """
    # Clean up the action string
    action = action.strip().rstrip('.')
    words = re.split(r'[\s_\-]+', action)
    words = [w for w in words if w and len(w) < 30]

    if not words or len(words) > 8:
        return None

    # PascalCase
    result = ''.join(w.capitalize() for w in words)

    # Validate: must look like a plausible function name
    if not re.match(r'^[A-Z][A-Za-z0-9]+$', result):
        return None

    return result


# ---------------------------------------------------------------------------
# Phase 3: System boundary detection
# ---------------------------------------------------------------------------

def _detect_system_boundaries(string_catalog, xref_map):
    """Group functions by the system-prefix of their referenced strings.

    Examines string prefixes like "Quest:", "[Spell]", "Guild_" etc.
    Functions that reference strings from the same prefix group are assumed
    to belong to the same game system.

    Returns:
        list of dict: System boundary records.
    """
    # Map each function to the system prefixes it references
    func_systems = defaultdict(lambda: defaultdict(int))
    system_functions = defaultdict(set)
    system_strings = defaultdict(list)

    for str_ea, str_val in string_catalog.items():
        referring_funcs = xref_map.get(str_ea, [])
        if not referring_funcs:
            continue

        # Try to classify this string's system
        system = _classify_string_system(str_val)
        if not system:
            continue

        for func_ea in referring_funcs:
            func_systems[func_ea][system] += 1
            system_functions[system].add(func_ea)

        # Keep a sample of strings per system (up to 20)
        if len(system_strings[system]) < 20:
            system_strings[system].append(str_val[:120])

    # Build system boundary records
    boundaries = []
    for system, func_eas in sorted(system_functions.items(),
                                    key=lambda x: len(x[1]), reverse=True):
        if len(func_eas) < 2:
            continue

        # Find the most common prefix for this system
        prefix = _find_dominant_prefix(system, system_strings.get(system, []))

        boundaries.append({
            "system_name": system,
            "prefix": prefix,
            "function_count": len(func_eas),
            "function_eas": sorted(func_eas)[:500],  # cap for storage
            "sample_strings": system_strings.get(system, [])[:10],
        })

    return boundaries


def _classify_string_system(str_val):
    """Determine which game system a string belongs to based on prefixes.

    Returns:
        str or None: System name, or None if unclassifiable.
    """
    # Strategy 1: Bracketed prefix [System]
    m = _RE_BRACKET_PREFIX.match(str_val)
    if m:
        prefix = m.group(1)
        system = SYSTEM_PREFIX_MAP.get(prefix)
        if system:
            return system
        # If not in map but looks like a system name, use it directly
        if len(prefix) >= 3 and prefix[0].isupper():
            return prefix

    # Strategy 2: Colon-delimited prefix "System: ..."
    m = _RE_COLON_PREFIX.match(str_val)
    if m:
        prefix = m.group(1)
        system = SYSTEM_PREFIX_MAP.get(prefix)
        if system:
            return system

    # Strategy 3: Class::Method in the string
    m = _RE_CLASS_METHOD.search(str_val)
    if m:
        class_name = m.group(1)
        # Strip common prefixes to get system
        clean = class_name
        for strip_prefix in ("C", "CG", "CGObj", "Obj"):
            if clean.startswith(strip_prefix) and len(clean) > len(strip_prefix) + 2:
                candidate = clean[len(strip_prefix):]
                if candidate[0].isupper():
                    clean = candidate
                    break

        # Try to map to a known system
        system = SYSTEM_PREFIX_MAP.get(clean)
        if system:
            return system

        # Use the class name itself as the system
        return clean

    # Strategy 4: Known keyword anywhere in the string (lower priority)
    str_upper = str_val.upper()
    for keyword, system in _KEYWORD_SYSTEM_MAP.items():
        if keyword in str_upper:
            return system

    return None


# Keyword → system for fallback classification (case-insensitive match)
_KEYWORD_SYSTEM_MAP = {
    "SPELL_AURA":       "Spell",
    "SPELL_EFFECT":     "Spell",
    "SPELLCAST":        "Spell",
    "QUEST_STATUS":     "Quest",
    "QUEST_OBJECTIVE":  "Quest",
    "ITEM_TEMPLATE":    "Item",
    "ITEM_INSTANCE":    "Item",
    "GUILD_BANK":       "Guild",
    "GUILD_RANK":       "Guild",
    "BATTLEGROUND":     "PvP",
    "RATED_PVP":        "PvP",
    "ARENA_TEAM":       "PvP",
    "CREATURE_AI":      "AI",
    "SMARTSCRIPT":      "AI",
    "WAYPOINT":         "AI",
    "GARRISON_":        "Garrison",
    "ACHIEVEMENT_":     "Achievement",
    "CALENDAR_":        "Calendar",
    "AUCTION_HOUSE":    "Auction",
    "GAME_OBJECT":      "GameObject",
    "TRANSPORT":        "Transport",
    "VEHICLE_SEAT":     "Vehicle",
    "VOID_STORAGE":     "VoidStorage",
    "BATTLE_PET":       "BattlePet",
    "TRANSMOG":         "Transmog",
    "HOUSING":          "Housing",
    "NEIGHBORHOOD":     "Housing",
    "WARBAND":          "Warband",
    "MYTHIC_PLUS":      "MythicPlus",
    "WORLD_QUEST":      "WorldQuest",
    "MAP_DIFFICULTY":   "Instance",
    "LFG_":             "LFG",
    "DUNGEON_FINDER":   "LFG",
}


def _find_dominant_prefix(system, sample_strings):
    """Find the most common prefix pattern for a system's strings.

    Returns the most frequently occurring prefix form.
    """
    prefix_counts = defaultdict(int)

    for s in sample_strings:
        # Try bracketed
        m = _RE_BRACKET_PREFIX.match(s)
        if m:
            prefix_counts[f"[{m.group(1)}]"] += 1
            continue

        # Try colon
        m = _RE_COLON_PREFIX.match(s)
        if m:
            prefix_counts[f"{m.group(1)}:"] += 1
            continue

        # Try class::method
        m = _RE_CLASS_METHOD.search(s)
        if m:
            prefix_counts[f"{m.group(1)}::"] += 1
            continue

    if prefix_counts:
        return max(prefix_counts, key=prefix_counts.get)
    return system


# ---------------------------------------------------------------------------
# Phase 4: Variable name recovery
# ---------------------------------------------------------------------------

def _recover_variable_names(string_catalog, xref_map):
    """Infer variable names from format strings and error messages.

    Patterns:
      - "Invalid spellId" → variable is probably named spellId
      - "Player %s not found" → function does player lookup
      - "questId = %d" → parameter named questId
      - "Invalid %s ID" → parameter is some kind of ID

    Returns:
        list of dict: Variable hint records.
    """
    hints = []
    seen = set()

    for str_ea, str_val in string_catalog.items():
        referring_funcs = xref_map.get(str_ea, [])
        if not referring_funcs:
            continue

        # Pattern 1: "Invalid X" / "Unknown X" / "Bad X"
        for m in _RE_INVALID_PARAM.finditer(str_val):
            var_name = m.group(1)
            if _is_plausible_variable_name(var_name):
                for func_ea in referring_funcs:
                    key = (func_ea, var_name, "invalid")
                    if key in seen:
                        continue
                    seen.add(key)

                    hints.append({
                        "ea": func_ea,
                        "variable_name": var_name,
                        "variable_role": "validated_parameter",
                        "source_string": str_val[:200],
                        "confidence": CONFIDENCE_VARIABLE_HINT,
                        "suggested_name": "",
                    })

        # Pattern 2: "X not found" / "X is null"
        for m in _RE_NOT_FOUND.finditer(str_val):
            var_name = m.group(1)
            if _is_plausible_variable_name(var_name):
                for func_ea in referring_funcs:
                    key = (func_ea, var_name, "not_found")
                    if key in seen:
                        continue
                    seen.add(key)

                    hints.append({
                        "ea": func_ea,
                        "variable_name": var_name,
                        "variable_role": "lookup_target",
                        "source_string": str_val[:200],
                        "confidence": CONFIDENCE_VARIABLE_HINT,
                        "suggested_name": "",
                    })

        # Pattern 3: "X ID" patterns
        for m in _RE_ID_PARAM.finditer(str_val):
            entity_name = m.group(1)
            var_name = f"{entity_name.lower()}Id"
            if len(entity_name) >= 3:
                for func_ea in referring_funcs:
                    key = (func_ea, var_name, "id_param")
                    if key in seen:
                        continue
                    seen.add(key)

                    hints.append({
                        "ea": func_ea,
                        "variable_name": var_name,
                        "variable_role": "id_parameter",
                        "source_string": str_val[:200],
                        "confidence": CONFIDENCE_VARIABLE_HINT + 5,
                        "suggested_name": "",
                    })

        # Pattern 4: "name = %d" / "name: %d" assignment-like patterns
        for m in _RE_ENUM_PARAM.finditer(str_val):
            var_name = m.group(1)
            if _is_plausible_variable_name(var_name):
                for func_ea in referring_funcs:
                    key = (func_ea, var_name, "enum_param")
                    if key in seen:
                        continue
                    seen.add(key)

                    hints.append({
                        "ea": func_ea,
                        "variable_name": var_name,
                        "variable_role": "enum_or_state",
                        "source_string": str_val[:200],
                        "confidence": CONFIDENCE_VARIABLE_HINT,
                        "suggested_name": "",
                    })

        # Pattern 5: Format string parameter count analysis
        fmt_params = _RE_FORMAT_PARAM.findall(str_val)
        if fmt_params and len(fmt_params) <= 8:
            # Extract meaningful words near format specifiers
            param_context = _analyze_format_string_params(str_val, fmt_params)
            for ctx in param_context:
                for func_ea in referring_funcs:
                    key = (func_ea, ctx["name"], "fmt")
                    if key in seen:
                        continue
                    seen.add(key)

                    hints.append({
                        "ea": func_ea,
                        "variable_name": ctx["name"],
                        "variable_role": ctx["role"],
                        "source_string": str_val[:200],
                        "confidence": CONFIDENCE_FORMAT_INFERRED - 10,
                        "suggested_name": "",
                    })

    return hints


def _is_plausible_variable_name(name):
    """Check if a string looks like a plausible C++ variable or type name."""
    if not name or len(name) < 3 or len(name) > 40:
        return False
    if not re.match(r'^[A-Za-z][A-Za-z0-9_]*$', name):
        return False
    # Exclude common English words that aren't variable names
    noise = {
        "the", "and", "for", "not", "this", "that", "with", "from",
        "has", "have", "was", "were", "are", "been", "being", "had",
        "does", "did", "will", "would", "could", "should", "may",
        "might", "must", "shall", "can", "need", "use", "set",
        "get", "put", "let", "run", "try", "see", "say", "got",
        "too", "also", "than", "then", "now", "here", "there",
        "when", "what", "where", "which", "who", "how", "why",
        "all", "any", "each", "every", "some", "many", "few",
        "more", "most", "other", "such", "only", "both", "own",
        "same", "new", "old", "first", "last", "next", "just",
        "Error", "Warning", "Debug", "Info", "error", "warning",
        "NULL", "null", "nil", "none", "true", "false", "True",
        "False", "None", "Yes", "yes", "No",
    }
    if name in noise:
        return False
    return True


def _analyze_format_string_params(str_val, fmt_params):
    """Analyze a format string to infer parameter names from context.

    Given "Player %s (GUID: %llu) has %d items", infers:
      param 0: "player_name" (string before %s)
      param 1: "guid" (preceded by "GUID:")
      param 2: "item_count" (preceded by "has", followed by "items")
    """
    results = []

    # Split the string around format specifiers
    parts = re.split(r'%[-+0 #]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[diouxXeEfFgGaAcspn]', str_val)

    for i, fmt in enumerate(fmt_params):
        if fmt == '%%':
            continue

        # Get the text before this format specifier
        prefix_text = parts[i].strip() if i < len(parts) else ""
        # Get the text after this format specifier
        suffix_text = parts[i + 1].strip() if (i + 1) < len(parts) else ""

        # Extract the last meaningful word from prefix
        prefix_words = re.findall(r'[A-Za-z][A-Za-z0-9_]+', prefix_text)
        suffix_words = re.findall(r'[A-Za-z][A-Za-z0-9_]+', suffix_text)

        name = None
        role = "format_param"

        if prefix_words:
            last_word = prefix_words[-1]
            if _is_plausible_variable_name(last_word):
                # Convert to camelCase variable name
                name = last_word[0].lower() + last_word[1:] if len(last_word) > 1 else last_word.lower()
                role = "named_parameter"

        if not name and suffix_words:
            first_word = suffix_words[0]
            if _is_plausible_variable_name(first_word):
                name = first_word[0].lower() + first_word[1:] if len(first_word) > 1 else first_word.lower()
                role = "contextual_parameter"

        if name:
            # Refine role based on format specifier type
            if 's' in fmt:
                role = "string_parameter"
            elif 'd' in fmt or 'i' in fmt or 'u' in fmt:
                role = "numeric_parameter"
            elif 'x' in fmt.lower():
                role = "hex_parameter"
            elif 'f' in fmt or 'e' in fmt.lower() or 'g' in fmt.lower():
                role = "float_parameter"

            results.append({"name": name, "role": role})

    return results


# ---------------------------------------------------------------------------
# Phase 5: Source file path extraction
# ---------------------------------------------------------------------------

def _extract_source_paths(string_catalog, xref_map):
    """Extract original source file paths from __FILE__ macro strings.

    Returns:
        list of dict: Source path records with associated functions.
    """
    path_functions = defaultdict(set)
    path_lines = defaultdict(set)

    for str_ea, str_val in string_catalog.items():
        referring_funcs = xref_map.get(str_ea, [])
        if not referring_funcs:
            continue

        # Try Windows-style paths
        for m in _RE_WINDOWS_PATH.finditer(str_val):
            path = m.group(0)
            path_norm = _normalize_source_path(path)
            if path_norm:
                for func_ea in referring_funcs:
                    path_functions[path_norm].add(func_ea)

                # Try to extract line number
                line_match = _RE_SOURCE_LINE.search(str_val)
                if line_match:
                    path_lines[path_norm].add(int(line_match.group(2)))

        # Try Unix-style paths
        for m in _RE_UNIX_PATH.finditer(str_val):
            path = m.group(0)
            path_norm = _normalize_source_path(path)
            if path_norm:
                for func_ea in referring_funcs:
                    path_functions[path_norm].add(func_ea)

                line_match = _RE_SOURCE_LINE.search(str_val)
                if line_match:
                    path_lines[path_norm].add(int(line_match.group(2)))

        # Also check for bare filename patterns like "SpellMgr.cpp:1234"
        for m in _RE_SOURCE_LINE.finditer(str_val):
            filename = m.group(1)
            line_no = int(m.group(2))
            # Validate this looks like a source file
            if _is_source_extension(filename):
                for func_ea in referring_funcs:
                    path_functions[filename].add(func_ea)
                path_lines[filename].add(line_no)

    # Build result records
    source_paths = []
    for path, func_eas in sorted(path_functions.items(),
                                  key=lambda x: len(x[1]), reverse=True):
        lines = sorted(path_lines.get(path, set()))
        source_paths.append({
            "path": path,
            "function_count": len(func_eas),
            "functions": sorted(func_eas)[:200],
            "known_lines": lines[:50],
            "directory": _extract_directory(path),
            "filename": _extract_filename(path),
        })

    return source_paths


def _normalize_source_path(path):
    """Normalize a source path for consistent grouping.

    Strips build machine prefixes and normalizes separators.
    """
    if not path:
        return None

    # Normalize separators to forward slash
    path = path.replace('\\', '/')

    # Strip common build machine prefixes
    # e.g., "C:/build/wow/Source/..." → "Source/..."
    # e.g., "/home/build/wow/Source/..." → "Source/..."
    strip_markers = [
        "/Source/",
        "/source/",
        "/src/",
        "/Src/",
        "/Code/",
        "/code/",
        "/Engine/",
        "/engine/",
        "/Client/",
        "/client/",
    ]
    for marker in strip_markers:
        idx = path.find(marker)
        if idx >= 0:
            return path[idx + 1:]  # keep the "Source/..." part

    # If no known marker, try to strip drive letter or leading /build/...
    # Keep everything after the last known directory separator
    parts = path.split('/')
    if len(parts) > 3:
        # Keep last 4 parts at most
        return '/'.join(parts[-4:])

    return path


def _is_source_extension(filename):
    """Check if a filename has a source code extension."""
    source_exts = {
        '.cpp', '.c', '.h', '.hpp', '.hxx', '.cxx', '.cc',
        '.inl', '.inc', '.lua', '.xml', '.toc',
    }
    for ext in source_exts:
        if filename.lower().endswith(ext):
            return True
    return False


def _extract_directory(path):
    """Extract the directory portion of a path."""
    path = path.replace('\\', '/')
    idx = path.rfind('/')
    if idx >= 0:
        return path[:idx]
    return ""


def _extract_filename(path):
    """Extract the filename from a path."""
    path = path.replace('\\', '/')
    idx = path.rfind('/')
    if idx >= 0:
        return path[idx + 1:]
    return path


# ---------------------------------------------------------------------------
# Phase 6: String neighborhood (co-reference clustering)
# ---------------------------------------------------------------------------

def _build_string_neighborhoods(xref_map, string_catalog):
    """Find clusters of functions that share many string references.

    The intuition: if functions A, B, and C all reference the same set of
    strings, they likely belong to the same subsystem or are closely related.

    Uses a Jaccard-like similarity on shared string references.

    Returns:
        list of dict: Neighborhood cluster records.
    """
    # Build reverse map: func_ea → set of string EAs
    func_strings = defaultdict(set)
    for str_ea, func_eas in xref_map.items():
        for func_ea in func_eas:
            func_strings[func_ea].add(str_ea)

    # Filter to functions with at least 3 string references (avoid noise)
    candidate_funcs = {
        ea: strs for ea, strs in func_strings.items()
        if len(strs) >= 3
    }

    if not candidate_funcs:
        return []

    # Build similarity graph via shared strings
    # For efficiency, we work with the string-to-functions direction
    # and only compute similarities for pairs that share at least 2 strings
    pair_shared = defaultdict(int)  # (ea1, ea2) → shared string count

    for str_ea, func_eas in xref_map.items():
        # Only consider functions in our candidate set
        filtered = [ea for ea in func_eas if ea in candidate_funcs]
        if len(filtered) < 2:
            continue

        # Record all pairs (use sorted tuple to deduplicate)
        for i in range(len(filtered)):
            for j in range(i + 1, len(filtered)):
                pair = (min(filtered[i], filtered[j]),
                        max(filtered[i], filtered[j]))
                pair_shared[pair] += 1

    # Cluster using a simple threshold-based approach
    # (Union-Find would be cleaner but this is sufficient)
    MIN_SHARED = 3
    adjacency = defaultdict(set)

    for (ea1, ea2), count in pair_shared.items():
        if count >= MIN_SHARED:
            # Compute Jaccard similarity
            set1 = candidate_funcs.get(ea1, set())
            set2 = candidate_funcs.get(ea2, set())
            if not set1 or not set2:
                continue
            jaccard = count / len(set1 | set2)
            if jaccard >= 0.15:  # reasonably related
                adjacency[ea1].add(ea2)
                adjacency[ea2].add(ea1)

    # Connected components via BFS
    visited = set()
    clusters = []

    for start_ea in adjacency:
        if start_ea in visited:
            continue

        cluster = set()
        queue = [start_ea]
        while queue:
            ea = queue.pop(0)
            if ea in visited:
                continue
            visited.add(ea)
            cluster.add(ea)
            for neighbor in adjacency.get(ea, set()):
                if neighbor not in visited:
                    queue.append(neighbor)

        if len(cluster) >= 2:
            clusters.append(cluster)

    # For each cluster, find the shared strings and derive a name
    neighborhoods = []
    for cluster in sorted(clusters, key=len, reverse=True)[:200]:
        # Find strings shared by at least half the cluster members
        shared_strs = []
        for str_ea in xref_map:
            refs = set(xref_map[str_ea])
            overlap = refs & cluster
            if len(overlap) >= max(2, len(cluster) // 2):
                str_val = string_catalog.get(str_ea, "")
                if str_val:
                    shared_strs.append(str_val[:100])

        # Try to name the cluster from its shared strings
        cluster_name = _name_cluster(shared_strs, cluster)

        neighborhoods.append({
            "cluster_name": cluster_name,
            "shared_strings": shared_strs[:15],
            "function_eas": sorted(cluster)[:100],
            "function_count": len(cluster),
            "shared_string_count": len(shared_strs),
        })

    return neighborhoods


def _name_cluster(shared_strings, func_eas):
    """Derive a descriptive name for a function cluster.

    Uses the most common class name or system prefix found in the shared
    strings.
    """
    # Count class names
    class_counts = defaultdict(int)
    system_counts = defaultdict(int)

    for s in shared_strings:
        # Class::Method patterns
        for m in _RE_CLASS_METHOD.finditer(s):
            class_counts[m.group(1)] += 1

        # System prefixes
        system = _classify_string_system(s)
        if system:
            system_counts[system] += 1

    # Prefer class name if found
    if class_counts:
        top_class = max(class_counts, key=class_counts.get)
        return f"{top_class}_cluster"

    # Fall back to system name
    if system_counts:
        top_system = max(system_counts, key=system_counts.get)
        return f"{top_system}_cluster"

    # Last resort: use function count
    return f"cluster_{len(func_eas)}funcs"


# ---------------------------------------------------------------------------
# Utility: Decompilation-based string extraction (for enrichment)
# ---------------------------------------------------------------------------

def enrich_function_from_strings(session, func_ea):
    """Enrich a single function's metadata by analyzing its string references.

    This is a per-function enrichment that can be called on demand (e.g.,
    from the UI when a user clicks on a function).

    Args:
        session: PluginSession
        func_ea: Function start address

    Returns:
        dict: Enrichment data for the function, or None if nothing found.
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    enrichment = {
        "ea": func_ea,
        "strings": [],
        "possible_names": [],
        "system_hints": [],
        "variable_hints": [],
        "source_file": None,
    }

    # Collect all string references from this function
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref_ea in idautils.DataRefsFrom(head):
            str_val = _get_string_at(ref_ea)
            if str_val and len(str_val) >= 4:
                enrichment["strings"].append({
                    "ea": ref_ea,
                    "value": str_val[:200],
                    "ref_from": head,
                })

                # Check for names
                for m in _RE_CLASS_METHOD.finditer(str_val):
                    enrichment["possible_names"].append({
                        "name": f"{m.group(1)}::{m.group(2)}",
                        "confidence": CONFIDENCE_DIRECT_NAME,
                        "source": str_val[:100],
                    })

                # Check for system hints
                system = _classify_string_system(str_val)
                if system and system not in enrichment["system_hints"]:
                    enrichment["system_hints"].append(system)

                # Check for source file paths
                for path_re in [_RE_WINDOWS_PATH, _RE_UNIX_PATH]:
                    pm = path_re.search(str_val)
                    if pm:
                        enrichment["source_file"] = _normalize_source_path(pm.group(0))
                        break

                # Check for variable hints
                for m in _RE_INVALID_PARAM.finditer(str_val):
                    var = m.group(1)
                    if _is_plausible_variable_name(var):
                        enrichment["variable_hints"].append(var)

    if not enrichment["strings"]:
        return None

    return enrichment


def _get_string_at(ea):
    """Try to read a string at the given address.

    Returns:
        str or None
    """
    str_type = idc.get_str_type(ea)
    if str_type is None or str_type < 0:
        return None

    s = idc.get_strlit_contents(ea, -1, str_type)
    if s is None:
        return None

    try:
        if isinstance(s, bytes):
            return s.decode('utf-8', errors='replace')
        return str(s)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Bulk rename helper
# ---------------------------------------------------------------------------

def apply_recovered_names(session, min_confidence=80, dry_run=True):
    """Apply recovered names to unnamed functions in the IDB.

    Only renames functions that are currently unnamed (sub_XXXXX) and have
    a high-confidence name recovery.

    Args:
        session: PluginSession
        min_confidence: Minimum confidence score to apply (default 80)
        dry_run: If True, only report what would be renamed (default True)

    Returns:
        int: Number of functions renamed (or would-be-renamed in dry run).
    """
    data = get_string_intelligence(session)
    if not data:
        msg_warn("No string intelligence data available. Run analysis first.")
        return 0

    recovered = data.get("recovered_names", [])
    if not recovered:
        msg_info("No recovered names found.")
        return 0

    # Sort by confidence (highest first) and deduplicate per EA
    sorted_names = sorted(recovered, key=lambda x: x.get("confidence", 0),
                          reverse=True)

    # Only keep the highest-confidence name per EA
    best_per_ea = {}
    for entry in sorted_names:
        ea = entry.get("ea")
        if ea is None:
            continue
        conf = entry.get("confidence", 0)
        if conf < min_confidence:
            continue
        if ea not in best_per_ea:
            best_per_ea[ea] = entry

    rename_count = 0

    for ea, entry in sorted(best_per_ea.items()):
        current = ida_name.get_name(ea)
        if current and not current.startswith("sub_"):
            continue  # already named

        suggested = entry["suggested_name"]
        confidence = entry["confidence"]

        # Sanitize the name for IDA
        safe_name = _sanitize_ida_name(suggested)
        if not safe_name:
            continue

        # Check for collisions
        existing_ea = ida_name.get_name_ea(idaapi.BADADDR, safe_name)
        if existing_ea != idaapi.BADADDR and existing_ea != ea:
            # Name collision — append address suffix
            safe_name = f"{safe_name}_{ea:X}"

        if dry_run:
            msg(f"  [DRY RUN] Would rename {ea_str(ea)} → {safe_name} "
                f"(confidence: {confidence})")
        else:
            if ida_name.set_name(ea, safe_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
                msg(f"  Renamed {ea_str(ea)} → {safe_name} (confidence: {confidence})")
            else:
                msg_warn(f"  Failed to rename {ea_str(ea)} → {safe_name}")
                continue

        rename_count += 1

    action = "Would rename" if dry_run else "Renamed"
    msg_info(f"{action} {rename_count} functions (min confidence: {min_confidence})")
    return rename_count


def _sanitize_ida_name(name):
    """Convert a name into a valid IDA name.

    - Replaces :: with _
    - Removes invalid characters
    - Ensures it starts with a letter or underscore
    """
    if not name:
        return None

    # Replace :: with _
    clean = name.replace("::", "_")

    # Replace other invalid chars
    clean = re.sub(r'[^A-Za-z0-9_]', '_', clean)

    # Collapse multiple underscores
    clean = re.sub(r'_+', '_', clean)

    # Strip leading/trailing underscores
    clean = clean.strip('_')

    # Must start with letter or underscore
    if clean and not clean[0].isalpha() and clean[0] != '_':
        clean = '_' + clean

    # Length limits
    if not clean or len(clean) < 3 or len(clean) > 200:
        return None

    return clean


# ---------------------------------------------------------------------------
# Source tree reconstruction
# ---------------------------------------------------------------------------

def get_source_tree(session):
    """Reconstruct the original WoW client source directory tree.

    Uses the source_paths extracted during analysis to build a hierarchical
    view of the original source code structure.

    Args:
        session: PluginSession

    Returns:
        dict: Nested directory tree with file counts.
    """
    data = get_string_intelligence(session)
    if not data:
        return {}

    source_paths = data.get("source_paths", [])
    if not source_paths:
        return {}

    tree = {}

    for sp in source_paths:
        path = sp.get("path", "")
        if not path:
            continue

        # Normalize to forward slashes
        path = path.replace('\\', '/')
        parts = path.split('/')

        node = tree
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                # Leaf (file)
                node[part] = {
                    "_type": "file",
                    "_function_count": sp.get("function_count", 0),
                    "_known_lines": sp.get("known_lines", []),
                }
            else:
                # Directory
                if part not in node:
                    node[part] = {}
                node = node[part]

    return tree


# ---------------------------------------------------------------------------
# Cross-system string sharing analysis
# ---------------------------------------------------------------------------

def analyze_cross_system_strings(session):
    """Find strings shared across multiple system boundaries.

    These are often utility functions, shared error paths, or common
    validation routines. Useful for identifying core infrastructure code
    versus system-specific code.

    Args:
        session: PluginSession

    Returns:
        list of dict: Shared string records with system membership.
    """
    data = get_string_intelligence(session)
    if not data:
        return []

    boundaries = data.get("system_boundaries", [])
    if not boundaries:
        return []

    # Build func → systems map
    func_to_systems = defaultdict(set)
    for sb in boundaries:
        system = sb["system_name"]
        for ea in sb.get("function_eas", []):
            func_to_systems[ea].add(system)

    # Find functions belonging to multiple systems
    cross_system = []
    for ea, systems in func_to_systems.items():
        if len(systems) >= 2:
            func_name = ida_name.get_name(ea) or ea_str(ea)
            cross_system.append({
                "ea": ea,
                "function_name": func_name,
                "systems": sorted(systems),
                "system_count": len(systems),
            })

    cross_system.sort(key=lambda x: x["system_count"], reverse=True)
    return cross_system[:500]


# ---------------------------------------------------------------------------
# Statistics and reporting
# ---------------------------------------------------------------------------

def get_string_intelligence_summary(session):
    """Generate a human-readable summary of string intelligence results.

    Args:
        session: PluginSession

    Returns:
        str: Formatted summary text.
    """
    data = get_string_intelligence(session)
    if not data:
        return "No string intelligence data available. Run analysis first."

    lines = []
    lines.append("=" * 70)
    lines.append("STRING INTELLIGENCE ANALYSIS SUMMARY")
    lines.append("=" * 70)
    lines.append("")

    lines.append(f"Total strings scanned:    {data.get('total_strings_scanned', 0):,}")
    lines.append(f"Names recovered:          {data.get('total_names_recovered', 0):,}")
    lines.append(f"Systems identified:       {data.get('total_systems_identified', 0):,}")
    lines.append(f"Analysis time:            {data.get('analysis_time_seconds', 0):.1f}s")
    lines.append("")

    # Name recovery breakdown by category
    recovered = data.get("recovered_names", [])
    if recovered:
        lines.append("NAME RECOVERY BREAKDOWN:")
        lines.append("-" * 40)
        cat_counts = defaultdict(int)
        for r in recovered:
            cat_counts[r.get("category", "unknown")] += 1
        for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {cat:30s}  {count:6,}")
        lines.append("")

    # Confidence distribution
    if recovered:
        lines.append("CONFIDENCE DISTRIBUTION:")
        lines.append("-" * 40)
        conf_buckets = defaultdict(int)
        for r in recovered:
            c = r.get("confidence", 0)
            bucket = (c // 10) * 10
            conf_buckets[bucket] += 1
        for bucket in sorted(conf_buckets.keys(), reverse=True):
            bar = "#" * (conf_buckets[bucket] // 5 + 1)
            lines.append(f"  {bucket:3d}-{bucket+9:3d}:  {conf_buckets[bucket]:6,}  {bar}")
        lines.append("")

    # System boundaries
    boundaries = data.get("system_boundaries", [])
    if boundaries:
        lines.append("SYSTEM BOUNDARIES (top 20):")
        lines.append("-" * 60)
        lines.append(f"  {'System':<25s}  {'Functions':>10s}  {'Prefix'}")
        lines.append(f"  {'------':<25s}  {'---------':>10s}  {'------'}")
        for sb in boundaries[:20]:
            lines.append(f"  {sb['system_name']:<25s}  "
                         f"{sb['function_count']:>10,}  "
                         f"{sb.get('prefix', '')}")
        lines.append("")

    # Source paths
    source_paths = data.get("source_paths", [])
    if source_paths:
        lines.append(f"SOURCE FILE PATHS ({len(source_paths)} total, top 20):")
        lines.append("-" * 60)
        for sp in source_paths[:20]:
            lines.append(f"  {sp['path']:<50s}  "
                         f"{sp['function_count']:>4} funcs")
        lines.append("")

    # Neighborhoods
    neighborhoods = data.get("string_neighborhoods", [])
    if neighborhoods:
        lines.append(f"STRING NEIGHBORHOODS ({len(neighborhoods)} clusters):")
        lines.append("-" * 60)
        for n in neighborhoods[:15]:
            lines.append(f"  {n['cluster_name']:<35s}  "
                         f"{n['function_count']:>4} funcs, "
                         f"{n['shared_string_count']:>3} shared strings")
        lines.append("")

    # High-confidence names (top 30)
    high_conf = [r for r in recovered if r.get("confidence", 0) >= 80]
    if high_conf:
        high_conf_sorted = sorted(high_conf, key=lambda x: x["confidence"], reverse=True)
        lines.append(f"TOP HIGH-CONFIDENCE NAME RECOVERIES ({len(high_conf)} total):")
        lines.append("-" * 70)
        for r in high_conf_sorted[:30]:
            ea_s = ea_str(r["ea"])
            name = r["suggested_name"]
            conf = r["confidence"]
            cat = r.get("category", "?")
            lines.append(f"  {ea_s}  {name:<40s}  conf={conf:3d}  [{cat}]")
        lines.append("")

    lines.append("=" * 70)
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Integration helpers
# ---------------------------------------------------------------------------

def get_function_strings(session, func_ea):
    """Get all strings referenced by a specific function.

    Useful for tooltips and annotations in the IDA UI.

    Args:
        session: PluginSession
        func_ea: Function start address

    Returns:
        list of str: String values referenced by the function.
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []

    strings = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref_ea in idautils.DataRefsFrom(head):
            str_val = _get_string_at(ref_ea)
            if str_val and len(str_val) >= 4:
                strings.append(str_val)

    return strings


def get_functions_referencing_string(session, search_text, case_sensitive=False):
    """Find all functions that reference a string containing the given text.

    Args:
        session: PluginSession
        search_text: Text to search for in strings
        case_sensitive: Whether to do case-sensitive matching

    Returns:
        list of dict: Matching records with function EA and string value.
    """
    results = []

    if not case_sensitive:
        search_lower = search_text.lower()

    sc = idautils.Strings()
    for s in sc:
        str_val = str(s)
        if not str_val:
            continue

        match = False
        if case_sensitive:
            match = search_text in str_val
        else:
            match = search_lower in str_val.lower()

        if not match:
            continue

        for xref_ea in idautils.DataRefsTo(s.ea):
            func = ida_funcs.get_func(xref_ea)
            if func:
                func_name = ida_name.get_name(func.start_ea) or ea_str(func.start_ea)
                results.append({
                    "func_ea": func.start_ea,
                    "func_name": func_name,
                    "string_ea": s.ea,
                    "string_value": str_val[:200],
                    "ref_ea": xref_ea,
                })

    return results


def get_system_functions(session, system_name):
    """Get all functions belonging to a given system.

    Args:
        session: PluginSession
        system_name: System name (e.g., "Spell", "Quest", "Housing")

    Returns:
        list of dict: Function records in the system.
    """
    data = get_string_intelligence(session)
    if not data:
        return []

    boundaries = data.get("system_boundaries", [])
    for sb in boundaries:
        if sb["system_name"].lower() == system_name.lower():
            funcs = []
            for ea in sb.get("function_eas", []):
                func_name = ida_name.get_name(ea) or ea_str(ea)
                funcs.append({
                    "ea": ea,
                    "name": func_name,
                })
            return funcs

    return []
