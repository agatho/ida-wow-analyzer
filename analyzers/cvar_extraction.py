"""
CVar (Console Variable) Extraction Analyzer
Extracts CVar definitions from the WoW x64 binary, including registration
patterns, default values, flags, descriptions, and change callbacks.

CVars control everything from graphics settings to gameplay behavior.  The
server-relevant subset (SERVER_SYNC, CHEAT_PROTECTED, movement, combat) is
critical for correct emulation and anti-cheat enforcement.

Strategy:
  1. String-based discovery -- find strings that match CVar naming conventions
     and trace xrefs back to registration call sites.
  2. CVar::Register pattern detection -- decompile registration call sites and
     parse the argument list: (name, defaultValue, flags, description, callback).
  3. Flag bitmask decoding -- classify each CVar by its flag bits.
  4. Callback analysis -- decompile change callbacks to understand side effects.
  5. Server relevance classification -- tag CVars that a server must handle.
  6. TC comparison -- cross-reference against TrinityCore source if available.
"""

import json
import re
import time

import ida_funcs
import ida_name
import ida_bytes
import idautils
import idaapi
import idc

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# CVar naming patterns
# ---------------------------------------------------------------------------

# CVar names are typically camelCase or UPPER_CASE with dotted or prefixed
# system qualifiers.  Examples: "spellQueueWindow", "maxFps",
# "SET chatStyle", "COMBAT_LOG_MAX_ENTRIES", "net.smoothing".
_RE_CVAR_NAME = re.compile(
    r'^[a-zA-Z][a-zA-Z0-9_.]*[a-zA-Z0-9]$'
)

# Known system prefixes for CVar names.  Used to classify discovered CVars
# into game systems even when the registration call lacks context.
CVAR_SYSTEM_PREFIXES = {
    "spell":        "Spell",
    "combat":       "Combat",
    "movement":     "Movement",
    "move":         "Movement",
    "net":          "Network",
    "network":      "Network",
    "world":        "World",
    "map":          "Map",
    "chat":         "Chat",
    "guild":        "Guild",
    "lfg":          "LFG",
    "dungeon":      "Dungeon",
    "raid":         "Raid",
    "pvp":          "PvP",
    "arena":        "PvP",
    "battleground": "PvP",
    "bg":           "PvP",
    "quest":        "Quest",
    "loot":         "Loot",
    "item":         "Item",
    "auction":      "AuctionHouse",
    "mail":         "Mail",
    "vehicle":      "Vehicle",
    "pet":          "Pet",
    "mount":        "Mount",
    "achievement":  "Achievement",
    "talent":       "Talent",
    "glyph":        "Talent",
    "camera":       "Camera",
    "sound":        "Sound",
    "music":        "Sound",
    "voice":        "Voice",
    "graphics":     "Graphics",
    "render":       "Graphics",
    "shadow":       "Graphics",
    "texture":      "Graphics",
    "shader":       "Graphics",
    "water":        "Graphics",
    "weather":      "Weather",
    "ui":           "UI",
    "interface":    "UI",
    "tooltip":      "UI",
    "nameplate":    "UI",
    "minimap":      "UI",
    "action":       "ActionBar",
    "bar":          "ActionBar",
    "group":        "Group",
    "party":        "Group",
    "trade":        "Trade",
    "craft":        "Crafting",
    "profession":   "Crafting",
    "garrison":     "Garrison",
    "delve":        "Delves",
    "mythic":       "MythicPlus",
    "keystone":     "MythicPlus",
    "housing":      "Housing",
    "neighborhood": "Housing",
    "warband":      "Warband",
    "flight":       "Flight",
    "taxi":         "Flight",
    "script":       "Scripting",
    "addon":        "Addon",
    "debug":        "Debug",
    "log":          "Logging",
    "test":         "Debug",
    "server":       "Server",
    "auth":         "Auth",
    "login":        "Auth",
    "character":    "Character",
    "player":       "Character",
    "npc":          "NPC",
    "creature":     "NPC",
    "object":       "Object",
    "aura":         "Spell",
    "effect":       "Spell",
    "cooldown":     "Spell",
    "gcd":          "Spell",
    "cast":         "Spell",
    "pathfind":     "Movement",
    "collision":    "Movement",
    "physics":      "Movement",
    "terrain":      "Map",
    "instance":     "Instance",
    "scenario":     "Instance",
    "warden":       "AntiCheat",
    "cheat":        "AntiCheat",
    "hack":         "AntiCheat",
    "ban":          "Moderation",
    "mute":         "Moderation",
    "report":       "Moderation",
    "social":       "Social",
    "friend":       "Social",
    "ignore":       "Social",
    "block":        "Social",
    "community":    "Community",
    "club":         "Community",
    "calendar":     "Calendar",
    "event":        "Calendar",
    "transmogrify": "Transmog",
    "transmog":     "Transmog",
    "wardrobe":     "Transmog",
    "collection":   "Collection",
    "toy":          "Collection",
    "heirloom":     "Collection",
    "cinematic":    "Cinematic",
    "cutscene":     "Cinematic",
}

# Known CVar flag bit definitions.  These are inferred from how the client
# checks the flags field; the actual bit positions may vary between builds
# but we start with the commonly observed layout.
CVAR_FLAGS = {
    0x00000001: "ARCHIVE",           # saved to config file
    0x00000002: "SERVER_SYNC",       # server must know this value
    0x00000004: "CHEAT_PROTECTED",   # GM-only / disabled in production
    0x00000008: "READ_ONLY",         # cannot be changed at runtime
    0x00000010: "HIDDEN",            # not shown in console autocomplete
    0x00000020: "PER_CHARACTER",     # stored per-character, not account
    0x00000040: "COMBAT_LOG",        # affects combat logging
    0x00000080: "NEEDS_RESTART",     # change requires client restart
    0x00000100: "ACCOUNT_SETTING",   # account-wide setting
    0x00000200: "SCRIPT_PROTECTED",  # cannot be changed by addons
    0x00000400: "NO_RESET",          # not reset on /console reset
    0x00000800: "LOADING_SCREEN",    # applied during loading screens
    0x00001000: "SESSION",           # valid for session only
    0x00002000: "SECURE",            # secure-mode only
    0x00004000: "SAVED",             # alternate persistent flag
    0x00008000: "WORLD_ONLY",        # only active while in world
}

# Regex for pulling CVar::Register arguments from decompiled pseudocode.
# The typical calling convention is:
#   CVar::Register(name, defaultVal, flags, description, callback, ...)
# But the actual decompiled form varies widely depending on inlining, register
# allocation, etc.  We try several patterns.

# Pattern 1: Direct string args visible in decompiled output
#   sub_XXX("cvarName", "defaultValue", 0x123, "Description", callback)
_RE_REGISTER_DIRECT = re.compile(
    r'"([a-zA-Z][a-zA-Z0-9_.]+)"'       # CVar name (group 1)
    r'\s*,\s*'
    r'"([^"]*)"'                          # default value (group 2)
    r'\s*,\s*'
    r'(0x[0-9A-Fa-f]+|\d+)'              # flags (group 3)
    r'(?:\s*,\s*"([^"]*)")?'             # description (group 4, optional)
    r'(?:\s*,\s*'
    r'(?:&?\s*)?(\w+|0x[0-9A-Fa-f]+|0)' # callback (group 5, optional)
    r')?',
    re.MULTILINE
)

# Pattern 2: Name + default as consecutive string references with a numeric
# between or after them (common when partially optimized)
_RE_NAME_DEFAULT_FLAGS = re.compile(
    r'"([a-zA-Z][a-zA-Z0-9_.]+)"'        # CVar name (group 1)
    r'.*?'
    r'"([^"]*)"'                           # default value (group 2)
    r'.*?'
    r'(0x[0-9A-Fa-f]+|\d+)[UuLl]*',       # flags (group 3)
    re.DOTALL
)

# Pattern 3: CVar name string near a numeric constant (minimal info)
_RE_NAME_ONLY = re.compile(
    r'"([a-zA-Z][a-zA-Z0-9_.]{2,60})"'
)

# Pattern for identifying callback function pointers in decompiled code
_RE_CALLBACK_PTR = re.compile(
    r'(?:callback|handler|pfn|func|notify)\w*\s*[=,]\s*'
    r'(?:&\s*)?(\w+)',
    re.IGNORECASE
)

# Heuristic: strings that are definitely NOT CVar names
_CVAR_NAME_BLACKLIST = {
    "true", "false", "yes", "no", "on", "off", "none", "null", "nil",
    "ok", "cancel", "default", "enabled", "disabled", "auto",
    "string", "float", "int", "bool", "double", "void", "char",
    "return", "break", "continue", "switch", "case", "while", "for",
    "class", "struct", "enum", "union", "typedef", "template",
    "public", "private", "protected", "virtual", "static", "const",
    "inline", "extern", "volatile", "register", "sizeof", "typeof",
}

# Minimum and maximum reasonable CVar name lengths
_CVAR_NAME_MIN_LEN = 3
_CVAR_NAME_MAX_LEN = 80

# Value type classification patterns
_RE_BOOL_VALUE = re.compile(r'^[01]$')
_RE_INT_VALUE = re.compile(r'^-?\d+$')
_RE_FLOAT_VALUE = re.compile(r'^-?\d+\.\d+$')
_RE_HEX_VALUE = re.compile(r'^0x[0-9A-Fa-f]+$')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_cvar_name(name):
    """Check if a string looks like a valid CVar name."""
    if not name or len(name) < _CVAR_NAME_MIN_LEN or len(name) > _CVAR_NAME_MAX_LEN:
        return False
    if name.lower() in _CVAR_NAME_BLACKLIST:
        return False
    if not _RE_CVAR_NAME.match(name):
        return False
    # Must contain at least one lowercase letter (excludes pure-uppercase
    # constants that are unlikely to be CVars) OR be a known pattern
    if not any(c.islower() for c in name) and "_" not in name:
        return False
    # Reject strings that look like file paths or URLs
    if "/" in name or "\\" in name or ":" in name:
        return False
    return True


def _classify_value_type(value_str):
    """Determine the type of a CVar default value string."""
    if value_str is None or value_str == "":
        return "string"
    if _RE_BOOL_VALUE.match(value_str):
        return "boolean"
    if _RE_INT_VALUE.match(value_str):
        return "integer"
    if _RE_FLOAT_VALUE.match(value_str):
        return "float"
    if _RE_HEX_VALUE.match(value_str):
        return "integer"
    return "string"


def _decode_flags(flags_int):
    """Decode a CVar flags bitmask into a list of flag names."""
    if flags_int is None:
        return []
    decoded = []
    for bit, name in sorted(CVAR_FLAGS.items()):
        if flags_int & bit:
            decoded.append(name)
    return decoded


def _classify_system(cvar_name):
    """Classify a CVar into a game system based on its name prefix."""
    name_lower = cvar_name.lower()
    # Try dotted prefix first: "net.smoothing" -> "net"
    if "." in name_lower:
        prefix = name_lower.split(".")[0]
        if prefix in CVAR_SYSTEM_PREFIXES:
            return CVAR_SYSTEM_PREFIXES[prefix]
    # Try camelCase prefix extraction
    # "spellQueueWindow" -> "spell"
    m = re.match(r'^([a-z]+)', name_lower)
    if m:
        prefix = m.group(1)
        if prefix in CVAR_SYSTEM_PREFIXES:
            return CVAR_SYSTEM_PREFIXES[prefix]
    # Try UPPER_CASE prefix: "COMBAT_LOG_MAX" -> "combat"
    m = re.match(r'^([A-Za-z]+)_', cvar_name)
    if m:
        prefix = m.group(1).lower()
        if prefix in CVAR_SYSTEM_PREFIXES:
            return CVAR_SYSTEM_PREFIXES[prefix]
    return "Unknown"


def _is_server_relevant(cvar_name, flags_decoded, system):
    """Determine if a CVar is relevant for server-side implementation."""
    # Explicit server-sync flag
    if "SERVER_SYNC" in flags_decoded:
        return True
    # Cheat-protected must be enforced server-side
    if "CHEAT_PROTECTED" in flags_decoded:
        return True
    # Certain systems are inherently server-relevant
    server_systems = {
        "Combat", "Spell", "Movement", "Network", "AntiCheat",
        "LFG", "Instance", "MythicPlus", "PvP", "Loot",
        "Quest", "AuctionHouse", "Trade", "Mail", "Guild",
        "Group", "Server", "Auth", "Character", "NPC",
        "Housing", "Warband",
    }
    if system in server_systems:
        return True
    # Movement-related names
    name_lower = cvar_name.lower()
    movement_keywords = {
        "speed", "jump", "fall", "swim", "fly", "gravity",
        "acceleration", "friction", "walk", "run", "mount",
        "collision", "pathfind", "teleport",
    }
    if any(kw in name_lower for kw in movement_keywords):
        return True
    # Network-related
    network_keywords = {
        "latency", "ping", "timeout", "bandwidth", "packet",
        "throttle", "queue", "sync", "replication",
    }
    if any(kw in name_lower for kw in network_keywords):
        return True
    return False


def _get_string_at(ea):
    """Read a C string at the given address, or return None."""
    s = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
    if s:
        try:
            return s.decode("utf-8", errors="replace")
        except Exception:
            return None
    return None


def _get_string_xrefs(string_ea):
    """Get all code/data cross-references TO a string address."""
    xrefs = []
    for xref in idautils.XrefsTo(string_ea, 0):
        xrefs.append(xref.frm)
    return xrefs


def _get_func_containing(ea):
    """Get the function that contains address ea, or None."""
    func = ida_funcs.get_func(ea)
    if func:
        return func.start_ea
    return None


def _parse_int_safe(s):
    """Parse an integer from a string, handling hex and decimal."""
    if s is None:
        return None
    s = s.strip().rstrip("UuLl")
    try:
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Phase 1: String-based CVar name discovery
# ---------------------------------------------------------------------------

def _discover_cvar_strings(session):
    """Scan all strings in the binary for potential CVar names.

    Returns a dict mapping CVar name -> list of (string_ea, referencing_func_ea).
    """
    msg_info("Phase 1: Scanning strings for CVar name candidates...")
    start = time.time()
    candidates = {}  # name -> [(string_ea, func_ea), ...]
    string_count = 0
    candidate_count = 0

    # Iterate all defined strings in the binary
    for s in idautils.Strings():
        string_count += 1
        val = str(s)
        if not val:
            continue

        # Quick length filter
        if len(val) < _CVAR_NAME_MIN_LEN or len(val) > _CVAR_NAME_MAX_LEN:
            continue

        # Check if it looks like a CVar name
        if not _is_valid_cvar_name(val):
            continue

        # Get xrefs to this string
        string_ea = s.ea
        xrefs = _get_string_xrefs(string_ea)
        if not xrefs:
            continue

        # Record each referencing function
        refs = []
        for xref_ea in xrefs:
            func_ea = _get_func_containing(xref_ea)
            if func_ea is not None:
                refs.append((string_ea, func_ea))

        if refs:
            if val not in candidates:
                candidates[val] = []
            candidates[val].extend(refs)
            candidate_count += 1

        # Progress reporting
        if string_count % 50000 == 0:
            msg(f"  Scanned {string_count} strings, {candidate_count} candidates...")

    elapsed = time.time() - start
    msg_info(f"  String scan complete: {string_count} strings scanned, "
             f"{candidate_count} CVar name candidates in {elapsed:.1f}s")
    return candidates


# ---------------------------------------------------------------------------
# Phase 2: CVar registration site analysis
# ---------------------------------------------------------------------------

def _find_cvar_register_functions(session):
    """Find functions that are likely CVar::Register or similar.

    Strategy: look for named functions containing "CVar", "ConsoleVar", or
    "Register" in their name.  Also look for functions that reference many
    CVar-like strings (bulk registration functions).

    Returns a set of function EAs.
    """
    msg_info("Phase 2a: Finding CVar registration functions...")
    register_funcs = set()

    # Strategy 1: Named functions
    cvar_name_patterns = [
        "CVar", "cvar", "ConsoleVar", "ConsoleVariable",
        "RegisterCVar", "RegisterConsoleVar", "CVar_Register",
        "CVar::Register", "CVar::Create",
    ]

    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if not name:
            continue
        name_lower = name.lower()
        for pattern in cvar_name_patterns:
            if pattern.lower() in name_lower:
                register_funcs.add(ea)
                break

    msg_info(f"  Found {len(register_funcs)} named CVar-related functions")

    # Strategy 2: Functions referencing "CVar" strings
    for s in idautils.Strings():
        val = str(s)
        if not val:
            continue
        # Look for strings like "CVar", "Console Variable", etc.
        if "CVar" in val or "ConsoleVar" in val or "Console Variable" in val:
            for xref in idautils.XrefsTo(s.ea, 0):
                func_ea = _get_func_containing(xref.frm)
                if func_ea is not None:
                    register_funcs.add(func_ea)

    msg_info(f"  Total CVar-related functions after string search: {len(register_funcs)}")
    return register_funcs


def _find_bulk_registration_functions(candidates):
    """Find functions that register many CVars (bulk registrars).

    These are functions that reference 10+ CVar name strings and are likely
    the top-level initialization functions like CVar::RegisterDefaults.

    Returns a set of function EAs with their referenced CVar names.
    """
    msg_info("Phase 2b: Finding bulk CVar registration functions...")
    # Count how many CVar candidates each function references
    func_cvar_counts = {}  # func_ea -> set of cvar names
    for name, refs in candidates.items():
        for string_ea, func_ea in refs:
            if func_ea not in func_cvar_counts:
                func_cvar_counts[func_ea] = set()
            func_cvar_counts[func_ea].add(name)

    bulk_funcs = {}
    for func_ea, names in func_cvar_counts.items():
        if len(names) >= 5:
            bulk_funcs[func_ea] = names
            func_name = ida_name.get_name(func_ea) or ea_str(func_ea)
            msg(f"  Bulk registrar: {func_name} references {len(names)} CVars")

    msg_info(f"  Found {len(bulk_funcs)} bulk registration functions")
    return bulk_funcs


# ---------------------------------------------------------------------------
# Phase 3: Decompile registration sites and extract CVar details
# ---------------------------------------------------------------------------

def _extract_cvar_from_decompiled(pseudocode, cvar_name, func_ea):
    """Extract CVar registration details from decompiled pseudocode.

    Looks for the CVar name string in the pseudocode and tries to extract
    surrounding arguments (default value, flags, description, callback).

    Returns a dict with extracted fields, or None if nothing useful found.
    """
    if not pseudocode or cvar_name not in pseudocode:
        return None

    result = {
        "name": cvar_name,
        "default_value": None,
        "value_type": "string",
        "flags": None,
        "flags_decoded": [],
        "description": None,
        "callback_ea": None,
        "callback_analysis": None,
        "system": _classify_system(cvar_name),
        "server_relevant": False,
        "tc_has_equivalent": False,
        "registration_func_ea": func_ea,
        "extraction_method": "decompiled",
    }

    # Try Pattern 1: direct string args
    # Find the line(s) containing the CVar name
    for m in _RE_REGISTER_DIRECT.finditer(pseudocode):
        if m.group(1) == cvar_name:
            result["default_value"] = m.group(2)
            flags_int = _parse_int_safe(m.group(3))
            result["flags"] = flags_int
            result["flags_decoded"] = _decode_flags(flags_int)
            if m.group(4):
                result["description"] = m.group(4)
            if m.group(5):
                cb = m.group(5)
                if cb != "0" and cb != "0x0":
                    cb_int = _parse_int_safe(cb)
                    if cb_int:
                        result["callback_ea"] = cb_int
                    else:
                        # It's a symbol name; try to resolve
                        cb_ea = ida_name.get_name_ea(idaapi.BADADDR, cb)
                        if cb_ea != idaapi.BADADDR:
                            result["callback_ea"] = cb_ea
            result["value_type"] = _classify_value_type(result["default_value"])
            result["extraction_method"] = "decompiled_pattern1"
            return result

    # Try Pattern 2: name + default + flags nearby
    # Search for the cvar name and then scan forward for a default value
    name_idx = pseudocode.find(f'"{cvar_name}"')
    if name_idx >= 0:
        # Get a window of text after the name string
        window = pseudocode[name_idx:name_idx + 500]
        m = _RE_NAME_DEFAULT_FLAGS.match(window)
        if m and m.group(1) == cvar_name:
            result["default_value"] = m.group(2)
            flags_int = _parse_int_safe(m.group(3))
            result["flags"] = flags_int
            result["flags_decoded"] = _decode_flags(flags_int)
            result["value_type"] = _classify_value_type(result["default_value"])
            result["extraction_method"] = "decompiled_pattern2"

            # Try to find description after flags
            desc_m = re.search(r'"([^"]{10,200})"', window[m.end():])
            if desc_m:
                desc = desc_m.group(1)
                # Description should be a human-readable sentence, not a var name
                if " " in desc and not _is_valid_cvar_name(desc):
                    result["description"] = desc

            return result

    # Minimal extraction: we know the name exists in this function
    result["extraction_method"] = "name_only"
    return result


def _analyze_registration_sites(session, candidates, register_funcs, bulk_funcs):
    """Decompile registration functions and extract CVar details.

    Returns a list of CVar info dicts.
    """
    msg_info("Phase 3: Analyzing CVar registration sites...")
    start = time.time()
    cvars = {}  # name -> cvar_info dict (deduplication by name)
    decompile_count = 0
    decompile_cache = {}  # func_ea -> pseudocode (avoid re-decompiling)

    # Collect all functions we need to decompile
    funcs_to_scan = set()
    for name, refs in candidates.items():
        for string_ea, func_ea in refs:
            funcs_to_scan.add((func_ea, name))
    for func_ea in register_funcs:
        funcs_to_scan.add((func_ea, None))
    for func_ea in bulk_funcs:
        funcs_to_scan.add((func_ea, None))

    # Group by function to minimize decompilation calls
    func_to_names = {}  # func_ea -> set of cvar names
    for func_ea, name in funcs_to_scan:
        if func_ea not in func_to_names:
            func_to_names[func_ea] = set()
        if name:
            func_to_names[func_ea].add(name)

    total_funcs = len(func_to_names)
    msg_info(f"  Will analyze {total_funcs} functions...")

    for idx, (func_ea, names) in enumerate(func_to_names.items()):
        # Decompile the function
        if func_ea in decompile_cache:
            pseudocode = decompile_cache[func_ea]
        else:
            pseudocode = get_decompiled_text(func_ea)
            decompile_cache[func_ea] = pseudocode
            decompile_count += 1

        if not pseudocode:
            continue

        # If we have specific CVar names to look for in this function
        if names:
            for name in names:
                if name in cvars:
                    # Already extracted with better info -- skip if current is name_only
                    existing = cvars[name]
                    if existing.get("extraction_method") != "name_only":
                        continue

                info = _extract_cvar_from_decompiled(pseudocode, name, func_ea)
                if info:
                    # Prefer more detailed extraction over name_only
                    if name in cvars and info["extraction_method"] == "name_only":
                        continue
                    cvars[name] = info

        # Also scan the entire pseudocode for CVar patterns we might have missed
        # (e.g., CVars whose name strings aren't in our candidates list)
        for m in _RE_REGISTER_DIRECT.finditer(pseudocode):
            name = m.group(1)
            if name in cvars and cvars[name].get("extraction_method") != "name_only":
                continue
            if _is_valid_cvar_name(name):
                info = {
                    "name": name,
                    "default_value": m.group(2),
                    "value_type": _classify_value_type(m.group(2)),
                    "flags": _parse_int_safe(m.group(3)),
                    "flags_decoded": _decode_flags(_parse_int_safe(m.group(3))),
                    "description": m.group(4) if m.group(4) else None,
                    "callback_ea": None,
                    "callback_analysis": None,
                    "system": _classify_system(name),
                    "server_relevant": False,
                    "tc_has_equivalent": False,
                    "registration_func_ea": func_ea,
                    "extraction_method": "decompiled_fullscan",
                }
                if m.group(5) and m.group(5) != "0" and m.group(5) != "0x0":
                    cb_int = _parse_int_safe(m.group(5))
                    if cb_int:
                        info["callback_ea"] = cb_int
                cvars[name] = info

        # Progress
        if (idx + 1) % 200 == 0:
            elapsed = time.time() - start
            msg(f"  Analyzed {idx + 1}/{total_funcs} functions, "
                f"{len(cvars)} CVars found ({elapsed:.1f}s)")

    elapsed = time.time() - start
    msg_info(f"  Registration analysis complete: {len(cvars)} CVars extracted "
             f"from {decompile_count} decompiled functions in {elapsed:.1f}s")
    return cvars


# ---------------------------------------------------------------------------
# Phase 4: CVar flag pattern analysis
# ---------------------------------------------------------------------------

def _analyze_flag_checking_patterns(session, cvars):
    """Analyze how the binary checks CVar flags to refine our flag definitions.

    Looks for patterns like:
      if (cvar->flags & 0x2)  // SERVER_SYNC
      if (cvar->flags & 0x4)  // CHEAT_PROTECTED

    This helps validate/correct our flag bit assignments.
    """
    msg_info("Phase 4: Analyzing CVar flag checking patterns...")

    # Look for functions that reference "cheat" or "server" strings
    # near flag-check patterns
    flag_evidence = {}  # bit_value -> set of evidence strings

    cvar_flag_funcs = set()
    flag_keywords = ["cheat", "server", "sync", "archive", "save",
                     "readonly", "hidden", "restart", "secure", "protected"]
    for s in idautils.Strings():
        val = str(s)
        if not val:
            continue
        val_lower = val.lower()
        for kw in flag_keywords:
            if kw in val_lower and ("cvar" in val_lower or "console" in val_lower
                                     or "variable" in val_lower):
                for xref in idautils.XrefsTo(s.ea, 0):
                    func_ea = _get_func_containing(xref.frm)
                    if func_ea is not None:
                        cvar_flag_funcs.add(func_ea)
                break

    msg_info(f"  Found {len(cvar_flag_funcs)} flag-checking candidate functions")

    # Decompile and search for flag AND patterns
    _re_flag_check = re.compile(
        r'(\w+)\s*&\s*(0x[0-9A-Fa-f]+|\d+)'
    )

    for func_ea in cvar_flag_funcs:
        pseudocode = get_decompiled_text(func_ea)
        if not pseudocode:
            continue

        for m in _re_flag_check.finditer(pseudocode):
            var_name = m.group(1).lower()
            bit_val = _parse_int_safe(m.group(2))
            if bit_val is None or bit_val == 0:
                continue
            # Only interested in flag-like variables
            if "flag" in var_name or "attr" in var_name or "prop" in var_name:
                if bit_val not in flag_evidence:
                    flag_evidence[bit_val] = set()
                # Get surrounding context
                start = max(0, m.start() - 200)
                end = min(len(pseudocode), m.end() + 200)
                context = pseudocode[start:end]
                flag_evidence[bit_val].add(context[:100])

    if flag_evidence:
        msg_info(f"  Found flag check evidence for {len(flag_evidence)} bit values")
        for bit_val, evidence in sorted(flag_evidence.items()):
            flag_name = CVAR_FLAGS.get(bit_val, "UNKNOWN")
            msg(f"    Bit 0x{bit_val:X} ({flag_name}): {len(evidence)} references")

    return flag_evidence


# ---------------------------------------------------------------------------
# Phase 5: Callback function analysis
# ---------------------------------------------------------------------------

def _analyze_callbacks(session, cvars):
    """For CVars with change callbacks, decompile and classify the callback.

    Callback classification:
      - validation: checks if the new value is acceptable
      - apply: applies the setting to a game system
      - notification: notifies other systems of the change
      - combined: multiple behaviors
    """
    msg_info("Phase 5: Analyzing CVar change callbacks...")
    start = time.time()
    analyzed_count = 0
    total_with_callback = sum(1 for c in cvars.values() if c.get("callback_ea"))

    msg_info(f"  {total_with_callback} CVars have callback functions")

    # Patterns indicating callback behavior
    _re_validate = re.compile(
        r'(?:return\s+(?:false|0)|'
        r'(?:clamp|min|max|limit|bound|range|valid|check|verify))',
        re.IGNORECASE
    )
    _re_apply = re.compile(
        r'(?:Set\w+|Apply\w+|Update\w+|Refresh\w+|Reload\w+|'
        r'Enable\w+|Disable\w+|Toggle\w+)',
        re.IGNORECASE
    )
    _re_notify = re.compile(
        r'(?:Notify\w+|Send\w+|Broadcast\w+|Signal\w+|Event\w+|'
        r'Callback\w+|OnChange\w+|Fire\w+)',
        re.IGNORECASE
    )

    for name, info in cvars.items():
        cb_ea = info.get("callback_ea")
        if not cb_ea or cb_ea == 0:
            continue

        pseudocode = get_decompiled_text(cb_ea)
        if not pseudocode:
            info["callback_analysis"] = "decompilation_failed"
            continue

        analyzed_count += 1

        # Classify the callback
        has_validate = bool(_re_validate.search(pseudocode))
        has_apply = bool(_re_apply.search(pseudocode))
        has_notify = bool(_re_notify.search(pseudocode))

        behaviors = []
        if has_validate:
            behaviors.append("validation")
        if has_apply:
            behaviors.append("apply")
        if has_notify:
            behaviors.append("notification")

        if len(behaviors) > 1:
            info["callback_analysis"] = "combined: " + ", ".join(behaviors)
        elif len(behaviors) == 1:
            info["callback_analysis"] = behaviors[0]
        else:
            info["callback_analysis"] = "unknown"

        # Try to extract what systems the callback touches
        cb_func_name = ida_name.get_name(cb_ea)
        if cb_func_name:
            info["callback_name"] = cb_func_name

        # Look for called functions to understand side effects
        func = ida_funcs.get_func(cb_ea)
        if func:
            callees = set()
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head, 0):
                    callee_func = ida_funcs.get_func(xref.to)
                    if callee_func and callee_func.start_ea != func.start_ea:
                        callee_name = ida_name.get_name(callee_func.start_ea)
                        if callee_name and not callee_name.startswith("sub_"):
                            callees.add(callee_name)
            if callees:
                info["callback_callees"] = sorted(callees)[:20]  # Cap at 20

    elapsed = time.time() - start
    msg_info(f"  Analyzed {analyzed_count} callbacks in {elapsed:.1f}s")
    return analyzed_count


# ---------------------------------------------------------------------------
# Phase 6: Server relevance classification
# ---------------------------------------------------------------------------

def _classify_server_relevance(cvars):
    """Classify all CVars for server relevance.

    A CVar is server-relevant if:
      - It has SERVER_SYNC flag
      - It has CHEAT_PROTECTED flag
      - It belongs to a server-relevant system (combat, movement, etc.)
      - Its name contains movement/network/combat keywords
    """
    msg_info("Phase 6: Classifying server relevance...")
    server_sync_names = []
    cheat_protected_names = []
    server_relevant_count = 0

    for name, info in cvars.items():
        flags_decoded = info.get("flags_decoded", [])
        system = info.get("system", "Unknown")

        # Check server relevance
        relevant = _is_server_relevant(name, flags_decoded, system)
        info["server_relevant"] = relevant
        if relevant:
            server_relevant_count += 1

        # Track specific flag categories
        if "SERVER_SYNC" in flags_decoded:
            server_sync_names.append(name)
        if "CHEAT_PROTECTED" in flags_decoded:
            cheat_protected_names.append(name)

    msg_info(f"  Server-relevant: {server_relevant_count}/{len(cvars)}")
    msg_info(f"  SERVER_SYNC: {len(server_sync_names)}")
    msg_info(f"  CHEAT_PROTECTED: {len(cheat_protected_names)}")

    return server_sync_names, cheat_protected_names, server_relevant_count


# ---------------------------------------------------------------------------
# Phase 7: TrinityCore comparison
# ---------------------------------------------------------------------------

# Known CVars that TrinityCore implements (partial list for comparison).
# This list can be extended or loaded from TC source scanning.
_TC_KNOWN_CVARS = {
    # Movement CVars
    "moveSpeed",
    "maxFallSpeed",
    "terminalVelocity",
    "terminalSafefall",
    # Spell CVars
    "spellQueueWindow",
    "MaxSpellCastTime",
    # Chat CVars
    "chatBubblesParty",
    "chatBubbles",
    "chatStyle",
    "whisperMode",
    # UI CVars
    "autoLootDefault",
    "autoSelfCast",
    "autoDismount",
    "autoDismountFlying",
    "autoUnshift",
    # Combat
    "TargetNearestDistance",
    "autoInteract",
    # Graphics/Performance (not server-relevant, but TC may reference)
    "maxFps",
    "maxFpsBk",
    "gxRefresh",
    # Network
    "realmList",
    "realmListbn",
    "portal",
    # Debug
    "scriptErrors",
    "taintLog",
    "bugSack",
}


def _compare_with_tc(session, cvars):
    """Compare discovered CVars against known TrinityCore CVars.

    If the TC source directory is configured, also scan TC source for CVar
    references.
    """
    msg_info("Phase 7: Comparing with TrinityCore...")
    cfg = session.cfg

    tc_known = set(_TC_KNOWN_CVARS)

    # Try to scan TC source for additional CVar references
    tc_source_dir = getattr(cfg, "tc_source_dir", None)
    if tc_source_dir:
        import os
        tc_extra = _scan_tc_source_for_cvars(tc_source_dir)
        tc_known.update(tc_extra)
        msg_info(f"  Found {len(tc_extra)} additional CVars in TC source")

    missing_in_tc = []
    for name, info in cvars.items():
        if name in tc_known:
            info["tc_has_equivalent"] = True
        else:
            info["tc_has_equivalent"] = False
            # Only report server-relevant missing CVars
            if info.get("server_relevant", False):
                missing_in_tc.append(name)

    tc_has_count = sum(1 for c in cvars.values() if c.get("tc_has_equivalent"))
    msg_info(f"  TC has equivalent: {tc_has_count}/{len(cvars)}")
    msg_info(f"  Server-relevant missing in TC: {len(missing_in_tc)}")

    return missing_in_tc


def _scan_tc_source_for_cvars(tc_source_dir):
    """Scan TrinityCore source files for CVar name references.

    Looks for patterns like:
      - sWorld->getCVar("cvarName")
      - WorldSession::GetCVar("cvarName")
      - "CVAR_NAME" in config/SQL files
      - CVar registration in player/world config
    """
    import os

    cvar_names = set()
    _re_tc_cvar_ref = re.compile(r'(?:getCVar|GetCVar|setCVar|SetCVar|'
                                  r'getWorldCVar|GetWorldCVar)\s*\(\s*"([^"]+)"')
    _re_tc_config_option = re.compile(r'(?:GetOption|getConfig|sConfigMgr->Get\w+)\s*\(\s*"([^"]+)"')

    scan_extensions = {".cpp", ".h", ".hpp", ".conf", ".conf.dist"}

    for root, dirs, files in os.walk(tc_source_dir):
        # Skip build directories
        dirs[:] = [d for d in dirs if d not in {"build", "cmake", ".git", "dep"}]
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in scan_extensions:
                continue
            filepath = os.path.join(root, fn)
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for m in _re_tc_cvar_ref.finditer(content):
                    cvar_names.add(m.group(1))
                for m in _re_tc_config_option.finditer(content):
                    cvar_names.add(m.group(1))
            except Exception:
                continue

    return cvar_names


# ---------------------------------------------------------------------------
# Phase 8: Supplementary string-neighbor analysis
# ---------------------------------------------------------------------------

def _analyze_string_neighbors(session, candidates, cvars):
    """For CVar candidates that we couldn't extract details for, try a
    neighbor-based approach.

    If a CVar name string is adjacent (within a few bytes) to another string
    that looks like a default value, pair them.  This catches cases where
    registration data is stored in static arrays rather than passed as
    function arguments.
    """
    msg_info("Phase 8: Analyzing string neighbor patterns for missing details...")
    improved = 0

    for name, info in cvars.items():
        if info.get("default_value") is not None:
            continue  # Already have default value

        # Find the string EA for this CVar name
        refs = candidates.get(name, [])
        if not refs:
            continue

        for string_ea, func_ea in refs:
            # Check the next string in the binary (often the default value)
            # Strings are typically aligned; scan forward from end of current string
            name_bytes = idc.get_strlit_contents(string_ea, -1, idc.STRTYPE_C)
            if not name_bytes:
                continue
            next_ea = string_ea + len(name_bytes) + 1  # +1 for null terminator

            # Align to 8 bytes (common on x64)
            next_ea = (next_ea + 7) & ~7

            # Try reading the next string
            next_str = _get_string_at(next_ea)
            if next_str and len(next_str) < 100:
                # Heuristic: if the next string looks like a value (short, no spaces,
                # or a number) then it's probably the default value
                if (len(next_str) <= 20 and " " not in next_str) or next_str in ("", "0", "1"):
                    info["default_value"] = next_str
                    info["value_type"] = _classify_value_type(next_str)
                    improved += 1
                    break

            # Also try reading a potential integer default right after the string
            # (when default is stored as immediate value in a struct)
            try:
                potential_int = ida_bytes.get_dword(next_ea)
                if potential_int is not None and 0 < potential_int < 0x10000:
                    # Could be flags -- check the next dword
                    pass  # Too ambiguous without more context
            except Exception:
                pass

    msg_info(f"  Improved {improved} CVars with neighbor analysis")
    return improved


# ---------------------------------------------------------------------------
# Phase 9: CVar vtable and object layout analysis
# ---------------------------------------------------------------------------

def _analyze_cvar_vtable(session):
    """Try to find the CVar class vtable and understand the object layout.

    The CVar object typically contains:
      - vtable pointer (offset 0)
      - name string pointer
      - current value (string or numeric union)
      - default value
      - flags
      - description string pointer
      - callback function pointer

    Returns layout info dict or None.
    """
    msg_info("Phase 9: Analyzing CVar class layout...")

    # Look for named CVar vtables
    cvar_vtable_ea = None
    for name_pattern in ["??_7CVar@@", "vtable_CVar", "CVar::`vftable'",
                         "CVar_vtbl", "??_7ConsoleVar@@"]:
        ea = ida_name.get_name_ea(idaapi.BADADDR, name_pattern)
        if ea != idaapi.BADADDR:
            cvar_vtable_ea = ea
            msg_info(f"  Found CVar vtable at {ea_str(ea)} ({name_pattern})")
            break

    if not cvar_vtable_ea:
        # Try searching for the vtable via constructor patterns
        # Constructors write the vtable pointer as the first operation
        msg_info("  CVar vtable not found by name, trying constructor search...")
        # Look for functions named like CVar constructor
        for ea in idautils.Functions():
            name = ida_name.get_name(ea)
            if not name:
                continue
            if "CVar" in name and ("ctor" in name.lower() or "::CVar" in name
                                    or name.endswith("CVar")):
                msg_info(f"  Potential CVar constructor: {name} at {ea_str(ea)}")
                # Decompile and look for vtable write
                pseudocode = get_decompiled_text(ea)
                if pseudocode:
                    # Look for: *this = &vtable
                    vtable_m = re.search(
                        r'\*\s*\w+\s*=\s*(?:&\s*)?(0x[0-9A-Fa-f]+|off_[0-9A-Fa-f]+)',
                        pseudocode
                    )
                    if vtable_m:
                        vt_ref = vtable_m.group(1)
                        vt_ea = _parse_int_safe(vt_ref)
                        if vt_ea:
                            cvar_vtable_ea = vt_ea
                            msg_info(f"  Found CVar vtable via constructor: {ea_str(vt_ea)}")
                            break

    layout = {
        "vtable_ea": cvar_vtable_ea,
        "layout_known": False,
        "fields": [],
    }

    if cvar_vtable_ea:
        # Read vtable entries to understand virtual methods
        vtable_entries = []
        for i in range(20):  # Read up to 20 virtual functions
            entry_ea = cvar_vtable_ea + i * 8  # x64: 8 bytes per pointer
            try:
                func_ptr = ida_bytes.get_qword(entry_ea)
            except Exception:
                break
            if func_ptr == 0 or func_ptr == idaapi.BADADDR:
                break
            func = ida_funcs.get_func(func_ptr)
            if not func:
                break
            func_name = ida_name.get_name(func_ptr) or ea_str(func_ptr)
            vtable_entries.append({
                "slot": i,
                "ea": func_ptr,
                "name": func_name,
            })

        layout["vtable_entries"] = vtable_entries
        if vtable_entries:
            layout["layout_known"] = True
            msg_info(f"  CVar vtable has {len(vtable_entries)} virtual methods")

    return layout


# ---------------------------------------------------------------------------
# Phase 10: Global CVar instance discovery
# ---------------------------------------------------------------------------

def _discover_global_cvar_instances(session, cvar_vtable_ea, candidates):
    """Find global CVar instances in .data/.bss sections.

    Global CVars are often declared as:
      CVar s_cvarName;
    and live in the data segment with a vtable pointer at offset 0.

    Returns list of (instance_ea, cvar_name) pairs.
    """
    if not cvar_vtable_ea:
        msg_info("Phase 10: Skipping global instance scan (no vtable found)")
        return []

    msg_info("Phase 10: Scanning for global CVar instances...")
    start = time.time()
    instances = []

    # Find all xrefs to the CVar vtable -- these are constructor sites
    # or direct vtable writes to global instances
    for xref in idautils.XrefsTo(cvar_vtable_ea, 0):
        xref_ea = xref.frm
        func_ea = _get_func_containing(xref_ea)

        # Read surrounding context to find the destination of the vtable write
        # In x64, writing vtable: mov [rax], offset vtable
        # We need to figure out what rax points to
        if func_ea:
            pseudocode = get_decompiled_text(func_ea)
            if pseudocode:
                # Look for global variable names referenced near the vtable write
                # Pattern: qword_XXXX = (type)&vtable
                globals_m = re.findall(
                    r'((?:qword|dword|byte|off)_[0-9A-Fa-f]+)',
                    pseudocode
                )
                for g in globals_m:
                    g_ea = ida_name.get_name_ea(idaapi.BADADDR, g)
                    if g_ea != idaapi.BADADDR:
                        # Check if any CVar name string is referenced near this global
                        # by reading nearby data
                        for offset in [8, 16, 24, 32]:
                            try:
                                str_ptr = ida_bytes.get_qword(g_ea + offset)
                            except Exception:
                                continue
                            s = _get_string_at(str_ptr)
                            if s and _is_valid_cvar_name(s):
                                instances.append((g_ea, s))
                                break

    elapsed = time.time() - start
    msg_info(f"  Found {len(instances)} global CVar instances in {elapsed:.1f}s")
    return instances


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def extract_cvars(session) -> int:
    """Extract Console Variable (CVar) definitions from the WoW binary.

    Runs all analysis phases and stores results in the session knowledge DB.

    Returns:
        Number of CVars found.
    """
    start_time = time.time()
    msg("=" * 70)
    msg("CVar Extraction Analyzer")
    msg("=" * 70)

    db = session.db
    if not db:
        msg_error("No database loaded")
        return 0

    # Phase 1: String-based discovery
    candidates = _discover_cvar_strings(session)
    if not candidates:
        msg_warn("No CVar name candidates found in strings")
        # Still continue -- we might find CVars via other methods

    # Phase 2: Find registration functions
    register_funcs = _find_cvar_register_functions(session)
    bulk_funcs = _find_bulk_registration_functions(candidates)

    # Phase 3: Decompile and extract details
    cvars = _analyze_registration_sites(session, candidates, register_funcs, bulk_funcs)

    # For candidates that weren't found via decompilation, add as name-only
    for name in candidates:
        if name not in cvars:
            refs = candidates[name]
            if refs:
                string_ea, func_ea = refs[0]
                cvars[name] = {
                    "name": name,
                    "default_value": None,
                    "value_type": "string",
                    "flags": None,
                    "flags_decoded": [],
                    "description": None,
                    "callback_ea": None,
                    "callback_analysis": None,
                    "system": _classify_system(name),
                    "server_relevant": False,
                    "tc_has_equivalent": False,
                    "registration_func_ea": func_ea,
                    "extraction_method": "string_candidate",
                }

    msg_info(f"Total CVars after all discovery phases: {len(cvars)}")

    # Phase 4: Flag analysis
    flag_evidence = _analyze_flag_checking_patterns(session, cvars)

    # Phase 5: Callback analysis
    _analyze_callbacks(session, cvars)

    # Phase 6: Server relevance
    server_sync_names, cheat_protected_names, server_relevant_count = (
        _classify_server_relevance(cvars)
    )

    # Phase 7: TC comparison
    missing_in_tc = _compare_with_tc(session, cvars)

    # Phase 8: String neighbor analysis (improve defaults)
    _analyze_string_neighbors(session, candidates, cvars)

    # Phase 9: CVar class layout
    layout = _analyze_cvar_vtable(session)

    # Phase 10: Global instance discovery
    cvar_vtable_ea = layout.get("vtable_ea")
    global_instances = _discover_global_cvar_instances(
        session, cvar_vtable_ea, candidates
    )

    # Merge global instance data
    for inst_ea, inst_name in global_instances:
        if inst_name in cvars:
            cvars[inst_name]["global_instance_ea"] = inst_ea
        else:
            cvars[inst_name] = {
                "name": inst_name,
                "default_value": None,
                "value_type": "string",
                "flags": None,
                "flags_decoded": [],
                "description": None,
                "callback_ea": None,
                "callback_analysis": None,
                "system": _classify_system(inst_name),
                "server_relevant": False,
                "tc_has_equivalent": False,
                "registration_func_ea": None,
                "global_instance_ea": inst_ea,
                "extraction_method": "global_instance",
            }
            # Re-classify server relevance for new entries
            info = cvars[inst_name]
            info["server_relevant"] = _is_server_relevant(
                inst_name, info["flags_decoded"], info["system"]
            )

    # ---------------------------------------------------------------------------
    # Build final results
    # ---------------------------------------------------------------------------

    # Convert to serialisable list (EAs become hex strings for JSON)
    cvar_list = []
    for name in sorted(cvars.keys()):
        info = cvars[name]
        entry = {
            "name": info["name"],
            "default_value": info.get("default_value"),
            "value_type": info.get("value_type", "string"),
            "flags": info.get("flags"),
            "flags_decoded": info.get("flags_decoded", []),
            "description": info.get("description"),
            "callback_ea": (ea_str(info["callback_ea"])
                            if info.get("callback_ea") else None),
            "callback_analysis": info.get("callback_analysis"),
            "callback_name": info.get("callback_name"),
            "callback_callees": info.get("callback_callees"),
            "system": info.get("system", "Unknown"),
            "server_relevant": info.get("server_relevant", False),
            "tc_has_equivalent": info.get("tc_has_equivalent", False),
            "extraction_method": info.get("extraction_method", "unknown"),
            "registration_func_ea": (ea_str(info["registration_func_ea"])
                                      if info.get("registration_func_ea") else None),
            "global_instance_ea": (ea_str(info["global_instance_ea"])
                                    if info.get("global_instance_ea") else None),
        }
        cvar_list.append(entry)

    # Recompute summary lists now that all phases are complete
    server_sync_final = sorted(set(
        e["name"] for e in cvar_list if "SERVER_SYNC" in e.get("flags_decoded", [])
    ))
    cheat_protected_final = sorted(set(
        e["name"] for e in cvar_list if "CHEAT_PROTECTED" in e.get("flags_decoded", [])
    ))
    missing_final = sorted(set(
        e["name"] for e in cvar_list
        if e.get("server_relevant") and not e.get("tc_has_equivalent")
    ))
    server_relevant_final = sum(1 for e in cvar_list if e.get("server_relevant"))

    # System breakdown
    system_counts = {}
    for e in cvar_list:
        sys = e.get("system", "Unknown")
        system_counts[sys] = system_counts.get(sys, 0) + 1

    # Extraction method breakdown
    method_counts = {}
    for e in cvar_list:
        method = e.get("extraction_method", "unknown")
        method_counts[method] = method_counts.get(method, 0) + 1

    # Flag distribution
    flag_distribution = {}
    for e in cvar_list:
        for flag in e.get("flags_decoded", []):
            flag_distribution[flag] = flag_distribution.get(flag, 0) + 1

    # Value type distribution
    type_distribution = {}
    for e in cvar_list:
        vt = e.get("value_type", "string")
        type_distribution[vt] = type_distribution.get(vt, 0) + 1

    results = {
        "cvars": cvar_list,
        "server_sync_cvars": server_sync_final,
        "cheat_protected_cvars": cheat_protected_final,
        "missing_in_tc": missing_final,
        "total_cvars": len(cvar_list),
        "server_relevant_count": server_relevant_final,
        "system_breakdown": system_counts,
        "extraction_method_breakdown": method_counts,
        "flag_distribution": flag_distribution,
        "value_type_distribution": type_distribution,
        "cvar_class_layout": {
            "vtable_ea": ea_str(layout["vtable_ea"]) if layout.get("vtable_ea") else None,
            "layout_known": layout.get("layout_known", False),
            "vtable_entries": [
                {
                    "slot": e["slot"],
                    "ea": ea_str(e["ea"]),
                    "name": e["name"],
                }
                for e in layout.get("vtable_entries", [])
            ],
        },
        "global_instances_found": len(global_instances),
        "flag_evidence_bits": sorted(flag_evidence.keys()) if flag_evidence else [],
        "analysis_time_seconds": round(time.time() - start_time, 1),
    }

    # Store in knowledge DB
    db.kv_set("cvars", results)
    db.commit()

    elapsed = time.time() - start_time
    msg("")
    msg("=" * 70)
    msg("CVar Extraction Summary")
    msg("=" * 70)
    msg(f"  Total CVars discovered:      {results['total_cvars']}")
    msg(f"  Server-relevant:             {results['server_relevant_count']}")
    msg(f"  SERVER_SYNC:                 {len(server_sync_final)}")
    msg(f"  CHEAT_PROTECTED:             {len(cheat_protected_final)}")
    msg(f"  Missing in TC (server-rel):  {len(missing_final)}")
    msg(f"  Global instances found:      {results['global_instances_found']}")
    msg(f"  CVar class vtable:           {'Found' if layout.get('vtable_ea') else 'Not found'}")
    msg(f"  Analysis time:               {elapsed:.1f}s")
    msg("")
    msg("  System breakdown:")
    for sys_name, count in sorted(system_counts.items(), key=lambda x: -x[1]):
        msg(f"    {sys_name:25s} {count:5d}")
    msg("")
    msg("  Extraction method breakdown:")
    for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
        msg(f"    {method:30s} {count:5d}")
    msg("")
    msg("  Value type distribution:")
    for vt, count in sorted(type_distribution.items(), key=lambda x: -x[1]):
        msg(f"    {vt:15s} {count:5d}")
    if flag_distribution:
        msg("")
        msg("  Flag distribution:")
        for flag, count in sorted(flag_distribution.items(), key=lambda x: -x[1]):
            msg(f"    {flag:25s} {count:5d}")
    msg("=" * 70)

    return results["total_cvars"]


# ---------------------------------------------------------------------------
# Report retrieval
# ---------------------------------------------------------------------------

def get_cvar_report(session):
    """Retrieve stored CVar extraction results from the knowledge DB.

    Returns the full results dict, or None if no extraction has been run.
    """
    if not session.db:
        msg_error("No database loaded")
        return None

    data = session.db.kv_get("cvars")
    if not data:
        msg_warn("No CVar extraction data found. Run extract_cvars() first.")
        return None

    return data


def get_server_relevant_cvars(session):
    """Convenience: return only server-relevant CVars."""
    report = get_cvar_report(session)
    if not report:
        return []
    return [c for c in report.get("cvars", []) if c.get("server_relevant")]


def get_missing_in_tc(session):
    """Convenience: return server-relevant CVars missing in TrinityCore."""
    report = get_cvar_report(session)
    if not report:
        return []
    return report.get("missing_in_tc", [])


def get_cvars_by_system(session, system_name):
    """Convenience: return CVars for a specific game system."""
    report = get_cvar_report(session)
    if not report:
        return []
    return [c for c in report.get("cvars", [])
            if c.get("system", "").lower() == system_name.lower()]


def get_cvars_by_flag(session, flag_name):
    """Convenience: return CVars that have a specific flag set."""
    report = get_cvar_report(session)
    if not report:
        return []
    return [c for c in report.get("cvars", [])
            if flag_name in c.get("flags_decoded", [])]


def print_server_relevant_summary(session):
    """Print a formatted summary of server-relevant CVars to the IDA output."""
    report = get_cvar_report(session)
    if not report:
        return

    msg("")
    msg("=" * 80)
    msg("SERVER-RELEVANT CVars")
    msg("=" * 80)

    relevant = [c for c in report.get("cvars", []) if c.get("server_relevant")]
    relevant.sort(key=lambda c: (c.get("system", "ZZZ"), c["name"]))

    current_system = None
    for cvar in relevant:
        sys = cvar.get("system", "Unknown")
        if sys != current_system:
            current_system = sys
            msg("")
            msg(f"  --- {sys} ---")

        flags_str = ", ".join(cvar.get("flags_decoded", [])) or "none"
        default = cvar.get("default_value", "?")
        tc_status = "TC:YES" if cvar.get("tc_has_equivalent") else "TC:MISSING"
        msg(f"    {cvar['name']:40s} default={default:>10s} "
            f"flags=[{flags_str}] {tc_status}")

    msg("")
    msg(f"Total server-relevant: {len(relevant)}")
    msg(f"Missing in TC: {len(report.get('missing_in_tc', []))}")
    msg("=" * 80)


def print_missing_in_tc_report(session):
    """Print a focused report on CVars the server needs but TC doesn't have."""
    report = get_cvar_report(session)
    if not report:
        return

    missing = report.get("missing_in_tc", [])
    if not missing:
        msg("No server-relevant CVars missing in TrinityCore.")
        return

    msg("")
    msg("=" * 80)
    msg(f"SERVER-RELEVANT CVars MISSING IN TRINITYCORE ({len(missing)})")
    msg("=" * 80)

    # Group by system
    cvar_map = {c["name"]: c for c in report.get("cvars", [])}
    by_system = {}
    for name in missing:
        cvar = cvar_map.get(name, {})
        sys = cvar.get("system", "Unknown")
        if sys not in by_system:
            by_system[sys] = []
        by_system[sys].append(cvar)

    for sys_name in sorted(by_system.keys()):
        cvars_in_sys = by_system[sys_name]
        msg(f"\n  --- {sys_name} ({len(cvars_in_sys)}) ---")
        for cvar in sorted(cvars_in_sys, key=lambda c: c.get("name", "")):
            default = cvar.get("default_value", "?")
            desc = cvar.get("description", "")
            flags_str = ", ".join(cvar.get("flags_decoded", [])) or "none"
            msg(f"    {cvar.get('name', '?'):40s} default={default:>10s} "
                f"flags=[{flags_str}]")
            if desc:
                msg(f"      Description: {desc}")
            cb = cvar.get("callback_analysis")
            if cb:
                msg(f"      Callback: {cb}")

    msg("")
    msg("=" * 80)
