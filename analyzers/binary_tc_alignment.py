"""
Binary-to-TrinityCore Handler Alignment Analyzer

Directly aligns decompiled binary handler pseudocode against TrinityCore handler
source code to find structural differences, missing code blocks, and divergences.
This is the most direct approach to identifying what TC is missing compared to
the actual game client/server binary.

For each matched handler pair:
  1. Decompile the binary handler via Hex-Rays
  2. Extract the TC handler body from source
  3. Normalize both sides for fair comparison
  4. Perform structural block-level alignment using SequenceMatcher
  5. Classify every divergence by type and severity
  6. Aggregate results per-system and overall

Results stored in session.db.kv_set("binary_tc_alignment", {...})
"""

import json
import os
import re
import time
import collections
import difflib

import ida_funcs
import ida_name
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Divergence type classifications
DIV_MISSING_VALIDATION = "MISSING_VALIDATION"
DIV_MISSING_LOGIC = "MISSING_LOGIC"
DIV_EXTRA_TC_CODE = "EXTRA_TC_CODE"
DIV_DIFFERENT_CONSTANTS = "DIFFERENT_CONSTANTS"
DIV_DIFFERENT_ORDER = "DIFFERENT_ORDER"
DIV_DIFFERENT_ERROR_HANDLING = "DIFFERENT_ERROR_HANDLING"
DIV_MISSING_NOTIFICATION = "MISSING_NOTIFICATION"

# Severity levels
SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"

# Opcode system classification keywords
_SYSTEM_KEYWORDS = {
    "HOUSING": "Housing", "HOUSE": "Housing", "DECOR": "Housing",
    "NEIGHBORHOOD": "Housing", "INTERIOR": "Housing", "PLOT": "Housing",
    "QUEST": "Quest", "QUESTGIVER": "Quest",
    "SPELL": "Combat", "AURA": "Combat", "ATTACK": "Combat", "CAST": "Combat",
    "GUILD": "Social", "CHAT": "Social", "MAIL": "Social", "FRIEND": "Social",
    "VOICE": "Social", "CHANNEL": "Social", "WHO": "Social",
    "BATTLEGROUND": "PvP", "ARENA": "PvP", "BG_": "PvP", "WAR_MODE": "PvP",
    "AUCTION": "Auction", "TRADE": "Trade", "CRAFT": "Crafting",
    "TALENT": "Talent", "SPEC": "Talent",
    "PET": "Pet", "PET_BATTLE": "PetBattle", "BATTLE_PET": "PetBattle",
    "ACHIEVEMENT": "Achievement",
    "LOOT": "Loot",
    "MOVE": "Movement", "MOVEMENT": "Movement",
    "ITEM": "Item", "EQUIP": "Item", "INVENTORY": "Item",
    "CHARACTER": "Character", "PLAYER": "Character", "CHAR_": "Character",
    "GARRISON": "Garrison", "SHIPMENT": "Garrison",
    "CALENDAR": "Calendar",
    "MYTHIC_PLUS": "MythicPlus", "CHALLENGE_MODE": "MythicPlus",
    "TRANSMOGRIFY": "Transmog", "TRANSMOG": "Transmog",
    "TAXI": "Transport", "FLIGHT": "Transport",
    "ADDON": "Addon",
    "GAME_OBJ": "GameObject", "GAMEOBJECT": "GameObject",
    "NPC": "NPC", "CREATURE": "NPC", "GOSSIP": "NPC",
    "GROUP": "Group", "PARTY": "Group", "RAID": "Group",
    "TICKET": "Support", "GM_": "Support",
    "WARBAND": "Warband",
    "DELVES": "Delves",
    "VEHICLE": "Vehicle",
    "WORLD_MAP": "Map", "MAP_": "Map",
    "INSTANCE": "Instance", "DUNGEON": "Instance",
    "WARDEN": "Anticheat",
    "LFG": "LFG",
    "BANK": "Bank",
    "VOID_STORAGE": "VoidStorage",
    "BARBER": "Barber",
    "SCENE": "Scene",
    "TOTEM": "Totem",
    "TOKEN": "Token",
    "CLUB": "Community",
    "CONTRIBUTION": "Contribution",
    "ISLAND": "Island",
    "AZERITE": "Azerite",
    "COVENANT": "Covenant",
    "SOUL_BIND": "Soulbind", "SOULBIND": "Soulbind",
}

# Type normalization map for fair comparison
_TYPE_NORMALIZATIONS = {
    "uint32_t": "uint32", "unsigned int": "uint32", "DWORD": "uint32",
    "uint32": "uint32", "unsigned": "uint32",
    "uint16_t": "uint16", "unsigned short": "uint16", "uint16": "uint16",
    "uint8_t": "uint8", "unsigned char": "uint8", "BYTE": "uint8",
    "uint8": "uint8",
    "int32_t": "int32", "int32": "int32", "signed int": "int32",
    "int16_t": "int16", "int16": "int16", "short": "int16",
    "int8_t": "int8", "int8": "int8", "signed char": "int8",
    "uint64_t": "uint64", "unsigned long long": "uint64", "uint64": "uint64",
    "int64_t": "int64", "long long": "int64", "int64": "int64",
    "float": "float", "double": "double",
    "bool": "bool", "_BOOL1": "bool", "_BOOL4": "bool", "_BOOL8": "bool",
    "BOOL": "bool",
    "ObjectGuid": "ObjectGuid", "WowGuid128": "ObjectGuid",
    "std::string": "string", "String": "string",
}

# C++ keywords and common macros to skip during call extraction
_CPP_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "break",
    "continue", "return", "sizeof", "static_cast", "dynamic_cast",
    "reinterpret_cast", "const_cast", "new", "delete", "throw",
    "try", "catch", "using", "typedef", "auto", "void", "const",
    "nullptr", "true", "false", "this", "struct", "class", "enum",
    "namespace", "operator", "template", "typename", "decltype",
    "default", "goto", "volatile", "register", "inline", "explicit",
    "virtual", "override", "final", "noexcept", "alignof",
    "ASSERT", "ABORT", "LOG", "TC_LOG_DEBUG", "TC_LOG_INFO",
    "TC_LOG_WARN", "TC_LOG_ERROR", "TC_LOG_FATAL",
    "sLog", "LOG_DEBUG", "LOG_INFO", "LOG_ERROR",
})


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def align_binary_to_tc(session):
    """Align binary handler pseudocode against TrinityCore handler source.

    Decompiles each binary handler, extracts matching TC handler source,
    normalizes both sides, and performs structural diff to classify
    divergences.

    Args:
        session: PluginSession with configured db and cfg.

    Returns:
        int: Number of handler pairs successfully aligned.
    """
    db = session.db
    cfg = session.cfg
    tc_dir = cfg.tc_source_dir

    if not tc_dir or not os.path.isdir(tc_dir):
        msg_error("TrinityCore source directory not configured or missing. "
                  "Set tc_source_dir in Settings.")
        return 0

    start_time = time.time()

    # Step 1: Discover all TC handler implementations
    msg_info("Phase 1: Discovering TC handler implementations...")
    tc_handlers = _discover_tc_handlers(tc_dir)
    msg_info(f"  Found {len(tc_handlers)} TC handler implementations")

    if not tc_handlers:
        msg_warn("No TC handlers found. Verify tc_source_dir points to "
                 "TrinityCore root with src/server/game/Handlers/")
        return 0

    # Step 2: Load opcode table for binary handler matching
    msg_info("Phase 2: Loading opcode-to-handler mapping...")
    opcode_rows = db.fetchall(
        "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL "
        "AND tc_name IS NOT NULL AND handler_ea != 0"
    )
    if not opcode_rows:
        msg_warn("No opcode-to-handler mappings found. "
                 "Run opcode dispatcher analysis first.")
        return 0

    msg_info(f"  {len(opcode_rows)} opcodes with binary handlers")

    # Build opcode name -> handler EA mapping
    opcode_handler_map = {}
    for row in opcode_rows:
        tc_name = row["tc_name"]
        handler_ea = row["handler_ea"]
        if tc_name and handler_ea:
            opcode_handler_map[tc_name] = {
                "ea": handler_ea,
                "direction": row["direction"],
                "internal_index": row["internal_index"],
            }

    # Step 3: Match binary handlers to TC handlers
    msg_info("Phase 3: Matching and aligning handler pairs...")
    alignments = []
    match_failures = []

    for tc_name, opcode_info in opcode_handler_map.items():
        handler_ea = opcode_info["ea"]

        # Try to find matching TC handler source
        handler_func_name = _opcode_to_handler_name(tc_name)
        tc_entry = tc_handlers.get(handler_func_name)

        if not tc_entry:
            # Try alternative name patterns
            tc_entry = _fuzzy_match_tc_handler(handler_func_name, tc_handlers)

        if not tc_entry:
            match_failures.append({
                "opcode": tc_name,
                "handler_func": handler_func_name,
                "reason": "no_tc_source",
            })
            continue

        # Decompile binary handler
        binary_text = get_decompiled_text(handler_ea)
        if not binary_text:
            match_failures.append({
                "opcode": tc_name,
                "handler_func": handler_func_name,
                "reason": "decompilation_failed",
            })
            continue

        tc_source = tc_entry["body"]
        if not tc_source or len(tc_source.strip()) < 10:
            match_failures.append({
                "opcode": tc_name,
                "handler_func": handler_func_name,
                "reason": "empty_tc_body",
            })
            continue

        # Normalize both sides
        norm_binary = _normalize_code(binary_text, is_binary=True)
        norm_tc = _normalize_code(tc_source, is_binary=False)

        # Perform structural alignment
        alignment = _structural_align(norm_binary, norm_tc)

        # Classify differences
        differences = _classify_differences(
            alignment, binary_text, tc_source, norm_binary, norm_tc
        )

        # Compute alignment score
        score = _compute_alignment_score(alignment, differences)

        entry = {
            "opcode": tc_name,
            "tc_handler": handler_func_name,
            "binary_ea": f"0x{handler_ea:X}",
            "binary_ea_int": handler_ea,
            "alignment_score": score,
            "matching_blocks": alignment["matching_blocks"],
            "differing_blocks": alignment["differing_blocks"],
            "differences": differences,
            "tc_file": tc_entry["file"],
            "tc_line_start": tc_entry["line_start"],
            "tc_line_end": tc_entry["line_end"],
            "binary_line_count": len(binary_text.splitlines()),
            "tc_line_count": len(tc_source.splitlines()),
            "system": _classify_system(tc_name),
        }
        alignments.append(entry)

    elapsed = time.time() - start_time
    msg_info(f"  Aligned {len(alignments)} handler pairs in {elapsed:.1f}s")
    msg_info(f"  {len(match_failures)} handlers could not be matched")

    # Step 4: Aggregate analysis
    msg_info("Phase 4: Computing aggregate statistics...")
    aggregate = _compute_aggregate(alignments)

    # Step 5: Extract missing-in-TC and extra-in-TC blocks
    missing_in_tc = _extract_missing_in_tc(alignments)
    extra_in_tc = _extract_extra_in_tc(alignments)

    # Build final result
    result = {
        "alignments": _serialize_alignments(alignments),
        "aggregate": aggregate,
        "missing_in_tc": missing_in_tc,
        "extra_in_tc": extra_in_tc,
        "match_failures": match_failures[:100],  # cap for storage
        "analysis_time_seconds": round(elapsed, 1),
        "timestamp": time.time(),
    }

    db.kv_set("binary_tc_alignment", result)
    db.commit()

    # Print summary
    _print_summary(aggregate, alignments)

    return len(alignments)


# ---------------------------------------------------------------------------
# TC Handler Discovery
# ---------------------------------------------------------------------------

def _discover_tc_handlers(tc_dir):
    """Scan TrinityCore source for all WorldSession::Handle* implementations.

    Searches:
      - src/server/game/Handlers/*.cpp
      - src/server/scripts/**/*.cpp

    Returns:
        dict: handler_name -> {file, line_start, line_end, body}
    """
    handlers = {}

    # Primary: Handlers directory
    handlers_dir = os.path.join(tc_dir, "src", "server", "game", "Handlers")
    if os.path.isdir(handlers_dir):
        for fname in os.listdir(handlers_dir):
            if fname.endswith(".cpp"):
                filepath = os.path.join(handlers_dir, fname)
                found = _extract_handlers_from_file(filepath)
                handlers.update(found)

    # Secondary: Scripts directory (some handlers live in scripts)
    scripts_dir = os.path.join(tc_dir, "src", "server", "scripts")
    if os.path.isdir(scripts_dir):
        for root, _dirs, files in os.walk(scripts_dir):
            for fname in files:
                if fname.endswith(".cpp"):
                    filepath = os.path.join(root, fname)
                    found = _extract_handlers_from_file(filepath)
                    handlers.update(found)

    # Tertiary: Game directory for any stray handlers
    game_dir = os.path.join(tc_dir, "src", "server", "game")
    if os.path.isdir(game_dir):
        for root, _dirs, files in os.walk(game_dir):
            # Skip Handlers dir (already processed) and avoid deep recursion
            rel = os.path.relpath(root, game_dir)
            if rel.startswith("Handlers"):
                continue
            for fname in files:
                if fname.endswith(".cpp"):
                    filepath = os.path.join(root, fname)
                    found = _extract_handlers_from_file(filepath)
                    handlers.update(found)

    return handlers


def _extract_handlers_from_file(filepath):
    """Extract all void WorldSession::Handle* function bodies from a C++ file.

    Returns:
        dict: handler_name -> {file, line_start, line_end, body}
    """
    handlers = {}

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except IOError:
        return handlers

    # Pattern: void WorldSession::HandleFoo(WorldPackets::Bar::Baz& pkt)
    # Also matches: void WorldSession::HandleFoo(WorldPacket& recvData)
    pattern = re.compile(
        r'^void\s+WorldSession::(Handle\w+)\s*\([^)]*\)\s*\{',
        re.MULTILINE
    )

    lines = content.split("\n")
    line_offsets = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line) + 1  # +1 for newline

    for match in pattern.finditer(content):
        func_name = match.group(1)
        func_start = match.start()

        # Find which line this is on
        line_start = _offset_to_line(line_offsets, func_start)

        # Extract body by brace matching
        brace_pos = content.index("{", match.start())
        depth = 1
        pos = brace_pos + 1
        while depth > 0 and pos < len(content):
            ch = content[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            elif ch == "/" and pos + 1 < len(content):
                # Skip string literals and comments
                next_ch = content[pos + 1]
                if next_ch == "/":
                    # Line comment — skip to end of line
                    nl = content.find("\n", pos)
                    if nl >= 0:
                        pos = nl
                    else:
                        break
                elif next_ch == "*":
                    # Block comment — skip to */
                    end_comment = content.find("*/", pos + 2)
                    if end_comment >= 0:
                        pos = end_comment + 1
                    else:
                        break
            elif ch == '"':
                # String literal — skip to closing quote
                pos += 1
                while pos < len(content) and content[pos] != '"':
                    if content[pos] == '\\':
                        pos += 1  # skip escaped char
                    pos += 1
            elif ch == "'":
                # Char literal
                pos += 1
                while pos < len(content) and content[pos] != "'":
                    if content[pos] == '\\':
                        pos += 1
                    pos += 1
            pos += 1

        body = content[func_start:pos]
        line_end = _offset_to_line(line_offsets, min(pos, len(content) - 1))

        handlers[func_name] = {
            "file": filepath,
            "line_start": line_start + 1,  # 1-indexed
            "line_end": line_end + 1,
            "body": body,
        }

    return handlers


def _offset_to_line(line_offsets, offset):
    """Convert a character offset to a 0-based line number."""
    lo, hi = 0, len(line_offsets) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if line_offsets[mid] <= offset:
            lo = mid + 1
        else:
            hi = mid - 1
    return hi


# ---------------------------------------------------------------------------
# Binary Handler Matching
# ---------------------------------------------------------------------------

def _opcode_to_handler_name(opcode_name):
    """Convert CMSG_FOO_BAR to HandleFooBar.

    Handles edge cases:
      - CMSG_QUERY_FOO → HandleQueryFoo
      - CMSG_DB_QUERY → HandleDbQuery
      - CMSG_SET_ACTIVE_MOVER → HandleSetActiveMover
    """
    # Strip direction prefix
    for prefix in ("CMSG_", "SMSG_", "MSG_"):
        if opcode_name.startswith(prefix):
            base = opcode_name[len(prefix):]
            break
    else:
        base = opcode_name

    # Convert UPPER_SNAKE_CASE to PascalCase
    parts = base.split("_")
    pascal = "".join(p.capitalize() for p in parts if p)
    return "Handle" + pascal


def _fuzzy_match_tc_handler(handler_func_name, tc_handlers):
    """Try to match a handler name using fuzzy strategies.

    Strategies:
      1. Exact match (already tried by caller)
      2. Case-insensitive match
      3. Suffix match (HandleFoo matches HandleSomethingFoo)
      4. Subsequence match on significant words
    """
    lower_target = handler_func_name.lower()

    # Case-insensitive exact
    for name, entry in tc_handlers.items():
        if name.lower() == lower_target:
            return entry

    # Check if the target is a substring of any TC handler or vice versa
    best_match = None
    best_score = 0.0
    for name, entry in tc_handlers.items():
        # Use SequenceMatcher for fuzzy name similarity
        ratio = difflib.SequenceMatcher(None, lower_target, name.lower()).ratio()
        if ratio > 0.85 and ratio > best_score:
            best_score = ratio
            best_match = entry

    if best_match:
        return best_match

    # Try matching by stripping common prefixes/suffixes
    # e.g., HandleSetFoo vs HandleFooSet
    stripped = lower_target.replace("handle", "")
    for name, entry in tc_handlers.items():
        name_stripped = name.lower().replace("handle", "")
        if stripped and name_stripped and (
            stripped in name_stripped or name_stripped in stripped
        ):
            return entry

    return None


# ---------------------------------------------------------------------------
# Code Normalization
# ---------------------------------------------------------------------------

def _normalize_code(code, is_binary=False):
    """Normalize code text for fair structural comparison.

    Strips comments, whitespace, normalizes types and variable names.
    Returns a list of normalized lines (blocks).
    """
    lines = code.split("\n")
    normalized = []

    for line in lines:
        norm = _normalize_line(line, is_binary)
        if norm:
            normalized.append(norm)

    return normalized


def _normalize_line(line, is_binary=False):
    """Normalize a single line of code.

    Returns normalized string, or empty string if line should be skipped.
    """
    stripped = line.strip()
    if not stripped:
        return ""

    # Strip single-line comments
    # Handle // comments but not inside strings
    result = _strip_line_comment(stripped)
    if not result.strip():
        return ""

    # Skip lines that are pure logging/debug
    if _is_logging_line(result):
        return ""

    # Skip opening/closing braces on their own lines
    if result.strip() in ("{", "}"):
        return ""

    # Normalize types
    result = _normalize_types(result)

    # Normalize whitespace
    result = re.sub(r'\s+', ' ', result).strip()

    # Normalize variable names to positional markers
    result = _normalize_variable_names(result, is_binary)

    return result


def _strip_line_comment(line):
    """Strip // comment from line, respecting string literals."""
    in_string = False
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if escape:
            escape = False
            i += 1
            continue
        if ch == '\\':
            escape = True
            i += 1
            continue
        if ch == '"':
            in_string = not in_string
        elif ch == '/' and not in_string and i + 1 < len(line) and line[i + 1] == '/':
            return line[:i]
        i += 1
    return line


def _is_logging_line(line):
    """Check if a line is a logging/debug statement that should be skipped."""
    lower = line.lower().strip()
    log_prefixes = (
        "tc_log_", "log_", "slog->", "printf(", "fprintf(",
        "msg(", "msg_info(", "msg_warn(", "msg_error(",
        "// ", "/* ", "* ", "/// ", "/** ",
    )
    for prefix in log_prefixes:
        if lower.startswith(prefix):
            return True

    # IDA-generated comments
    if lower.startswith("//") or lower.startswith("/*"):
        return True

    # Hex-Rays labels and jumps
    if re.match(r'^label_\d+:', lower) or re.match(r'^goto label_\d+', lower):
        return True

    return False


def _normalize_types(text):
    """Replace type variants with canonical forms."""
    for original, canonical in _TYPE_NORMALIZATIONS.items():
        # Word-boundary replacement
        text = re.sub(r'\b' + re.escape(original) + r'\b', canonical, text)
    return text


def _normalize_variable_names(text, is_binary=False):
    """Normalize variable names for comparison.

    Binary pseudocode uses v1, v2, a1, a2 style names.
    TC source uses descriptive names.
    We normalize both to positional: var_0, var_1, etc.

    This is done conservatively: only single-letter+digit patterns in
    binary code, and only local variable assignments in TC code.
    """
    if is_binary:
        # Replace Hex-Rays auto-names: v1, v2, a1, a2, result
        text = re.sub(r'\b[va]\d+\b', 'VAR', text)
        text = re.sub(r'\bresult\b', 'VAR', text)
    else:
        # In TC code, we keep meaningful names but normalize common patterns
        # like 'recvData', 'packet', 'pkt' to generic 'PKT'
        text = re.sub(r'\brecvData\b', 'PKT', text)
        text = re.sub(r'\bpacket\b', 'PKT', text)
        text = re.sub(r'\brecv\b', 'PKT', text)

    return text


# ---------------------------------------------------------------------------
# Structural Alignment
# ---------------------------------------------------------------------------

def _structural_align(norm_binary, norm_tc):
    """Perform structural alignment between normalized binary and TC code.

    Uses difflib.SequenceMatcher for initial alignment, then refines
    with block-level matching.

    Returns:
        dict: {matching_blocks, differing_blocks, matched_pairs,
               binary_only, tc_only, block_diff}
    """
    # Filter out empty lines
    bin_lines = [l for l in norm_binary if l]
    tc_lines = [l for l in norm_tc if l]

    if not bin_lines and not tc_lines:
        return {
            "matching_blocks": 0,
            "differing_blocks": 0,
            "matched_pairs": [],
            "binary_only": [],
            "tc_only": [],
            "block_diff": [],
            "ratio": 1.0,
        }

    if not bin_lines or not tc_lines:
        return {
            "matching_blocks": 0,
            "differing_blocks": max(len(bin_lines), len(tc_lines)),
            "matched_pairs": [],
            "binary_only": bin_lines,
            "tc_only": tc_lines,
            "block_diff": [],
            "ratio": 0.0,
        }

    # Phase 1: SequenceMatcher for overall alignment
    matcher = difflib.SequenceMatcher(None, bin_lines, tc_lines, autojunk=False)
    ratio = matcher.ratio()
    matching_blocks_raw = matcher.get_matching_blocks()

    # Count matching vs differing
    matching_count = sum(block.size for block in matching_blocks_raw)
    total_lines = max(len(bin_lines), len(tc_lines))
    differing_count = total_lines - matching_count

    # Phase 2: Extract matched pairs with context
    matched_pairs = []
    for block in matching_blocks_raw:
        if block.size > 0:
            for offset in range(block.size):
                matched_pairs.append({
                    "binary_idx": block.a + offset,
                    "tc_idx": block.b + offset,
                    "binary_line": bin_lines[block.a + offset],
                    "tc_line": tc_lines[block.b + offset],
                })

    # Phase 3: Extract binary-only and TC-only blocks
    binary_matched = set()
    tc_matched = set()
    for pair in matched_pairs:
        binary_matched.add(pair["binary_idx"])
        tc_matched.add(pair["tc_idx"])

    binary_only = []
    for i, line in enumerate(bin_lines):
        if i not in binary_matched:
            binary_only.append({"idx": i, "line": line})

    tc_only = []
    for i, line in enumerate(tc_lines):
        if i not in tc_matched:
            tc_only.append({"idx": i, "line": line})

    # Phase 4: Generate unified block diff
    block_diff = _generate_block_diff(bin_lines, tc_lines, matcher)

    return {
        "matching_blocks": matching_count,
        "differing_blocks": differing_count,
        "matched_pairs": matched_pairs,
        "binary_only": binary_only,
        "tc_only": tc_only,
        "block_diff": block_diff,
        "ratio": ratio,
    }


def _generate_block_diff(bin_lines, tc_lines, matcher):
    """Generate a block-level diff with operation tags.

    Each block has:
      - op: 'equal', 'replace', 'insert', 'delete'
      - binary_lines: lines from binary side
      - tc_lines: lines from TC side
    """
    blocks = []
    opcodes = matcher.get_opcodes()

    for tag, i1, i2, j1, j2 in opcodes:
        block = {
            "op": tag,
            "binary_range": [i1, i2],
            "tc_range": [j1, j2],
            "binary_lines": bin_lines[i1:i2],
            "tc_lines": tc_lines[j1:j2],
        }
        blocks.append(block)

    return blocks


# ---------------------------------------------------------------------------
# Difference Classification
# ---------------------------------------------------------------------------

def _classify_differences(alignment, raw_binary, raw_tc, norm_binary, norm_tc):
    """Classify each structural difference by type and severity.

    Examines binary-only blocks, TC-only blocks, and replace blocks
    to determine what kind of divergence each represents.

    Returns:
        list of dicts: [{type, severity, binary_code, tc_code, description}]
    """
    differences = []

    for block in alignment.get("block_diff", []):
        op = block["op"]
        bin_lines = block.get("binary_lines", [])
        tc_lines = block.get("tc_lines", [])

        if op == "equal":
            continue

        if op == "delete":
            # Lines present in binary but not TC
            for line in bin_lines:
                diff = _classify_single_binary_only(line, raw_binary)
                if diff:
                    differences.append(diff)

        elif op == "insert":
            # Lines present in TC but not binary
            for line in tc_lines:
                diff = _classify_single_tc_only(line, raw_tc)
                if diff:
                    differences.append(diff)

        elif op == "replace":
            # Both sides have code but it differs
            diffs = _classify_replacement(bin_lines, tc_lines, raw_binary, raw_tc)
            differences.extend(diffs)

    # Deduplicate similar differences
    differences = _deduplicate_differences(differences)

    return differences


def _classify_single_binary_only(norm_line, raw_binary):
    """Classify a single binary-only line."""
    lower = norm_line.lower()

    # Check for validation patterns
    if _is_validation_pattern(norm_line):
        return {
            "type": DIV_MISSING_VALIDATION,
            "severity": SEV_HIGH,
            "binary_code": norm_line,
            "tc_code": "",
            "description": f"Binary has validation check not present in TC: {norm_line[:120]}",
        }

    # Check for notification/response sends
    if _is_notification_pattern(norm_line):
        return {
            "type": DIV_MISSING_NOTIFICATION,
            "severity": SEV_MEDIUM,
            "binary_code": norm_line,
            "tc_code": "",
            "description": f"Binary sends response/notification not in TC: {norm_line[:120]}",
        }

    # Check for function calls that look like important logic
    if _is_logic_call(norm_line):
        return {
            "type": DIV_MISSING_LOGIC,
            "severity": SEV_HIGH,
            "binary_code": norm_line,
            "tc_code": "",
            "description": f"Binary has logic block not in TC: {norm_line[:120]}",
        }

    # Generic missing code
    if len(norm_line) > 5:
        return {
            "type": DIV_MISSING_LOGIC,
            "severity": SEV_MEDIUM,
            "binary_code": norm_line,
            "tc_code": "",
            "description": f"Binary-only code: {norm_line[:120]}",
        }

    return None


def _classify_single_tc_only(norm_line, raw_tc):
    """Classify a single TC-only line."""
    lower = norm_line.lower()

    # TC-only validation might be extra server-side hardening
    if _is_validation_pattern(norm_line):
        return {
            "type": DIV_EXTRA_TC_CODE,
            "severity": SEV_LOW,
            "binary_code": "",
            "tc_code": norm_line,
            "description": f"TC has extra validation not in binary (server-side hardening): "
                          f"{norm_line[:120]}",
        }

    # TC-only logic (could be server-specific)
    if len(norm_line) > 5:
        return {
            "type": DIV_EXTRA_TC_CODE,
            "severity": SEV_LOW,
            "binary_code": "",
            "tc_code": norm_line,
            "description": f"TC-only code (may be server-specific): {norm_line[:120]}",
        }

    return None


def _classify_replacement(bin_lines, tc_lines, raw_binary, raw_tc):
    """Classify a replacement block where both sides have different code."""
    differences = []

    # Try to pair up lines within the replacement block
    inner_matcher = difflib.SequenceMatcher(
        None, bin_lines, tc_lines, autojunk=False
    )

    for tag, i1, i2, j1, j2 in inner_matcher.get_opcodes():
        if tag == "equal":
            continue

        bin_chunk = bin_lines[i1:i2]
        tc_chunk = tc_lines[j1:j2]
        bin_text = " ".join(bin_chunk)
        tc_text = " ".join(tc_chunk)

        # Check if same structure but different constants
        if _are_structurally_similar(bin_text, tc_text):
            const_diffs = _find_constant_differences(bin_text, tc_text)
            if const_diffs:
                differences.append({
                    "type": DIV_DIFFERENT_CONSTANTS,
                    "severity": SEV_MEDIUM,
                    "binary_code": bin_text[:200],
                    "tc_code": tc_text[:200],
                    "description": f"Same structure, different constants: {const_diffs}",
                })
                continue

        # Check for reordered operations
        if _are_reordered(bin_chunk, tc_chunk):
            differences.append({
                "type": DIV_DIFFERENT_ORDER,
                "severity": SEV_LOW,
                "binary_code": bin_text[:200],
                "tc_code": tc_text[:200],
                "description": "Same operations in different order",
            })
            continue

        # Check for different error handling
        if _is_error_handling_diff(bin_text, tc_text):
            differences.append({
                "type": DIV_DIFFERENT_ERROR_HANDLING,
                "severity": SEV_MEDIUM,
                "binary_code": bin_text[:200],
                "tc_code": tc_text[:200],
                "description": "Different error handling paths",
            })
            continue

        # Check for binary-only validation
        if bin_chunk and not tc_chunk:
            for line in bin_chunk:
                d = _classify_single_binary_only(line, raw_binary)
                if d:
                    differences.append(d)
            continue

        # Check for TC-only code
        if tc_chunk and not bin_chunk:
            for line in tc_chunk:
                d = _classify_single_tc_only(line, raw_tc)
                if d:
                    differences.append(d)
            continue

        # Generic difference
        if bin_chunk:
            severity = SEV_HIGH if _is_validation_pattern(bin_text) else SEV_MEDIUM
            differences.append({
                "type": DIV_MISSING_LOGIC if not tc_chunk else DIV_MISSING_LOGIC,
                "severity": severity,
                "binary_code": bin_text[:200],
                "tc_code": tc_text[:200],
                "description": f"Structural divergence ({len(bin_chunk)} binary lines "
                              f"vs {len(tc_chunk)} TC lines)",
            })

    return differences


def _is_validation_pattern(text):
    """Check if text represents a validation/guard check."""
    lower = text.lower()
    patterns = [
        r'if\s*\(.+\)\s*return',
        r'if\s*\(\s*!\w+\s*\)',
        r'if\s*\(.+[<>=!]+.+\)\s*\{?\s*return',
        r'check\w*\(',
        r'validate\w*\(',
        r'is_?valid\w*\(',
        r'has_?permission\(',
        r'can_?\w+\(',
        r'assert\s*\(',
    ]
    for pattern in patterns:
        if re.search(pattern, lower):
            return True
    return False


def _is_notification_pattern(text):
    """Check if text is sending a response packet or notification."""
    lower = text.lower()
    indicators = [
        "sendpacket", "send_packet", "sendmessage",
        "worldpacket", "smsg_", "send(", "sendto(",
        "response", "notify", "broadcast",
    ]
    return any(ind in lower for ind in indicators)


def _is_logic_call(text):
    """Check if text contains a meaningful logic function call."""
    # Look for function calls that aren't just utility/accessor
    call_match = re.search(r'\b([A-Z]\w{3,})\s*\(', text)
    if call_match:
        func_name = call_match.group(1)
        # Skip common accessors
        accessors = {"GetGUID", "GetName", "GetLevel", "GetMap", "GetSession",
                      "GetPlayer", "GetEntry", "GetGO", "ToString", "GetSize"}
        if func_name not in accessors:
            return True
    return False


def _are_structurally_similar(text_a, text_b):
    """Check if two code snippets have the same structure but different values."""
    # Replace all numbers and identifiers, compare skeletons
    skeleton_a = re.sub(r'0x[0-9a-fA-F]+|\b\d+\b', 'NUM', text_a)
    skeleton_a = re.sub(r'\b[a-zA-Z_]\w*\b', 'ID', skeleton_a)
    skeleton_b = re.sub(r'0x[0-9a-fA-F]+|\b\d+\b', 'NUM', text_b)
    skeleton_b = re.sub(r'\b[a-zA-Z_]\w*\b', 'ID', skeleton_b)
    return skeleton_a == skeleton_b


def _find_constant_differences(text_a, text_b):
    """Extract specific constant value differences between two code snippets."""
    nums_a = re.findall(r'0x[0-9a-fA-F]+|\b\d{2,}\b', text_a)
    nums_b = re.findall(r'0x[0-9a-fA-F]+|\b\d{2,}\b', text_b)

    diffs = []
    for na, nb in zip(nums_a, nums_b):
        if na != nb:
            diffs.append(f"{na} vs {nb}")

    return "; ".join(diffs[:5]) if diffs else ""


def _are_reordered(bin_lines, tc_lines):
    """Check if the same operations appear in a different order."""
    if not bin_lines or not tc_lines:
        return False

    # Extract operation signatures (function calls)
    def extract_ops(lines):
        ops = []
        for line in lines:
            calls = re.findall(r'\b([A-Za-z]\w+)\s*\(', line)
            ops.extend(c for c in calls if c not in _CPP_KEYWORDS)
        return ops

    bin_ops = extract_ops(bin_lines)
    tc_ops = extract_ops(tc_lines)

    if not bin_ops or not tc_ops:
        return False

    # Same operations but different order?
    return sorted(bin_ops) == sorted(tc_ops) and bin_ops != tc_ops


def _is_error_handling_diff(text_a, text_b):
    """Check if the difference is in error handling paths."""
    error_keywords = ["error", "fail", "invalid", "return", "throw", "abort",
                      "disconnect", "kick", "close"]
    a_has_error = any(kw in text_a.lower() for kw in error_keywords)
    b_has_error = any(kw in text_b.lower() for kw in error_keywords)
    return a_has_error and b_has_error


def _deduplicate_differences(differences):
    """Remove near-duplicate difference entries."""
    if len(differences) <= 1:
        return differences

    seen_keys = set()
    unique = []
    for diff in differences:
        # Create a dedup key from type + first 50 chars of code
        key = (
            diff["type"],
            diff.get("binary_code", "")[:50],
            diff.get("tc_code", "")[:50],
        )
        if key not in seen_keys:
            seen_keys.add(key)
            unique.append(diff)

    return unique


# ---------------------------------------------------------------------------
# Alignment Scoring
# ---------------------------------------------------------------------------

def _compute_alignment_score(alignment, differences):
    """Compute a 0-100 alignment score.

    Factors:
      - Base ratio from SequenceMatcher (40%)
      - Penalty for critical/high divergences (30%)
      - Penalty for missing validations (20%)
      - Bonus for matching block count (10%)
    """
    ratio = alignment.get("ratio", 0.0)
    matching = alignment.get("matching_blocks", 0)
    differing = alignment.get("differing_blocks", 0)
    total_blocks = matching + differing

    # Base score from ratio
    base_score = ratio * 100.0

    # Severity penalty
    severity_weights = {
        SEV_CRITICAL: 8.0,
        SEV_HIGH: 4.0,
        SEV_MEDIUM: 2.0,
        SEV_LOW: 0.5,
    }
    total_penalty = 0.0
    for diff in differences:
        sev = diff.get("severity", SEV_LOW)
        total_penalty += severity_weights.get(sev, 0.5)

    # Cap penalty at 60 points
    severity_penalty = min(60.0, total_penalty)

    # Missing validation penalty
    missing_val_count = sum(
        1 for d in differences if d["type"] == DIV_MISSING_VALIDATION
    )
    validation_penalty = min(20.0, missing_val_count * 5.0)

    # Block match bonus
    if total_blocks > 0:
        block_ratio = matching / total_blocks
        block_bonus = block_ratio * 10.0
    else:
        block_bonus = 5.0

    score = (
        base_score * 0.40
        - severity_penalty * 0.30
        - validation_penalty * 0.20
        + block_bonus * 0.10
    )

    return max(0.0, min(100.0, round(score, 1)))


# ---------------------------------------------------------------------------
# System Classification
# ---------------------------------------------------------------------------

def _classify_system(opcode_name):
    """Map an opcode name to a game system."""
    upper = opcode_name.upper()
    for keyword, system in _SYSTEM_KEYWORDS.items():
        if keyword in upper:
            return system
    return "Other"


# ---------------------------------------------------------------------------
# Aggregate Computation
# ---------------------------------------------------------------------------

def _compute_aggregate(alignments):
    """Compute aggregate statistics across all aligned handlers."""
    if not alignments:
        return {
            "total_handlers_compared": 0,
            "avg_alignment_score": 0.0,
            "fully_aligned": 0,
            "partially_aligned": 0,
            "severely_divergent": 0,
            "divergence_by_type": {},
            "divergence_by_system": {},
            "divergence_by_severity": {},
        }

    scores = [a["alignment_score"] for a in alignments]
    avg_score = sum(scores) / len(scores)

    fully_aligned = sum(1 for s in scores if s >= 90.0)
    partially_aligned = sum(1 for s in scores if 50.0 <= s < 90.0)
    severely_divergent = sum(1 for s in scores if s < 50.0)

    # Count divergences by type
    div_by_type = collections.Counter()
    div_by_severity = collections.Counter()
    for a in alignments:
        for d in a.get("differences", []):
            div_by_type[d["type"]] += 1
            div_by_severity[d["severity"]] += 1

    # Per-system scores
    system_scores = collections.defaultdict(list)
    for a in alignments:
        system = a.get("system", "Other")
        system_scores[system].append(a["alignment_score"])

    div_by_system = {}
    for system, sys_scores in system_scores.items():
        div_by_system[system] = {
            "avg_score": round(sum(sys_scores) / len(sys_scores), 1),
            "handler_count": len(sys_scores),
            "min_score": round(min(sys_scores), 1),
            "max_score": round(max(sys_scores), 1),
            "fully_aligned": sum(1 for s in sys_scores if s >= 90.0),
            "severely_divergent": sum(1 for s in sys_scores if s < 50.0),
        }

    return {
        "total_handlers_compared": len(alignments),
        "avg_alignment_score": round(avg_score, 1),
        "median_alignment_score": round(sorted(scores)[len(scores) // 2], 1),
        "fully_aligned": fully_aligned,
        "partially_aligned": partially_aligned,
        "severely_divergent": severely_divergent,
        "divergence_by_type": dict(div_by_type),
        "divergence_by_system": div_by_system,
        "divergence_by_severity": dict(div_by_severity),
    }


# ---------------------------------------------------------------------------
# Missing / Extra Extraction
# ---------------------------------------------------------------------------

def _extract_missing_in_tc(alignments):
    """Extract all binary-only code blocks as potential TC additions.

    These are code blocks present in the binary handler but absent from
    the TC implementation — strong candidates for missing features.
    """
    missing = []

    for a in alignments:
        handler_diffs = [
            d for d in a.get("differences", [])
            if d["type"] in (DIV_MISSING_VALIDATION, DIV_MISSING_LOGIC,
                             DIV_MISSING_NOTIFICATION)
        ]
        if not handler_diffs:
            continue

        binary_blocks = [d["binary_code"] for d in handler_diffs if d["binary_code"]]
        if not binary_blocks:
            continue

        # Determine overall severity (highest from any difference)
        severity_order = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_LOW: 3}
        worst_severity = min(
            handler_diffs,
            key=lambda d: severity_order.get(d["severity"], 99)
        )["severity"]

        missing.append({
            "handler": a["tc_handler"],
            "opcode": a["opcode"],
            "binary_ea": a["binary_ea"],
            "binary_blocks": binary_blocks[:20],  # cap to avoid huge results
            "severity": worst_severity,
            "tc_file": a["tc_file"],
            "tc_line_start": a["tc_line_start"],
            "difference_count": len(handler_diffs),
        })

    # Sort by severity then by number of differences
    severity_sort = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_LOW: 3}
    missing.sort(key=lambda m: (
        severity_sort.get(m["severity"], 99),
        -m["difference_count"]
    ))

    return missing


def _extract_extra_in_tc(alignments):
    """Extract TC-only code blocks — server-specific additions beyond binary."""
    extra = []

    for a in alignments:
        tc_diffs = [
            d for d in a.get("differences", [])
            if d["type"] == DIV_EXTRA_TC_CODE
        ]
        if not tc_diffs:
            continue

        tc_blocks = [d["tc_code"] for d in tc_diffs if d["tc_code"]]
        if not tc_blocks:
            continue

        extra.append({
            "handler": a["tc_handler"],
            "opcode": a["opcode"],
            "tc_blocks": tc_blocks[:20],
            "tc_file": a["tc_file"],
        })

    return extra


# ---------------------------------------------------------------------------
# Serialization Helpers
# ---------------------------------------------------------------------------

def _serialize_alignments(alignments):
    """Prepare alignments for JSON storage, stripping large internal data."""
    serialized = []
    for a in alignments:
        entry = {
            "opcode": a["opcode"],
            "tc_handler": a["tc_handler"],
            "binary_ea": a["binary_ea"],
            "alignment_score": a["alignment_score"],
            "matching_blocks": a["matching_blocks"],
            "differing_blocks": a["differing_blocks"],
            "differences": a["differences"][:50],  # cap per handler
            "tc_file": a["tc_file"],
            "tc_line_start": a["tc_line_start"],
            "tc_line_end": a["tc_line_end"],
            "binary_line_count": a["binary_line_count"],
            "tc_line_count": a["tc_line_count"],
            "system": a["system"],
        }
        serialized.append(entry)
    return serialized


# ---------------------------------------------------------------------------
# Summary Output
# ---------------------------------------------------------------------------

def _print_summary(aggregate, alignments):
    """Print a human-readable summary to IDA output."""
    msg("")
    msg("=" * 70)
    msg("  BINARY <-> TRINITYCORE HANDLER ALIGNMENT REPORT")
    msg("=" * 70)
    msg("")
    msg(f"  Handlers compared:   {aggregate['total_handlers_compared']}")
    msg(f"  Average alignment:   {aggregate['avg_alignment_score']}%")
    msg(f"  Median alignment:    {aggregate.get('median_alignment_score', 'N/A')}%")
    msg(f"  Fully aligned (90%+): {aggregate['fully_aligned']}")
    msg(f"  Partially aligned:    {aggregate['partially_aligned']}")
    msg(f"  Severely divergent:   {aggregate['severely_divergent']}")
    msg("")

    # Per-system breakdown
    sys_data = aggregate.get("divergence_by_system", {})
    if sys_data:
        msg("  Per-System Alignment Scores:")
        msg("  " + "-" * 50)
        for system, data in sorted(sys_data.items(),
                                    key=lambda x: x[1]["avg_score"]):
            msg(f"    {system:20s}  {data['avg_score']:5.1f}%  "
                f"({data['handler_count']} handlers, "
                f"min={data['min_score']:.0f}%, max={data['max_score']:.0f}%)")
        msg("")

    # Divergence type breakdown
    div_types = aggregate.get("divergence_by_type", {})
    if div_types:
        msg("  Divergence Types:")
        msg("  " + "-" * 50)
        for dtype, count in sorted(div_types.items(), key=lambda x: -x[1]):
            msg(f"    {dtype:30s}  {count:5d}")
        msg("")

    # Severity breakdown
    div_sev = aggregate.get("divergence_by_severity", {})
    if div_sev:
        msg("  Severity Distribution:")
        msg("  " + "-" * 50)
        for sev, count in sorted(div_sev.items()):
            msg(f"    {sev:12s}  {count:5d}")
        msg("")

    # Top 20 most divergent handlers
    worst = sorted(alignments, key=lambda a: a["alignment_score"])[:20]
    if worst:
        msg("  20 Most Divergent Handlers:")
        msg("  " + "-" * 60)
        for a in worst:
            ndiffs = len(a.get("differences", []))
            msg(f"    {a['alignment_score']:5.1f}%  {a['opcode']:40s}  "
                f"{ndiffs:3d} diffs  {a['binary_ea']}")
        msg("")

    msg("=" * 70)
    msg("")


# ---------------------------------------------------------------------------
# Export Functions
# ---------------------------------------------------------------------------

def export_handler_diff(session, handler_name):
    """Generate a side-by-side diff report for a single handler.

    Args:
        session: PluginSession
        handler_name: TC handler function name (e.g. 'HandleFooBar')
                      or opcode name (e.g. 'CMSG_FOO_BAR')

    Returns:
        str: Formatted diff text, or error message.
    """
    data = get_alignment_report(session)
    if not data:
        return "No alignment data available. Run align_binary_to_tc() first."

    # Find the alignment entry
    target = None
    for a in data.get("alignments", []):
        if (a.get("tc_handler") == handler_name or
                a.get("opcode") == handler_name):
            target = a
            break

    if not target:
        return f"Handler '{handler_name}' not found in alignment data."

    lines = []
    lines.append(f"Handler Diff: {target['opcode']}")
    lines.append(f"  TC Handler:  {target['tc_handler']}")
    lines.append(f"  Binary EA:   {target['binary_ea']}")
    lines.append(f"  TC File:     {target['tc_file']}")
    lines.append(f"  TC Lines:    {target['tc_line_start']}-{target['tc_line_end']}")
    lines.append(f"  Alignment:   {target['alignment_score']}%")
    lines.append(f"  Matching:    {target['matching_blocks']} blocks")
    lines.append(f"  Differing:   {target['differing_blocks']} blocks")
    lines.append("")

    diffs = target.get("differences", [])
    if not diffs:
        lines.append("  No differences found — handlers are aligned.")
    else:
        lines.append(f"  {len(diffs)} Differences:")
        lines.append("  " + "-" * 60)
        for i, d in enumerate(diffs, 1):
            lines.append(f"  [{i}] {d['type']} ({d['severity']})")
            lines.append(f"      {d['description']}")
            if d.get("binary_code"):
                lines.append(f"      BINARY: {d['binary_code'][:120]}")
            if d.get("tc_code"):
                lines.append(f"      TC:     {d['tc_code'][:120]}")
            lines.append("")

    return "\n".join(lines)


def export_missing_blocks(session):
    """Export all binary-only code blocks formatted as potential TC patches.

    Returns:
        str: Formatted text with all missing blocks grouped by handler.
    """
    data = get_alignment_report(session)
    if not data:
        return "No alignment data available. Run align_binary_to_tc() first."

    missing = data.get("missing_in_tc", [])
    if not missing:
        return "No missing blocks detected. TC handlers appear complete."

    lines = []
    lines.append("=" * 70)
    lines.append("  MISSING CODE BLOCKS — Binary Has, TC Doesn't")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"  Total handlers with missing code: {len(missing)}")
    lines.append("")

    for entry in missing:
        lines.append(f"  Handler: {entry['handler']} ({entry['opcode']})")
        lines.append(f"  Binary:  {entry['binary_ea']}")
        lines.append(f"  TC File: {entry['tc_file']}:{entry['tc_line_start']}")
        lines.append(f"  Severity: {entry['severity']}")
        lines.append(f"  Missing blocks ({entry['difference_count']}):")

        for j, block in enumerate(entry.get("binary_blocks", []), 1):
            lines.append(f"    [{j}] {block}")

        lines.append("")
        lines.append("  " + "-" * 50)
        lines.append("")

    return "\n".join(lines)


def get_worst_handlers(session, n=20):
    """Return the N most divergent handlers from stored alignment data.

    Args:
        session: PluginSession
        n: Number of handlers to return (default 20)

    Returns:
        list of dicts with opcode, tc_handler, alignment_score,
        difference_count, system, binary_ea.
    """
    data = get_alignment_report(session)
    if not data:
        return []

    alignments = data.get("alignments", [])
    if not alignments:
        return []

    # Sort by alignment score ascending (worst first)
    sorted_aligns = sorted(alignments, key=lambda a: a["alignment_score"])

    results = []
    for a in sorted_aligns[:n]:
        results.append({
            "opcode": a["opcode"],
            "tc_handler": a["tc_handler"],
            "alignment_score": a["alignment_score"],
            "difference_count": len(a.get("differences", [])),
            "system": a.get("system", "Other"),
            "binary_ea": a["binary_ea"],
            "matching_blocks": a["matching_blocks"],
            "differing_blocks": a["differing_blocks"],
            "tc_file": a.get("tc_file", ""),
        })

    return results


def get_system_summary(session):
    """Return per-system alignment summary from stored data.

    Returns:
        dict: system_name -> {avg_score, handler_count, worst_handler, ...}
    """
    data = get_alignment_report(session)
    if not data:
        return {}

    aggregate = data.get("aggregate", {})
    return aggregate.get("divergence_by_system", {})


def get_divergence_stats(session):
    """Return divergence type and severity statistics.

    Returns:
        dict: {by_type: {type: count}, by_severity: {sev: count},
               total_differences: int}
    """
    data = get_alignment_report(session)
    if not data:
        return {"by_type": {}, "by_severity": {}, "total_differences": 0}

    aggregate = data.get("aggregate", {})
    by_type = aggregate.get("divergence_by_type", {})
    by_severity = aggregate.get("divergence_by_severity", {})
    total = sum(by_type.values())

    return {
        "by_type": by_type,
        "by_severity": by_severity,
        "total_differences": total,
    }


def export_system_report(session, system_name):
    """Export a detailed report for all handlers in a specific system.

    Args:
        session: PluginSession
        system_name: e.g. 'Housing', 'Combat', 'Quest'

    Returns:
        str: Formatted report text.
    """
    data = get_alignment_report(session)
    if not data:
        return "No alignment data available."

    system_alignments = [
        a for a in data.get("alignments", [])
        if a.get("system", "").lower() == system_name.lower()
    ]

    if not system_alignments:
        return f"No handlers found for system '{system_name}'."

    system_alignments.sort(key=lambda a: a["alignment_score"])

    lines = []
    lines.append(f"System Report: {system_name}")
    lines.append("=" * 60)
    lines.append(f"  Handlers: {len(system_alignments)}")

    scores = [a["alignment_score"] for a in system_alignments]
    lines.append(f"  Average Score: {sum(scores) / len(scores):.1f}%")
    lines.append(f"  Min Score:     {min(scores):.1f}%")
    lines.append(f"  Max Score:     {max(scores):.1f}%")
    lines.append("")

    for a in system_alignments:
        ndiffs = len(a.get("differences", []))
        lines.append(f"  {a['alignment_score']:5.1f}%  {a['opcode']:40s}  "
                     f"{ndiffs} diffs")
        for d in a.get("differences", [])[:5]:
            lines.append(f"         [{d['severity'][:3]}] {d['type']}: "
                        f"{d['description'][:80]}")
        lines.append("")

    return "\n".join(lines)


def export_conformance_patches(session, min_severity=SEV_HIGH):
    """Export suggested TC code patches based on binary-only blocks.

    Generates pseudo-patch output for handlers where the binary has
    code blocks not present in TC, filtered by minimum severity.

    Args:
        session: PluginSession
        min_severity: Minimum severity to include (default HIGH)

    Returns:
        str: Patch-like text output.
    """
    data = get_alignment_report(session)
    if not data:
        return "No alignment data available."

    severity_order = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_LOW: 3}
    min_sev_val = severity_order.get(min_severity, 1)

    lines = []
    lines.append("// TC Conformance Patches — Generated from Binary Analysis")
    lines.append(f"// Minimum severity: {min_severity}")
    lines.append(f"// Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    patch_count = 0
    for a in data.get("alignments", []):
        handler_patches = []
        for d in a.get("differences", []):
            sev_val = severity_order.get(d.get("severity", SEV_LOW), 3)
            if sev_val > min_sev_val:
                continue
            if d["type"] not in (DIV_MISSING_VALIDATION, DIV_MISSING_LOGIC,
                                  DIV_MISSING_NOTIFICATION):
                continue
            if not d.get("binary_code"):
                continue
            handler_patches.append(d)

        if not handler_patches:
            continue

        lines.append(f"// --- {a['tc_handler']} ({a['opcode']}) ---")
        lines.append(f"// File: {a.get('tc_file', 'unknown')}")
        lines.append(f"// Line: {a.get('tc_line_start', '?')}")
        lines.append(f"// Alignment: {a['alignment_score']}%")
        lines.append("")

        for d in handler_patches:
            lines.append(f"// [{d['severity']}] {d['type']}: {d['description']}")
            lines.append(f"// Binary code to add:")
            for code_line in d["binary_code"].split("\n"):
                lines.append(f"+  {code_line.strip()}")
            lines.append("")
            patch_count += 1

        lines.append("")

    lines.insert(3, f"// Total patches: {patch_count}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Data Retrieval
# ---------------------------------------------------------------------------

def get_alignment_report(session):
    """Retrieve the stored binary-TC alignment data.

    Returns:
        dict or None: The full alignment report, or None if not yet run.
    """
    return session.db.kv_get("binary_tc_alignment")


def get_handler_alignment(session, handler_name):
    """Retrieve alignment data for a specific handler.

    Args:
        session: PluginSession
        handler_name: TC handler name or opcode name.

    Returns:
        dict or None: The alignment entry for this handler.
    """
    data = get_alignment_report(session)
    if not data:
        return None

    for a in data.get("alignments", []):
        if (a.get("tc_handler") == handler_name or
                a.get("opcode") == handler_name):
            return a

    return None


def get_handlers_by_system(session, system_name):
    """Retrieve all alignment entries for a specific game system.

    Args:
        session: PluginSession
        system_name: e.g. 'Housing', 'Combat'

    Returns:
        list of dicts: Alignment entries for the system.
    """
    data = get_alignment_report(session)
    if not data:
        return []

    return [
        a for a in data.get("alignments", [])
        if a.get("system", "").lower() == system_name.lower()
    ]


def get_critical_divergences(session):
    """Retrieve all CRITICAL severity divergences across all handlers.

    Returns:
        list of dicts: Each with handler info and the critical difference.
    """
    data = get_alignment_report(session)
    if not data:
        return []

    critical = []
    for a in data.get("alignments", []):
        for d in a.get("differences", []):
            if d.get("severity") == SEV_CRITICAL:
                critical.append({
                    "handler": a["tc_handler"],
                    "opcode": a["opcode"],
                    "binary_ea": a["binary_ea"],
                    "tc_file": a.get("tc_file", ""),
                    "difference": d,
                })

    return critical


# ---------------------------------------------------------------------------
# Incremental / Filtered Analysis
# ---------------------------------------------------------------------------

def align_single_handler(session, opcode_name):
    """Align a single handler by opcode name.

    Useful for quick checks without running the full analysis.

    Args:
        session: PluginSession
        opcode_name: e.g. 'CMSG_HOUSING_PLACE_DECOR'

    Returns:
        dict or None: Alignment result for this handler.
    """
    db = session.db
    cfg = session.cfg
    tc_dir = cfg.tc_source_dir

    if not tc_dir or not os.path.isdir(tc_dir):
        msg_error("TC source directory not configured")
        return None

    # Find handler EA from opcodes table
    row = db.fetchone(
        "SELECT * FROM opcodes WHERE tc_name = ? AND handler_ea IS NOT NULL",
        (opcode_name,)
    )
    if not row:
        msg_warn(f"No handler found for opcode {opcode_name}")
        return None

    handler_ea = row["handler_ea"]
    handler_func_name = _opcode_to_handler_name(opcode_name)

    # Find TC source
    tc_handlers = _discover_tc_handlers(tc_dir)
    tc_entry = tc_handlers.get(handler_func_name)
    if not tc_entry:
        tc_entry = _fuzzy_match_tc_handler(handler_func_name, tc_handlers)
    if not tc_entry:
        msg_warn(f"TC handler '{handler_func_name}' not found in source")
        return None

    # Decompile
    binary_text = get_decompiled_text(handler_ea)
    if not binary_text:
        msg_warn(f"Failed to decompile handler at {ea_str(handler_ea)}")
        return None

    tc_source = tc_entry["body"]

    # Normalize
    norm_binary = _normalize_code(binary_text, is_binary=True)
    norm_tc = _normalize_code(tc_source, is_binary=False)

    # Align
    alignment = _structural_align(norm_binary, norm_tc)
    differences = _classify_differences(
        alignment, binary_text, tc_source, norm_binary, norm_tc
    )
    score = _compute_alignment_score(alignment, differences)

    result = {
        "opcode": opcode_name,
        "tc_handler": handler_func_name,
        "binary_ea": f"0x{handler_ea:X}",
        "alignment_score": score,
        "matching_blocks": alignment["matching_blocks"],
        "differing_blocks": alignment["differing_blocks"],
        "differences": differences,
        "tc_file": tc_entry["file"],
        "tc_line_start": tc_entry["line_start"],
        "tc_line_end": tc_entry["line_end"],
        "system": _classify_system(opcode_name),
    }

    msg_info(f"Single handler alignment: {opcode_name} = {score:.1f}% "
             f"({len(differences)} differences)")

    return result


def align_system(session, system_name):
    """Align all handlers for a specific game system.

    Args:
        session: PluginSession
        system_name: e.g. 'Housing', 'Combat'

    Returns:
        int: Number of handlers aligned.
    """
    db = session.db
    cfg = session.cfg
    tc_dir = cfg.tc_source_dir

    if not tc_dir:
        msg_error("TC source directory not configured")
        return 0

    # Find all opcodes matching the system
    all_opcodes = db.fetchall(
        "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL "
        "AND tc_name IS NOT NULL AND handler_ea != 0"
    )

    system_opcodes = [
        row for row in all_opcodes
        if _classify_system(row["tc_name"]).lower() == system_name.lower()
    ]

    if not system_opcodes:
        msg_warn(f"No opcodes found for system '{system_name}'")
        return 0

    msg_info(f"Aligning {len(system_opcodes)} handlers for system '{system_name}'")

    # Discover TC handlers once
    tc_handlers = _discover_tc_handlers(tc_dir)
    alignments = []

    for row in system_opcodes:
        tc_name = row["tc_name"]
        handler_ea = row["handler_ea"]
        handler_func_name = _opcode_to_handler_name(tc_name)

        tc_entry = tc_handlers.get(handler_func_name)
        if not tc_entry:
            tc_entry = _fuzzy_match_tc_handler(handler_func_name, tc_handlers)
        if not tc_entry:
            continue

        binary_text = get_decompiled_text(handler_ea)
        if not binary_text:
            continue

        tc_source = tc_entry["body"]
        if not tc_source or len(tc_source.strip()) < 10:
            continue

        norm_binary = _normalize_code(binary_text, is_binary=True)
        norm_tc = _normalize_code(tc_source, is_binary=False)

        alignment = _structural_align(norm_binary, norm_tc)
        differences = _classify_differences(
            alignment, binary_text, tc_source, norm_binary, norm_tc
        )
        score = _compute_alignment_score(alignment, differences)

        entry = {
            "opcode": tc_name,
            "tc_handler": handler_func_name,
            "binary_ea": f"0x{handler_ea:X}",
            "alignment_score": score,
            "matching_blocks": alignment["matching_blocks"],
            "differing_blocks": alignment["differing_blocks"],
            "differences": differences,
            "tc_file": tc_entry["file"],
            "tc_line_start": tc_entry["line_start"],
            "tc_line_end": tc_entry["line_end"],
            "system": system_name,
        }
        alignments.append(entry)

    msg_info(f"  Aligned {len(alignments)} handlers for {system_name}")

    # Store under system-specific key
    system_key = f"binary_tc_alignment_{system_name.lower()}"
    aggregate = _compute_aggregate(alignments)
    result = {
        "alignments": _serialize_alignments(alignments),
        "aggregate": aggregate,
        "missing_in_tc": _extract_missing_in_tc(alignments),
        "extra_in_tc": _extract_extra_in_tc(alignments),
        "timestamp": time.time(),
    }
    db.kv_set(system_key, result)
    db.commit()

    _print_summary(aggregate, alignments)
    return len(alignments)
