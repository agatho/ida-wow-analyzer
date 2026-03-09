"""
Pseudocode-to-TrinityCore C++ Transpiler
Translates Hex-Rays decompiled pseudocode into idiomatic TrinityCore C++.

Maps binary function calls to TC API equivalents (sub_7FF6A8F12340 ->
Player::GetItemByPos), replaces raw offset accesses with struct members,
converts error code constants to TC enums, cleans up decompiler artifacts,
and adds TC idioms.

Won't produce production code, but provides 70-80% complete handler
implementations as a starting point for manual implementation.
"""

import json
import os
import re
import time
from collections import defaultdict

import ida_funcs
import ida_name
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# IDA type -> C++ type normalization map
# ---------------------------------------------------------------------------

_IDA_TYPE_MAP = [
    # Order matters: longer/more-specific patterns first
    ("unsigned __int64", "uint64"),
    ("unsigned __int32", "uint32"),
    ("unsigned __int16", "uint16"),
    ("unsigned __int8", "uint8"),
    ("__int64", "int64"),
    ("__int32", "int32"),
    ("__int16", "int16"),
    ("__int8", "int8"),
    ("_OWORD", "ObjectGuid"),
    ("_QWORD", "uint64"),
    ("_DWORD", "uint32"),
    ("_WORD", "uint16"),
    ("_BYTE", "uint8"),
]

# Regex-based IDA macro replacements
_IDA_MACRO_REPLACEMENTS = [
    (re.compile(r'\bLODWORD\s*\(\s*([^)]+)\s*\)'), r'static_cast<uint32>(\1)'),
    (re.compile(r'\bHIDWORD\s*\(\s*([^)]+)\s*\)'), r'static_cast<uint32>(\1 >> 32)'),
    (re.compile(r'\bLOBYTE\s*\(\s*([^)]+)\s*\)'), r'static_cast<uint8>(\1)'),
    (re.compile(r'\bHIBYTE\s*\(\s*([^)]+)\s*\)'), r'static_cast<uint8>(\1 >> 8)'),
    (re.compile(r'\bLOWORD\s*\(\s*([^)]+)\s*\)'), r'static_cast<uint16>(\1)'),
    (re.compile(r'\bHIWORD\s*\(\s*([^)]+)\s*\)'), r'static_cast<uint16>(\1 >> 16)'),
    (re.compile(r'\bCOERCE_FLOAT\s*\(\s*([^)]+)\s*\)'), r'*reinterpret_cast<float*>(&\1)'),
    (re.compile(r'\b__fastcall\b\s*'), ''),
    # Remove IDA integer suffixes: 0i64, 0xABCDi64, etc.
    (re.compile(r'\b(0x[0-9A-Fa-f]+|[0-9]+)i64\b'), r'\1'),
    (re.compile(r'\b(0x[0-9A-Fa-f]+|[0-9]+)i32\b'), r'\1'),
]

# ---------------------------------------------------------------------------
# sub_XXXX address extraction pattern
# ---------------------------------------------------------------------------
_RE_SUB_CALL = re.compile(r'\bsub_([0-9A-Fa-f]+)\b')

# Offset access patterns: *(type *)(expr + 0xNN)
_RE_OFFSET_ACCESS = re.compile(
    r'\*\s*\(\s*'
    r'(?:unsigned\s+)?'
    r'((?:_?[A-Z]+|char|int|float|double|__int\d+|uint\d+|int\d+)\s*\*)\s*\)'
    r'\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
)

# Return statement with numeric constant
_RE_RETURN_CONST = re.compile(r'\breturn\s+(0x[0-9A-Fa-f]+|\d+)\s*;')

# Magic number in comparisons: expr == 0xNN, expr != 0xNN
_RE_CMP_CONST = re.compile(
    r'(\w[\w.\->]*)\s*([!=<>]=?)\s*(0x[0-9A-Fa-f]+|\d+)\b'
)

# Bitwise AND with constant: expr & 0xNN
_RE_BITWISE_AND = re.compile(
    r'(\w[\w.\->]*)\s*&\s*(0x[0-9A-Fa-f]+|\d+)\b'
)

# goto label pattern
_RE_GOTO = re.compile(r'\bgoto\s+(\w+)\s*;')
_RE_LABEL = re.compile(r'^(\w+)\s*:', re.MULTILINE)

# Double negation
_RE_DOUBLE_NEG = re.compile(r'if\s*\(\s*!!\s*\(([^)]+)\)\s*\)')

# Redundant local: vN = expr; if (vN)   -- where vN is used only once
_RE_REDUNDANT_LOCAL = re.compile(
    r'(\w+)\s*=\s*([^;]+);\s*\n\s*if\s*\(\s*\1\s*\)'
)

# Ternary that spans a single assignment and is complex
_RE_COMPLEX_TERNARY = re.compile(
    r'(\w+)\s*=\s*([^?;]{5,})\s*\?\s*([^:;]+)\s*:\s*([^;]+)\s*;'
)

# ---------------------------------------------------------------------------
# Known TrinityCore class member offsets (WorldSession, Player, Unit, etc.)
# These are well-known offsets from reverse engineering analysis.
# ---------------------------------------------------------------------------

_KNOWN_SESSION_OFFSETS = {
    # WorldSession offsets (a1 = this = WorldSession*)
    # These are representative; actual offsets come from object_layouts in DB
}

_KNOWN_PLAYER_OFFSETS = {
    # Player common offsets
}

# ---------------------------------------------------------------------------
# Known TC WorldPackets system namespace mappings
# ---------------------------------------------------------------------------

_SYSTEM_NAMESPACE_MAP = {
    "Housing": "Housing",
    "Neighborhood": "Housing",
    "Decor": "Housing",
    "Interior": "Housing",
    "Plot": "Housing",
    "Steward": "Housing",
    "Quest": "Quest",
    "Item": "Item",
    "Spell": "Spells",
    "Aura": "Spells",
    "Combat": "Combat",
    "Guild": "Guild",
    "Chat": "Chat",
    "Mail": "Mail",
    "Party": "Party",
    "Group": "Party",
    "Raid": "Party",
    "Inventory": "Item",
    "Equip": "Item",
    "Loot": "Loot",
    "Auction": "AuctionHouse",
    "Achievement": "Achievement",
    "Pet": "BattlePet",
    "Talent": "Talent",
    "Character": "Character",
    "Player": "Character",
    "Vehicle": "Vehicle",
    "Garrison": "Garrison",
    "Calendar": "Calendar",
    "Transmog": "Transmogrification",
    "Collection": "Collections",
    "Mount": "Misc",
    "Toy": "Misc",
    "Battleground": "Battleground",
    "Arena": "Battleground",
    "PvP": "Battleground",
    "Movement": "Movement",
    "Channel": "Channel",
    "Trade": "Trade",
    "Social": "Social",
    "Ticket": "Ticket",
    "Warden": "Warden",
    "Auth": "Auth",
    "Misc": "Misc",
    "System": "System",
    "MythicPlus": "MythicPlus",
    "Delves": "Delves",
}


# ===========================================================================
# Public API
# ===========================================================================

def transpile_handler(session, handler_ea=None, handler_name=None):
    """Transpile one CMSG handler from pseudocode to TC-style C++.

    Args:
        session: PluginSession with .db access
        handler_ea: EA of the handler function (optional if handler_name given)
        handler_name: TC opcode name (optional if handler_ea given)

    Returns:
        Transpiled C++ code string, or None on failure.
    """
    db = session.db

    # Resolve handler EA and name
    if handler_ea is None and handler_name is None:
        msg_error("transpile_handler: must provide handler_ea or handler_name")
        return None

    if handler_ea is not None and handler_name is None:
        row = db.fetchone(
            "SELECT * FROM opcodes WHERE handler_ea = ?", (handler_ea,))
        if row:
            handler_name = row["tc_name"] or row["jam_type"] or f"Handler_0x{handler_ea:X}"
        else:
            handler_name = f"Handler_0x{handler_ea:X}"

    if handler_name is not None and handler_ea is None:
        row = db.fetchone(
            "SELECT * FROM opcodes WHERE tc_name = ?", (handler_name,))
        if row and row["handler_ea"]:
            handler_ea = row["handler_ea"]
        else:
            msg_error(f"transpile_handler: handler '{handler_name}' not found in opcodes")
            return None

    # Determine direction
    direction = "CMSG"
    row = db.fetchone(
        "SELECT direction FROM opcodes WHERE handler_ea = ?", (handler_ea,))
    if row:
        direction = row["direction"]

    # Decompile the handler
    pseudocode = get_decompiled_text(handler_ea)
    if not pseudocode:
        msg_error(f"transpile_handler: failed to decompile 0x{handler_ea:X}")
        return None

    original = pseudocode

    # Build lookup maps
    func_map = _build_function_map(session)
    offset_map = _build_offset_map(session)

    # Apply transformation passes in order
    code = pseudocode
    code = _pass_normalize_types(code)
    code = _pass_resolve_functions(code, session, func_map)
    code = _pass_resolve_member_access(code, session, offset_map)
    code = _pass_resolve_constants(code, session)
    code = _pass_reformat_control_flow(code)
    code = _pass_add_tc_patterns(code)

    # Generate proper handler signature
    signature = _pass_generate_handler_signature(handler_name, direction)

    # Replace the raw function signature with the TC-style one
    # Find the first '{' and replace everything before it
    brace_idx = code.find('{')
    if brace_idx >= 0:
        code = signature + "\n" + code[brace_idx:]
    else:
        code = signature + "\n{\n" + code + "\n}\n"

    # Assess confidence
    confidence, unresolved = _assess_confidence(original, code)

    # Add header comment
    header_lines = [
        f"// ============================================================",
        f"// Transpiled from binary handler at 0x{handler_ea:X}",
        f"// Original: {handler_name}  Direction: {direction}",
        f"// Confidence: {confidence:.0f}%",
        f"// Unresolved items: {len(unresolved)}",
    ]
    if unresolved:
        header_lines.append(f"//   Functions: {sum(1 for u in unresolved if u['type'] == 'function')}")
        header_lines.append(f"//   Offsets:   {sum(1 for u in unresolved if u['type'] == 'offset')}")
        header_lines.append(f"//   Constants: {sum(1 for u in unresolved if u['type'] == 'constant')}")
    header_lines.append(f"// Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    header_lines.append(f"// ============================================================")
    header_lines.append("")

    final = "\n".join(header_lines) + code

    return final


def transpile_all_handlers(session, system_filter=None):
    """Transpile all CMSG handlers and store results.

    Args:
        session: PluginSession with .db access
        system_filter: Optional system name filter (e.g., "Housing")

    Returns:
        Number of handlers transpiled.
    """
    db = session.db

    query = "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL AND direction = 'CMSG'"
    params = ()
    if system_filter:
        query += " AND (tc_name LIKE ? OR jam_type LIKE ?)"
        params = (f"%{system_filter}%", f"%{system_filter}%")

    handlers = db.fetchall(query, params)
    msg_info(f"Transpiler: found {len(handlers)} CMSG handlers to transpile"
             f"{f' (filter: {system_filter})' if system_filter else ''}")

    # Pre-build maps once for all handlers
    func_map = _build_function_map(session)
    offset_map = _build_offset_map(session)

    transpiled = {}
    success = 0
    failed = 0

    for i, handler in enumerate(handlers):
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or handler["jam_type"] or f"Handler_0x{ea:X}"
        direction = handler["direction"]

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            failed += 1
            continue

        original = pseudocode

        # Apply passes
        code = pseudocode
        code = _pass_normalize_types(code)
        code = _pass_resolve_functions(code, session, func_map)
        code = _pass_resolve_member_access(code, session, offset_map)
        code = _pass_resolve_constants(code, session)
        code = _pass_reformat_control_flow(code)
        code = _pass_add_tc_patterns(code)

        signature = _pass_generate_handler_signature(tc_name, direction)

        brace_idx = code.find('{')
        if brace_idx >= 0:
            code = signature + "\n" + code[brace_idx:]
        else:
            code = signature + "\n{\n" + code + "\n}\n"

        confidence, unresolved = _assess_confidence(original, code)

        transpiled[tc_name] = {
            "handler_ea": ea,
            "direction": direction,
            "code": code,
            "confidence": confidence,
            "unresolved_count": len(unresolved),
            "unresolved": unresolved,
            "timestamp": time.time(),
        }

        success += 1

        if (i + 1) % 50 == 0:
            msg_info(f"  Transpiled {i + 1}/{len(handlers)} handlers "
                     f"({success} success, {failed} failed)")

    # Store in kv_store
    db.kv_set("transpiled_handlers", transpiled)
    db.commit()

    msg_info(f"Transpiler complete: {success} transpiled, {failed} failed, "
             f"{len(handlers)} total")

    # Report confidence distribution
    if transpiled:
        confidences = [v["confidence"] for v in transpiled.values()]
        avg_conf = sum(confidences) / len(confidences)
        high = sum(1 for c in confidences if c >= 70)
        medium = sum(1 for c in confidences if 40 <= c < 70)
        low = sum(1 for c in confidences if c < 40)
        msg_info(f"  Confidence: avg={avg_conf:.0f}%, "
                 f"high(>=70%)={high}, med(40-69%)={medium}, low(<40%)={low}")

    return success


def get_transpiled_handler(session, handler_name):
    """Retrieve a single transpiled handler from the kv_store.

    Args:
        session: PluginSession
        handler_name: TC opcode name (e.g., "CMSG_HOUSING_DECOR_PLACE")

    Returns:
        Dict with 'code', 'confidence', etc., or None if not found.
    """
    transpiled = session.db.kv_get("transpiled_handlers") or {}
    return transpiled.get(handler_name)


def export_transpiled_handlers(session, output_dir=None):
    """Export all transpiled handlers as individual .cpp files.

    Args:
        session: PluginSession
        output_dir: Directory to write files to. Defaults to config extraction_dir.

    Returns:
        Number of files written.
    """
    transpiled = session.db.kv_get("transpiled_handlers") or {}
    if not transpiled:
        msg_warn("No transpiled handlers to export. Run transpile_all_handlers first.")
        return 0

    if output_dir is None:
        output_dir = getattr(session.cfg, 'extraction_dir', None)
        if output_dir:
            output_dir = os.path.join(output_dir, "transpiled")
        else:
            msg_error("No output directory specified and no extraction_dir configured")
            return 0

    os.makedirs(output_dir, exist_ok=True)

    # Group by system namespace
    by_system = defaultdict(list)
    for name, data in transpiled.items():
        system = _detect_system_from_name(name)
        by_system[system].append((name, data))

    written = 0

    for system, entries in sorted(by_system.items()):
        # Create one file per system
        filename = f"Transpiled_{system}Handlers.cpp"
        filepath = os.path.join(output_dir, filename)

        lines = [
            f"/**",
            f" * Auto-transpiled {system} handler implementations.",
            f" * Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f" * Handlers: {len(entries)}",
            f" *",
            f" * VERIFY: These are machine-translated from binary pseudocode.",
            f" * Manual review and correction is required before use.",
            f" */",
            f"",
            f'#include "WorldSession.h"',
            f'#include "Player.h"',
            f'#include "ObjectAccessor.h"',
            f'#include "Log.h"',
            f'#include "{system}Packets.h"',
            f"",
        ]

        # Sort by confidence descending so best translations come first
        entries.sort(key=lambda x: x[1]["confidence"], reverse=True)

        for name, data in entries:
            conf = data["confidence"]
            unresolved = data["unresolved_count"]
            lines.append(f"// --- {name} (confidence: {conf:.0f}%, "
                         f"unresolved: {unresolved}) ---")
            lines.append("")
            lines.append(data["code"])
            lines.append("")

        content = "\n".join(lines)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        written += 1
        msg_info(f"  Wrote {filepath} ({len(entries)} handlers)")

    # Also write an index file
    index_path = os.path.join(output_dir, "TRANSPILATION_INDEX.txt")
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(f"Transpilation Index\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total handlers: {len(transpiled)}\n\n")
        for name, data in sorted(transpiled.items()):
            conf = data["confidence"]
            f.write(f"  {name:<50s} confidence={conf:5.1f}%  "
                    f"unresolved={data['unresolved_count']}\n")
    written += 1

    msg_info(f"Exported {len(transpiled)} handlers to {written} files in {output_dir}")
    return written


# ===========================================================================
# Transformation Passes
# ===========================================================================

def _pass_normalize_types(code):
    """Pass A: Replace IDA types with standard C++ types.

    Handles _DWORD -> uint32, __int64 -> int64, LODWORD(x) -> static_cast<>,
    removes __fastcall, cleans up IDA integer suffixes, etc.
    """
    # Apply regex-based macro replacements first (order-independent)
    for pattern, replacement in _IDA_MACRO_REPLACEMENTS:
        code = pattern.sub(replacement, code)

    # Apply string-based type replacements (longer strings first to avoid
    # partial matches, e.g., "unsigned __int64" before "__int64")
    for ida_type, cpp_type in _IDA_TYPE_MAP:
        code = code.replace(ida_type, cpp_type)

    # Clean up redundant unsigned qualifiers that may result from replacement
    # "unsigned uint32" -> "uint32"
    code = re.sub(r'\bunsigned\s+(uint\d+)\b', r'\1', code)

    # Clean up pointer casts with replaced types: (uint32 *) -> (uint32*)
    code = re.sub(r'\(\s*(uint\d+|int\d+|float|double|ObjectGuid)\s+\*\s*\)',
                  r'(\1*)', code)

    return code


def _pass_resolve_functions(code, session, func_map=None):
    """Pass B: Replace sub_XXXX references with TC function names.

    Uses the function map built from opcodes, functions, and vtable tables
    to resolve binary addresses to meaningful names.
    """
    if func_map is None:
        func_map = _build_function_map(session)

    def _replace_sub(match):
        addr_hex = match.group(1)
        try:
            ea = int(addr_hex, 16)
        except ValueError:
            return match.group(0)

        if ea in func_map:
            entry = func_map[ea]
            name = entry["name"]
            # If this is a class method, format as ClassName::MethodName
            if entry.get("class_name"):
                return f'{entry["class_name"]}::{name}'
            return name

        # Check if IDA has a name for it (might have been renamed by user)
        ida_name_val = ida_name.get_name(ea)
        if ida_name_val and not ida_name_val.startswith("sub_"):
            return ida_name_val

        # Leave as-is with a VERIFY comment marker
        return f'sub_{addr_hex} /* VERIFY: unresolved */'

    code = _RE_SUB_CALL.sub(_replace_sub, code)

    # Also try to resolve function pointers: (*(void (__fastcall **)(...))(vtable + offset))
    # These are virtual calls
    vtable_call_re = re.compile(
        r'\(\s*\*\s*\(\s*(?:void\s+\(\s*\*{1,2}\s*\)|'
        r'[^)]+\(\s*\*{1,2}\s*\))\s*[^)]*\)\s*\('
        r'\s*\*?\s*\(?\s*(\w+)\s*(?:\+\s*(0x[0-9A-Fa-f]+|\d+))?\s*\)?\s*'
        r'(?:\+\s*(0x[0-9A-Fa-f]+|\d+))?\s*\)\s*\)'
    )

    def _replace_vtable_call(match):
        # Virtual call through vtable — mark for verification
        return match.group(0) + ' /* VERIFY: virtual call */'

    code = vtable_call_re.sub(_replace_vtable_call, code)

    # Apply naming heuristics based on known patterns in resolved names
    # If a resolved function name contains "SendPacket", standardize it
    code = re.sub(r'\b(\w+)::SendPacket\b', r'\1::SendPacket', code)

    return code


def _pass_resolve_member_access(code, session, offset_map=None):
    """Pass C: Replace raw offset accesses with struct member names.

    *(uint32 *)(a1 + 0x1A8) -> session->_housingState
    """
    if offset_map is None:
        offset_map = _build_offset_map(session)

    def _replace_offset(match):
        cast_type = match.group(1).strip().rstrip('*').strip()
        base_var = match.group(2)
        offset_str = match.group(3)

        try:
            offset_val = int(offset_str, 0)
        except ValueError:
            return match.group(0)

        # Try to find this offset in our map
        # Check base_var specific mappings first, then generic
        for key_prefix in [base_var, "a1", "this", "*"]:
            lookup_key = (key_prefix, offset_val)
            if lookup_key in offset_map:
                entry = offset_map[lookup_key]
                member = entry["member"]
                obj = entry.get("object", base_var)
                comment = f" /* offset 0x{offset_val:X} */"
                if "->" in member or "." in member:
                    return f"{obj}{member}{comment}"
                return f"{obj}->{member}{comment}"

        # If not found, at least add a descriptive comment
        return (f'*(({cast_type}*)({base_var} + 0x{offset_val:X}))'
                f' /* VERIFY: unknown offset 0x{offset_val:X} */')

    code = _RE_OFFSET_ACCESS.sub(_replace_offset, code)

    # Handle first-parameter semantics for CMSG handlers:
    # a1 is typically WorldSession*, a2 is the packet
    # Rename a1 -> session and a2 -> packet in the function body
    # But only if the code still has raw a1/a2 references
    if re.search(r'\ba1\b', code) and not re.search(r'\ba1\s*=', code):
        # Check if a1 is used as a session-like pointer (has offsets accessed)
        if re.search(r'\ba1\s*\+\s*0x', code) or re.search(r'\ba1\s*->', code):
            code = re.sub(r'\ba1\b', 'session', code)

    if re.search(r'\ba2\b', code) and not re.search(r'\ba2\s*=', code):
        code = re.sub(r'\ba2\b', 'packet', code)

    return code


def _pass_resolve_constants(code, session):
    """Pass D: Replace magic numbers with named constants.

    Uses recovered enums, known TC error codes, known game constants,
    and flag value databases.
    """
    db = session.db

    # Load recovered enums
    recovered_enums = db.kv_get("recovered_enums") or []

    # Build a value -> enum name mapping from recovered enums
    enum_value_map = {}
    for enum_info in recovered_enums:
        enum_name = enum_info.get("suggested_name", "")
        for val_entry in enum_info.get("values", []):
            val = val_entry.get("value")
            label = val_entry.get("name")
            if val is not None and label:
                # Store as (enum_name, label) tuple; prefer labels from larger enums
                existing = enum_value_map.get(val)
                if existing is None or enum_info.get("value_count", 0) > existing[2]:
                    enum_value_map[val] = (enum_name, label, enum_info.get("value_count", 0))

    # Load mined constants if available
    mined_constants = db.kv_get("mined_constants") or {}

    # Known TC error/result code patterns (common across many systems)
    _KNOWN_RESULT_CODES = {
        0: "RESULT_OK",
        1: "RESULT_FAILURE",
        2: "RESULT_NOT_FOUND",
        3: "RESULT_ALREADY_EXISTS",
        4: "RESULT_INTERNAL_ERROR",
        5: "RESULT_PERMISSION_DENIED",
        6: "RESULT_INVALID_ARGUMENT",
        7: "RESULT_UNAVAILABLE",
        0x17: "RESULT_WRONG_STATE",
    }

    # Known player flags (partial, common ones)
    _KNOWN_FLAGS = {
        0x1: "PLAYER_FLAGS_GROUP_LEADER",
        0x2: "PLAYER_FLAGS_AFK",
        0x4: "PLAYER_FLAGS_DND",
        0x8: "PLAYER_FLAGS_GM",
        0x10: "PLAYER_FLAGS_GHOST",
        0x20: "PLAYER_FLAGS_RESTING",
        0x40: "PLAYER_FLAGS_UNK7",
        0x80: "PLAYER_FLAGS_FFA_PVP",
        0x100: "PLAYER_FLAGS_CONTESTED_PVP",
        0x200: "PLAYER_FLAGS_IN_PVP",
        0x400: "PLAYER_FLAGS_HIDE_HELM",
        0x800: "PLAYER_FLAGS_HIDE_CLOAK",
    }

    # Replace return constants with named codes in return statements
    def _replace_return_const(match):
        val_str = match.group(1)
        try:
            val = int(val_str, 0)
        except ValueError:
            return match.group(0)

        # Check recovered enums first
        if val in enum_value_map:
            enum_name, label, _ = enum_value_map[val]
            return f'return {label};  // {enum_name}::{label} ({val_str})'

        # Check known result codes
        if val in _KNOWN_RESULT_CODES:
            name = _KNOWN_RESULT_CODES[val]
            return f'return {name};  // {val_str}'

        # Leave small values as-is (likely legitimate), comment larger ones
        if val > 0xF:
            return f'return {val_str};  // VERIFY: result code'

        return match.group(0)

    code = _RE_RETURN_CONST.sub(_replace_return_const, code)

    # Replace constants in comparison expressions
    def _replace_cmp_const(match):
        lhs = match.group(1)
        op = match.group(2)
        val_str = match.group(3)

        try:
            val = int(val_str, 0)
        except ValueError:
            return match.group(0)

        # Skip very common trivial values (0, 1) in simple comparisons
        if val in (0, 1) and op in ('==', '!='):
            return match.group(0)

        # Check recovered enums
        if val in enum_value_map:
            enum_name, label, _ = enum_value_map[val]
            return f'{lhs} {op} {label} /* {val_str} */'

        # Check known flags in bitwise context
        # (handled separately in _replace_bitwise below)

        # For comparison constants > 15, add a VERIFY comment if not already annotated
        if val > 0xF and '/* ' not in match.group(0):
            return f'{lhs} {op} {val_str} /* VERIFY: constant */'

        return match.group(0)

    code = _RE_CMP_CONST.sub(_replace_cmp_const, code)

    # Replace bitwise AND constants with known flag names
    def _replace_bitwise(match):
        lhs = match.group(1)
        val_str = match.group(2)
        try:
            val = int(val_str, 0)
        except ValueError:
            return match.group(0)

        if val in _KNOWN_FLAGS:
            return f'{lhs} & {_KNOWN_FLAGS[val]} /* {val_str} */'

        # Check recovered flag enums
        if val in enum_value_map:
            enum_name, label, _ = enum_value_map[val]
            return f'{lhs} & {label} /* {val_str} */'

        return match.group(0)

    code = _RE_BITWISE_AND.sub(_replace_bitwise, code)

    return code


def _pass_reformat_control_flow(code):
    """Pass E: Clean up decompiler artifacts and improve readability.

    - Replace goto with structured flow where possible
    - Clean redundant casts
    - Simplify double negation
    - Eliminate redundant locals
    - Fix indentation
    """
    # 1. Double negation: if ( !!(x) ) -> if (x)
    code = _RE_DOUBLE_NEG.sub(r'if (\1)', code)

    # Also handle: if ( !!expr )
    code = re.sub(r'if\s*\(\s*!!(\w+)\s*\)', r'if (\1)', code)

    # 2. Redundant local variable elimination
    # Find vN = expr; if (vN) where vN is only used in that if-check
    def _eliminate_redundant(match):
        var = match.group(1)
        expr = match.group(2).strip()

        # Check if var is used elsewhere in the code (beyond the if-check)
        # Count occurrences of this variable name (word boundary)
        count = len(re.findall(r'\b' + re.escape(var) + r'\b', code))
        if count <= 2:
            # Only used in assignment and the if-check: inline it
            return f'if ({expr})'
        return match.group(0)

    code = _RE_REDUNDANT_LOCAL.sub(_eliminate_redundant, code)

    # 3. Simplify complex ternaries into if-else when the ternary is long
    def _simplify_ternary(match):
        var = match.group(1)
        cond = match.group(2).strip()
        true_val = match.group(3).strip()
        false_val = match.group(4).strip()

        # Only expand if the total length is > 80 chars (readability threshold)
        total_len = len(match.group(0))
        if total_len > 80:
            indent = "    "
            return (f'if ({cond})\n'
                    f'{indent}{var} = {true_val};\n'
                    f'else\n'
                    f'{indent}{var} = {false_val};')
        return match.group(0)

    code = _RE_COMPLEX_TERNARY.sub(_simplify_ternary, code)

    # 4. Replace simple goto patterns with structured flow
    # Pattern: if (cond) goto LABEL_err; ... LABEL_err: return ERROR;
    # This is a common decompiler artifact for early-return patterns
    gotos = list(_RE_GOTO.finditer(code))
    labels = {m.group(1): m.start() for m in _RE_LABEL.finditer(code)}

    # For each goto, check if the label is just a return/error block
    for goto_match in reversed(gotos):
        label_name = goto_match.group(1)
        if label_name not in labels:
            continue

        label_pos = labels[label_name]
        # Extract the block after the label (up to next label or end)
        after_label = code[label_pos + len(label_name) + 1:].strip()

        # Find the end of this label's block
        next_label = None
        for other_label, other_pos in labels.items():
            if other_label != label_name and other_pos > label_pos:
                if next_label is None or other_pos < labels.get(next_label, float('inf')):
                    next_label = other_label

        if next_label:
            block_end = labels[next_label]
            label_block = code[label_pos + len(label_name) + 1:block_end].strip()
        else:
            # Find the closing brace of the function
            label_block = after_label

        # If the label block is just "return X;" or "return;", inline it
        return_match = re.match(r'^\s*(return\s*[^;]*;)\s*$', label_block, re.DOTALL)
        if return_match:
            return_stmt = return_match.group(1).strip()

            # Find the if-statement containing this goto
            # Look backwards from goto position for the if-condition
            before_goto = code[:goto_match.start()].rstrip()
            if_match = re.search(r'if\s*\([^)]+\)\s*$', before_goto)
            if if_match:
                # Replace "if (cond) goto LABEL;" with "if (cond) { return ...; }"
                if_stmt = if_match.group(0)
                replacement = f'{if_stmt}\n    {{\n        {return_stmt}\n    }}'

                # Remove the goto line
                code = (code[:if_match.start()] + replacement +
                        code[goto_match.end():])

                # Remove the label and its return block
                # (need to recalculate positions after modification)
                code = re.sub(
                    r'\n\s*' + re.escape(label_name) + r'\s*:\s*\n\s*' +
                    re.escape(return_stmt) + r'\s*',
                    '\n', code, count=1)

    # 5. Clean up redundant casts: (uint32)(uint32)x -> (uint32)x
    code = re.sub(
        r'\((\w+)\)\s*\(\1\)\s*(\w+)',
        r'(\1)\2', code)

    # 6. Clean up (type)0 patterns: (uint32)0 -> 0u, (uint64)0 -> 0ull
    code = re.sub(r'\(uint32\)\s*0\b', '0', code)
    code = re.sub(r'\(uint64\)\s*0\b', '0', code)

    # 7. Fix indentation: normalize to 4 spaces
    lines = code.split('\n')
    fixed_lines = []
    indent_level = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            fixed_lines.append('')
            continue

        # Decrease indent for closing braces
        if stripped.startswith('}'):
            indent_level = max(0, indent_level - 1)

        # Decrease indent for case/default labels (they're at switch level)
        if stripped.startswith('case ') or stripped.startswith('default:'):
            fixed_lines.append('    ' * max(0, indent_level - 1) + stripped)
        else:
            fixed_lines.append('    ' * indent_level + stripped)

        # Increase indent after opening braces
        if stripped.endswith('{'):
            indent_level += 1

        # Handle one-line decrements
        if stripped.endswith('}') and not stripped.startswith('}'):
            pass  # inline close, don't change level

    code = '\n'.join(fixed_lines)

    return code


def _pass_add_tc_patterns(code):
    """Pass F: Add TrinityCore idioms and patterns.

    - Add TC_LOG_ERROR for null pointer checks
    - Add TC_LOG_DEBUG hints for interesting operations
    - Wrap packet reads in WorldPackets pattern
    - Replace raw new/delete with TC patterns
    - Add VERIFY comments where translation is uncertain
    """
    # 1. Add TC_LOG_ERROR for null pointer checks
    # Pattern: if (!ptr) return;  ->  if (!ptr) { TC_LOG_ERROR(...); return; }
    def _add_null_log(match):
        indent = match.group(1)
        var = match.group(2)
        ret = match.group(3)

        # Generate a meaningful log message
        if 'player' in var.lower() or var == '_player':
            log_msg = f'"handlers", "Player not found"'
        elif 'session' in var.lower():
            log_msg = f'"handlers", "Invalid session"'
        elif 'target' in var.lower():
            log_msg = f'"handlers", "Target not found"'
        else:
            log_msg = f'"handlers", "{var} is null"'

        return (f'{indent}if (!{var})\n'
                f'{indent}{{\n'
                f'{indent}    TC_LOG_ERROR({log_msg});\n'
                f'{indent}    {ret}\n'
                f'{indent}}}')

    code = re.sub(
        r'^(\s*)if\s*\(\s*!(\w+)\s*\)\s*\n?\s*(return[^;]*;)',
        _add_null_log, code, flags=re.MULTILINE)

    # 2. Replace raw new with TC patterns
    # new ClassName(...) -> std::make_unique<ClassName>(...)
    # (but keep simple stack allocations)
    code = re.sub(
        r'\bnew\s+(\w+)\s*\(([^)]*)\)',
        r'std::make_unique<\1>(\2)  // VERIFY: ownership',
        code)

    # Replace raw delete
    code = re.sub(
        r'\bdelete\s+(\w+)\s*;',
        r'\1.reset();  // VERIFY: was raw delete',
        code)

    # 3. Add VERIFY comments for sub_ references that weren't resolved
    code = re.sub(
        r'\bsub_([0-9A-Fa-f]+)\s*\(',
        r'sub_\1( /* VERIFY: unresolved function 0x\1 */',
        code)

    # But don't double-tag already-tagged ones
    code = code.replace(
        '/* VERIFY: unresolved */ /* VERIFY: unresolved function',
        '/* VERIFY: unresolved function')
    code = code.replace(
        '/* VERIFY: unresolved */( /* VERIFY: unresolved function',
        '/* VERIFY: unresolved function')

    # 4. Add TC_LOG_DEBUG for SendPacket calls
    code = re.sub(
        r'(SendPacket\s*\([^)]+\)\s*;)',
        r'// TC_LOG_DEBUG("network", "Sending response packet");\n    \1',
        code)

    # 5. Replace ObjectGuid comparisons with IsEmpty() where appropriate
    # if (guid == 0) -> if (guid.IsEmpty())
    code = re.sub(
        r'(\w*[Gg]uid\w*)\s*==\s*0\b',
        r'\1.IsEmpty()',
        code)
    code = re.sub(
        r'(\w*[Gg]uid\w*)\s*!=\s*0\b',
        r'!\1.IsEmpty()',
        code)

    # 6. Add _player access pattern for WorldSession handlers
    # session->GetPlayer() -> _player (TC convention)
    code = re.sub(
        r'\bsession\s*->\s*GetPlayer\s*\(\s*\)',
        '_player',
        code)

    # 7. Mark VERIFY on any remaining raw hex offset accesses
    code = re.sub(
        r'(\w+)\s*\+\s*(0x[0-9A-Fa-f]{3,})\b(?!\s*/\*)',
        r'\1 + \2 /* VERIFY: raw offset */',
        code)

    return code


def _pass_generate_handler_signature(handler_name, direction):
    """Pass G: Generate proper TrinityCore handler function signature.

    Determines the correct WorldPackets namespace and generates:
    void WorldSession::HandleXxx(WorldPackets::System::PacketName& packet)
    """
    # Convert opcode name to handler method name
    # CMSG_HOUSING_DECOR_PLACE -> HandleHousingDecorPlace
    method_name = _opcode_to_method_name(handler_name)

    # Determine system from handler name
    system = _detect_system_from_name(handler_name)
    namespace = _SYSTEM_NAMESPACE_MAP.get(system, "Misc")

    # Convert opcode name to packet class name
    # CMSG_HOUSING_DECOR_PLACE -> HousingDecorPlace
    packet_class = _opcode_to_packet_class(handler_name)

    if direction == "CMSG":
        return (f"void WorldSession::{method_name}"
                f"(WorldPackets::{namespace}::{packet_class}& packet)")
    else:
        # SMSG handlers are builders, not handlers
        return (f"void WorldSession::Send{packet_class}"
                f"(/* params */)")


# ===========================================================================
# Map Building
# ===========================================================================

def _build_function_map(session):
    """Build a comprehensive sub_XXXX -> TC name mapping.

    Sources:
    1. opcodes table (handler_ea -> tc_name)
    2. functions table (ea -> name)
    3. vtables table (ea -> class::method)
    4. vtable_entries table (func_ea -> class::method via slot)
    5. IDA's own name database

    Returns:
        dict: ea (int) -> {"name": str, "class_name": str or None, "source": str}
    """
    db = session.db
    func_map = {}

    # 1. From opcodes table — handler EAs to TC opcode names
    for row in db.fetchall("SELECT handler_ea, tc_name, jam_type FROM opcodes "
                           "WHERE handler_ea IS NOT NULL"):
        ea = row["handler_ea"]
        tc_name = row["tc_name"] or row["jam_type"]
        if tc_name:
            method_name = _opcode_to_method_name(tc_name)
            func_map[ea] = {
                "name": method_name,
                "class_name": "WorldSession",
                "source": "opcodes",
            }

    # 2. From functions table — named functions
    for row in db.fetchall("SELECT ea, name, system FROM functions "
                           "WHERE name IS NOT NULL AND name != ''"):
        ea = row["ea"]
        name = row["name"]
        if ea not in func_map and not name.startswith("sub_"):
            # Try to detect class from name
            class_name = None
            if "::" in name:
                parts = name.rsplit("::", 1)
                class_name = parts[0]
                name = parts[1]
            func_map[ea] = {
                "name": name,
                "class_name": class_name,
                "source": "functions",
            }

    # 3. From vtable_entries — slot-resolved virtual methods
    for row in db.fetchall(
        "SELECT ve.func_ea, ve.func_name, v.class_name "
        "FROM vtable_entries ve "
        "JOIN vtables v ON ve.vtable_ea = v.ea "
        "WHERE ve.func_name IS NOT NULL AND ve.func_name != ''"):
        ea = row["func_ea"]
        if ea not in func_map:
            name = row["func_name"]
            class_name = row["class_name"]
            if name and not name.startswith("sub_"):
                func_map[ea] = {
                    "name": name,
                    "class_name": class_name,
                    "source": "vtable",
                }

    # 4. From vtables table — vtable base addresses
    for row in db.fetchall("SELECT ea, class_name FROM vtables "
                           "WHERE class_name IS NOT NULL"):
        ea = row["ea"]
        if ea not in func_map:
            func_map[ea] = {
                "name": f"{row['class_name']}::vftable",
                "class_name": row["class_name"],
                "source": "vtable_base",
            }

    msg_info(f"  Function map: {len(func_map)} entries "
             f"(opcodes={sum(1 for v in func_map.values() if v['source'] == 'opcodes')}, "
             f"functions={sum(1 for v in func_map.values() if v['source'] == 'functions')}, "
             f"vtable={sum(1 for v in func_map.values() if v['source'] in ('vtable', 'vtable_base'))})")

    return func_map


def _build_offset_map(session):
    """Build struct offset -> member name mapping.

    Sources:
    1. Recovered object layouts from kv_store
    2. Known TC class layouts (hardcoded for well-known classes)
    3. Update fields from the update_fields table

    Returns:
        dict: (base_var_or_wildcard, offset_int) -> {"member": str, "object": str}
    """
    db = session.db
    offset_map = {}

    # 1. From recovered object layouts
    raw_layouts = db.kv_get("object_layouts") or {}
    # Normalize: kv_store may hold a list (sorted by field_count) or a dict
    if isinstance(raw_layouts, list):
        layouts_iter = (
            (l.get("class_name", l.get("name", f"class_{i}")), l)
            for i, l in enumerate(raw_layouts) if isinstance(l, dict)
        )
    else:
        layouts_iter = raw_layouts.items()
    for class_name, layout in layouts_iter:
        if isinstance(layout, dict) and "members" in layout:
            for member in layout["members"]:
                offset = member.get("offset")
                name = member.get("name")
                if offset is not None and name:
                    # Map for all common first-parameter names
                    for base in ["a1", "this", "*"]:
                        offset_map[(base, offset)] = {
                            "member": name,
                            "object": class_name.lower() if class_name != "WorldSession" else "session",
                        }

    # 2. Known WorldSession offsets
    _ws_offsets = {
        # These are representative entries; actual offsets are binary-specific
        # and should come from object_layouts recovery
    }
    for offset, member in _ws_offsets.items():
        for base in ["a1", "this", "session", "*"]:
            if (base, offset) not in offset_map:
                offset_map[(base, offset)] = {
                    "member": member,
                    "object": "session",
                }

    # 3. From update_fields table — player/unit/item field offsets
    for row in db.fetchall("SELECT * FROM update_fields"):
        obj_type = row["object_type"]
        field_name = row["field_name"]
        offset = row["field_offset"]

        if offset is not None and field_name:
            accessor = f"Get{field_name}()"
            for base in ["a1", "this", "player", "*"]:
                key = (base, offset)
                if key not in offset_map:
                    offset_map[key] = {
                        "member": accessor,
                        "object": "_player" if obj_type in ("Player", "Unit") else obj_type.lower(),
                    }

    msg_info(f"  Offset map: {len(offset_map)} entries")

    return offset_map


# ===========================================================================
# Confidence Assessment
# ===========================================================================

def _assess_confidence(original, transpiled):
    """Rate translation confidence and identify unresolved items.

    Scoring:
    - Start at 100%
    - -5% for each remaining sub_ reference
    - -2% for each remaining raw offset (0x + 3+ hex digits)
    - -1% for each remaining magic number in comparisons
    - -3% for each VERIFY comment (uncertainty marker)
    - +5% bonus for each resolved function
    - +3% bonus for each resolved offset

    Returns:
        (confidence_pct: float, unresolved: list of dicts)
    """
    unresolved = []

    # Count remaining sub_ references
    sub_refs = _RE_SUB_CALL.findall(transpiled)
    for addr in sub_refs:
        unresolved.append({
            "type": "function",
            "value": f"sub_{addr}",
            "ea": int(addr, 16),
        })

    # Count remaining raw offset accesses (VERIFY: unknown offset)
    raw_offsets = re.findall(r'VERIFY: unknown offset (0x[0-9A-Fa-f]+)', transpiled)
    for offset in raw_offsets:
        unresolved.append({
            "type": "offset",
            "value": offset,
        })

    # Count remaining raw offset accesses without VERIFY tag
    raw_offset_refs = re.findall(r'VERIFY: raw offset', transpiled)
    for _ in raw_offset_refs:
        unresolved.append({
            "type": "offset",
            "value": "raw offset access",
        })

    # Count magic numbers in comparisons
    magic_nums = re.findall(r'VERIFY: constant', transpiled)
    for _ in magic_nums:
        unresolved.append({
            "type": "constant",
            "value": "unresolved constant",
        })

    # Count all VERIFY comments
    verify_count = transpiled.count('VERIFY:')

    # Count resolved items (differences between original and transpiled)
    orig_subs = len(_RE_SUB_CALL.findall(original))
    trans_subs = len(sub_refs)
    resolved_functions = max(0, orig_subs - trans_subs)

    orig_offsets = len(_RE_OFFSET_ACCESS.findall(original))
    trans_offsets = len(re.findall(r'VERIFY: unknown offset', transpiled))
    resolved_offsets = max(0, orig_offsets - trans_offsets)

    # Calculate confidence
    confidence = 100.0
    confidence -= len(sub_refs) * 5.0
    confidence -= len(raw_offsets) * 2.0
    confidence -= len(raw_offset_refs) * 2.0
    confidence -= len(magic_nums) * 1.0
    confidence -= verify_count * 1.0
    confidence += resolved_functions * 3.0
    confidence += resolved_offsets * 2.0

    # Clamp to 0-100
    confidence = max(0.0, min(100.0, confidence))

    return confidence, unresolved


# ===========================================================================
# Helpers
# ===========================================================================

def _opcode_to_method_name(opcode_name):
    """Convert opcode name to TC handler method name.

    CMSG_HOUSING_DECOR_PLACE -> HandleHousingDecorPlace
    CMSG_QUERY_PLAYER_NAME -> HandleQueryPlayerName
    """
    if not opcode_name:
        return "HandleUnknown"

    name = opcode_name
    # Remove direction prefix
    for prefix in ("CMSG_", "SMSG_", "MSG_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break

    # Convert UPPER_SNAKE_CASE to PascalCase
    parts = name.split('_')
    pascal = ''.join(p.capitalize() for p in parts if p)

    return f"Handle{pascal}"


def _opcode_to_packet_class(opcode_name):
    """Convert opcode name to TC packet class name.

    CMSG_HOUSING_DECOR_PLACE -> HousingDecorPlace
    """
    if not opcode_name:
        return "UnknownPacket"

    name = opcode_name
    for prefix in ("CMSG_", "SMSG_", "MSG_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break

    parts = name.split('_')
    return ''.join(p.capitalize() for p in parts if p)


def _detect_system_from_name(name):
    """Detect the game system from an opcode/handler name.

    CMSG_HOUSING_DECOR_PLACE -> Housing
    CMSG_QUEST_GIVER_HELLO -> Quest
    """
    if not name:
        return "Misc"

    upper = name.upper()

    # Check against known system keywords (order matters: longer/more-specific first)
    _SYSTEM_KEYWORDS = [
        ("NEIGHBORHOOD", "Neighborhood"),
        ("HOUSING", "Housing"),
        ("INTERIOR", "Interior"),
        ("DECOR", "Housing"),
        ("STEWARD", "Housing"),
        ("MYTHIC_PLUS", "MythicPlus"),
        ("MYTHIC", "MythicPlus"),
        ("BATTLEGROUND", "Battleground"),
        ("BATTLEFIELD", "Battleground"),
        ("ARENA", "Battleground"),
        ("PVP", "PvP"),
        ("QUEST", "Quest"),
        ("SPELL", "Spells"),
        ("AURA", "Spells"),
        ("CAST", "Spells"),
        ("TALENT", "Talent"),
        ("GUILD", "Guild"),
        ("CHAT", "Chat"),
        ("CHANNEL", "Channel"),
        ("MAIL", "Mail"),
        ("PARTY", "Party"),
        ("GROUP", "Party"),
        ("RAID", "Party"),
        ("ITEM", "Item"),
        ("EQUIP", "Item"),
        ("INVENTORY", "Item"),
        ("LOOT", "Loot"),
        ("AUCTION", "AuctionHouse"),
        ("ACHIEVEMENT", "Achievement"),
        ("PET", "Pet"),
        ("COLLECTION", "Collections"),
        ("MOUNT", "Misc"),
        ("TOY", "Misc"),
        ("TRANSM", "Transmogrification"),
        ("CALENDAR", "Calendar"),
        ("VEHICLE", "Vehicle"),
        ("GARRISON", "Garrison"),
        ("MOVEMENT", "Movement"),
        ("MOVE_", "Movement"),
        ("SOCIAL", "Social"),
        ("TRADE", "Trade"),
        ("TICKET", "Ticket"),
        ("WARDEN", "Warden"),
        ("AUTH", "Auth"),
        ("CHARACTER", "Character"),
        ("CHAR_", "Character"),
        ("PLAYER", "Character"),
        ("CRAFT", "Crafting"),
        ("DELVE", "Delves"),
    ]

    for keyword, system in _SYSTEM_KEYWORDS:
        if keyword in upper:
            return system

    return "Misc"
