"""
Game Constant Mining
Extracts hardcoded numeric constants from WoW binary handler functions and
classified game functions.  Each constant is categorized (distance, timer,
count limit, flag, mask, error code, ...) and cross-referenced against
TrinityCore source to surface value mismatches.

This is a direct bug-finding tool: if the binary uses 40.0f for a distance
check but TrinityCore uses 100.0f, this module flags the discrepancy.
"""

import json
import math
import os
import re
import time

import ida_funcs
import ida_name
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Regex patterns for extracting numeric literals from Hex-Rays pseudocode
# ---------------------------------------------------------------------------

# Hex integer: 0x1A, 0xDEADBEEF, 0x1Au, 0x1Aull, etc.
_RE_HEX = re.compile(
    r'\b(0x[0-9A-Fa-f]+)[Uu]?(?:[Ll]{0,2})\b'
)

# Decimal integer (possibly negative): 42, -5, 1000u, 200LL
_RE_DEC = re.compile(
    r'(?<![0-9A-Fa-fxX.])(-?\b[0-9]+)[Uu]?(?:[Ll]{0,2})\b(?![.xX0-9A-Fa-f])'
)

# Float literal: 3.14, 3.14f, -0.5, 1.0e10, 40.0F
_RE_FLOAT = re.compile(
    r'(?<![0-9A-Fa-fxX])(-?\b\d+\.\d+(?:[eE][+-]?\d+)?)[fFdD]?\b'
)

# Comparison: var OP constant  or  constant OP var
_RE_COMPARISON = re.compile(
    r'(\w[\w.>\-\[\]]*)\s*([<>=!]=?)\s*'
    r'(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+)[UuLl]*)\b'
)

# Reverse comparison: constant OP var
_RE_COMPARISON_REV = re.compile(
    r'(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+)[UuLl]*)\s*'
    r'([<>=!]=?)\s*(\w[\w.>\-\[\]]*)'
)

# Function call with constant argument: FuncName(arg, 5000)
_RE_CALL_CONST_ARG = re.compile(
    r'(\w+)\s*\(([^)]*)\)'
)

# Bitwise AND: expr & 0xFF
_RE_BITWISE_AND = re.compile(
    r'(\w[\w.>\-\[\]]*)\s*&\s*(0x[0-9A-Fa-f]+|\d+)'
)

# Bitwise OR: expr | 0x4
_RE_BITWISE_OR = re.compile(
    r'(\w[\w.>\-\[\]]*)\s*\|\s*(0x[0-9A-Fa-f]+|\d+)'
)

# Shift: expr << N  or  1 << N
_RE_SHIFT = re.compile(
    r'(\w[\w.>\-\[\]]*|\d+)\s*<<\s*(\d+)'
)

# Return with constant: return 0x17;
_RE_RETURN = re.compile(
    r'\breturn\s+(0x[0-9A-Fa-f]+|\d+)\s*;'
)

# Assignment with constant: var = 5000;
_RE_ASSIGN = re.compile(
    r'(\w[\w.>\-\[\]]*)\s*=\s*(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+)[UuLl]*)\s*;'
)

# Multiplication / division with constant: x * 100, x / 1000
_RE_MUL_DIV = re.compile(
    r'(\w[\w.>\-\[\]]*)\s*([*/])\s*(-?(?:0x[0-9A-Fa-f]+|\d+\.\d+[fF]?|\d+)[UuLl]*)'
)

# Timer/delay/cooldown related function names (case insensitive matching)
_TIMER_CALL_NAMES = {
    "settimer", "starttimer", "resettimer", "addtimer",
    "schedule", "scheduleevent", "delay", "setcooldown",
    "addcooldown", "modifycooldown", "setduration", "sleep",
    "waitfor", "setinterval", "setperiod", "setexpiry",
    "setremainingtime", "setmaxduration",
}

# Distance related function names
_DISTANCE_CALL_NAMES = {
    "getdistance", "getexactdist", "getexactdist2d",
    "iswithindist", "iswithinrange", "iswithinlosindist",
    "iswithinmeleerange", "iswithinspellrange",
    "getdist2d", "getcombatreach", "getspellmaxrange",
    "getspellminrange", "getattackdistance",
    "iswithinboundaryradius", "getdistanceto",
    "isindistance", "getrange", "checkdistance",
}

# Variables that hint at distance semantics
_DISTANCE_VAR_HINTS = {
    "dist", "distance", "range", "radius", "reach", "maxdist",
    "mindist", "maxrange", "minrange",
}

# Variables that hint at timer semantics
_TIMER_VAR_HINTS = {
    "timer", "delay", "cooldown", "duration", "interval",
    "timeout", "period", "ms", "msec", "millisec",
    "expiry", "time", "elapsed", "remaining",
}

# Variables that hint at count/limit semantics
_COUNT_VAR_HINTS = {
    "count", "max", "min", "limit", "size", "capacity", "slot",
    "num", "total", "amount", "stack", "level", "maxlevel",
    "index", "maxslot", "maxstack",
}

# System keyword mapping (reused from conformance analyzer pattern)
_SYSTEM_KEYWORDS = {
    "HOUSING": "Housing", "HOUSE": "Housing", "DECOR": "Housing",
    "NEIGHBORHOOD": "Housing", "INTERIOR": "Housing",
    "CATALOG": "Housing", "ROOM": "Housing", "FURNITURE": "Housing",
    "QUEST": "Quest", "SPELL": "Combat", "AURA": "Combat",
    "DAMAGE": "Combat", "HEAL": "Combat", "ATTACK": "Combat",
    "GUILD": "Social", "CHAT": "Social", "MAIL": "Social",
    "FRIEND": "Social", "PARTY": "Social", "GROUP": "Social",
    "BATTLEGROUND": "PvP", "ARENA": "PvP", "DUEL": "PvP",
    "AUCTION": "Auction", "TRADE": "Crafting", "RECIPE": "Crafting",
    "TALENT": "Talent", "PET": "Pet", "MOUNT": "Mount",
    "ACHIEVEMENT": "Achievement", "LOOT": "Loot",
    "MOVEMENT": "Movement", "MOVE": "Movement",
    "ITEM": "Item", "INVENTORY": "Item", "BAG": "Item", "EQUIP": "Item",
    "CHARACTER": "Character", "PLAYER": "Character",
    "GARRISON": "Garrison", "DELVE": "Delves",
    "MYTHIC": "MythicPlus", "KEYSTONE": "MythicPlus",
    "VEHICLE": "Vehicle", "TAXI": "Movement",
    "CURRENCY": "Currency", "TOKEN": "Currency",
    "BANK": "Item", "VOID_STORAGE": "Item",
    "TRANSMOG": "Transmog", "WARDROBE": "Transmog",
    "CALENDAR": "Calendar", "EVENT": "Calendar",
}

# Trivial constants to skip by default
_TRIVIAL_INTS = {0, 1, -1, 2, 4, 8}

# Struct offset patterns to skip (pointer arithmetic)
_RE_STRUCT_OFFSET = re.compile(
    r'\*\s*\(\s*\w+\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
)

# Cast patterns to recognize and strip
_RE_CAST = re.compile(
    r'\(\s*(?:unsigned\s+)?(?:__)?(?:int(?:8|16|32|64)|char|short|long|float|double|'
    r'DWORD|WORD|BYTE|QWORD|_DWORD|_WORD|_BYTE|_QWORD)\s*\*?\s*\)'
)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def mine_constants(session, system_filter=None):
    """Mine hardcoded game constants from handler and classified functions.

    Scans all CMSG handler functions.  If *system_filter* is given, also
    scans classified functions in that system.

    Results are stored in kv_store under ``"game_constants"`` and per-function
    keys like ``"constants:<func_name>"``.

    Returns:
        Total number of non-trivial constants mined.
    """
    db = session.db
    total_constants = 0
    all_constants = []
    functions_processed = 0

    # ── Phase 1: Handler functions (always scanned) ──────────────────
    query = "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL"
    if system_filter:
        query += f" AND tc_name LIKE '%{system_filter}%'"
    handlers = db.fetchall(query)

    msg_info(f"Mining constants from {len(handlers)} handler functions"
             f"{f' (filter: {system_filter})' if system_filter else ''}...")

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"handler_{ea_str(ea)}"
        system = _extract_system(tc_name)

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        constants = _extract_constants_from_function(pseudocode, tc_name, ea)
        if not constants:
            continue

        # Tag each constant with system from opcode name
        for c in constants:
            c["system"] = system

        # Store per-function
        db.kv_set(f"constants:{tc_name}", constants)
        all_constants.extend(constants)
        total_constants += len(constants)
        functions_processed += 1

        if functions_processed % 50 == 0:
            db.commit()
            msg_info(f"  Processed {functions_processed} functions, "
                     f"{total_constants} constants so far...")

    # ── Phase 2: Classified functions (if system_filter or scan all) ──
    if system_filter:
        func_query = ("SELECT * FROM functions WHERE system = ? "
                      "AND ea NOT IN (SELECT handler_ea FROM opcodes "
                      "                WHERE handler_ea IS NOT NULL)")
        classified = db.fetchall(func_query, (system_filter.lower(),))
    else:
        classified = []

    if classified:
        msg_info(f"Also scanning {len(classified)} classified functions...")
        for func_row in classified:
            ea = func_row["ea"]
            func_name = func_row["name"] or f"func_{ea_str(ea)}"
            system = func_row["system"] or "Unknown"

            pseudocode = get_decompiled_text(ea)
            if not pseudocode:
                continue

            constants = _extract_constants_from_function(pseudocode, func_name, ea)
            if not constants:
                continue

            for c in constants:
                if not c.get("system") or c["system"] == "Unknown":
                    c["system"] = system

            db.kv_set(f"constants:{func_name}", constants)
            all_constants.extend(constants)
            total_constants += len(constants)
            functions_processed += 1

    # ── Phase 3: Build summary and store ─────────────────────────────
    summary = _build_summary(all_constants)
    db.kv_set("game_constants", {
        "total": total_constants,
        "functions_processed": functions_processed,
        "by_category": summary["by_category"],
        "by_system": summary["by_system"],
        "constants": all_constants,
        "mined_at": time.time(),
    })
    db.commit()

    msg_info(f"Constant mining complete: {total_constants} constants from "
             f"{functions_processed} functions")
    for cat, count in sorted(summary["by_category"].items(),
                             key=lambda x: -x[1]):
        msg(f"  {cat}: {count}")

    return total_constants


# ---------------------------------------------------------------------------
# Per-function constant extraction
# ---------------------------------------------------------------------------

def _extract_constants_from_function(pseudocode, func_name, func_ea):
    """Extract all meaningful numeric constants from one function's pseudocode.

    Returns a list of constant dicts, each with fields:
        value, value_hex, type, category, context, variable, function,
        function_ea, comparison_op, suggested_name
    """
    constants = []
    lines = pseudocode.split("\n")
    seen = set()  # deduplicate (value, line_idx) pairs

    for line_idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue

        # Skip struct offset dereferences: *(ptr + 0x48)
        # We still process the line but will filter those specific constants
        struct_offsets = set()
        for m in _RE_STRUCT_OFFSET.finditer(line):
            struct_offsets.add(_parse_number(m.group(1)))

        # Strip casts for cleaner matching
        clean_line = _RE_CAST.sub("", line)

        # ── Comparisons ──────────────────────────────────────────────
        for m in _RE_COMPARISON.finditer(clean_line):
            variable = m.group(1)
            operator = m.group(2)
            raw_value = m.group(3)
            value = _parse_number(raw_value)
            if value is None or value in struct_offsets:
                continue
            key = (value, line_idx, "cmp")
            if key in seen:
                continue
            seen.add(key)
            ctx = _find_constant_context(lines, line_idx, variable)
            entry = _make_constant_entry(
                value, raw_value, func_name, func_ea, line,
                variable=variable, comparison_op=operator, context=ctx
            )
            if entry:
                constants.append(entry)

        for m in _RE_COMPARISON_REV.finditer(clean_line):
            raw_value = m.group(1)
            operator = _flip_operator(m.group(2))
            variable = m.group(3)
            value = _parse_number(raw_value)
            if value is None or value in struct_offsets:
                continue
            key = (value, line_idx, "rcmp")
            if key in seen:
                continue
            seen.add(key)
            ctx = _find_constant_context(lines, line_idx, variable)
            entry = _make_constant_entry(
                value, raw_value, func_name, func_ea, line,
                variable=variable, comparison_op=operator, context=ctx
            )
            if entry:
                constants.append(entry)

        # ── Bitwise AND (masks) ──────────────────────────────────────
        for m in _RE_BITWISE_AND.finditer(clean_line):
            variable = m.group(1)
            raw_value = m.group(2)
            value = _parse_number(raw_value)
            if value is None or value in struct_offsets:
                continue
            key = (value, line_idx, "and")
            if key in seen:
                continue
            seen.add(key)
            entry = _make_constant_entry(
                value, raw_value, func_name, func_ea, line,
                variable=variable, force_category="mask",
                context={"nearby_calls": [], "semantic_hint": "bitwise_and"}
            )
            if entry:
                constants.append(entry)

        # ── Bitwise OR (flags) ───────────────────────────────────────
        for m in _RE_BITWISE_OR.finditer(clean_line):
            variable = m.group(1)
            raw_value = m.group(2)
            value = _parse_number(raw_value)
            if value is None or value in struct_offsets:
                continue
            key = (value, line_idx, "or")
            if key in seen:
                continue
            seen.add(key)
            entry = _make_constant_entry(
                value, raw_value, func_name, func_ea, line,
                variable=variable, force_category="flag",
                context={"nearby_calls": [], "semantic_hint": "bitwise_or"}
            )
            if entry:
                constants.append(entry)

        # ── Shift expressions (1 << N = flag bit) ───────────────────
        for m in _RE_SHIFT.finditer(clean_line):
            base = m.group(1)
            shift_amount_str = m.group(2)
            shift_amount = int(shift_amount_str)
            if base.strip() in ("0", ""):
                continue
            # The computed flag value is interesting
            try:
                base_val = int(base)
                computed = base_val << shift_amount
            except ValueError:
                computed = 1 << shift_amount  # assume base is 1
            key = (computed, line_idx, "shift")
            if key in seen:
                continue
            seen.add(key)
            entry = _make_constant_entry(
                computed, hex(computed), func_name, func_ea, line,
                variable=f"{base}<<{shift_amount}", force_category="flag",
                context={"nearby_calls": [], "semantic_hint": "bit_shift"}
            )
            if entry:
                constants.append(entry)

        # ── Return constants (error codes) ───────────────────────────
        rm = _RE_RETURN.search(clean_line)
        if rm:
            raw_value = rm.group(1)
            value = _parse_number(raw_value)
            if value is not None and value not in struct_offsets:
                key = (value, line_idx, "ret")
                if key not in seen:
                    seen.add(key)
                    # Only flag as error_code if value > 1 (0 and 1 are common
                    # success/failure which we handle below)
                    if isinstance(value, int) and value > 1:
                        entry = _make_constant_entry(
                            value, raw_value, func_name, func_ea, line,
                            variable="return_value", force_category="error_code",
                            context={"nearby_calls": [], "semantic_hint": "return"}
                        )
                        if entry:
                            constants.append(entry)

        # ── Multiplication / Division (percentage, scale) ────────────
        for m in _RE_MUL_DIV.finditer(clean_line):
            variable = m.group(1)
            op = m.group(2)
            raw_value = m.group(3)
            value = _parse_number(raw_value)
            if value is None or value in struct_offsets:
                continue
            key = (value, line_idx, "muldiv")
            if key in seen:
                continue
            seen.add(key)
            ctx = _find_constant_context(lines, line_idx, variable)
            hint = "multiplication" if op == "*" else "division"
            if ctx:
                ctx["semantic_hint"] = hint
            else:
                ctx = {"nearby_calls": [], "semantic_hint": hint}
            entry = _make_constant_entry(
                value, raw_value, func_name, func_ea, line,
                variable=variable, context=ctx
            )
            if entry:
                constants.append(entry)

        # ── Function calls with constant arguments ───────────────────
        for m in _RE_CALL_CONST_ARG.finditer(clean_line):
            call_name = m.group(1)
            args_str = m.group(2)
            if not args_str:
                continue
            # Skip control flow keywords
            if call_name in ("if", "for", "while", "switch", "return",
                             "sizeof", "static_cast", "dynamic_cast",
                             "reinterpret_cast", "const_cast", "LODWORD",
                             "HIDWORD", "LOWORD", "HIWORD", "LOBYTE",
                             "HIBYTE", "BYTE1", "BYTE2", "BYTE3"):
                continue

            args = [a.strip() for a in args_str.split(",")]
            for arg_idx, arg in enumerate(args):
                arg_val = _parse_number(arg.rstrip("UuLlFf"))
                if arg_val is None or arg_val in struct_offsets:
                    continue
                key = (arg_val, line_idx, f"call_{call_name}_{arg_idx}")
                if key in seen:
                    continue
                seen.add(key)

                call_ctx = {
                    "nearby_calls": [call_name],
                    "semantic_hint": f"arg{arg_idx}_of_{call_name}",
                    "call_name": call_name,
                    "arg_index": arg_idx,
                }
                # Timer detection by function name
                fc = None
                if call_name.lower() in _TIMER_CALL_NAMES:
                    fc = "timer"
                elif call_name.lower() in _DISTANCE_CALL_NAMES:
                    fc = "distance"

                entry = _make_constant_entry(
                    arg_val, arg, func_name, func_ea, line,
                    variable=f"arg{arg_idx}", force_category=fc, context=call_ctx
                )
                if entry:
                    constants.append(entry)

        # ── Assignment constants ─────────────────────────────────────
        for m in _RE_ASSIGN.finditer(clean_line):
            variable = m.group(1)
            raw_value = m.group(2)
            value = _parse_number(raw_value)
            if value is None or value in struct_offsets:
                continue
            key = (value, line_idx, "assign")
            if key in seen:
                continue
            seen.add(key)
            ctx = _find_constant_context(lines, line_idx, variable)
            entry = _make_constant_entry(
                value, raw_value, func_name, func_ea, line,
                variable=variable, context=ctx
            )
            if entry:
                constants.append(entry)

    return constants


# ---------------------------------------------------------------------------
# Constant classification
# ---------------------------------------------------------------------------

def _categorize_constant(value, context):
    """Classify a constant into a semantic category.

    Args:
        value: The numeric value (int or float).
        context: Dict with keys: nearby_calls, semantic_hint, variable,
                 comparison_op, etc.

    Returns:
        One of: "distance", "timer", "count_limit", "percentage",
                "currency", "error_code", "flag", "mask", "id",
                "scale_factor", "game_rule"
    """
    if context is None:
        context = {}

    hint = context.get("semantic_hint", "")
    variable = (context.get("variable") or "").lower()
    nearby = [n.lower() for n in context.get("nearby_calls", [])]
    op = context.get("comparison_op", "")

    # ── Already forced by extraction site ────────────────────────────
    # (handled by caller via force_category)

    # ── Float values ─────────────────────────────────────────────────
    if isinstance(value, float):
        # Distance: float near distance function calls
        if any(n in _DISTANCE_CALL_NAMES for n in nearby):
            return "distance"
        if any(h in variable for h in _DISTANCE_VAR_HINTS):
            return "distance"
        # Small multipliers/divisors are scale factors
        if 0.0 < abs(value) < 1.0 or hint in ("multiplication", "division"):
            return "scale_factor"
        # Larger float values in comparison context likely distances
        if abs(value) >= 1.0 and op in ("<", "<=", ">", ">="):
            return "distance"
        return "scale_factor"

    # ── Integer values ───────────────────────────────────────────────
    # Mask: used in AND operation
    if hint == "bitwise_and":
        return "mask"

    # Flag: used in OR or shift, or is a power of 2
    if hint in ("bitwise_or", "bit_shift"):
        return "flag"
    if isinstance(value, int) and value > 0 and (value & (value - 1)) == 0 and value >= 4:
        return "flag"

    # Timer: near timer functions or timer-like variable names
    if any(n in _TIMER_CALL_NAMES for n in nearby):
        return "timer"
    if any(h in variable for h in _TIMER_VAR_HINTS):
        return "timer"
    # Common timer values in milliseconds
    if isinstance(value, int) and value >= 100 and value % 100 == 0 and value <= 3600000:
        if hint in ("multiplication", "division"):
            pass  # not necessarily a timer
        elif any(h in variable for h in _TIMER_VAR_HINTS):
            return "timer"
        # Large round numbers (5000, 10000, 30000) are often timers
        elif value >= 1000 and value % 1000 == 0 and value <= 600000:
            # Only if we have no better classification
            pass  # defer to later checks

    # Error code: returned from function
    if hint == "return":
        return "error_code"

    # Distance: near distance functions or variable names
    if any(n in _DISTANCE_CALL_NAMES for n in nearby):
        return "distance"
    if any(h in variable for h in _DISTANCE_VAR_HINTS):
        return "distance"

    # Percentage: 1-100 with percentage hints
    if isinstance(value, int) and 1 <= value <= 100:
        if any(kw in variable for kw in ("rate", "chance", "pct", "percent",
                                          "prob", "reduction")):
            return "percentage"
        if hint in ("multiplication", "division") and value == 100:
            return "percentage"

    # Currency: gold/silver/copper contexts
    if any(kw in variable for kw in ("gold", "silver", "copper", "money",
                                      "cost", "price", "currency")):
        return "currency"

    # ID: large values that look like database entry IDs
    if isinstance(value, int) and value >= 100000:
        if any(kw in variable for kw in ("id", "entry", "spell", "item",
                                          "creature", "quest", "aura")):
            return "id"
        # Very large values with no other context are likely IDs
        if value >= 100000 and hint not in ("bitwise_and", "bitwise_or"):
            return "id"

    # Count/limit: integer in comparison with count-like variable
    if any(h in variable for h in _COUNT_VAR_HINTS):
        return "count_limit"
    if op in (">", ">=", "<", "<=") and isinstance(value, int):
        return "count_limit"

    # Timer fallback for large round millisecond-ish values
    if isinstance(value, int) and value >= 1000 and value % 1000 == 0 and value <= 600000:
        return "timer"

    return "game_rule"


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------

def _find_constant_context(lines, line_idx, variable=None):
    """Build semantic context around a constant at the given line.

    Looks at surrounding lines for function call names, variable names,
    and semantic hints that help classify the constant.
    """
    nearby_calls = []
    semantic_hint = None

    # Scan a small window around the constant's line
    start = max(0, line_idx - 3)
    end = min(len(lines), line_idx + 4)

    for i in range(start, end):
        stripped = lines[i].strip()

        # Collect function call names
        for m in re.finditer(r'\b([A-Za-z_]\w+)\s*\(', stripped):
            name = m.group(1)
            if name not in ("if", "for", "while", "switch", "return",
                            "sizeof", "LODWORD", "HIDWORD", "LOWORD",
                            "HIWORD", "LOBYTE", "HIBYTE"):
                nearby_calls.append(name)

        # Look for semantic hints on the same line as the constant
        if i == line_idx:
            lower = stripped.lower()
            if any(kw in lower for kw in ("distance", "dist", "range", "radius")):
                semantic_hint = "distance"
            elif any(kw in lower for kw in ("timer", "cooldown", "delay",
                                              "duration", "interval")):
                semantic_hint = "timer"
            elif any(kw in lower for kw in ("count", "max", "limit", "size",
                                              "capacity", "slot", "level")):
                semantic_hint = "count_limit"
            elif any(kw in lower for kw in ("flag", "flags", "mask")):
                semantic_hint = "flag"

    ctx = {
        "nearby_calls": nearby_calls,
    }
    if semantic_hint:
        ctx["semantic_hint"] = semantic_hint
    if variable:
        ctx["variable"] = variable

    return ctx


# ---------------------------------------------------------------------------
# Constant entry construction
# ---------------------------------------------------------------------------

def _make_constant_entry(value, raw_str, func_name, func_ea, context_line,
                         variable=None, comparison_op=None, force_category=None,
                         context=None):
    """Build a constant record dict, applying filtering and classification.

    Returns None if the constant should be skipped (trivial, struct offset, etc.).
    """
    if value is None:
        return None

    # Determine numeric type
    if isinstance(value, float):
        value_type = "float"
    elif isinstance(value, int):
        if value < 0:
            value_type = "int32"
        elif value > 0xFFFFFFFF:
            value_type = "uint64"
        else:
            value_type = "uint32"
    else:
        return None

    # Filter trivial constants
    if isinstance(value, int) and value in _TRIVIAL_INTS:
        # Allow trivial values only in meaningful contexts
        if not force_category and (not context or not context.get("semantic_hint")):
            return None

    # Filter very small floats that are likely rounding artifacts
    if isinstance(value, float) and abs(value) < 0.001 and value != 0.0:
        return None

    # Build hex representation
    if isinstance(value, float):
        import struct
        try:
            packed = struct.pack("<f", value)
            value_hex = "0x" + packed[::-1].hex().upper()
        except (struct.error, OverflowError):
            value_hex = str(value)
    elif isinstance(value, int):
        if value < 0:
            # Two's complement for negative
            value_hex = f"-0x{abs(value):X}"
        else:
            value_hex = f"0x{value:X}"
    else:
        value_hex = str(value)

    # Merge context
    if context is None:
        context = {"nearby_calls": []}
    if variable:
        context["variable"] = variable
    if comparison_op:
        context["comparison_op"] = comparison_op

    # Categorize
    if force_category:
        category = force_category
    else:
        category = _categorize_constant(value, context)

    # Generate a suggested constant name
    suggested = _suggest_name(value, category, func_name, variable, context)

    return {
        "value": value,
        "value_hex": value_hex,
        "type": value_type,
        "category": category,
        "context": context_line.strip()[:300],
        "variable": variable or "",
        "function": func_name,
        "function_ea": func_ea,
        "system": "Unknown",  # filled in by caller
        "comparison_op": comparison_op or "",
        "suggested_name": suggested,
        "tc_value": None,
        "is_mismatch": False,
    }


def _suggest_name(value, category, func_name, variable, context):
    """Generate a suggested C++ constant name.

    Examples:
        MAX_DECOR_PLACE_DISTANCE, HOUSING_TIMER_COOLDOWN_MS,
        MAX_CATALOG_ITEMS, INVENTORY_SLOT_FLAG_0x10
    """
    parts = []

    # Extract system prefix from function name
    prefix = _extract_name_prefix(func_name)
    if prefix:
        parts.append(prefix)

    # Category-specific naming
    if category == "distance":
        parts.append("MAX" if context and context.get("comparison_op") in (
            ">", ">=", "<=", "<") else "")
        var_part = _clean_variable_for_name(variable or "RANGE")
        parts.append(var_part)
        parts.append("DISTANCE")
    elif category == "timer":
        var_part = _clean_variable_for_name(variable or "TIMER")
        parts.append(var_part)
        parts.append("MS")
    elif category == "count_limit":
        op = context.get("comparison_op", "") if context else ""
        if op in (">", ">="):
            parts.append("MAX")
        elif op in ("<", "<="):
            parts.append("MIN")
        else:
            parts.append("MAX")
        var_part = _clean_variable_for_name(variable or "COUNT")
        parts.append(var_part)
    elif category == "percentage":
        var_part = _clean_variable_for_name(variable or "RATE")
        parts.append(var_part)
        parts.append("PCT")
    elif category == "flag":
        if isinstance(value, int) and value > 0 and (value & (value - 1)) == 0:
            bit = int(math.log2(value))
            parts.append(f"FLAG_BIT_{bit}")
        else:
            parts.append(f"FLAG_{value}")
    elif category == "mask":
        parts.append(f"MASK_{_format_hex_upper(value)}")
    elif category == "error_code":
        parts.append(f"ERR_{_format_hex_upper(value)}")
    elif category == "id":
        var_part = _clean_variable_for_name(variable or "ENTRY")
        parts.append(f"{var_part}_ID_{value}")
    elif category == "scale_factor":
        parts.append("SCALE_FACTOR")
    elif category == "currency":
        var_part = _clean_variable_for_name(variable or "COST")
        parts.append(var_part)
    else:
        # game_rule
        var_part = _clean_variable_for_name(variable or "VALUE")
        parts.append(var_part)

    # Clean up and join
    name = "_".join(p for p in parts if p)
    name = re.sub(r'_+', '_', name).strip("_").upper()
    if not name:
        name = f"CONST_{_format_hex_upper(value)}"
    return name


def _extract_name_prefix(func_name):
    """Extract a system prefix from a function name.

    HandleHousingDecorPlace → HOUSING
    HandleBattlegroundJoin  → BATTLEGROUND
    """
    if not func_name:
        return ""
    # Try to extract from Handle* pattern
    m = re.match(r'Handle(\w+?)(?:Request|Response|Result|Update|Ack)?$',
                 func_name)
    if m:
        body = m.group(1)
        # CamelCase → UPPER_SNAKE
        words = re.findall(r'[A-Z][a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\b)', body)
        if words:
            return words[0].upper()

    # Try CMSG_ prefix
    m = re.match(r'CMSG_(\w+?)_', func_name)
    if m:
        return m.group(1).upper()

    return ""


def _clean_variable_for_name(variable):
    """Clean a variable name for use in a constant name."""
    if not variable:
        return ""
    # Remove -> and . and [] and pointer/array syntax
    clean = re.sub(r'[.\->\[\]*&]', '_', variable)
    # Remove leading v/a (decompiler-generated names like v42, a3)
    clean = re.sub(r'^[va]\d+$', '', clean)
    # Convert camelCase to UPPER_SNAKE
    clean = re.sub(r'([a-z])([A-Z])', r'\1_\2', clean)
    return clean.upper().strip("_")


def _format_hex_upper(value):
    """Format a value as hex for constant names."""
    if isinstance(value, float):
        return str(value).replace(".", "_").replace("-", "NEG")
    if isinstance(value, int):
        if value < 0:
            return f"NEG{abs(value):X}"
        return f"0x{value:X}"
    return str(value)


# ---------------------------------------------------------------------------
# TC Source comparison
# ---------------------------------------------------------------------------

def compare_constants_with_tc(session):
    """Compare mined binary constants against TrinityCore source.

    For each handler with mined constants, finds the corresponding TC
    handler source and checks if the same constants appear.  Flags
    mismatches where the binary uses a different value than TC.

    Returns:
        Number of mismatches found.
    """
    db = session.db
    cfg = session.cfg
    tc_dir = cfg.tc_source_dir

    if not tc_dir:
        msg_warn("TrinityCore source not configured - cannot compare constants")
        return 0

    handlers_dir = os.path.join(tc_dir, "src", "server", "game", "Handlers")
    if not os.path.isdir(handlers_dir):
        msg_warn(f"TC Handlers directory not found: {handlers_dir}")
        return 0

    # Load all mined constants
    data = db.kv_get("game_constants")
    if not data or not data.get("constants"):
        msg_warn("No mined constants found. Run mine_constants() first.")
        return 0

    all_constants = data["constants"]
    mismatches = []
    handlers_compared = 0

    # Group constants by function (handler) name
    by_handler = {}
    for c in all_constants:
        fn = c["function"]
        by_handler.setdefault(fn, []).append(c)

    msg_info(f"Comparing constants from {len(by_handler)} functions "
             f"against TC source...")

    for handler_name, handler_constants in by_handler.items():
        tc_func_name = _opcode_to_handler_name(handler_name)
        tc_source = _find_tc_handler_source(handlers_dir, tc_func_name)
        if not tc_source:
            # Also try the raw name as a handler name
            tc_source = _find_tc_handler_source(handlers_dir, handler_name)
            if not tc_source:
                continue

        handlers_compared += 1
        tc_numbers = _extract_tc_numbers(tc_source)

        for c in handler_constants:
            value = c["value"]
            category = c["category"]

            # Skip IDs and masks -- they are expected to differ or match
            # trivially
            if category in ("id", "mask"):
                continue

            # Check if the exact value exists in TC source
            if _value_in_tc(value, tc_numbers):
                c["tc_value"] = value
                c["is_mismatch"] = False
                continue

            # For distance/timer/count, look for similar-magnitude values
            # that might be the "wrong" version
            tc_match = _find_closest_tc_value(value, category, tc_numbers)
            if tc_match is not None:
                c["tc_value"] = tc_match
                c["is_mismatch"] = True
                mismatches.append(c)
            else:
                # Value not found in TC at all — might be missing implementation
                c["tc_value"] = None
                c["is_mismatch"] = True
                mismatches.append(c)

    # Update stored data with mismatch info
    data["constants"] = all_constants
    data["mismatches"] = mismatches
    data["comparison"] = {
        "handlers_compared": handlers_compared,
        "total_mismatches": len(mismatches),
        "compared_at": time.time(),
    }
    db.kv_set("game_constants", data)
    db.kv_set("game_constant_mismatches", mismatches)
    db.commit()

    msg_info(f"Constant comparison complete: {len(mismatches)} mismatches "
             f"across {handlers_compared} handlers")
    if mismatches:
        # Show top mismatches
        by_category = {}
        for m in mismatches:
            cat = m["category"]
            by_category.setdefault(cat, []).append(m)
        for cat, items in sorted(by_category.items(), key=lambda x: -len(x[1])):
            msg(f"  {cat}: {len(items)} mismatches")
            for item in items[:3]:
                tc_val = item.get("tc_value")
                tc_str = f" (TC uses {tc_val})" if tc_val is not None else " (missing in TC)"
                msg(f"    {item['function']}: {item['value']}{tc_str} "
                    f"- {item['context'][:80]}")

    return len(mismatches)


def _opcode_to_handler_name(opcode_name):
    """Convert CMSG_FOO_BAR to HandleFooBar."""
    if not opcode_name:
        return opcode_name
    prefix_end = opcode_name.find("_")
    if prefix_end < 0:
        return opcode_name
    base = opcode_name[prefix_end + 1:]
    parts = base.split("_")
    return "Handle" + "".join(p.capitalize() for p in parts)


def _find_tc_handler_source(handlers_dir, func_name):
    """Search TC Handlers directory for a function body by name."""
    if not func_name:
        return None
    for fname in os.listdir(handlers_dir):
        if not fname.endswith(".cpp"):
            continue
        filepath = os.path.join(handlers_dir, fname)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except IOError:
            continue

        if func_name not in content:
            continue

        # Find function definition
        pattern = re.compile(
            rf'\b{re.escape(func_name)}\s*\([^)]*\)\s*\{{',
            re.MULTILINE
        )
        match = pattern.search(content)
        if not match:
            continue

        # Extract body
        brace_pos = content.index("{", match.start())
        depth = 1
        pos = brace_pos + 1
        while depth > 0 and pos < len(content):
            if content[pos] == "{":
                depth += 1
            elif content[pos] == "}":
                depth -= 1
            pos += 1
        return content[match.start():pos]

    return None


def _extract_tc_numbers(source):
    """Extract all numeric literals from TC C++ source code.

    Returns a dict mapping numeric value → list of context strings.
    """
    numbers = {}

    # Hex integers
    for m in _RE_HEX.finditer(source):
        try:
            val = int(m.group(1), 16)
            numbers.setdefault(val, []).append(m.group(0))
        except ValueError:
            pass

    # Decimal integers
    for m in _RE_DEC.finditer(source):
        try:
            val = int(m.group(1))
            numbers.setdefault(val, []).append(m.group(0))
        except ValueError:
            pass

    # Floats
    for m in _RE_FLOAT.finditer(source):
        try:
            val = float(m.group(1))
            numbers.setdefault(val, []).append(m.group(0))
        except ValueError:
            pass

    return numbers


def _value_in_tc(value, tc_numbers):
    """Check if a value appears in TC source numbers."""
    if value in tc_numbers:
        return True
    # Float comparison with tolerance
    if isinstance(value, float):
        for tc_val in tc_numbers:
            if isinstance(tc_val, float) and abs(tc_val - value) < 0.01:
                return True
    return False


def _find_closest_tc_value(value, category, tc_numbers):
    """Find the closest TC value that looks like it serves the same purpose.

    For distance: find a float in a similar range
    For timer: find an integer in a similar magnitude
    For count_limit: find an integer in the same rough range

    Returns the TC value if a plausible match is found, else None.
    """
    if not tc_numbers:
        return None

    if category == "distance" and isinstance(value, float):
        # Look for other floats in the same order of magnitude
        candidates = []
        for tc_val in tc_numbers:
            if isinstance(tc_val, float) and tc_val > 0:
                ratio = max(value, tc_val) / max(min(value, tc_val), 0.001)
                if ratio < 10.0 and abs(tc_val - value) > 0.1:
                    candidates.append(tc_val)
        if candidates:
            # Return the closest one
            return min(candidates, key=lambda x: abs(x - value))

    elif category == "timer" and isinstance(value, int):
        # Look for integers in similar magnitude
        for tc_val in tc_numbers:
            if isinstance(tc_val, int) and tc_val > 0:
                ratio = max(value, tc_val) / max(min(value, tc_val), 1)
                if ratio < 5.0 and tc_val != value:
                    return tc_val

    elif category == "count_limit" and isinstance(value, int):
        for tc_val in tc_numbers:
            if isinstance(tc_val, int) and tc_val > 0:
                ratio = max(value, tc_val) / max(min(value, tc_val), 1)
                if ratio < 3.0 and tc_val != value:
                    return tc_val

    return None


# ---------------------------------------------------------------------------
# C++ header export
# ---------------------------------------------------------------------------

def export_constants_header(session, system_filter=None):
    """Generate a C++ constants header from mined game constants.

    Args:
        session: PluginSession
        system_filter: Only export constants from this system (e.g. "Housing")

    Returns:
        The generated header as a string, also stored in kv_store.
    """
    db = session.db
    data = db.kv_get("game_constants")
    if not data or not data.get("constants"):
        msg_warn("No mined constants found. Run mine_constants() first.")
        return ""

    all_constants = data["constants"]

    # Filter
    if system_filter:
        all_constants = [c for c in all_constants
                         if c.get("system", "").lower() == system_filter.lower()]

    if not all_constants:
        msg_warn(f"No constants found"
                 f"{f' for system {system_filter}' if system_filter else ''}")
        return ""

    # Group by system then by category
    by_system = {}
    for c in all_constants:
        system = c.get("system", "Unknown")
        by_system.setdefault(system, []).append(c)

    # Deduplicate: within each system, keep unique (suggested_name, value) pairs
    for system in by_system:
        seen_names = {}
        deduped = []
        for c in by_system[system]:
            name = c["suggested_name"]
            val = c["value"]
            key = (name, val)
            if key not in seen_names:
                seen_names[key] = True
                deduped.append(c)
        by_system[system] = deduped

    # Generate header
    lines = []
    lines.append("/**")
    lines.append(" * Game Constants extracted from WoW binary")
    lines.append(f" * Generated by TC WoW Analyzer - constant_mining")
    lines.append(f" * Total constants: {len(all_constants)}")
    lines.append(f" * Systems: {', '.join(sorted(by_system.keys()))}")
    lines.append(" *")
    lines.append(" * WARNING: Auto-generated file. Values extracted from binary analysis.")
    lines.append(" * Cross-reference with live server behavior before using in production.")
    lines.append(" */")
    lines.append("")
    lines.append("#pragma once")
    lines.append("")
    lines.append("#include <cstdint>")
    lines.append("")
    lines.append("namespace GameConstants")
    lines.append("{")

    for system in sorted(by_system.keys()):
        constants = by_system[system]
        if not constants:
            continue

        lines.append(f"    namespace {system}")
        lines.append("    {")

        # Sort by category then name
        constants.sort(key=lambda c: (c["category"], c["suggested_name"]))

        current_category = None
        for c in constants:
            if c["category"] != current_category:
                current_category = c["category"]
                lines.append(f"        // --- {current_category} ---")

            value = c["value"]
            name = c["suggested_name"]
            comment_parts = []
            if c.get("context"):
                comment_parts.append(c["context"][:80])
            if c.get("is_mismatch") and c.get("tc_value") is not None:
                comment_parts.append(f"TC uses {c['tc_value']}")
            comment = "  // " + " | ".join(comment_parts) if comment_parts else ""

            if isinstance(value, float):
                lines.append(f"        constexpr float {name} = {value}f;{comment}")
            elif isinstance(value, int):
                if value < 0:
                    lines.append(
                        f"        constexpr int32_t {name} = {value};{comment}")
                elif value > 0xFFFFFFFF:
                    lines.append(
                        f"        constexpr uint64_t {name} = 0x{value:X}ULL;{comment}")
                elif value > 0xFF:
                    lines.append(
                        f"        constexpr uint32_t {name} = 0x{value:X};{comment}")
                else:
                    lines.append(
                        f"        constexpr uint32_t {name} = {value};{comment}")

        lines.append("    }")
        lines.append("")

    lines.append("} // namespace GameConstants")
    lines.append("")

    header = "\n".join(lines)

    # Store
    key = "game_constants_header"
    if system_filter:
        key += f":{system_filter}"
    db.kv_set(key, header)
    db.commit()

    msg_info(f"Generated constants header: {len(lines)} lines, "
             f"{sum(len(v) for v in by_system.values())} constants")
    return header


# ---------------------------------------------------------------------------
# Query/retrieval functions
# ---------------------------------------------------------------------------

def get_constants(session, category=None, system=None):
    """Retrieve mined constants with optional filters.

    Args:
        session: PluginSession
        category: Filter by category (distance, timer, count_limit, etc.)
        system: Filter by game system (Housing, Combat, etc.)

    Returns:
        List of constant dicts.
    """
    db = session.db
    data = db.kv_get("game_constants")
    if not data or not data.get("constants"):
        return []

    constants = data["constants"]

    if category:
        constants = [c for c in constants if c["category"] == category]
    if system:
        constants = [c for c in constants
                     if c.get("system", "").lower() == system.lower()]

    return constants


def get_constant_mismatches(session):
    """Retrieve all TC vs binary constant mismatches.

    Returns:
        List of constant dicts where is_mismatch is True.
    """
    db = session.db
    mismatches = db.kv_get("game_constant_mismatches")
    if mismatches:
        return mismatches

    # Fallback: filter from main data
    data = db.kv_get("game_constants")
    if not data or not data.get("constants"):
        return []

    return [c for c in data["constants"] if c.get("is_mismatch")]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _parse_number(raw):
    """Parse a numeric string from pseudocode into int or float.

    Handles: 0xFF, 42, -5, 3.14, 3.14f, 1000u, 200LL, etc.
    Returns None if unparseable.
    """
    if raw is None:
        return None

    s = raw.strip()
    # Strip type suffixes
    s = re.sub(r'[UuLlFfDd]+$', '', s)

    if not s:
        return None

    # Float
    if '.' in s:
        try:
            return float(s)
        except ValueError:
            return None

    # Hex
    if s.startswith("0x") or s.startswith("0X") or s.startswith("-0x") or s.startswith("-0X"):
        try:
            return int(s, 16)
        except ValueError:
            return None

    # Decimal
    try:
        return int(s)
    except ValueError:
        return None


def _flip_operator(op):
    """Flip a comparison operator for reversed comparison (const OP var)."""
    flips = {
        "<": ">", ">": "<",
        "<=": ">=", ">=": "<=",
        "==": "==", "!=": "!=",
    }
    return flips.get(op, op)


def _extract_system(name):
    """Extract game system from a function or opcode name."""
    name_upper = name.upper()
    for keyword, system in _SYSTEM_KEYWORDS.items():
        if keyword in name_upper:
            return system
    return "Unknown"


def _build_summary(constants):
    """Build summary statistics from a list of constant dicts."""
    by_category = {}
    by_system = {}

    for c in constants:
        cat = c.get("category", "unknown")
        sys = c.get("system", "Unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
        by_system[sys] = by_system.get(sys, 0) + 1

    return {
        "by_category": by_category,
        "by_system": by_system,
    }
