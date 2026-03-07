"""
Callee Behavioral Contracts
Analyzes shared utility functions called by multiple handlers to recover
behavioral contracts: preconditions, postconditions, side effects, error
returns.  When TrinityCore implements the same utility differently, the
contract comparison catches bugs.

Workflow:
  1. Find all named functions called by 3+ different handlers
  2. Decompile each utility to understand its own behavior
  3. Analyze all call sites to understand usage patterns
  4. Build a behavioral contract (params, returns, side effects)
  5. Optionally compare against TC implementations
"""

import json
import os
import re
from collections import defaultdict

import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Regex patterns for pseudocode analysis
# ---------------------------------------------------------------------------

# Null checks: if (!param) or if (param == 0)
RE_NULL_CHECK = re.compile(
    r'if\s*\(\s*!(\w+)\s*\)', re.MULTILINE
)
RE_NULL_EQ_CHECK = re.compile(
    r'if\s*\(\s*(\w+)\s*==\s*0\s*\)', re.MULTILINE
)

# Range checks: if (x > VAL) or if (x < VAL) etc.
RE_RANGE_CHECK = re.compile(
    r'if\s*\(\s*(\w+)\s*([><=!]+)\s*(0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)\s*\)',
    re.MULTILINE
)

# Type/dynamic cast checks
RE_DYNAMIC_CAST = re.compile(
    r'dynamic_cast<([^>]+)>\s*\(\s*(\w+)\s*\)', re.MULTILINE
)

# Member access patterns: *(this + OFFSET) or this->field
RE_MEMBER_READ = re.compile(
    r'\*\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)', re.MULTILINE
)
RE_MEMBER_WRITE = re.compile(
    r'\*\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*=', re.MULTILINE
)

# Return statements
RE_RETURN = re.compile(
    r'return\s+(0x[0-9A-Fa-f]+|\d+(?:\.\d+)?|true|false|[A-Z_][A-Z_0-9]*|\w+)\s*;',
    re.MULTILINE
)
RE_RETURN_VOID = re.compile(r'return\s*;', re.MULTILINE)

# Function calls in pseudocode
RE_FUNC_CALL = re.compile(
    r'\b([A-Za-z_]\w*)\s*\(', re.MULTILINE
)

# Global writes
RE_GLOBAL_WRITE = re.compile(
    r'(qword|dword|byte|word)_[0-9A-Fa-f]+\s*=', re.MULTILINE
)

# SendPacket calls
RE_SEND_PACKET = re.compile(
    r'SendPacket|Send_?(?:Message|Packet|Update)', re.IGNORECASE
)

# Database calls
RE_DB_CALL = re.compile(
    r'(?:PExecute|PQuery|Execute|AsyncPQuery|PrepareStatement)', re.IGNORECASE
)

# Event/hook fire
RE_EVENT_FIRE = re.compile(
    r'(?:FireEvent|TriggerEvent|ScriptMgr|sScriptMgr|OnEvent)', re.IGNORECASE
)

# Memory allocation
RE_ALLOC = re.compile(
    r'\b(?:new\s+\w|malloc|calloc|realloc|BlzAlloc|SMemAlloc)', re.MULTILINE
)

# Caller return-value usage: if (result) / if (!result) / result == / result !=
RE_CALLER_CHECKS_RETVAL = re.compile(
    r'if\s*\(\s*!?\s*\w+\s*(?:[!=<>]=?\s*(?:0x[0-9A-Fa-f]+|\d+|true|false|nullptr))?\s*\)',
    re.MULTILINE
)

# Parameter constants passed at call site
RE_CONST_ARG = re.compile(
    r'(0x[0-9A-Fa-f]+|\d+(?:\.\d+)?f?)\s*[,)]', re.MULTILINE
)

# System classification for filtering
SYSTEM_PATTERNS = {
    "Housing":    ["HOUSING", "HOUSE", "DECOR", "NEIGHBORHOOD", "INTERIOR",
                   "PLOT", "STEWARD"],
    "Quest":      ["QUEST", "QUESTGIVER", "QUEST_COMPLETE"],
    "Combat":     ["SPELL", "AURA", "ATTACK", "DAMAGE", "HEAL", "CAST", "COMBAT"],
    "Movement":   ["MOVE", "MOVEMENT", "TELEPORT", "TRANSPORT", "FLIGHT"],
    "Social":     ["GUILD", "CHAT", "MAIL", "FRIEND", "PARTY", "GROUP",
                   "RAID", "WHO", "CHANNEL"],
    "Item":       ["ITEM", "INVENTORY", "EQUIP", "BAG", "LOOT"],
    "PvP":        ["BATTLEGROUND", "ARENA", "PVP", "HONOR", "CONQUEST"],
    "Auction":    ["AUCTION"],
    "Crafting":   ["TRADE", "PROFESSION", "CRAFT", "RECIPE", "REAGENT"],
    "Achievement": ["ACHIEVEMENT", "CRITERIA"],
    "Pet":        ["PET", "BATTLE_PET", "COMPANION"],
    "Talent":     ["TALENT", "SPEC", "GLYPH"],
    "Character":  ["CHARACTER", "PLAYER", "LOGIN", "LOGOUT", "CREATE_CHAR"],
    "NPC":        ["CREATURE", "GOSSIP", "TRAINER", "VENDOR", "NPC"],
    "Map":        ["MAP", "ZONE", "AREA", "INSTANCE", "SCENARIO", "PHASE"],
}

# C/pseudo keywords that look like function calls but are not
_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "static_cast",
    "dynamic_cast", "reinterpret_cast", "const_cast", "else", "do",
    "goto", "case", "break", "continue", "default", "throw", "catch",
    "try", "typedef", "struct", "class", "enum", "union", "void",
    "unsigned", "signed", "char", "short", "int", "long", "float",
    "double", "bool", "true", "false", "nullptr", "NULL", "LABEL",
    "__int64", "__int32", "__int16", "__int8", "__fastcall", "__cdecl",
    "__stdcall", "__thiscall", "LODWORD", "HIDWORD", "LOBYTE", "HIBYTE",
    "LOWORD", "HIWORD", "BYTE1", "BYTE2", "BYTE3", "COERCE",
})


# ===================================================================
# Public API
# ===================================================================

def recover_contracts(session, min_callers=3, system_filter=None):
    """Main entry point: recover behavioral contracts for shared utilities.

    Args:
        session: PluginSession with db attached.
        min_callers: Minimum distinct handler callers for a function to qualify.
        system_filter: Only consider handlers from this game system (e.g. 'Housing').

    Returns:
        Number of contracts recovered.
    """
    db = session.db

    msg_info(f"Recovering callee contracts (min_callers={min_callers}, "
             f"system_filter={system_filter or 'all'})...")

    # Step 1 -- find shared utilities
    utilities = _find_shared_utilities(session, min_callers, system_filter)
    if not utilities:
        msg_warn("No shared utility functions found meeting the criteria.")
        return 0

    msg_info(f"Found {len(utilities)} shared utility functions to analyze")

    # Step 2 -- build contracts
    contracts = []
    for idx, util in enumerate(utilities):
        ea = util["ea"]
        name = util["name"]
        caller_eas = util["caller_eas"]

        contract = _analyze_function_contract(ea, name, caller_eas)
        if contract:
            contract["caller_count"] = util["caller_count"]
            contract["callers"] = util["callers"]
            contracts.append(contract)

        if (idx + 1) % 25 == 0:
            msg_info(f"  Analyzed {idx + 1}/{len(utilities)} utilities, "
                     f"{len(contracts)} contracts so far...")

    # Step 3 -- store
    db.kv_set("callee_contracts", contracts)
    db.commit()

    msg_info(f"Recovered {len(contracts)} behavioral contracts")
    _print_summary(contracts)

    return len(contracts)


def get_contracts(session, func_name=None):
    """Retrieve stored contracts, optionally filtered by function name.

    Args:
        session: PluginSession.
        func_name: If provided, return only the contract for this function.

    Returns:
        A list of contract dicts, or a single dict if func_name matched exactly.
    """
    all_contracts = session.db.kv_get("callee_contracts") or []
    if not func_name:
        return all_contracts

    func_lower = func_name.lower()
    matches = [c for c in all_contracts if func_lower in c.get("function", "").lower()]
    if len(matches) == 1:
        return matches[0]
    return matches


def compare_contracts_with_tc(session):
    """Compare recovered contracts against TrinityCore source implementations.

    For each contract, finds the equivalent TC function and checks:
      - parameter count match
      - return type match
      - precondition checks present
      - side effects present
      - return value semantics match

    Returns list of violation dicts stored as 'callee_contract_violations'.
    """
    db = session.db
    cfg = session.cfg
    tc_dir = cfg.tc_source_dir

    if not tc_dir:
        msg_warn("TrinityCore source not configured -- cannot compare contracts")
        return []

    contracts = db.kv_get("callee_contracts") or []
    if not contracts:
        msg_warn("No contracts recovered yet. Run recover_contracts first.")
        return []

    msg_info(f"Comparing {len(contracts)} contracts against TC source...")
    violations = []

    for contract in contracts:
        func_name = contract.get("function", "")
        if not func_name or func_name.startswith("sub_"):
            continue

        tc_source = _find_tc_function_source(tc_dir, func_name)
        if not tc_source:
            continue

        func_violations = _compare_single_contract(contract, tc_source, func_name)
        if func_violations:
            violations.append({
                "function": func_name,
                "ea": contract.get("ea"),
                "caller_count": contract.get("caller_count", 0),
                "violations": func_violations,
            })

    db.kv_set("callee_contract_violations", violations)
    db.commit()

    total_violations = sum(len(v["violations"]) for v in violations)
    msg_info(f"Contract comparison: {total_violations} violations in "
             f"{len(violations)} functions")
    for v in violations[:10]:
        msg_info(f"  {v['function']}: {len(v['violations'])} violations")
        for viol in v["violations"][:3]:
            msg_info(f"    - {viol}")

    return violations


def get_contract_violations(session):
    """Retrieve stored contract violation data."""
    return session.db.kv_get("callee_contract_violations") or []


def generate_contract_docs(session, func_name=None):
    """Generate human-readable documentation for contracts.

    Args:
        session: PluginSession.
        func_name: If given, generate docs for just this function.

    Returns:
        Documentation string.
    """
    contracts = session.db.kv_get("callee_contracts") or []
    if not contracts:
        return "No contracts recovered yet."

    if func_name:
        func_lower = func_name.lower()
        contracts = [c for c in contracts
                     if func_lower in c.get("function", "").lower()]
        if not contracts:
            return f"No contract found for '{func_name}'."

    doc_parts = []
    for contract in contracts:
        doc_parts.append(_format_single_contract_doc(contract))

    return "\n\n".join(doc_parts)


# ===================================================================
# Shared Utility Discovery
# ===================================================================

def _find_shared_utilities(session, min_callers, system_filter=None):
    """Find functions called by many different handlers.

    Queries the opcodes table for handler EAs, traces callees via IDA xrefs,
    and returns functions called by >= min_callers distinct handlers.

    Also includes vtable virtual methods that have many call sites.

    Returns:
        List of dicts: [{ea, name, caller_count, callers, caller_eas}]
    """
    db = session.db

    # Gather all handler EAs
    query = "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL"
    if system_filter:
        query += f" AND (tc_name LIKE '%{system_filter}%' OR jam_type LIKE '%{system_filter}%')"
    handlers = db.fetchall(query)

    if not handlers:
        msg_warn("No handlers found in opcodes table.")
        return []

    msg_info(f"Tracing callees of {len(handlers)} handlers...")

    # callee_ea -> set of (handler_name, handler_ea)
    callee_callers = defaultdict(set)

    for h in handlers:
        handler_ea = h["handler_ea"]
        handler_name = h["tc_name"] or h["jam_type"] or f"handler_0x{handler_ea:X}"

        func = ida_funcs.get_func(handler_ea)
        if not func:
            continue

        # Walk all call instructions in the handler
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN):
                    continue
                target_func = ida_funcs.get_func(xref.to)
                if not target_func or target_func.start_ea == func.start_ea:
                    continue
                callee_name = ida_name.get_name(target_func.start_ea)
                if not callee_name or callee_name.startswith("sub_"):
                    continue
                callee_callers[target_func.start_ea].add(
                    (handler_name, handler_ea)
                )

    # Also pull in vtable functions with many implementations / call sites
    vtable_entries = db.fetchall(
        "SELECT DISTINCT func_ea, func_name FROM vtable_entries "
        "WHERE func_name IS NOT NULL AND func_name != ''"
    )
    for row in vtable_entries:
        func_ea = row["func_ea"]
        func_name = row["func_name"]
        if func_ea in callee_callers:
            continue  # already counted above
        # Count xrefs-to as a proxy for how many callers
        xref_count = 0
        caller_set = set()
        for xref in idautils.XrefsTo(func_ea, 0):
            if xref.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                xref_count += 1
                caller_name = ida_name.get_name(xref.frm)
                if caller_name:
                    caller_set.add((caller_name, xref.frm))
        if xref_count >= min_callers:
            callee_callers[func_ea] = caller_set

    # Filter to functions meeting the threshold
    result = []
    for callee_ea, caller_set in callee_callers.items():
        if len(caller_set) < min_callers:
            continue
        callee_name = ida_name.get_name(callee_ea) or ea_str(callee_ea)
        caller_names = sorted(set(name for name, _ in caller_set))
        caller_eas = sorted(set(ea for _, ea in caller_set))

        # Check if this is a vtable function
        is_virtual = db.fetchone(
            "SELECT 1 FROM vtable_entries WHERE func_ea = ? LIMIT 1",
            (callee_ea,)
        ) is not None

        result.append({
            "ea": callee_ea,
            "name": callee_name,
            "caller_count": len(caller_set),
            "callers": caller_names[:50],  # cap for storage
            "caller_eas": caller_eas[:50],
            "is_virtual": is_virtual,
        })

    # Sort by caller count descending (most-shared first)
    result.sort(key=lambda x: -x["caller_count"])
    return result


# ===================================================================
# Contract Analysis
# ===================================================================

def _analyze_function_contract(ea, func_name, caller_eas):
    """Build a behavioral contract for a single utility function.

    Decompiles the function itself and a sample of its callers, then
    synthesises parameter constraints, return semantics, and side effects.

    Returns a contract dict or None on failure.
    """
    pseudocode = get_decompiled_text(ea)
    if not pseudocode:
        return None

    # --- Analyze the function itself ---
    params = _extract_function_parameters(pseudocode)
    return_info = _extract_return_values(pseudocode)
    side_effects = _extract_side_effects(pseudocode)
    error_conditions = _extract_error_conditions(pseudocode)
    transitive_calls = _extract_transitive_calls(pseudocode)

    # --- Analyze call sites (sample up to 20 callers) ---
    sample_eas = caller_eas[:20]
    caller_pseudocodes = []
    for caller_ea in sample_eas:
        caller_pc = get_decompiled_text(caller_ea)
        if caller_pc:
            caller_pseudocodes.append(caller_pc)

    # Enrich parameters with caller-observed values
    for param in params:
        param_constraints = _extract_parameter_constraints(pseudocode, param["index"])
        param["constraints"] = param_constraints

    # Enrich with call-site observations
    observed_args = _extract_caller_arg_values(func_name, caller_pseudocodes)
    for param in params:
        idx = param["index"]
        if idx in observed_args and observed_args[idx]:
            param["observed_values"] = sorted(set(observed_args[idx]))[:20]
            if all(isinstance(v, (int, float)) for v in param["observed_values"]):
                lo = min(param["observed_values"])
                hi = max(param["observed_values"])
                param["constraints"] += f", range [{lo}, {hi}] (observed)"

    # Enrich return value with caller usage
    return_semantics = _extract_return_semantics(pseudocode, caller_pseudocodes)
    return_info.update(return_semantics)

    # Determine preconditions from both function body and caller behaviour
    preconditions = _infer_preconditions(pseudocode, caller_pseudocodes, func_name)

    # Determine postconditions
    postconditions = _infer_postconditions(pseudocode, side_effects)

    # Purity: no side effects at all
    is_pure = len(side_effects) == 0

    # Check if it is a virtual function via DB (already known from discovery)
    # The caller passes is_virtual through the util dict; we will attach it
    # after return.

    contract = {
        "function": func_name,
        "ea": ea,
        "parameters": params,
        "return_value": return_info,
        "preconditions": preconditions,
        "postconditions": postconditions,
        "side_effects": side_effects,
        "error_conditions": error_conditions,
        "transitive_calls": transitive_calls[:15],
        "is_pure": is_pure,
        "is_virtual": False,  # will be overridden by caller if known
    }
    return contract


# ===================================================================
# Parameter Analysis
# ===================================================================

def _extract_function_parameters(pseudocode):
    """Parse the function signature from pseudocode to extract parameters.

    HexRays signatures look like:
        __int64 __fastcall sub_XXX(__int64 a1, __int64 a2, float a3)
    or with named types:
        bool __fastcall IsWithinDist(WorldObject *this, WorldObject *a2, float a3)
    """
    params = []
    lines = pseudocode.strip().split("\n")
    if not lines:
        return params

    # First line is typically the signature
    sig_line = lines[0]
    # Find the parameter list inside parentheses
    paren_match = re.search(r'\(([^)]*)\)', sig_line)
    if not paren_match:
        return params

    param_str = paren_match.group(1).strip()
    if not param_str or param_str == "void":
        return params

    # Split on commas (careful with nested templates)
    raw_params = _split_params(param_str)

    for idx, raw in enumerate(raw_params):
        raw = raw.strip()
        if not raw:
            continue

        # Try to split type and name
        parts = raw.rsplit(None, 1)
        if len(parts) == 2:
            ptype = parts[0].strip()
            pname = parts[1].strip().lstrip("*&")
        else:
            ptype = raw
            pname = f"a{idx + 1}"

        # Clean up pointer decorators left in type
        if pname.startswith("*"):
            ptype += " *"
            pname = pname.lstrip("*")

        params.append({
            "index": idx,
            "name": pname,
            "type": ptype,
            "constraints": "",
            "observed_values": [],
        })

    return params


def _split_params(param_str):
    """Split parameter string on commas, respecting template brackets."""
    parts = []
    depth = 0
    current = []
    for ch in param_str:
        if ch in ("<", "("):
            depth += 1
            current.append(ch)
        elif ch in (">", ")"):
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def _extract_parameter_constraints(pseudocode, param_idx):
    """Analyze the function body for constraints on one parameter.

    Looks for null checks, range checks, type checks, enum validation.
    """
    constraints = []

    # Determine the likely parameter variable name (a1, a2, ... or this)
    if param_idx == 0:
        var_candidates = ["this", "a1"]
    else:
        var_candidates = [f"a{param_idx + 1}"]

    body = pseudocode.split("{", 1)[-1] if "{" in pseudocode else pseudocode

    for var in var_candidates:
        # Null checks
        if re.search(rf'if\s*\(\s*!{re.escape(var)}\s*\)', body):
            constraints.append(f"{var} must be non-null (null-guarded)")
        if re.search(rf'if\s*\(\s*{re.escape(var)}\s*==\s*0\s*\)', body):
            constraints.append(f"{var} checked against zero")

        # Range checks
        for m in re.finditer(
            rf'if\s*\(\s*{re.escape(var)}\s*([><=!]+)\s*(0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)',
            body
        ):
            op = m.group(1)
            val = m.group(2)
            constraints.append(f"{var} {op} {val} (boundary check)")

        # Dynamic cast / type check
        for m in RE_DYNAMIC_CAST.finditer(body):
            if m.group(2) == var:
                constraints.append(f"{var} must be castable to {m.group(1)}")

    return "; ".join(constraints) if constraints else "no explicit constraints found"


# ===================================================================
# Return Value Analysis
# ===================================================================

def _extract_return_values(pseudocode):
    """Enumerate all return statements in the function body."""
    return_values = []

    for m in RE_RETURN.finditer(pseudocode):
        val = m.group(1)
        if val not in return_values:
            return_values.append(val)

    has_void_return = bool(RE_RETURN_VOID.search(pseudocode))

    # Infer return type from signature
    sig_line = pseudocode.strip().split("\n")[0] if pseudocode.strip() else ""
    ret_type = "unknown"
    sig_match = re.match(r'(\w[\w\s\*]+?)\s+(?:__\w+\s+)?(\w+)\s*\(', sig_line)
    if sig_match:
        ret_type = sig_match.group(1).strip()

    # Classify
    if ret_type == "void" or (has_void_return and not return_values):
        semantics = "void (no return value)"
    elif set(return_values) <= {"true", "false", "0", "1"}:
        semantics = "boolean"
        ret_type = "bool" if ret_type in ("__int64", "char", "unsigned __int8") else ret_type
    elif all(_is_integer_literal(v) for v in return_values):
        semantics = "integer/enum code"
    elif any(v.startswith("0x") and len(v) > 6 for v in return_values):
        semantics = "pointer or handle"
    else:
        semantics = "mixed/unknown"

    return {
        "type": ret_type,
        "semantics": semantics,
        "possible_values": return_values[:20],
        "has_void_return": has_void_return,
        "callers_check": False,  # will be enriched later
    }


def _extract_return_semantics(pseudocode, caller_pseudocodes):
    """Understand how callers use the return value.

    Examines caller pseudocode for patterns like:
        if (FuncName(...))
        result = FuncName(...)
        ignoring the return value entirely
    """
    # Get the function name from the signature
    sig_line = pseudocode.strip().split("\n")[0] if pseudocode.strip() else ""
    sig_match = re.match(r'[\w\s\*]+\s+(?:__\w+\s+)?(\w+)\s*\(', sig_line)
    if not sig_match:
        return {}

    func_name = sig_match.group(1)
    if func_name.startswith("sub_"):
        return {}

    callers_that_check = 0
    callers_that_assign = 0
    callers_that_ignore = 0
    total_call_sites = 0

    for caller_pc in caller_pseudocodes:
        # Find all call sites of this function in the caller
        call_pattern = re.compile(
            rf'(.{{0,60}})\b{re.escape(func_name)}\s*\(', re.MULTILINE
        )
        for m in call_pattern.finditer(caller_pc):
            total_call_sites += 1
            prefix = m.group(1).strip()

            if re.search(r'if\s*\(\s*!?\s*$', prefix):
                callers_that_check += 1
            elif re.search(r'(\w+)\s*=\s*$', prefix):
                callers_that_assign += 1
            elif prefix.endswith("(") or not prefix:
                # Likely a standalone call or nested call
                callers_that_ignore += 1
            else:
                # Could be part of a larger expression
                callers_that_assign += 1

    if total_call_sites == 0:
        return {}

    callers_check = callers_that_check > total_call_sites * 0.5
    callers_ignore = callers_that_ignore > total_call_sites * 0.7

    result = {
        "callers_check": callers_check,
        "callers_ignore_result": callers_ignore,
        "call_site_stats": {
            "total": total_call_sites,
            "checked": callers_that_check,
            "assigned": callers_that_assign,
            "ignored": callers_that_ignore,
        },
    }
    return result


# ===================================================================
# Side Effect Analysis
# ===================================================================

def _extract_side_effects(pseudocode):
    """Identify all side effects in the function body.

    Categories:
      - member_write: *(this+offset) = value
      - global_write: writing to a global variable
      - db_call: database operation
      - packet_send: SendPacket or similar
      - event_fire: event/hook trigger
      - memory_alloc: new/malloc
    """
    body = pseudocode.split("{", 1)[-1] if "{" in pseudocode else pseudocode
    effects = []

    # Member writes
    for m in RE_MEMBER_WRITE.finditer(body):
        obj = m.group(1)
        offset = m.group(2)
        effects.append({
            "type": "member_write",
            "detail": f"writes to {obj}+{offset}",
        })

    # Global writes
    for m in RE_GLOBAL_WRITE.finditer(body):
        effects.append({
            "type": "global_write",
            "detail": f"writes global: {m.group(0)[:60]}",
        })

    # Database calls
    for m in RE_DB_CALL.finditer(body):
        effects.append({
            "type": "db_call",
            "detail": f"database operation: {m.group(0)}",
        })

    # Packet sends
    for m in RE_SEND_PACKET.finditer(body):
        effects.append({
            "type": "packet_send",
            "detail": f"network send: {m.group(0)}",
        })

    # Event/hook triggers
    for m in RE_EVENT_FIRE.finditer(body):
        effects.append({
            "type": "event_fire",
            "detail": f"event trigger: {m.group(0)}",
        })

    # Memory allocation
    for m in RE_ALLOC.finditer(body):
        effects.append({
            "type": "memory_alloc",
            "detail": f"allocation: {m.group(0)[:40]}",
        })

    # Deduplicate by (type, detail)
    seen = set()
    unique = []
    for eff in effects:
        key = (eff["type"], eff["detail"])
        if key not in seen:
            seen.add(key)
            unique.append(eff)

    return unique


# ===================================================================
# Error Condition Extraction
# ===================================================================

def _extract_error_conditions(pseudocode):
    """Find early-return error paths in the function.

    Looks for if-check → return patterns near the top of the function.
    """
    errors = []
    lines = pseudocode.split("\n")
    body_start = 0
    for i, line in enumerate(lines):
        if "{" in line:
            body_start = i
            break

    # Scan the first ~60% of the function for guard checks
    end_idx = body_start + max(10, int((len(lines) - body_start) * 0.6))
    end_idx = min(end_idx, len(lines))

    i = body_start
    while i < end_idx:
        stripped = lines[i].strip()
        if not stripped.startswith("if"):
            i += 1
            continue

        # Grab the if-block
        block_lines = [stripped]
        brace_depth = stripped.count("{") - stripped.count("}")
        j = i + 1
        while j < min(i + 8, len(lines)):
            block_lines.append(lines[j].strip())
            brace_depth += lines[j].count("{") - lines[j].count("}")
            if "return" in lines[j] or (brace_depth <= 0 and "}" in lines[j]):
                break
            j += 1

        block = " ".join(block_lines)

        # Check if this is an early-return guard
        if "return" in block:
            # Extract condition and return value
            cond_match = re.match(r'if\s*\((.+?)\)', stripped)
            ret_match = re.search(
                r'return\s+(0x[0-9A-Fa-f]+|\d+|true|false|[A-Z_]+|\w+)\s*;',
                block
            )
            condition = cond_match.group(1).strip() if cond_match else stripped
            result_val = ret_match.group(1) if ret_match else "void"

            errors.append({
                "condition": condition[:200],
                "result": f"returns {result_val}",
            })

        i = j + 1

    return errors


# ===================================================================
# Transitive Calls
# ===================================================================

def _extract_transitive_calls(pseudocode):
    """Extract named function calls made by this function (transitive effects)."""
    calls = []
    for m in RE_FUNC_CALL.finditer(pseudocode):
        name = m.group(1)
        if name not in _KEYWORDS and name not in calls:
            calls.append(name)
    return calls


# ===================================================================
# Caller Argument Observation
# ===================================================================

def _extract_caller_arg_values(func_name, caller_pseudocodes):
    """Across all callers, collect the constant values passed to each parameter.

    Returns: {param_index: [observed_values]}
    """
    if not func_name or func_name.startswith("sub_"):
        return {}

    observed = defaultdict(list)

    call_re = re.compile(
        rf'\b{re.escape(func_name)}\s*\(([^){{;]*)\)', re.MULTILINE
    )

    for caller_pc in caller_pseudocodes:
        for m in call_re.finditer(caller_pc):
            args_str = m.group(1)
            args = _split_params(args_str)
            for idx, arg in enumerate(args):
                arg = arg.strip()
                val = _try_parse_constant(arg)
                if val is not None:
                    observed[idx].append(val)

    return dict(observed)


def _try_parse_constant(arg_str):
    """Try to parse a constant value from an argument string."""
    arg_str = arg_str.strip()

    # Remove casts
    arg_str = re.sub(r'\(\w[\w\s\*]*\)\s*', '', arg_str)
    arg_str = arg_str.strip()

    # Float literal
    float_match = re.match(r'^(\d+\.\d+)f?$', arg_str)
    if float_match:
        return float(float_match.group(1))

    # Hex literal
    hex_match = re.match(r'^(0x[0-9A-Fa-f]+)$', arg_str, re.IGNORECASE)
    if hex_match:
        return int(hex_match.group(1), 16)

    # Decimal literal
    dec_match = re.match(r'^(\d+)$', arg_str)
    if dec_match:
        return int(dec_match.group(1))

    return None


def _is_integer_literal(val_str):
    """Check if a string is an integer literal (dec or hex)."""
    return bool(re.match(r'^(?:0x[0-9A-Fa-f]+|\d+)$', val_str))


# ===================================================================
# Precondition / Postcondition Inference
# ===================================================================

def _infer_preconditions(pseudocode, caller_pseudocodes, func_name):
    """Infer preconditions from both the function body and caller behaviour."""
    preconditions = []

    # From function body: null checks on parameters
    body = pseudocode.split("{", 1)[-1] if "{" in pseudocode else pseudocode
    for m in RE_NULL_CHECK.finditer(body):
        var = m.group(1)
        preconditions.append(f"{var} != nullptr (null-guarded in body)")
    for m in RE_NULL_EQ_CHECK.finditer(body):
        var = m.group(1)
        preconditions.append(f"{var} != 0 (zero-guarded in body)")

    # From callers: do they null-check a variable before calling this function?
    if func_name and not func_name.startswith("sub_"):
        pre_check_count = 0
        total_callers = len(caller_pseudocodes)
        for caller_pc in caller_pseudocodes:
            # Look for null check immediately before the function call
            check_pattern = re.compile(
                rf'if\s*\(\s*!?\s*(\w+)\s*\)[\s\S]{{0,200}}'
                rf'{re.escape(func_name)}\s*\(',
                re.MULTILINE
            )
            if check_pattern.search(caller_pc):
                pre_check_count += 1

        if total_callers > 0 and pre_check_count > total_callers * 0.5:
            preconditions.append(
                f"callers typically null-check arguments before calling "
                f"({pre_check_count}/{total_callers} callers)"
            )

    # Map check: common in WoW -- objects must be on same map
    if re.search(r'GetMap|GetMapId|GetZoneId|FindMap', body):
        preconditions.append("involves map/zone lookup (implicit same-map requirement)")

    # Deduplicate
    return list(dict.fromkeys(preconditions))


def _infer_postconditions(pseudocode, side_effects):
    """Infer postconditions from the function body and side effects."""
    postconditions = []

    if not side_effects:
        postconditions.append("no state mutation (pure function)")
    else:
        effect_types = set(e["type"] for e in side_effects)
        if "member_write" in effect_types:
            postconditions.append("mutates object state (member writes)")
        if "global_write" in effect_types:
            postconditions.append("modifies global state")
        if "db_call" in effect_types:
            postconditions.append("performs database operations (persistent effect)")
        if "packet_send" in effect_types:
            postconditions.append("sends network packets")
        if "event_fire" in effect_types:
            postconditions.append("triggers events/hooks (cascading effects possible)")
        if "memory_alloc" in effect_types:
            postconditions.append("allocates memory (caller may need to free)")

    return postconditions


# ===================================================================
# TC Comparison
# ===================================================================

def _find_tc_function_source(tc_dir, func_name):
    """Search the TrinityCore source tree for a function by name.

    Looks in game server directories for C++ definitions.
    """
    search_dirs = [
        os.path.join(tc_dir, "src", "server", "game"),
        os.path.join(tc_dir, "src", "server", "scripts"),
    ]

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for root, _dirs, files in os.walk(search_dir):
            for fname in files:
                if not fname.endswith((".cpp", ".h")):
                    continue
                filepath = os.path.join(root, fname)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except IOError:
                    continue

                # Look for function definition (ClassName::FuncName or standalone)
                pattern = re.compile(
                    rf'(?:\w+::)?{re.escape(func_name)}\s*\([^)]*\)\s*(?:const\s*)?\{{',
                    re.MULTILINE
                )
                match = pattern.search(content)
                if not match:
                    continue

                # Extract body by brace matching
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


def _compare_single_contract(contract, tc_source, func_name):
    """Compare one contract against its TC source implementation.

    Returns list of violation strings.
    """
    violations = []

    # 1. Parameter count
    contract_params = contract.get("parameters", [])
    tc_param_match = re.search(
        rf'(?:\w+::)?{re.escape(func_name)}\s*\(([^)]*)\)',
        tc_source
    )
    if tc_param_match:
        tc_param_str = tc_param_match.group(1).strip()
        if tc_param_str and tc_param_str != "void":
            tc_param_count = len(_split_params(tc_param_str))
        else:
            tc_param_count = 0

        # Skip 'this' in the binary count for member functions
        binary_count = len(contract_params)
        if binary_count > 0 and contract_params[0].get("name") == "this":
            binary_count -= 1

        if tc_param_count != binary_count:
            violations.append(
                f"Parameter count mismatch: binary={binary_count}, TC={tc_param_count}"
            )

    # 2. Return type
    ret_type = contract.get("return_value", {}).get("type", "unknown")
    tc_ret_match = re.match(
        rf'(\w[\w\s\*:&<>]*?)\s+(?:\w+::)?{re.escape(func_name)}\s*\(',
        tc_source
    )
    if tc_ret_match and ret_type != "unknown":
        tc_ret = tc_ret_match.group(1).strip()
        # Normalize for comparison
        binary_ret = ret_type.replace("__int64", "int64").replace("unsigned ", "u")
        tc_ret_norm = tc_ret.replace("uint32", "u32").replace("int32", "i32")
        # Check bool mismatch
        if "bool" in ret_type.lower() and "bool" not in tc_ret.lower():
            violations.append(
                f"Return type mismatch: binary={ret_type}, TC={tc_ret}"
            )
        elif "void" in ret_type.lower() and "void" not in tc_ret.lower():
            violations.append(
                f"Return type mismatch: binary=void, TC={tc_ret}"
            )

    # 3. Precondition checks present in TC
    for precond in contract.get("preconditions", []):
        if "null-guarded" in precond or "nullptr" in precond:
            # Check if TC also has a null check
            if "nullptr" not in tc_source and "NULL" not in tc_source and "!(" not in tc_source:
                violations.append(f"Missing null check in TC: {precond}")

    # 4. Side effects match
    for effect in contract.get("side_effects", []):
        etype = effect["type"]
        if etype == "packet_send":
            if not RE_SEND_PACKET.search(tc_source):
                violations.append(
                    f"Binary sends packets but TC does not: {effect['detail']}"
                )
        elif etype == "db_call":
            if not RE_DB_CALL.search(tc_source):
                violations.append(
                    f"Binary does DB operations but TC does not: {effect['detail']}"
                )

    # 5. Error conditions -- binary has early returns that TC might be missing
    for err in contract.get("error_conditions", []):
        condition = err.get("condition", "")
        # Very heuristic: if binary checks something, TC should too
        if "==" in condition or "!=" in condition:
            # Extract the core comparison value
            val_match = re.search(r'([!=]=)\s*(0x[0-9A-Fa-f]+|\d+)', condition)
            if val_match:
                cmp_val = val_match.group(2)
                if cmp_val not in tc_source:
                    violations.append(
                        f"Binary error check not found in TC: {condition[:100]}"
                    )

    return violations


# ===================================================================
# Documentation Generation
# ===================================================================

def _format_single_contract_doc(contract):
    """Format a single contract as human-readable documentation."""
    func = contract.get("function", "unknown")
    ea = contract.get("ea", 0)
    caller_count = contract.get("caller_count", 0)
    is_pure = contract.get("is_pure", False)
    is_virtual = contract.get("is_virtual", False)
    params = contract.get("parameters", [])
    ret = contract.get("return_value", {})
    preconditions = contract.get("preconditions", [])
    postconditions = contract.get("postconditions", [])
    side_effects = contract.get("side_effects", [])
    error_conditions = contract.get("error_conditions", [])
    callers = contract.get("callers", [])

    # Build signature
    ret_type = ret.get("type", "void")
    param_strs = []
    for p in params:
        if p.get("name") == "this":
            continue
        ptype = p.get("type", "?")
        pname = p.get("name", f"a{p['index']}")
        param_strs.append(f"{ptype} {pname}")
    sig = f"{ret_type} {func}({', '.join(param_strs)})"

    lines = []
    lines.append(f"## {func} Contract")
    lines.append(f"**Signature:** `{sig}`")
    lines.append(f"**Address:** {ea_str(ea)}")
    lines.append(f"**Called by:** {caller_count} handlers")
    lines.append(f"**Pure function:** {'Yes' if is_pure else 'No'}")
    if is_virtual:
        lines.append(f"**Virtual:** Yes")
    lines.append("")

    # Preconditions
    if preconditions:
        lines.append("### Preconditions")
        for pc in preconditions:
            lines.append(f"- {pc}")
        lines.append("")

    # Parameters table
    non_this_params = [p for p in params if p.get("name") != "this"]
    if non_this_params:
        lines.append("### Parameters")
        lines.append("| # | Name | Type | Constraints | Common Values |")
        lines.append("|---|------|------|-------------|---------------|")
        for p in non_this_params:
            idx = p["index"]
            name = p.get("name", f"a{idx}")
            ptype = p.get("type", "?")
            constraints = p.get("constraints", "")[:60]
            observed = p.get("observed_values", [])
            obs_str = ", ".join(str(v) for v in observed[:6])
            lines.append(f"| {idx} | {name} | {ptype} | {constraints} | {obs_str} |")
        lines.append("")

    # Return value
    lines.append("### Return Value")
    lines.append(f"- Type: {ret.get('type', '?')}")
    lines.append(f"- Semantics: {ret.get('semantics', '?')}")
    possible = ret.get("possible_values", [])
    if possible:
        lines.append(f"- Possible values: {', '.join(str(v) for v in possible[:10])}")
    if ret.get("callers_check"):
        lines.append("- Callers typically CHECK the return value")
    elif ret.get("callers_ignore_result"):
        lines.append("- Callers typically IGNORE the return value")
    lines.append("")

    # Postconditions
    if postconditions:
        lines.append("### Postconditions")
        for pc in postconditions:
            lines.append(f"- {pc}")
        lines.append("")

    # Side effects
    if side_effects:
        lines.append("### Side Effects")
        for se in side_effects:
            lines.append(f"- [{se['type']}] {se['detail']}")
        lines.append("")

    # Error conditions
    if error_conditions:
        lines.append("### Error Conditions")
        for ec in error_conditions:
            lines.append(f"- **{ec['condition'][:80]}** -> {ec['result']}")
        lines.append("")

    # Callers
    if callers:
        shown = callers[:15]
        lines.append(f"### Callers ({caller_count} total)")
        lines.append(", ".join(shown))
        if len(callers) > 15:
            lines.append(f"... and {caller_count - 15} more")
        lines.append("")

    return "\n".join(lines)


# ===================================================================
# Helpers
# ===================================================================

def _classify_system(name):
    """Classify a handler/function name into a game system."""
    name_upper = name.upper()
    for system, keywords in SYSTEM_PATTERNS.items():
        for kw in keywords:
            if kw in name_upper:
                return system
    return "Other"


def _print_summary(contracts):
    """Print a brief summary of the recovered contracts."""
    pure_count = sum(1 for c in contracts if c.get("is_pure"))
    with_effects = len(contracts) - pure_count
    virtual_count = sum(1 for c in contracts if c.get("is_virtual"))

    msg_info(f"  Pure functions: {pure_count}")
    msg_info(f"  Functions with side effects: {with_effects}")
    msg_info(f"  Virtual functions: {virtual_count}")

    # Top 5 most-called
    top = sorted(contracts, key=lambda c: -c.get("caller_count", 0))[:5]
    if top:
        msg_info("  Most-shared utilities:")
        for c in top:
            msg_info(f"    {c['function']}: {c['caller_count']} callers, "
                     f"{'pure' if c.get('is_pure') else f\"{len(c.get('side_effects', []))} side effects\"}")
