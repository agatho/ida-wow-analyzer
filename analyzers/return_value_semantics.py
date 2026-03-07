"""
Return Value Semantics Analyzer

Recovers return value semantics for functions in the WoW x64 binary:
what does the return value mean, how do callers use it, and are there
mismatches between binary behaviour and TrinityCore implementation.

Analysis phases:
  1. Return Value Pattern Detection -- decompile, classify return values
  2. Caller Usage Analysis -- how each caller consumes the return value
  3. Return Contract Inference -- combine (1) and (2) into a contract
  4. Unchecked Return Value Detection -- callers that ignore error returns
  5. Error Propagation Chains -- track error values across call chains
  6. HRESULT / WoW Result Code Analysis -- map numeric result codes
  7. TC Comparison -- compare binary contracts against TrinityCore source

Results stored in session.db.kv_set("return_value_semantics", {...}).
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
# Return value conventions
# ---------------------------------------------------------------------------

CONV_SUCCESS_IS_ZERO = "SUCCESS_IS_ZERO"
CONV_SUCCESS_IS_NONZERO = "SUCCESS_IS_NONZERO"
CONV_NEGATIVE_IS_ERROR = "NEGATIVE_IS_ERROR"
CONV_POINTER_OR_NULL = "POINTER_OR_NULL"
CONV_ENUM_RESULT = "ENUM_RESULT"
CONV_PROPAGATED = "PROPAGATED"
CONV_IGNORED = "IGNORED"
CONV_BOOLEAN = "BOOLEAN"
CONV_UNKNOWN = "UNKNOWN"

# Risk levels for unchecked returns
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"


# ---------------------------------------------------------------------------
# Regex patterns for pseudocode analysis
# ---------------------------------------------------------------------------

# Function signature: return_type __calling_conv func_name(params)
RE_SIGNATURE = re.compile(
    r'^([\w\s\*]+?)\s+(?:__\w+\s+)?(\w+)\s*\(([^)]*)\)',
    re.MULTILINE
)

# Return statements with values
RE_RETURN_VALUE = re.compile(
    r'return\s+([^;]+?)\s*;', re.MULTILINE
)

# Bare return (void)
RE_RETURN_VOID = re.compile(r'return\s*;', re.MULTILINE)

# Caller checks: if (result == 0)
RE_CHECK_EQ_ZERO = re.compile(
    r'if\s*\(\s*(\w+)\s*==\s*0\s*\)', re.MULTILINE
)

# Caller checks: if (result != 0)
RE_CHECK_NEQ_ZERO = re.compile(
    r'if\s*\(\s*(\w+)\s*!=\s*0\s*\)', re.MULTILINE
)

# Caller checks: if (result)
RE_CHECK_TRUTHY = re.compile(
    r'if\s*\(\s*(\w+)\s*\)', re.MULTILINE
)

# Caller checks: if (!result)
RE_CHECK_FALSY = re.compile(
    r'if\s*\(\s*!(\w+)\s*\)', re.MULTILINE
)

# Caller checks: if (result < 0)
RE_CHECK_NEGATIVE = re.compile(
    r'if\s*\(\s*(\w+)\s*<\s*0\s*\)', re.MULTILINE
)

# Caller checks: if (result > 0) or if (result >= 0)
RE_CHECK_POSITIVE = re.compile(
    r'if\s*\(\s*(\w+)\s*>=?\s*0\s*\)', re.MULTILINE
)

# Caller checks: if (result == nullptr) or if (result == NULL)
RE_CHECK_NULLPTR = re.compile(
    r'if\s*\(\s*(\w+)\s*==\s*(?:nullptr|NULL|0i64)\s*\)', re.MULTILINE
)

# switch statement
RE_SWITCH = re.compile(
    r'switch\s*\(\s*(\w+)\s*\)', re.MULTILINE
)

# Assignment from function call: result = FuncName(...)
RE_ASSIGN_CALL = re.compile(
    r'(\w+)\s*=\s*(\w+)\s*\(', re.MULTILINE
)

# Return forwarding: return FuncName(...)
RE_RETURN_CALL = re.compile(
    r'return\s+(\w+)\s*\(', re.MULTILINE
)

# Integer literal
RE_INT_LITERAL = re.compile(
    r'^(?:0x[0-9A-Fa-f]+|\d+)$'
)

# Enum-like constant (ALL_CAPS_WITH_UNDERSCORES)
RE_ENUM_CONST = re.compile(
    r'^[A-Z][A-Z0-9_]+$'
)

# Global write / side effect indicators
RE_GLOBAL_WRITE = re.compile(
    r'(?:qword|dword|byte|word)_[0-9A-Fa-f]+\s*=', re.MULTILINE
)

RE_SEND_PACKET = re.compile(
    r'SendPacket|Send_?(?:Message|Packet|Update)', re.IGNORECASE
)

RE_DB_CALL = re.compile(
    r'(?:PExecute|PQuery|Execute|AsyncPQuery|PrepareStatement|DirectExecute)',
    re.IGNORECASE
)

# C/pseudo keywords to ignore
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

# WoW-specific result code string patterns
RE_RESULT_STRING = re.compile(
    r'"(ERR_\w+|RESULT_\w+|SPELL_FAILED_\w+|AUCTION_\w+|GUILD_\w+|'
    r'CHAR_CREATE_\w+|CHAR_DELETE_\w+|CHAR_LOGIN_\w+|AUTH_\w+|'
    r'TRANSFER_\w+|REALM_\w+|RESPONSE_\w+)"',
    re.MULTILINE
)

# Security-relevant function names (for unchecked return risk)
_SECURITY_FUNCTIONS = frozenset({
    "IsValidPos", "CheckItem", "CheckBagFreeSpace", "CanUseItem",
    "CheckSpellCast", "IsValidTarget", "CanAttack", "CheckLOS",
    "HasPermission", "IsGameMaster", "CheckSecurityLevel",
    "HasInArc", "IsWithinDist", "IsWithinLOS", "CanSeeOrDetect",
    "Validate", "Verify", "Authenticate", "CheckAuth",
})


# ===================================================================
# Public API
# ===================================================================

def analyze_return_semantics(session) -> int:
    """Main entry point: analyze return value semantics across the binary.

    Args:
        session: PluginSession with .db (KnowledgeDB) and .cfg.

    Returns:
        Total number of functions with recovered return semantics.
    """
    db = session.db
    t0 = time.time()

    msg_info("Return Value Semantics: starting analysis...")

    # Phase 1+2+3: Gather candidate functions and analyze each
    candidates = _gather_candidate_functions(session)
    msg_info(f"Found {len(candidates)} candidate functions with return values")

    function_semantics = []
    unchecked_returns = []
    error_chains_raw = defaultdict(list)  # callee_ea -> list of caller info
    result_code_dict = {}

    for idx, cand in enumerate(candidates):
        ea = cand["ea"]
        name = cand["name"]

        # Phase 1: Return value pattern detection
        ret_info = _analyze_return_patterns(ea, name)
        if ret_info is None:
            continue

        if ret_info["return_type"] == "void":
            continue

        # Phase 2: Caller usage analysis
        caller_analysis = _analyze_caller_usage(ea, name, ret_info)

        # Phase 3: Return contract inference
        contract = _infer_return_contract(ret_info, caller_analysis)

        func_entry = {
            "ea": ea,
            "name": name,
            "return_type": ret_info["return_type"],
            "convention": contract["convention"],
            "success_value": contract["success_value"],
            "error_values": contract["error_values"],
            "caller_count": caller_analysis["total_callers"],
            "callers_that_check": caller_analysis["callers_that_check"],
            "callers_that_ignore": caller_analysis["callers_that_ignore"],
            "can_be_null": contract["can_be_null"],
            "is_enum_result": contract["is_enum_result"],
            "return_values": ret_info["return_values"][:20],
            "caller_conventions": caller_analysis["convention_votes"],
        }
        function_semantics.append(func_entry)

        # Phase 4: Unchecked return detection
        for uc in caller_analysis["unchecked_sites"]:
            risk = _classify_unchecked_risk(
                name, ret_info, contract, caller_analysis
            )
            unchecked_returns.append({
                "call_ea": uc["call_ea"],
                "caller_name": uc["caller_name"],
                "callee_name": name,
                "callee_ea": ea,
                "risk_level": risk,
                "return_type": ret_info["return_type"],
                "possible_errors": contract["error_values"][:10],
            })

        # Phase 5 prep: Record error propagation data
        for prop in caller_analysis["propagation_info"]:
            error_chains_raw[ea].append(prop)

        # Phase 6: Result code analysis
        if contract["is_enum_result"] and ret_info["return_values"]:
            code_map = _analyze_result_codes(ea, name, ret_info)
            if code_map:
                result_code_dict[name] = code_map

        if (idx + 1) % 100 == 0:
            msg_info(f"  Processed {idx + 1}/{len(candidates)} functions, "
                     f"{len(function_semantics)} with return semantics...")

    # Phase 5: Build error propagation chains
    error_chains = _build_error_propagation_chains(
        function_semantics, error_chains_raw
    )

    # Phase 7: TC comparison
    tc_mismatches = _compare_with_tc(session, function_semantics)

    # Assemble results
    results = {
        "function_semantics": function_semantics,
        "unchecked_returns": unchecked_returns,
        "error_chains": error_chains,
        "tc_mismatches": tc_mismatches,
        "result_code_dictionary": result_code_dict,
        "total_functions": len(function_semantics),
        "total_unchecked": len(unchecked_returns),
        "total_mismatches": len(tc_mismatches),
        "total_error_chains": len(error_chains),
        "analysis_time_sec": round(time.time() - t0, 2),
    }

    db.kv_set("return_value_semantics", results)
    db.commit()

    msg_info(f"Return Value Semantics: completed in {results['analysis_time_sec']}s")
    _print_summary(results)

    return results["total_functions"]


def get_return_semantics(session):
    """Retrieve stored return value semantics data.

    Returns:
        Dict with keys: function_semantics, unchecked_returns,
        error_chains, tc_mismatches, result_code_dictionary,
        total_functions, total_unchecked, total_mismatches.
        Returns None if analysis has not been run.
    """
    return session.db.kv_get("return_value_semantics")


# ===================================================================
# Phase 0: Candidate Gathering
# ===================================================================

def _gather_candidate_functions(session):
    """Collect functions worth analyzing for return semantics.

    Prioritizes:
      - Named functions (not sub_XXX)
      - Functions called by CMSG/SMSG handlers
      - Virtual functions from vtables
      - Functions with multiple callers

    Returns:
        List of dicts: [{ea, name, source}]
    """
    db = session.db
    seen_eas = set()
    candidates = []

    def _add_candidate(ea, name, source):
        if ea in seen_eas:
            return
        seen_eas.add(ea)
        candidates.append({"ea": ea, "name": name, "source": source})

    # 1. Handler callees: functions called by CMSG handlers
    try:
        handlers = db.fetchall(
            "SELECT handler_ea, tc_name FROM opcodes "
            "WHERE direction = 'CMSG' AND handler_ea IS NOT NULL"
        )
    except Exception:
        handlers = []

    for h in handlers:
        handler_ea = h["handler_ea"]
        func = ida_funcs.get_func(handler_ea)
        if not func:
            continue
        # Add the handler itself
        hname = h["tc_name"] or ida_name.get_name(handler_ea) or ea_str(handler_ea)
        _add_candidate(handler_ea, hname, "handler")

        # Add its direct callees
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type not in (1, 17):  # fl_CF, fl_CN
                    continue
                target = ida_funcs.get_func(xref.to)
                if not target or target.start_ea == func.start_ea:
                    continue
                tname = ida_name.get_name(target.start_ea)
                if tname and not tname.startswith("sub_"):
                    _add_candidate(target.start_ea, tname, "handler_callee")

    # 2. Vtable functions
    try:
        vtable_funcs = db.fetchall(
            "SELECT DISTINCT func_ea, func_name FROM vtable_entries "
            "WHERE func_name IS NOT NULL AND func_name != ''"
        )
        for row in vtable_funcs:
            _add_candidate(row["func_ea"], row["func_name"], "vtable")
    except Exception:
        pass

    # 3. Named functions with xrefs (broad sweep, capped)
    count_from_sweep = 0
    max_sweep = 3000
    for seg_ea in idautils.Segments():
        if count_from_sweep >= max_sweep:
            break
        for func_ea in idautils.Functions(
            idaapi.getseg(seg_ea).start_ea,
            idaapi.getseg(seg_ea).end_ea
        ):
            if count_from_sweep >= max_sweep:
                break
            name = ida_name.get_name(func_ea)
            if not name or name.startswith("sub_") or name.startswith("j_"):
                continue
            if func_ea in seen_eas:
                continue
            # Only include if it has at least 2 callers
            xref_count = sum(1 for _ in idautils.XrefsTo(func_ea, 0))
            if xref_count >= 2:
                _add_candidate(func_ea, name, "named_function")
                count_from_sweep += 1

    msg_info(f"Candidate sources: {len(handlers)} handlers, "
             f"{len(candidates) - count_from_sweep - len(handlers)} vtable/callees, "
             f"{count_from_sweep} named sweep")

    return candidates


# ===================================================================
# Phase 1: Return Value Pattern Detection
# ===================================================================

def _analyze_return_patterns(ea, func_name):
    """Decompile a function and classify all its return values.

    Returns:
        Dict with keys: return_type, return_values, value_classes,
        has_void_return, signature_return_type.
        Returns None on decompilation failure.
    """
    pseudocode = get_decompiled_text(ea)
    if not pseudocode:
        return None

    # Parse return type from signature
    sig_return_type = _parse_signature_return_type(pseudocode)

    # Find all return statements
    return_values = []
    value_classes = []

    for m in RE_RETURN_VALUE.finditer(pseudocode):
        raw_val = m.group(1).strip()
        if not raw_val:
            continue

        classified = _classify_return_value(raw_val)
        return_values.append(raw_val)
        value_classes.append(classified)

    has_void_return = bool(RE_RETURN_VOID.search(pseudocode))

    # Determine effective return type
    return_type = _determine_return_type(
        sig_return_type, return_values, value_classes, has_void_return
    )

    return {
        "return_type": return_type,
        "return_values": return_values,
        "value_classes": value_classes,
        "has_void_return": has_void_return,
        "signature_return_type": sig_return_type,
        "pseudocode": pseudocode,
    }


def _parse_signature_return_type(pseudocode):
    """Extract the return type from the function signature line."""
    lines = pseudocode.strip().split("\n")
    if not lines:
        return "unknown"

    sig_line = lines[0].strip()
    # Match: return_type [calling_conv] func_name(
    m = re.match(r'^([\w\s\*]+?)\s+(?:__\w+\s+)?\w+\s*\(', sig_line)
    if m:
        rtype = m.group(1).strip()
        # Normalize common IDA types
        rtype = rtype.replace("unsigned __int64", "uint64")
        rtype = rtype.replace("signed __int64", "int64")
        rtype = rtype.replace("unsigned __int32", "uint32")
        rtype = rtype.replace("__int64", "int64")
        rtype = rtype.replace("__int32", "int32")
        rtype = rtype.replace("unsigned __int8", "uint8")
        rtype = rtype.replace("__int8", "int8")
        rtype = rtype.replace("unsigned __int16", "uint16")
        rtype = rtype.replace("__int16", "int16")
        return rtype
    return "unknown"


def _classify_return_value(raw_val):
    """Classify a single return value expression.

    Returns one of:
        LITERAL_ZERO, LITERAL_ONE, LITERAL_NEG_ONE, LITERAL_INT,
        ENUM_VALUE, TRUE, FALSE, NULLPTR, POINTER_EXPR, VARIABLE,
        FUNCTION_CALL, EXPRESSION
    """
    val = raw_val.strip()

    # Boolean literals
    if val == "true":
        return "TRUE"
    if val == "false":
        return "FALSE"

    # Null
    if val in ("0i64", "nullptr", "NULL", "0LL"):
        return "NULLPTR"

    # Integer literals
    if val == "0":
        return "LITERAL_ZERO"
    if val == "1":
        return "LITERAL_ONE"
    if val == "-1" or val == "0xFFFFFFFF" or val == "0xFFFFFFFFFFFFFFFF":
        return "LITERAL_NEG_ONE"

    if RE_INT_LITERAL.match(val):
        return "LITERAL_INT"

    # Negative integer
    if val.startswith("-") and RE_INT_LITERAL.match(val[1:]):
        return "LITERAL_INT"

    # Enum-like constant
    if RE_ENUM_CONST.match(val):
        return "ENUM_VALUE"

    # Function call
    if re.match(r'\w+\s*\(', val):
        return "FUNCTION_CALL"

    # Pointer/address expression
    if "*" in val or "&" in val or "->" in val:
        return "POINTER_EXPR"

    # Cast expression
    if "cast" in val.lower() or val.startswith("("):
        return "EXPRESSION"

    # Simple variable
    if re.match(r'^[a-zA-Z_]\w*$', val):
        return "VARIABLE"

    return "EXPRESSION"


def _determine_return_type(sig_type, return_values, value_classes, has_void_return):
    """Determine the effective return type from signature and return patterns."""
    # Void
    if sig_type == "void":
        return "void"
    if has_void_return and not return_values:
        return "void"

    # Pointer
    if "*" in sig_type:
        return "pointer"

    # Bool
    if sig_type in ("bool", "_BOOL1", "_BOOL4", "_BOOL8"):
        return "bool"
    # Heuristic: only returns 0/1/true/false
    bool_classes = {"LITERAL_ZERO", "LITERAL_ONE", "TRUE", "FALSE"}
    if value_classes and all(c in bool_classes for c in value_classes):
        return "bool"

    # Enum
    enum_classes = {"ENUM_VALUE", "LITERAL_ZERO", "LITERAL_INT"}
    if value_classes and any(c == "ENUM_VALUE" for c in value_classes):
        return "enum"

    # Integer
    int_types = {"int64", "int32", "uint64", "uint32", "int", "unsigned int",
                 "uint8", "int8", "uint16", "int16", "char"}
    if sig_type in int_types:
        return "int"

    # Check if all returns are integers
    int_classes = {"LITERAL_ZERO", "LITERAL_ONE", "LITERAL_NEG_ONE", "LITERAL_INT"}
    if value_classes and all(c in int_classes for c in value_classes):
        return "int"

    # Pointer heuristic
    null_classes = {"NULLPTR", "POINTER_EXPR"}
    if value_classes and any(c in null_classes for c in value_classes):
        return "pointer"

    if sig_type != "unknown":
        return sig_type

    return "unknown"


# ===================================================================
# Phase 2: Caller Usage Analysis
# ===================================================================

def _analyze_caller_usage(ea, func_name, ret_info):
    """Analyze how all callers of a function use its return value.

    Returns:
        Dict with: total_callers, callers_that_check, callers_that_ignore,
        convention_votes, unchecked_sites, propagation_info.
    """
    convention_votes = defaultdict(int)
    callers_that_check = 0
    callers_that_ignore = 0
    total_callers = 0
    unchecked_sites = []
    propagation_info = []

    # Gather all xrefs to this function
    caller_eas = set()
    for xref in idautils.XrefsTo(ea, 0):
        if xref.type in (1, 17):  # fl_CF, fl_CN
            caller_func = ida_funcs.get_func(xref.frm)
            if caller_func and caller_func.start_ea != ea:
                caller_eas.add((caller_func.start_ea, xref.frm))

    # Cap to avoid spending too long on very popular functions
    caller_list = sorted(caller_eas)
    if len(caller_list) > 50:
        caller_list = caller_list[:50]

    for caller_start, call_site_ea in caller_list:
        caller_name = ida_name.get_name(caller_start) or ea_str(caller_start)
        caller_pc = get_decompiled_text(caller_start)
        if not caller_pc:
            continue

        total_callers += 1

        # Find how this caller uses func_name's return value
        usage = _classify_caller_return_usage(caller_pc, func_name)

        for u in usage:
            conv = u["convention"]
            convention_votes[conv] += 1

            if conv == CONV_IGNORED:
                callers_that_ignore += 1
                unchecked_sites.append({
                    "call_ea": call_site_ea,
                    "caller_name": caller_name,
                })
            else:
                callers_that_check += 1

            if conv == CONV_PROPAGATED:
                propagation_info.append({
                    "caller_ea": caller_start,
                    "caller_name": caller_name,
                    "action": "propagate",
                })
            elif conv == CONV_IGNORED:
                propagation_info.append({
                    "caller_ea": caller_start,
                    "caller_name": caller_name,
                    "action": "swallow",
                })
            else:
                propagation_info.append({
                    "caller_ea": caller_start,
                    "caller_name": caller_name,
                    "action": "check",
                })

    return {
        "total_callers": total_callers,
        "callers_that_check": callers_that_check,
        "callers_that_ignore": callers_that_ignore,
        "convention_votes": dict(convention_votes),
        "unchecked_sites": unchecked_sites,
        "propagation_info": propagation_info,
    }


def _classify_caller_return_usage(caller_pc, func_name):
    """Find all call sites of func_name in caller_pc and classify each.

    Returns:
        List of dicts: [{convention, context_line}]
    """
    results = []

    # Escape for regex
    escaped = re.escape(func_name)

    # Pattern: capture what comes before and after the call
    # We look for lines containing the function call
    call_pattern = re.compile(
        rf'(.{{0,120}})\b{escaped}\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)(.*)',
        re.MULTILINE
    )

    for m in call_pattern.finditer(caller_pc):
        prefix = m.group(1).strip()
        suffix = m.group(3).strip() if m.group(3) else ""
        context = m.group(0).strip()

        conv = _infer_convention_from_context(prefix, suffix, caller_pc, func_name)
        results.append({"convention": conv, "context_line": context[:200]})

    # If we found no call sites via regex, this might be an indirect call or
    # the name is mangled differently; count as a single UNKNOWN usage
    if not results:
        results.append({"convention": CONV_UNKNOWN, "context_line": ""})

    return results


def _infer_convention_from_context(prefix, suffix, full_pc, func_name):
    """Given the text before and after a call, determine how return value is used."""
    prefix_stripped = prefix.rstrip()

    # Check for assignment: result = FuncName(...)
    assign_match = re.search(r'(\w+)\s*=\s*$', prefix_stripped)
    if assign_match:
        result_var = assign_match.group(1)
        return _check_variable_usage(full_pc, result_var, func_name)

    # Check for direct conditional: if (FuncName(...))
    if re.search(r'if\s*\(\s*!?\s*$', prefix_stripped):
        # if (FuncName(...)) => SUCCESS_IS_NONZERO
        if re.search(r'if\s*\(\s*!\s*$', prefix_stripped):
            return CONV_SUCCESS_IS_NONZERO  # if (!Func()) means success is nonzero
        return CONV_SUCCESS_IS_NONZERO

    # Check for direct conditional with comparison: if (FuncName(...) == 0)
    if suffix:
        if re.match(r'\s*==\s*0\s*\)', suffix):
            return CONV_SUCCESS_IS_ZERO
        if re.match(r'\s*!=\s*0\s*\)', suffix):
            return CONV_SUCCESS_IS_NONZERO
        if re.match(r'\s*<\s*0\s*\)', suffix):
            return CONV_NEGATIVE_IS_ERROR
        if re.match(r'\s*>=?\s*0\s*\)', suffix):
            return CONV_NEGATIVE_IS_ERROR
        if re.match(r'\s*==\s*(?:nullptr|NULL|0i64)\s*\)', suffix):
            return CONV_POINTER_OR_NULL
        if re.match(r'\s*!=\s*(?:nullptr|NULL|0i64)\s*\)', suffix):
            return CONV_POINTER_OR_NULL

    # Check for return forwarding: return FuncName(...)
    if re.search(r'return\s+$', prefix_stripped):
        return CONV_PROPAGATED

    # Check for switch: switch(FuncName(...))
    if re.search(r'switch\s*\(\s*$', prefix_stripped):
        return CONV_ENUM_RESULT

    # Bare call on its own line (no assignment, no conditional) => IGNORED
    # Check if the prefix ends with a semicolon-starting context or line start
    if not assign_match and not re.search(r'[=(<]\s*$', prefix_stripped):
        # Could be part of a larger expression; check suffix
        if not suffix or suffix.startswith(";") or suffix.startswith(")"):
            # Standalone call
            if not re.search(r'(?:return|if|while|for|switch)\s*', prefix_stripped):
                return CONV_IGNORED

    return CONV_UNKNOWN


def _check_variable_usage(full_pc, var_name, func_name):
    """After `var = FuncName(...)`, check how `var` is subsequently used."""
    escaped_var = re.escape(var_name)

    # if (var == 0)
    if re.search(rf'if\s*\(\s*{escaped_var}\s*==\s*0\s*\)', full_pc):
        return CONV_SUCCESS_IS_ZERO

    # if (var != 0) or if (var)
    if re.search(rf'if\s*\(\s*{escaped_var}\s*!=\s*0\s*\)', full_pc):
        return CONV_SUCCESS_IS_NONZERO
    if re.search(rf'if\s*\(\s*{escaped_var}\s*\)', full_pc):
        return CONV_SUCCESS_IS_NONZERO

    # if (!var)
    if re.search(rf'if\s*\(\s*!{escaped_var}\s*\)', full_pc):
        return CONV_SUCCESS_IS_NONZERO

    # if (var < 0) / if (var >= 0)
    if re.search(rf'if\s*\(\s*{escaped_var}\s*<\s*0\s*\)', full_pc):
        return CONV_NEGATIVE_IS_ERROR
    if re.search(rf'if\s*\(\s*{escaped_var}\s*>=?\s*0\s*\)', full_pc):
        return CONV_NEGATIVE_IS_ERROR

    # if (var == nullptr)
    if re.search(rf'if\s*\(\s*{escaped_var}\s*==\s*(?:nullptr|NULL|0i64)\s*\)', full_pc):
        return CONV_POINTER_OR_NULL
    if re.search(rf'if\s*\(\s*!{escaped_var}\s*\)', full_pc):
        # Could be pointer null check
        return CONV_POINTER_OR_NULL

    # switch (var)
    if re.search(rf'switch\s*\(\s*{escaped_var}\s*\)', full_pc):
        return CONV_ENUM_RESULT

    # return var;
    if re.search(rf'return\s+{escaped_var}\s*;', full_pc):
        return CONV_PROPAGATED

    # var == specific constant (not 0)
    if re.search(rf'if\s*\(\s*{escaped_var}\s*==\s*(?:0x[0-9A-Fa-f]+|[1-9]\d*|[A-Z_]+)\s*\)',
                 full_pc):
        return CONV_ENUM_RESULT

    return CONV_UNKNOWN


# ===================================================================
# Phase 3: Return Contract Inference
# ===================================================================

def _infer_return_contract(ret_info, caller_analysis):
    """Combine function return patterns with caller usage to infer a contract.

    Returns:
        Dict with: convention, success_value, error_values, can_be_null,
        is_enum_result.
    """
    value_classes = ret_info["value_classes"]
    return_values = ret_info["return_values"]
    return_type = ret_info["return_type"]
    convention_votes = caller_analysis["convention_votes"]

    # Determine winning convention from caller votes
    convention = CONV_UNKNOWN
    if convention_votes:
        # Filter out UNKNOWN and IGNORED for winning vote
        meaningful_votes = {
            k: v for k, v in convention_votes.items()
            if k not in (CONV_UNKNOWN, CONV_IGNORED)
        }
        if meaningful_votes:
            convention = max(meaningful_votes, key=meaningful_votes.get)

    # If no callers gave a strong signal, infer from the function itself
    if convention == CONV_UNKNOWN:
        convention = _infer_convention_from_function(
            return_type, value_classes, return_values
        )

    # Determine success and error values
    success_value = None
    error_values = []

    if convention == CONV_SUCCESS_IS_ZERO:
        success_value = 0
        error_values = [v for v in return_values
                        if v not in ("0", "false", "nullptr", "NULL", "0i64")]
    elif convention == CONV_SUCCESS_IS_NONZERO:
        success_value = "nonzero"
        error_values = ["0", "false", "nullptr", "NULL"]
        error_values = [v for v in error_values if v in return_values]
    elif convention == CONV_NEGATIVE_IS_ERROR:
        success_value = ">= 0"
        error_values = [v for v in return_values if _is_negative_value(v)]
    elif convention == CONV_POINTER_OR_NULL:
        success_value = "non-null pointer"
        error_values = ["nullptr", "NULL", "0i64", "0"]
        error_values = [v for v in error_values if v in return_values]
    elif convention == CONV_BOOLEAN:
        success_value = "true/1"
        error_values = ["false/0"]
    elif convention == CONV_ENUM_RESULT:
        # First value is often the success case
        if return_values:
            success_value = return_values[0]
            error_values = return_values[1:]

    # Can be null?
    can_be_null = False
    if return_type == "pointer":
        null_classes = {"NULLPTR", "LITERAL_ZERO"}
        can_be_null = any(c in null_classes for c in value_classes)

    # Is enum result?
    is_enum_result = (
        convention == CONV_ENUM_RESULT or
        any(c == "ENUM_VALUE" for c in value_classes) or
        (return_type == "enum")
    )

    return {
        "convention": convention,
        "success_value": success_value,
        "error_values": error_values[:20],
        "can_be_null": can_be_null,
        "is_enum_result": is_enum_result,
    }


def _infer_convention_from_function(return_type, value_classes, return_values):
    """When callers don't give a clear signal, infer from the function body."""
    if return_type == "bool":
        return CONV_BOOLEAN

    if return_type == "pointer":
        if any(c in ("NULLPTR", "LITERAL_ZERO") for c in value_classes):
            return CONV_POINTER_OR_NULL
        return CONV_POINTER_OR_NULL

    if return_type == "enum":
        return CONV_ENUM_RESULT

    if any(c == "ENUM_VALUE" for c in value_classes):
        return CONV_ENUM_RESULT

    # Check for negative error pattern
    if any(_is_negative_value(v) for v in return_values):
        return CONV_NEGATIVE_IS_ERROR

    # Check for 0/1 pattern
    val_set = set(return_values)
    if val_set <= {"0", "1"}:
        return CONV_BOOLEAN
    if "0" in val_set and len(val_set) > 1:
        return CONV_SUCCESS_IS_ZERO

    return CONV_UNKNOWN


def _is_negative_value(val):
    """Check if a return value represents a negative number."""
    if val.startswith("-"):
        return True
    # 0xFFFFFFFF and similar are -1 as signed
    if val.startswith("0x") or val.startswith("0X"):
        try:
            n = int(val, 16)
            if n >= 0x80000000:
                return True
        except ValueError:
            pass
    return False


# ===================================================================
# Phase 4: Unchecked Return Value Detection
# ===================================================================

def _classify_unchecked_risk(func_name, ret_info, contract, caller_analysis):
    """Classify the risk level of ignoring a function's return value.

    HIGH:  Function returns errors AND is security-relevant or has side effects
    MEDIUM: Function returns errors but is not security-critical
    LOW:   Function's return value is informational only
    """
    has_errors = bool(contract["error_values"])
    is_security = _is_security_relevant(func_name)
    return_type = ret_info["return_type"]
    pseudocode = ret_info.get("pseudocode", "")

    # Check for side effects in the function
    has_side_effects = bool(
        RE_GLOBAL_WRITE.search(pseudocode) or
        RE_SEND_PACKET.search(pseudocode) or
        RE_DB_CALL.search(pseudocode)
    )

    # HIGH: errors exist AND (security-relevant OR has critical side effects)
    if has_errors and is_security:
        return RISK_HIGH
    if has_errors and return_type == "pointer" and contract["can_be_null"]:
        return RISK_HIGH  # Ignoring a nullable pointer return is dangerous

    # Also HIGH if many callers check but this one doesn't
    total = caller_analysis["total_callers"]
    checking = caller_analysis["callers_that_check"]
    if total > 3 and checking > 0:
        check_ratio = checking / total
        if check_ratio > 0.8 and has_errors:
            return RISK_HIGH  # Vast majority check, this caller is outlier

    # MEDIUM: errors exist
    if has_errors:
        return RISK_MEDIUM

    # MEDIUM: pointer that can be null
    if return_type == "pointer" and contract["can_be_null"]:
        return RISK_MEDIUM

    # MEDIUM: function has side effects that might fail
    if has_side_effects and return_type != "void":
        return RISK_MEDIUM

    return RISK_LOW


def _is_security_relevant(func_name):
    """Check if a function name suggests security relevance."""
    name_lower = func_name.lower()

    # Direct match
    if func_name in _SECURITY_FUNCTIONS:
        return True

    # Pattern match
    security_patterns = [
        "validate", "verify", "check", "auth", "permission",
        "security", "access", "login", "valid", "allowed",
        "can_use", "can_attack", "can_equip", "can_cast",
        "has_permission", "is_valid", "is_allowed",
    ]
    for pattern in security_patterns:
        if pattern in name_lower:
            return True

    return False


# ===================================================================
# Phase 5: Error Propagation Chains
# ===================================================================

def _build_error_propagation_chains(function_semantics, error_chains_raw):
    """Build error propagation graphs from the per-function caller data.

    Tracks how error values propagate through call chains:
    func_A returns error -> func_B checks and propagates -> func_C checks
    or: func_A returns error -> func_B swallows it (broken chain)

    Returns:
        List of chain dicts.
    """
    # Build lookup: ea -> function entry
    ea_to_func = {}
    for fs in function_semantics:
        ea_to_func[fs["ea"]] = fs

    # Build adjacency: for each function, who are its callers and what do they do?
    # error_chains_raw: callee_ea -> [{caller_ea, caller_name, action}]

    chains = []
    visited_roots = set()

    # Find chain roots: functions with error returns that have propagating callers
    for fs in function_semantics:
        ea = fs["ea"]
        if ea in visited_roots:
            continue
        if not fs["error_values"]:
            continue

        # Build chains starting from this function
        raw_entries = error_chains_raw.get(ea, [])
        if not raw_entries:
            continue

        for entry in raw_entries:
            action = entry["action"]
            caller_name = entry["caller_name"]
            caller_ea = entry.get("caller_ea")

            chain_steps = [
                {"function": fs["name"], "ea": ea, "action": "returns_error"},
                {"function": caller_name, "ea": caller_ea, "action": action},
            ]

            break_point = None
            if action == "swallow":
                break_point = caller_name

            # Follow propagation further if caller propagates
            if action == "propagate" and caller_ea and caller_ea in ea_to_func:
                _follow_chain(
                    caller_ea, ea_to_func, error_chains_raw,
                    chain_steps, set(), 5  # max depth
                )
                # Check if chain ends with a swallow
                if chain_steps[-1]["action"] == "swallow":
                    break_point = chain_steps[-1]["function"]

            if len(chain_steps) >= 2:
                chains.append({
                    "chain": chain_steps,
                    "break_point": break_point,
                    "root_function": fs["name"],
                    "chain_length": len(chain_steps),
                    "is_broken": break_point is not None,
                })

        visited_roots.add(ea)

    # Sort: broken chains first, then by length descending
    chains.sort(key=lambda c: (not c["is_broken"], -c["chain_length"]))

    # Cap output
    return chains[:500]


def _follow_chain(current_ea, ea_to_func, error_chains_raw, chain_steps,
                  visited, max_depth):
    """Recursively follow error propagation up the call chain."""
    if max_depth <= 0 or current_ea in visited:
        return
    visited.add(current_ea)

    raw_entries = error_chains_raw.get(current_ea, [])
    if not raw_entries:
        return

    # Take the first propagation path (avoid exponential blowup)
    for entry in raw_entries[:1]:
        action = entry["action"]
        caller_name = entry["caller_name"]
        caller_ea = entry.get("caller_ea")

        chain_steps.append({
            "function": caller_name,
            "ea": caller_ea,
            "action": action,
        })

        if action == "propagate" and caller_ea and caller_ea in ea_to_func:
            _follow_chain(
                caller_ea, ea_to_func, error_chains_raw,
                chain_steps, visited, max_depth - 1
            )


# ===================================================================
# Phase 6: HRESULT / WoW Result Code Analysis
# ===================================================================

def _analyze_result_codes(ea, func_name, ret_info):
    """For functions that return enum-like result codes, map values to meanings.

    Searches for:
      - String references near return values (error message strings)
      - Named constants in switch/case blocks
      - Known WoW result code patterns

    Returns:
        Dict mapping return value -> meaning string, or None.
    """
    pseudocode = ret_info.get("pseudocode", "")
    if not pseudocode:
        return None

    code_map = {}

    # Strategy 1: Look for error strings near return values
    # Pattern: if (condition) { SetError("ERR_XXX"); return N; }
    string_return_pattern = re.compile(
        r'"((?:ERR_|RESULT_|SPELL_FAILED_|AUCTION_|GUILD_|CHAR_|AUTH_|'
        r'TRANSFER_|REALM_|RESPONSE_)\w+)"[^;]*;[^}]*?return\s+([^;]+)\s*;',
        re.DOTALL
    )
    for m in string_return_pattern.finditer(pseudocode):
        meaning = m.group(1)
        value = m.group(2).strip()
        code_map[value] = meaning

    # Strategy 2: Look for case N: ... "STRING" patterns
    case_string_pattern = re.compile(
        r'case\s+(0x[0-9A-Fa-f]+|\d+|[A-Z_]+)\s*:.*?"(\w+)"',
        re.DOTALL
    )
    for m in case_string_pattern.finditer(pseudocode):
        value = m.group(1)
        meaning = m.group(2)
        if len(meaning) > 3:  # skip very short strings
            code_map[value] = meaning

    # Strategy 3: Named enum constants in return statements
    for val in ret_info["return_values"]:
        val_stripped = val.strip()
        if RE_ENUM_CONST.match(val_stripped) and val_stripped not in code_map:
            code_map[val_stripped] = val_stripped  # self-documenting

    # Strategy 4: Known WoW result code ranges
    for val in ret_info["return_values"]:
        val_stripped = val.strip()
        meaning = _lookup_known_result_code(val_stripped, func_name)
        if meaning and val_stripped not in code_map:
            code_map[val_stripped] = meaning

    return code_map if code_map else None


def _lookup_known_result_code(value, func_context):
    """Map known WoW result code values to meanings based on function context."""
    # Common patterns across WoW
    context_lower = func_context.lower()

    try:
        if value.startswith("0x"):
            int_val = int(value, 16)
        elif value.isdigit():
            int_val = int(value)
        else:
            return None
    except (ValueError, AttributeError):
        return None

    # Generic success
    if int_val == 0:
        return "SUCCESS / OK"

    # Spell cast result codes
    if "spell" in context_lower or "cast" in context_lower:
        spell_codes = {
            0: "SPELL_CAST_OK",
            1: "SPELL_FAILED_AFFECTING_COMBAT",
            2: "SPELL_FAILED_ALREADY_AT_FULL_HEALTH",
            173: "SPELL_FAILED_UNKNOWN",
        }
        return spell_codes.get(int_val)

    # Character create result codes
    if "char" in context_lower or "create" in context_lower:
        char_codes = {
            0: "CHAR_CREATE_SUCCESS",
            1: "CHAR_CREATE_ERROR",
            2: "CHAR_CREATE_FAILED",
            48: "CHAR_CREATE_NAME_IN_USE",
        }
        return char_codes.get(int_val)

    # Auction result codes
    if "auction" in context_lower:
        auction_codes = {
            0: "AUCTION_OK",
            1: "AUCTION_ERR_INVENTORY",
            6: "AUCTION_ERR_NOT_ENOUGH_MONEY",
        }
        return auction_codes.get(int_val)

    return None


# ===================================================================
# Phase 7: TC Comparison
# ===================================================================

def _compare_with_tc(session, function_semantics):
    """Compare binary return semantics against TrinityCore source.

    Checks for:
      - TC returns bool but binary returns enum (TC loses error detail)
      - TC ignores return value but binary always checks (TC has bug)
      - TC checks wrong value (SUCCESS_IS_ZERO vs SUCCESS_IS_NONZERO)

    Returns:
        List of mismatch dicts.
    """
    cfg = session.cfg
    tc_dir = getattr(cfg, "tc_source_dir", None)
    if not tc_dir:
        msg_info("TC source dir not configured; skipping TC comparison.")
        return []

    import os
    if not os.path.isdir(tc_dir):
        msg_warn(f"TC source dir does not exist: {tc_dir}")
        return []

    mismatches = []
    functions_compared = 0

    for fs in function_semantics:
        func_name = fs["name"]
        if not func_name or func_name.startswith("sub_"):
            continue

        # Try to find this function in TC source
        tc_info = _find_tc_function_info(tc_dir, func_name)
        if not tc_info:
            continue

        functions_compared += 1

        # Compare return type
        binary_type = fs["return_type"]
        tc_type = tc_info.get("return_type", "unknown")

        if binary_type == "enum" and tc_type == "bool":
            mismatches.append({
                "function": func_name,
                "ea": fs["ea"],
                "binary_convention": fs["convention"],
                "tc_convention": CONV_BOOLEAN,
                "mismatch_type": "TC_LOSES_ERROR_DETAIL",
                "detail": (f"Binary returns enum/int with {len(fs['error_values'])} "
                           f"error values, but TC returns bool"),
                "binary_return_type": binary_type,
                "tc_return_type": tc_type,
                "error_values_lost": fs["error_values"][:10],
            })

        if binary_type == "int" and tc_type == "bool":
            # Check if binary has more than 2 distinct return values
            if len(fs.get("return_values", [])) > 2:
                mismatches.append({
                    "function": func_name,
                    "ea": fs["ea"],
                    "binary_convention": fs["convention"],
                    "tc_convention": CONV_BOOLEAN,
                    "mismatch_type": "TC_LOSES_ERROR_DETAIL",
                    "detail": (f"Binary has {len(fs['return_values'])} distinct "
                               f"return values but TC only returns bool"),
                    "binary_return_type": binary_type,
                    "tc_return_type": tc_type,
                    "error_values_lost": fs["error_values"][:10],
                })

        # Compare convention
        binary_conv = fs["convention"]
        tc_conv = tc_info.get("convention", CONV_UNKNOWN)

        if (binary_conv != CONV_UNKNOWN and tc_conv != CONV_UNKNOWN and
                binary_conv != tc_conv):
            # Check for specific dangerous mismatches
            if ({binary_conv, tc_conv} == {CONV_SUCCESS_IS_ZERO, CONV_SUCCESS_IS_NONZERO}):
                mismatches.append({
                    "function": func_name,
                    "ea": fs["ea"],
                    "binary_convention": binary_conv,
                    "tc_convention": tc_conv,
                    "mismatch_type": "INVERTED_SUCCESS_CHECK",
                    "detail": (f"Binary uses {binary_conv} but TC uses {tc_conv} "
                               f"-- logic is INVERTED"),
                    "binary_return_type": binary_type,
                    "tc_return_type": tc_type,
                })

        # Check for TC ignoring return value that binary always checks
        tc_unchecked = tc_info.get("callers_ignore_count", 0)
        tc_total = tc_info.get("caller_count", 0)
        binary_ignore_ratio = (
            fs["callers_that_ignore"] / max(fs["caller_count"], 1)
        )
        tc_ignore_ratio = tc_unchecked / max(tc_total, 1) if tc_total else 0

        if (binary_ignore_ratio < 0.1 and tc_ignore_ratio > 0.5 and
                fs["caller_count"] >= 3 and tc_total >= 2):
            mismatches.append({
                "function": func_name,
                "ea": fs["ea"],
                "binary_convention": binary_conv,
                "tc_convention": tc_conv,
                "mismatch_type": "TC_IGNORES_RETURN_VALUE",
                "detail": (f"Binary callers check return {100 * (1 - binary_ignore_ratio):.0f}% "
                           f"of the time, but TC callers ignore it "
                           f"{100 * tc_ignore_ratio:.0f}% of the time"),
                "binary_return_type": binary_type,
                "tc_return_type": tc_type,
            })

        # Check for nullable pointer that TC doesn't null-check
        if fs["can_be_null"] and not tc_info.get("checks_null", True):
            mismatches.append({
                "function": func_name,
                "ea": fs["ea"],
                "binary_convention": CONV_POINTER_OR_NULL,
                "tc_convention": tc_conv,
                "mismatch_type": "TC_MISSING_NULL_CHECK",
                "detail": "Binary can return null but TC doesn't check for it",
                "binary_return_type": binary_type,
                "tc_return_type": tc_type,
            })

    msg_info(f"TC comparison: compared {functions_compared} functions, "
             f"found {len(mismatches)} mismatches")

    return mismatches


def _find_tc_function_info(tc_dir, func_name):
    """Search TrinityCore source for a function and extract its return info.

    Returns:
        Dict with: return_type, convention, caller_count,
        callers_ignore_count, checks_null.
        Returns None if not found.
    """
    import os

    # Determine search name -- strip common prefixes/namespaces
    search_name = func_name
    for prefix in ("WowClientDB2_", "WowClientDB_", "CGUnit_C__", "CGPlayer_C__",
                   "CGObject_C__", "CGGameObject_C__", "CMovement__"):
        if search_name.startswith(prefix):
            search_name = search_name[len(prefix):]
            break

    # Replace __ with :: for C++ namespace
    search_name_cpp = search_name.replace("__", "::")

    # Search in common TC source directories
    search_dirs = [
        os.path.join(tc_dir, "src", "server", "game"),
        os.path.join(tc_dir, "src", "server", "scripts"),
        os.path.join(tc_dir, "src", "common"),
    ]

    found_files = []
    for sdir in search_dirs:
        if not os.path.isdir(sdir):
            continue
        for root, dirs, files in os.walk(sdir):
            for fname in files:
                if not fname.endswith((".cpp", ".h")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if search_name in content or search_name_cpp in content:
                        found_files.append((fpath, content))
                except OSError:
                    continue

    if not found_files:
        return None

    # Analyze the found source
    tc_return_type = "unknown"
    tc_convention = CONV_UNKNOWN
    caller_count = 0
    callers_ignore = 0
    checks_null = True

    for fpath, content in found_files:
        # Find function definition
        # Pattern: ReturnType ClassName::FuncName(
        def_pattern = re.compile(
            rf'(\w[\w\s\*&:<>]*?)\s+(?:\w+::)*{re.escape(search_name)}\s*\(',
            re.MULTILINE
        )
        for m in def_pattern.finditer(content):
            raw_type = m.group(1).strip()
            # Clean up
            for qualifier in ("static", "virtual", "inline", "const",
                              "override", "final"):
                raw_type = raw_type.replace(qualifier, "").strip()

            if raw_type in ("bool", "_Bool"):
                tc_return_type = "bool"
                tc_convention = CONV_BOOLEAN
            elif "*" in raw_type:
                tc_return_type = "pointer"
                tc_convention = CONV_POINTER_OR_NULL
            elif raw_type == "void":
                tc_return_type = "void"
            elif raw_type in ("int", "int32", "uint32", "int64", "uint64",
                              "SpellCastResult", "InventoryResult"):
                tc_return_type = raw_type
                if "Result" in raw_type:
                    tc_convention = CONV_ENUM_RESULT
            break

        # Count how callers use it
        call_pattern = re.compile(
            rf'(\w+)\s*=\s*(?:\w+(?:::|\.|->))*{re.escape(search_name)}\s*\(',
            re.MULTILINE
        )
        for cm in call_pattern.finditer(content):
            caller_count += 1
            result_var = cm.group(1)
            # Check if result_var is used in a condition after this
            pos = cm.end()
            after = content[pos:pos + 500]
            escaped_rv = re.escape(result_var)
            if not re.search(rf'if\s*\(\s*!?\s*{escaped_rv}\b', after):
                callers_ignore += 1

        # Check for bare calls (no assignment)
        bare_pattern = re.compile(
            rf'^\s+(?:\w+(?:::|\.|->))*{re.escape(search_name)}\s*\(',
            re.MULTILINE
        )
        for _ in bare_pattern.finditer(content):
            caller_count += 1
            callers_ignore += 1

        # Check for null checks on pointer returns
        if tc_return_type == "pointer":
            null_check = re.search(
                rf'(?:\w+)\s*=\s*(?:\w+(?:::|\.|->))*{re.escape(search_name)}\s*\([^)]*\)\s*;'
                rf'[^{{}}]*?if\s*\(\s*!?\s*\w+\s*\)',
                content, re.DOTALL
            )
            checks_null = null_check is not None

    if tc_return_type == "unknown":
        return None

    return {
        "return_type": tc_return_type,
        "convention": tc_convention,
        "caller_count": caller_count,
        "callers_ignore_count": callers_ignore,
        "checks_null": checks_null,
    }


# ===================================================================
# Summary / Reporting
# ===================================================================

def _print_summary(results):
    """Print a human-readable summary of the analysis."""
    msg("=" * 70)
    msg("RETURN VALUE SEMANTICS ANALYSIS SUMMARY")
    msg("=" * 70)

    total = results["total_functions"]
    msg(f"  Functions analyzed:      {total}")
    msg(f"  Unchecked return values: {results['total_unchecked']}")
    msg(f"  Error propagation chains:{results['total_error_chains']}")
    msg(f"  TC mismatches:           {results['total_mismatches']}")
    msg(f"  Analysis time:           {results['analysis_time_sec']}s")

    # Convention breakdown
    conv_counts = defaultdict(int)
    for fs in results["function_semantics"]:
        conv_counts[fs["convention"]] += 1
    msg("")
    msg("  Convention breakdown:")
    for conv, count in sorted(conv_counts.items(), key=lambda x: -x[1]):
        pct = 100 * count / max(total, 1)
        msg(f"    {conv:30s} {count:5d} ({pct:5.1f}%)")

    # Return type breakdown
    type_counts = defaultdict(int)
    for fs in results["function_semantics"]:
        type_counts[fs["return_type"]] += 1
    msg("")
    msg("  Return type breakdown:")
    for rtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        pct = 100 * count / max(total, 1)
        msg(f"    {rtype:30s} {count:5d} ({pct:5.1f}%)")

    # Unchecked return risk breakdown
    risk_counts = defaultdict(int)
    for uc in results["unchecked_returns"]:
        risk_counts[uc["risk_level"]] += 1
    if risk_counts:
        msg("")
        msg("  Unchecked return risk levels:")
        for risk in (RISK_HIGH, RISK_MEDIUM, RISK_LOW):
            if risk in risk_counts:
                msg(f"    {risk:10s} {risk_counts[risk]:5d}")

    # Top unchecked HIGH risk
    high_risk = [uc for uc in results["unchecked_returns"]
                 if uc["risk_level"] == RISK_HIGH]
    if high_risk:
        msg("")
        msg("  Top HIGH-risk unchecked returns:")
        for uc in high_risk[:10]:
            msg(f"    {uc['caller_name']} ignores {uc['callee_name']} "
                f"(errors: {uc['possible_errors'][:3]})")

    # Broken error chains
    broken = [c for c in results["error_chains"] if c["is_broken"]]
    if broken:
        msg("")
        msg(f"  Broken error propagation chains: {len(broken)}")
        for chain in broken[:5]:
            steps = " -> ".join(
                f"{s['function']}({s['action']})"
                for s in chain["chain"]
            )
            msg(f"    {steps}")
            msg(f"      Break at: {chain['break_point']}")

    # TC mismatches
    if results["tc_mismatches"]:
        msg("")
        msg("  TC mismatches (top 10):")
        for mm in results["tc_mismatches"][:10]:
            msg(f"    [{mm['mismatch_type']}] {mm['function']}")
            msg(f"      {mm['detail']}")

    # Result code dictionary summary
    rcd = results.get("result_code_dictionary", {})
    if rcd:
        msg("")
        msg(f"  Result code dictionaries recovered: {len(rcd)} functions")
        total_codes = sum(len(v) for v in rcd.values())
        msg(f"  Total result codes mapped:          {total_codes}")
        for func_name, codes in sorted(rcd.items())[:5]:
            msg(f"    {func_name}: {len(codes)} codes")
            for val, meaning in list(codes.items())[:3]:
                msg(f"      {val} => {meaning}")

    msg("=" * 70)
