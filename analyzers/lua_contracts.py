"""
Lua<->C++ Interface Completeness Analysis (Feature #13)

Decompiles each Lua API function's C++ implementation to extract its
behavioral contract: parameters read from the Lua stack, return values
pushed back, game state accessed, validations performed.  Compares
against TrinityCore's Lua bindings to find missing functions, incomplete
implementations, and wrong return types.
"""

import json
import os
import re
import time

import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text,
    get_func_name_safe,
)


# ---------------------------------------------------------------------------
# Lua stack access patterns (parameter extraction)
# ---------------------------------------------------------------------------

# lua_to* family -- mandatory parameter extraction
_PARAM_PATTERNS = [
    # lua_tointeger(L, N)  /  lua_tointegerx(L, N, &ok)
    re.compile(
        r'lua_tointeger[x]?\s*\(\s*\w+\s*,\s*(\d+)',
        re.IGNORECASE,
    ),
    # lua_tonumber(L, N) / lua_tonumberx
    re.compile(
        r'lua_tonumber[x]?\s*\(\s*\w+\s*,\s*(\d+)',
        re.IGNORECASE,
    ),
    # lua_tostring(L, N) / lua_tolstring
    re.compile(
        r'lua_to[l]?string\s*\(\s*\w+\s*,\s*(\d+)',
        re.IGNORECASE,
    ),
    # lua_toboolean(L, N)
    re.compile(
        r'lua_toboolean\s*\(\s*\w+\s*,\s*(\d+)',
        re.IGNORECASE,
    ),
    # lua_touserdata(L, N)
    re.compile(
        r'lua_touserdata\s*\(\s*\w+\s*,\s*(\d+)',
        re.IGNORECASE,
    ),
]

# Type string for each pattern above (same order)
_PARAM_TYPES = ["integer", "number", "string", "boolean", "userdata"]

# luaL_check* family -- mandatory with type enforcement
_CHECK_PATTERNS = [
    # luaL_checkinteger(L, N)
    (re.compile(r'luaL_checkinteger\s*\(\s*\w+\s*,\s*(\d+)', re.IGNORECASE), "integer"),
    # luaL_checknumber(L, N)
    (re.compile(r'luaL_checknumber\s*\(\s*\w+\s*,\s*(\d+)', re.IGNORECASE), "number"),
    # luaL_checkstring / luaL_checklstring
    (re.compile(r'luaL_check[l]?string\s*\(\s*\w+\s*,\s*(\d+)', re.IGNORECASE), "string"),
    # luaL_checkudata(L, N, tname)
    (re.compile(r'luaL_checkudata\s*\(\s*\w+\s*,\s*(\d+)', re.IGNORECASE), "userdata"),
]

# luaL_opt* family -- optional parameters with default
_OPT_PATTERNS = [
    # luaL_optinteger(L, N, default)
    (re.compile(
        r'luaL_optinteger\s*\(\s*\w+\s*,\s*(\d+)\s*,\s*([^)]+)\)',
        re.IGNORECASE,
    ), "integer"),
    # luaL_optnumber(L, N, default)
    (re.compile(
        r'luaL_optnumber\s*\(\s*\w+\s*,\s*(\d+)\s*,\s*([^)]+)\)',
        re.IGNORECASE,
    ), "number"),
    # luaL_optstring / luaL_optlstring
    (re.compile(
        r'luaL_opt[l]?string\s*\(\s*\w+\s*,\s*(\d+)\s*,\s*([^)]+)\)',
        re.IGNORECASE,
    ), "string"),
]

# ---------------------------------------------------------------------------
# Lua stack push patterns (return values)
# ---------------------------------------------------------------------------

_PUSH_PATTERNS = [
    (re.compile(r'lua_pushinteger\s*\(', re.IGNORECASE), "integer"),
    (re.compile(r'lua_pushnumber\s*\(', re.IGNORECASE), "number"),
    (re.compile(r'lua_pushstring\s*\(', re.IGNORECASE), "string"),
    (re.compile(r'lua_pushlstring\s*\(', re.IGNORECASE), "string"),
    (re.compile(r'lua_pushboolean\s*\(', re.IGNORECASE), "boolean"),
    (re.compile(r'lua_pushnil\s*\(', re.IGNORECASE), "nil"),
    (re.compile(r'lua_newtable\s*\(', re.IGNORECASE), "table"),
    (re.compile(r'lua_createtable\s*\(', re.IGNORECASE), "table"),
    (re.compile(r'lua_pushlightuserdata\s*\(', re.IGNORECASE), "userdata"),
    (re.compile(r'lua_pushfstring\s*\(', re.IGNORECASE), "string"),
    (re.compile(r'lua_pushvalue\s*\(', re.IGNORECASE), "value"),
]

# Table field assignment patterns
_TABLE_SETFIELD = re.compile(
    r'lua_setfield\s*\(\s*\w+\s*,\s*[^,]+,\s*"([^"]+)"',
    re.IGNORECASE,
)
_TABLE_RAWSETI = re.compile(
    r'lua_rawseti\s*\(\s*\w+\s*,\s*[^,]+,\s*(\d+)',
    re.IGNORECASE,
)

# Return count: ``return N;`` at the end of a Lua C function
_RETURN_N = re.compile(r'return\s+(\d+)\s*;')

# Secure-transfer / hardware-event markers
_SECURE_PATTERNS = re.compile(
    r'SecureTransfer|IsHardwareEvent|C_PlayerInteraction|IsSecureAction',
    re.IGNORECASE,
)

# Game-state accessor patterns
_GAME_STATE_READ_PATTERNS = [
    (re.compile(r'GetPlayer\s*\(', re.IGNORECASE), "Player"),
    (re.compile(r'GetUnit\s*\(', re.IGNORECASE), "Unit"),
    (re.compile(r'GetMap\s*\(', re.IGNORECASE), "Map"),
    (re.compile(r'GetGroup\s*\(', re.IGNORECASE), "Group"),
    (re.compile(r'GetGuild\s*\(', re.IGNORECASE), "Guild"),
    (re.compile(r'GetBattleground\s*\(', re.IGNORECASE), "Battleground"),
    (re.compile(r'GetArena\s*\(', re.IGNORECASE), "Arena"),
    (re.compile(r'GetHousing\s*\(', re.IGNORECASE), "Housing"),
    (re.compile(r'GetNeighborhood\s*\(', re.IGNORECASE), "Neighborhood"),
    (re.compile(r'ObjectMgr', re.IGNORECASE), "ObjectMgr"),
    (re.compile(r'sWorld\b', re.IGNORECASE), "World"),
    (re.compile(r'DB2.*Get\w*Row|DB2.*Lookup|sDB2', re.IGNORECASE), "DB2"),
    (re.compile(r'CharacterDatabase|WorldDatabase|LoginDatabase', re.IGNORECASE), "Database"),
]

_GAME_STATE_WRITE_PATTERNS = [
    (re.compile(r'Set[A-Z]\w+\s*\(', re.IGNORECASE), "setter"),
    (re.compile(r'Add[A-Z]\w+\s*\(', re.IGNORECASE), "adder"),
    (re.compile(r'Remove[A-Z]\w+\s*\(', re.IGNORECASE), "remover"),
    (re.compile(r'Update[A-Z]\w+\s*\(', re.IGNORECASE), "updater"),
    (re.compile(r'SendPacket\s*\(', re.IGNORECASE), "network_send"),
    (re.compile(r'CastSpell\s*\(', re.IGNORECASE), "spell_cast"),
    (re.compile(r'Teleport\w*\s*\(', re.IGNORECASE), "teleport"),
    (re.compile(r'Save\w*ToDB\s*\(', re.IGNORECASE), "db_write"),
]

# Validation patterns in Lua C functions
_VALIDATION_PATTERNS = [
    (re.compile(r'luaL_argerror\s*\(', re.IGNORECASE), "arg_error"),
    (re.compile(r'luaL_typerror\s*\(', re.IGNORECASE), "type_error"),
    (re.compile(r'luaL_argcheck\s*\(', re.IGNORECASE), "arg_check"),
    (re.compile(r'lua_gettop\s*\(', re.IGNORECASE), "arg_count_check"),
]

# Called function extraction
_FUNC_CALL_PATTERN = re.compile(
    r'\b([A-Z]\w{2,}(?:::[A-Z]\w+)?)\s*\(',
)

_CPP_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "static_cast",
    "dynamic_cast", "reinterpret_cast", "const_cast", "typeid", "throw",
    "delete", "new", "break", "continue", "else", "case", "default",
    "goto", "typedef", "struct", "class", "enum", "union", "namespace",
    "try", "catch", "void", "unsigned", "signed", "const", "volatile",
    "LABEL", "LODWORD", "HIDWORD", "LOBYTE", "HIBYTE", "LOWORD", "HIWORD",
    "BYTE", "WORD", "DWORD", "QWORD", "BOOL", "JUMPOUT",
})


# ===================================================================
# Public API
# ===================================================================

def analyze_lua_contracts(session, system_filter=None):
    """Main entry point: decompile every Lua API function, extract its
    behavioral contract, store results in kv_store as ``lua_contracts``.

    Args:
        session: PluginSession with .db and .cfg
        system_filter: Optional system name to limit analysis (e.g. "Housing")

    Returns:
        Number of contracts successfully analyzed.
    """
    db = session.db

    query = "SELECT namespace, method, handler_ea, arg_count FROM lua_api"
    params = ()
    if system_filter:
        query += " WHERE namespace LIKE ? OR method LIKE ?"
        like = f"%{system_filter}%"
        params = (like, like)

    rows = db.fetchall(query, params)
    if not rows:
        msg_warn("No Lua API functions in DB. Run lua_api analysis first.")
        return 0

    msg_info(f"Analyzing Lua contracts for {len(rows)} functions...")
    contracts = []
    failed = 0

    for idx, row in enumerate(rows):
        ea = row["handler_ea"]
        ns = row["namespace"] or ""
        method = row["method"] or ""
        full_name = f"{ns}.{method}" if ns else method

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            failed += 1
            continue

        contract = _analyze_lua_function(ea, full_name, pseudocode)
        contracts.append(contract)

        if (idx + 1) % 100 == 0:
            msg_info(f"  Processed {idx + 1}/{len(rows)}...")

    # Store in kv_store
    db.kv_set("lua_contracts", contracts)

    # Also update lua_api rows with extracted param/return info
    for contract in contracts:
        ea = contract["ea"]
        db.execute(
            "UPDATE lua_api SET args_json = ?, returns_json = ? "
            "WHERE handler_ea = ?",
            (
                json.dumps(contract["parameters"]),
                json.dumps(contract["return_values"]),
                ea,
            ),
        )

    db.commit()
    msg_info(
        f"Lua contract analysis complete: {len(contracts)} analyzed, "
        f"{failed} failed to decompile"
    )
    return len(contracts)


def _analyze_lua_function(ea, name, pseudocode):
    """Analyze one Lua C function's pseudocode and extract its full
    behavioral contract.

    Args:
        ea: Effective address of the handler
        name: Full Lua name (e.g. "C_Housing.GetDecorInfo")
        pseudocode: Decompiled C text

    Returns:
        Contract dict.
    """
    parameters = _extract_lua_params(pseudocode)
    return_values, num_returns = _extract_lua_returns(pseudocode)
    reads, writes, side_effects = _extract_game_state_access(pseudocode, ea)
    validations = _extract_validations(pseudocode)
    called_funcs = _extract_called_functions(pseudocode)
    error_returns = _extract_error_returns(pseudocode)
    is_secure = bool(_SECURE_PATTERNS.search(pseudocode))

    # Infer system from name
    system = _infer_system(name)

    return {
        "name": name,
        "ea": ea,
        "parameters": parameters,
        "return_values": return_values,
        "num_returns": num_returns,
        "validations": validations,
        "game_state_reads": reads,
        "game_state_writes": writes,
        "side_effects": side_effects,
        "called_functions": called_funcs,
        "error_returns": error_returns,
        "is_secure": is_secure,
        "system": system,
    }


# ===================================================================
# Parameter extraction
# ===================================================================

def _extract_lua_params(pseudocode):
    """Extract all parameter reads from the Lua stack.

    Returns a list of parameter dicts sorted by stack index.
    """
    params = {}  # keyed by stack index (int)

    # 1. lua_to* (basic extraction, not type-checked)
    for pat, ptype in zip(_PARAM_PATTERNS, _PARAM_TYPES):
        for m in pat.finditer(pseudocode):
            idx = int(m.group(1))
            if idx not in params or params[idx].get("optional"):
                params[idx] = {
                    "index": idx,
                    "type": ptype,
                    "name": _guess_param_name(pseudocode, m, ptype, idx),
                    "optional": False,
                    "checked": False,
                }

    # 2. luaL_check* (mandatory with type enforcement -- overrides lua_to*)
    for pat, ptype in _CHECK_PATTERNS:
        for m in pat.finditer(pseudocode):
            idx = int(m.group(1))
            params[idx] = {
                "index": idx,
                "type": ptype,
                "name": _guess_param_name(pseudocode, m, ptype, idx),
                "optional": False,
                "checked": True,
            }

    # 3. luaL_opt* (optional with default)
    for pat, ptype in _OPT_PATTERNS:
        for m in pat.finditer(pseudocode):
            idx = int(m.group(1))
            default_val = m.group(2).strip().rstrip(")")
            params[idx] = {
                "index": idx,
                "type": ptype,
                "name": _guess_param_name(pseudocode, m, ptype, idx),
                "optional": True,
                "checked": True,
                "default": default_val,
            }

    # 4. Detect varargs via lua_gettop
    gettop_pat = re.compile(r'lua_gettop\s*\(\s*\w+\s*\)', re.IGNORECASE)
    if gettop_pat.search(pseudocode):
        # If gettop is used and there are existing params, mark the function
        # as accepting variable arguments
        max_idx = max(params.keys()) if params else 0
        if max_idx not in params:
            params[max_idx] = {
                "index": max_idx,
                "type": "varargs",
                "name": "...",
                "optional": True,
                "checked": False,
            }

    # Sort by index and return
    return [params[k] for k in sorted(params.keys())]


def _guess_param_name(pseudocode, match, ptype, idx):
    """Try to guess a meaningful parameter name from assignment context.

    Looks for patterns like:
        int decorId = lua_tointeger(L, 1);
        v5 = lua_tostring(L, 2);
    """
    # Search backward from match for assignment target
    line_start = pseudocode.rfind("\n", 0, match.start())
    if line_start < 0:
        line_start = 0
    line = pseudocode[line_start:match.start()].strip()

    # Pattern: ``type varName = ``  or  ``varName = ``
    assign_pat = re.compile(r'(?:\w+\s+\*?\s*)?(\w+)\s*=\s*$')
    am = assign_pat.search(line)
    if am:
        varname = am.group(1)
        # Skip IDA temporaries like v5, a1
        if not re.match(r'^[av]\d+$', varname):
            return varname

    # Fall back to generic names
    generic = {
        "integer": f"arg{idx}",
        "number": f"value{idx}",
        "string": f"str{idx}",
        "boolean": f"flag{idx}",
        "userdata": f"ud{idx}",
    }
    return generic.get(ptype, f"param{idx}")


# ===================================================================
# Return value extraction
# ===================================================================

def _extract_lua_returns(pseudocode):
    """Extract return value construction from pseudocode.

    Returns:
        (return_values_list, max_num_returns)
    """
    return_values = []
    seen_types = []

    # Count each push type
    for pat, rtype in _PUSH_PATTERNS:
        count = len(pat.findall(pseudocode))
        if count > 0:
            seen_types.append(rtype)
            return_values.append({
                "type": rtype,
                "count": count,
            })

    # Detect table field construction
    table_fields = []
    for m in _TABLE_SETFIELD.finditer(pseudocode):
        field_name = m.group(1)
        # Determine the type of value set for this field by looking at the
        # push call immediately before the setfield call
        field_type = _infer_table_field_type(pseudocode, m.start())
        table_fields.append({
            "name": field_name,
            "type": field_type,
        })

    # Detect array-style table construction (rawseti)
    array_indices = []
    for m in _TABLE_RAWSETI.finditer(pseudocode):
        array_indices.append(int(m.group(1)))

    if table_fields:
        # Enrich the table return entry
        for rv in return_values:
            if rv["type"] == "table":
                rv["fields"] = table_fields
                break
        else:
            # Table created without explicit newtable (possible via C API)
            return_values.append({
                "type": "table",
                "count": 1,
                "fields": table_fields,
            })

    if array_indices:
        for rv in return_values:
            if rv["type"] == "table":
                rv["array_size"] = max(array_indices) if array_indices else 0
                break

    # Determine num_returns from ``return N;`` statements
    return_counts = [int(m.group(1)) for m in _RETURN_N.finditer(pseudocode)]
    if return_counts:
        num_returns = max(return_counts)
    elif return_values:
        # Estimate from push count minus table-internal pushes
        table_push_count = sum(
            rv["count"] for rv in return_values if rv["type"] == "table"
        )
        total_pushes = sum(rv["count"] for rv in return_values)
        # Table fields are pushed then consumed by setfield, not returned
        table_field_count = len(table_fields) + len(array_indices)
        num_returns = max(1, total_pushes - table_field_count * 2 - table_push_count + (1 if table_fields or array_indices else 0))
    else:
        num_returns = 0

    return return_values, num_returns


def _infer_table_field_type(pseudocode, setfield_pos):
    """Look backward from a lua_setfield call to find what was pushed."""
    # Search the ~200 chars before the setfield for the last push call
    search_start = max(0, setfield_pos - 300)
    segment = pseudocode[search_start:setfield_pos]

    # Find the last push call in the segment
    last_type = "unknown"
    last_pos = -1
    for pat, rtype in _PUSH_PATTERNS:
        for m in pat.finditer(segment):
            if m.start() > last_pos:
                last_pos = m.start()
                last_type = rtype
    return last_type


# ===================================================================
# Game state access extraction
# ===================================================================

def _extract_game_state_access(pseudocode, ea):
    """Determine what game data is read and written.

    Returns:
        (reads: list[str], writes: list[str], side_effects: list[str])
    """
    reads = []
    writes = []
    side_effects = []

    # Reads
    for pat, label in _GAME_STATE_READ_PATTERNS:
        if pat.search(pseudocode):
            reads.append(label)

    # Writes / side effects
    for pat, label in _GAME_STATE_WRITE_PATTERNS:
        matches = pat.findall(pseudocode)
        if matches:
            if label == "network_send":
                side_effects.append("sends_packet")
            elif label == "spell_cast":
                side_effects.append("casts_spell")
            elif label == "teleport":
                side_effects.append("teleports")
            elif label == "db_write":
                writes.append("database")
            else:
                # Extract the specific setter/adder/remover names
                for m_text in matches:
                    writes.append(m_text.strip().rstrip("("))

    # Deduplicate
    reads = sorted(set(reads))
    writes = sorted(set(writes))
    side_effects = sorted(set(side_effects))

    return reads, writes, side_effects


# ===================================================================
# Validation extraction
# ===================================================================

def _extract_validations(pseudocode):
    """Extract validation / guard patterns from the pseudocode."""
    validations = []

    # Explicit Lua arg-check calls
    for pat, vtype in _VALIDATION_PATTERNS:
        for m in pat.finditer(pseudocode):
            validations.append({
                "type": vtype,
                "detail": _extract_surrounding_context(pseudocode, m.start(), 120),
            })

    # If-return-nil patterns (common error guard in Lua C functions)
    # Pattern: if (condition) { lua_pushnil(L); return 1; }
    nil_guard = re.compile(
        r'if\s*\(([^{;]{3,80})\)\s*\{?\s*(?:\n\s*)?lua_pushnil\s*\(',
        re.IGNORECASE | re.DOTALL,
    )
    for m in nil_guard.finditer(pseudocode):
        condition = m.group(1).strip()
        vtype = _classify_validation(condition)
        validations.append({
            "type": vtype,
            "detail": condition[:200],
        })

    # If-return-0 patterns (return nothing)
    zero_guard = re.compile(
        r'if\s*\(([^{;]{3,80})\)\s*\{?\s*(?:\n\s*)?return\s+0\s*;',
        re.IGNORECASE | re.DOTALL,
    )
    for m in zero_guard.finditer(pseudocode):
        condition = m.group(1).strip()
        vtype = _classify_validation(condition)
        validations.append({
            "type": vtype,
            "detail": condition[:200],
        })

    # Early returns with luaL_error
    error_guard = re.compile(
        r'luaL_error\s*\(\s*\w+\s*,\s*"([^"]+)"',
        re.IGNORECASE,
    )
    for m in error_guard.finditer(pseudocode):
        validations.append({
            "type": "lua_error",
            "detail": m.group(1)[:200],
        })

    return validations


def _classify_validation(condition):
    """Classify a validation condition string into a category."""
    cond_lower = condition.lower()
    if "null" in cond_lower or "!" in condition and "(" not in condition:
        return "null_check"
    if any(op in condition for op in ["<", ">", "<=", ">="]):
        return "range_check"
    if "combat" in cond_lower or "dead" in cond_lower or "alive" in cond_lower:
        return "state_check"
    if "permission" in cond_lower or "access" in cond_lower:
        return "permission_check"
    if "==" in condition or "!=" in condition:
        return "equality_check"
    return "arg_check"


def _extract_surrounding_context(text, pos, radius):
    """Get text around a position for context."""
    start = max(0, pos - radius)
    end = min(len(text), pos + radius)
    snippet = text[start:end].strip()
    # Collapse whitespace
    snippet = re.sub(r'\s+', ' ', snippet)
    return snippet[:250]


# ===================================================================
# Called function extraction
# ===================================================================

def _extract_called_functions(pseudocode):
    """Extract named function/method calls from pseudocode."""
    funcs = set()
    for m in _FUNC_CALL_PATTERN.finditer(pseudocode):
        name = m.group(1)
        # Filter out C++ keywords and IDA artifacts
        base = name.split("::")[0] if "::" in name else name
        if base.upper() in _CPP_KEYWORDS or base in _CPP_KEYWORDS:
            continue
        # Skip lua_* and luaL_* -- those are infrastructure, not game logic
        if name.startswith("lua_") or name.startswith("luaL_"):
            continue
        funcs.add(name)
    return sorted(funcs)


# ===================================================================
# Error return extraction
# ===================================================================

def _extract_error_returns(pseudocode):
    """Find return paths that indicate errors (pushnil+return, return 0)."""
    errors = []

    # Pattern: if (condition) { lua_pushnil(...); return 1; }
    nil_return = re.compile(
        r'if\s*\(([^{;]{3,120})\)\s*\{?\s*(?:\n\s*)?'
        r'lua_pushnil\s*\([^)]*\)\s*;'
        r'(?:\s*\n\s*)?return\s+(\d+)\s*;',
        re.IGNORECASE | re.DOTALL,
    )
    for m in nil_return.finditer(pseudocode):
        errors.append({
            "condition": m.group(1).strip()[:200],
            "returns": "nil",
            "return_count": int(m.group(2)),
        })

    # Pattern: if (condition) { return 0; }  (no return values)
    zero_return = re.compile(
        r'if\s*\(([^{;]{3,120})\)\s*\{?\s*(?:\n\s*)?return\s+0\s*;',
        re.IGNORECASE | re.DOTALL,
    )
    for m in zero_return.finditer(pseudocode):
        condition = m.group(1).strip()
        # Avoid duplicating entries already captured by nil_return
        if not any(e["condition"] == condition[:200] for e in errors):
            errors.append({
                "condition": condition[:200],
                "returns": "nothing",
                "return_count": 0,
            })

    # Pattern: luaL_error (raises Lua error, does not return normally)
    lua_error = re.compile(
        r'luaL_error\s*\(\s*\w+\s*,\s*"([^"]+)"',
        re.IGNORECASE,
    )
    for m in lua_error.finditer(pseudocode):
        errors.append({
            "condition": "explicit error",
            "returns": f"lua_error: {m.group(1)[:150]}",
            "return_count": -1,
        })

    return errors


# ===================================================================
# System inference
# ===================================================================

_SYSTEM_KEYWORDS = {
    "Housing": ["Housing", "House", "Decor", "Interior", "Plot", "Furniture"],
    "Neighborhood": ["Neighborhood", "Neighbour"],
    "Quest": ["Quest"],
    "Combat": ["Spell", "Aura", "Combat", "Attack", "Damage", "Heal"],
    "Social": ["Guild", "Chat", "Friends", "Mail", "Calendar"],
    "PvP": ["Battleground", "Arena", "PvP", "Honor", "Conquest"],
    "Auction": ["Auction", "AH"],
    "Crafting": ["Crafting", "Trade", "Recipe", "Profession"],
    "Pet": ["PetBattle", "Pet", "BattlePet"],
    "Achievement": ["Achievement"],
    "Loot": ["Loot", "Roll"],
    "Item": ["Item", "Container", "Equipment", "Inventory"],
    "Map": ["Map", "Zone", "Area", "Instance"],
    "Talent": ["Talent", "Spec"],
    "Character": ["Character", "Player", "Unit"],
    "Vehicle": ["Vehicle"],
    "MythicPlus": ["MythicPlus", "Keystone", "Affix"],
    "Delves": ["Delve"],
    "Garrison": ["Garrison", "Shipyard"],
    "UI": ["Frame", "Widget", "Button", "EditBox", "Tooltip", "Cursor"],
}


def _infer_system(name):
    """Infer the game system from a Lua API function name."""
    # Check C_ namespace prefix first (e.g. C_Housing.GetDecorInfo)
    if "." in name:
        ns = name.split(".")[0]
        ns_clean = ns.replace("C_", "")
        for system, keywords in _SYSTEM_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() == ns_clean.lower():
                    return system

    # Fall back to keyword search in full name
    name_lower = name.lower()
    for system, keywords in _SYSTEM_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in name_lower:
                return system

    return "Unknown"


# ===================================================================
# TrinityCore comparison
# ===================================================================

def compare_with_tc_lua(session):
    """Compare extracted binary Lua contracts against TrinityCore's Lua
    bindings to find gaps.

    Returns a comparison report dict.
    """
    db = session.db
    cfg = session.cfg
    tc_dir = cfg.tc_source_dir

    contracts = db.kv_get("lua_contracts")
    if not contracts:
        msg_warn("No Lua contracts in DB. Run analyze_lua_contracts first.")
        return {}

    # Build a set of binary Lua function names
    binary_funcs = {}
    for c in contracts:
        binary_funcs[c["name"]] = c

    # Discover TC's Lua registrations
    tc_lua_funcs = _discover_tc_lua_registrations(tc_dir) if tc_dir else {}

    binary_names = set(binary_funcs.keys())
    tc_names = set(tc_lua_funcs.keys())

    # Missing from TC (in binary but not in TC)
    missing_in_tc = sorted(binary_names - tc_names)

    # Extra in TC (in TC but not in binary -- custom additions)
    extra_in_tc = sorted(tc_names - binary_names)

    # Present in both -- compare details
    mismatches = []
    matched = sorted(binary_names & tc_names)

    for name in matched:
        bc = binary_funcs[name]
        tc = tc_lua_funcs[name]
        issues = []

        # Compare parameter count
        binary_param_count = len(bc["parameters"])
        tc_param_count = tc.get("param_count", -1)
        if tc_param_count >= 0 and binary_param_count != tc_param_count:
            issues.append({
                "type": "param_count_mismatch",
                "binary": binary_param_count,
                "tc": tc_param_count,
            })

        # Compare return count
        binary_ret = bc["num_returns"]
        tc_ret = tc.get("return_count", -1)
        if tc_ret >= 0 and binary_ret != tc_ret:
            issues.append({
                "type": "return_count_mismatch",
                "binary": binary_ret,
                "tc": tc_ret,
            })

        # Check for missing validations (binary has them, TC doesn't)
        if bc["validations"] and not tc.get("has_validations", True):
            issues.append({
                "type": "missing_validations",
                "binary_validation_count": len(bc["validations"]),
            })

        if issues:
            mismatches.append({
                "name": name,
                "issues": issues,
            })

    report = {
        "total_binary": len(binary_funcs),
        "total_tc": len(tc_lua_funcs),
        "matched": len(matched),
        "missing_in_tc": missing_in_tc,
        "missing_in_tc_count": len(missing_in_tc),
        "extra_in_tc": extra_in_tc,
        "extra_in_tc_count": len(extra_in_tc),
        "mismatches": mismatches,
        "mismatch_count": len(mismatches),
    }

    db.kv_set("lua_tc_comparison", report)
    db.commit()

    msg_info(f"Lua TC comparison: {len(matched)} matched, "
             f"{len(missing_in_tc)} missing from TC, "
             f"{len(extra_in_tc)} extra in TC, "
             f"{len(mismatches)} with mismatches")

    return report


def _discover_tc_lua_registrations(tc_dir):
    """Scan TrinityCore source for Lua function registrations.

    Looks for patterns like:
        LuaFunction("FuncName", &Handler)
        RegisterLuaFunction("FuncName", handler, nargs, nrets)
        { "FuncName", &handler },

    Returns dict of name -> {param_count, return_count, source_file, has_validations}.
    """
    if not tc_dir or not os.path.isdir(tc_dir):
        return {}

    tc_lua_funcs = {}

    # Directories to search for Lua bindings
    search_dirs = [
        os.path.join(tc_dir, "src", "server", "game"),
        os.path.join(tc_dir, "src", "server", "scripts"),
    ]

    # Registration patterns
    patterns = [
        # { "FuncName", &handler, nargs }
        re.compile(
            r'\{\s*"([^"]+)"\s*,\s*&?\s*(\w+)\s*'
            r'(?:,\s*(\d+))?\s*(?:,\s*(\d+))?\s*\}',
        ),
        # RegisterFunction("FuncName", handler, nargs, nrets)
        re.compile(
            r'Register\w*Function\s*\(\s*"([^"]+)"\s*,\s*&?\s*(\w+)\s*'
            r'(?:,\s*(\d+))?\s*(?:,\s*(\d+))?\s*\)',
        ),
        # LuaFunction("FuncName", &Handler)
        re.compile(
            r'LuaFunction\s*\(\s*"([^"]+)"\s*,\s*&?\s*(\w+)\s*'
            r'(?:,\s*(\d+))?\s*(?:,\s*(\d+))?\s*\)',
        ),
    ]

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for root, _dirs, files in os.walk(search_dir):
            for fname in files:
                if not fname.endswith((".cpp", ".h")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except IOError:
                    continue

                for pat in patterns:
                    for m in pat.finditer(content):
                        func_name = m.group(1)
                        handler_name = m.group(2)
                        param_count = int(m.group(3)) if m.group(3) else -1
                        return_count = int(m.group(4)) if m.group(4) else -1

                        # Check if handler has validations by scanning for
                        # if-return patterns in the same file
                        has_validations = _tc_handler_has_validations(
                            content, handler_name
                        )

                        tc_lua_funcs[func_name] = {
                            "handler": handler_name,
                            "param_count": param_count,
                            "return_count": return_count,
                            "source_file": os.path.relpath(fpath, tc_dir),
                            "has_validations": has_validations,
                        }

    return tc_lua_funcs


def _tc_handler_has_validations(content, handler_name):
    """Quick heuristic: does the TC handler function contain if-return
    validation patterns?"""
    # Find the handler function body
    pattern = re.compile(
        rf'\b{re.escape(handler_name)}\s*\([^)]*\)\s*\{{',
        re.MULTILINE,
    )
    match = pattern.search(content)
    if not match:
        return True  # assume yes if we can't find the body

    # Extract ~500 chars of body
    body_start = match.end()
    body_end = min(body_start + 2000, len(content))
    body = content[body_start:body_end]

    # Count if-return patterns
    validation_count = len(re.findall(
        r'if\s*\([^)]+\)\s*\{?\s*(?:\n\s*)?(?:return|lua_pushnil|luaL_error)',
        body,
        re.IGNORECASE,
    ))

    return validation_count > 0


# ===================================================================
# Code generation
# ===================================================================

def generate_lua_binding(session, func_name):
    """Generate a TrinityCore-style Lua binding C++ function from the
    binary's behavioral contract.

    Args:
        session: PluginSession
        func_name: Lua function name (e.g. "C_Housing.GetDecorInfo")

    Returns:
        Generated C++ source string, or None if contract not found.
    """
    contracts = session.db.kv_get("lua_contracts")
    if not contracts:
        msg_warn("No Lua contracts. Run analyze_lua_contracts first.")
        return None

    contract = None
    for c in contracts:
        if c["name"] == func_name:
            contract = c
            break

    if not contract:
        msg_warn(f"No contract found for '{func_name}'")
        return None

    # Build C++ binding
    lines = []
    safe_name = func_name.replace(".", "_").replace("C_", "")
    lines.append(f"// Auto-generated from binary analysis at {ea_str(contract['ea'])}")
    lines.append(f"// System: {contract['system']}")
    lines.append(f"int LuaBinding_{safe_name}(lua_State* L)")
    lines.append("{")

    # Parameters
    if contract["parameters"]:
        lines.append("    // Parameters")
        for param in contract["parameters"]:
            ptype = param["type"]
            pname = param["name"]
            idx = param["index"]
            optional = param.get("optional", False)
            default = param.get("default", "")
            checked = param.get("checked", False)

            if ptype == "integer":
                cpp_type = "int64"
                if optional:
                    lines.append(
                        f"    {cpp_type} {pname} = luaL_optinteger(L, {idx}, {default});"
                    )
                elif checked:
                    lines.append(
                        f"    {cpp_type} {pname} = luaL_checkinteger(L, {idx});"
                    )
                else:
                    lines.append(
                        f"    {cpp_type} {pname} = static_cast<{cpp_type}>"
                        f"(lua_tointeger(L, {idx}));"
                    )
            elif ptype == "number":
                cpp_type = "double"
                if optional:
                    lines.append(
                        f"    {cpp_type} {pname} = luaL_optnumber(L, {idx}, {default});"
                    )
                elif checked:
                    lines.append(
                        f"    {cpp_type} {pname} = luaL_checknumber(L, {idx});"
                    )
                else:
                    lines.append(
                        f"    {cpp_type} {pname} = lua_tonumber(L, {idx});"
                    )
            elif ptype == "string":
                if optional:
                    lines.append(
                        f"    char const* {pname} = luaL_optstring(L, {idx}, {default});"
                    )
                elif checked:
                    lines.append(
                        f"    char const* {pname} = luaL_checkstring(L, {idx});"
                    )
                else:
                    lines.append(
                        f"    char const* {pname} = lua_tostring(L, {idx});"
                    )
            elif ptype == "boolean":
                lines.append(
                    f"    bool {pname} = lua_toboolean(L, {idx});"
                )
            elif ptype == "userdata":
                if checked:
                    lines.append(
                        f"    void* {pname} = luaL_checkudata(L, {idx}, \"\");"
                    )
                else:
                    lines.append(
                        f"    void* {pname} = lua_touserdata(L, {idx});"
                    )
            else:
                lines.append(
                    f"    // TODO: unknown param type '{ptype}' at index {idx}"
                )
        lines.append("")

    # Validations
    if contract["validations"]:
        lines.append("    // Validations (from binary)")
        for val in contract["validations"]:
            detail = val.get("detail", "")
            lines.append(f"    // {val['type']}: {detail[:80]}")

            # Generate a plausible guard for common patterns
            if val["type"] == "null_check":
                lines.append("    // if (!<value>) { lua_pushnil(L); return 1; }")
            elif val["type"] == "range_check":
                lines.append("    // if (<value> out of range) { lua_pushnil(L); return 1; }")
            elif val["type"] == "state_check":
                lines.append("    // if (!player state ok) { lua_pushnil(L); return 1; }")
        lines.append("")

    # Game state access
    if contract["game_state_reads"]:
        lines.append("    // Game state access")
        if "Player" in contract["game_state_reads"]:
            lines.append("    Player* player = GetPlayerFromLua(L);")
            lines.append("    if (!player)")
            lines.append("    {")
            lines.append("        lua_pushnil(L);")
            lines.append("        return 1;")
            lines.append("    }")
        for read in contract["game_state_reads"]:
            if read != "Player":
                lines.append(f"    // Reads: {read}")
        lines.append("")

    # Return values
    if contract["return_values"]:
        lines.append("    // Return values")
        has_table = any(rv["type"] == "table" for rv in contract["return_values"])

        if has_table:
            table_rv = next(
                (rv for rv in contract["return_values"] if rv["type"] == "table"),
                None,
            )
            lines.append("    lua_newtable(L);")
            if table_rv and table_rv.get("fields"):
                for field in table_rv["fields"]:
                    ftype = field["type"]
                    fname = field["name"]
                    if ftype == "string":
                        lines.append(
                            f'    lua_pushstring(L, "" /* {fname} */);'
                        )
                    elif ftype == "integer":
                        lines.append(
                            f"    lua_pushinteger(L, 0 /* {fname} */);")
                    elif ftype == "number":
                        lines.append(
                            f"    lua_pushnumber(L, 0.0 /* {fname} */);")
                    elif ftype == "boolean":
                        lines.append(
                            f"    lua_pushboolean(L, 0 /* {fname} */);")
                    else:
                        lines.append(
                            f"    lua_pushnil(L); /* {fname} ({ftype}) */"
                        )
                    lines.append(
                        f'    lua_setfield(L, -2, "{fname}");'
                    )
        else:
            for rv in contract["return_values"]:
                rtype = rv["type"]
                if rtype == "integer":
                    lines.append("    lua_pushinteger(L, 0 /* result */);")
                elif rtype == "number":
                    lines.append("    lua_pushnumber(L, 0.0 /* result */);")
                elif rtype == "string":
                    lines.append('    lua_pushstring(L, "" /* result */);')
                elif rtype == "boolean":
                    lines.append("    lua_pushboolean(L, 0 /* result */);")
                elif rtype == "nil":
                    lines.append("    lua_pushnil(L);")
        lines.append("")

    lines.append(f"    return {contract['num_returns']};")
    lines.append("}")
    lines.append("")

    result = "\n".join(lines)
    msg_info(f"Generated binding for {func_name} ({len(lines)} lines)")
    return result


# ===================================================================
# API documentation generation
# ===================================================================

def generate_lua_api_docs(session, system_filter=None):
    """Generate Markdown API documentation from Lua contracts.

    Args:
        session: PluginSession
        system_filter: Optional system to filter (e.g. "Housing")

    Returns:
        Markdown string with full API documentation.
    """
    contracts = session.db.kv_get("lua_contracts")
    if not contracts:
        msg_warn("No Lua contracts. Run analyze_lua_contracts first.")
        return ""

    if system_filter:
        contracts = [
            c for c in contracts
            if c.get("system", "").lower() == system_filter.lower()
        ]

    if not contracts:
        msg_warn(f"No contracts for system '{system_filter}'")
        return ""

    # Group by system
    by_system = {}
    for c in contracts:
        sys = c.get("system", "Unknown")
        by_system.setdefault(sys, []).append(c)

    doc_lines = []
    doc_lines.append("# WoW Lua API Reference (Binary-Extracted)")
    doc_lines.append("")
    doc_lines.append(
        f"Generated from binary analysis. "
        f"{len(contracts)} functions documented."
    )
    doc_lines.append("")

    # Table of contents
    doc_lines.append("## Table of Contents")
    doc_lines.append("")
    for sys in sorted(by_system.keys()):
        count = len(by_system[sys])
        doc_lines.append(f"- [{sys}](#{sys.lower()}) ({count} functions)")
    doc_lines.append("")

    # Per-system documentation
    for sys in sorted(by_system.keys()):
        funcs = sorted(by_system[sys], key=lambda c: c["name"])
        doc_lines.append(f"## {sys}")
        doc_lines.append("")

        for c in funcs:
            # Function header
            param_str = ", ".join(
                p.get("name", f"arg{p['index']}") for p in c["parameters"]
            )
            doc_lines.append(f"### {c['name']}({param_str})")
            doc_lines.append("")

            if c.get("is_secure"):
                doc_lines.append("> **Protected function** - requires hardware event")
                doc_lines.append("")

            doc_lines.append(f"Address: `{ea_str(c['ea'])}`")
            doc_lines.append("")

            # Parameters table
            if c["parameters"]:
                doc_lines.append("#### Parameters")
                doc_lines.append("")
                doc_lines.append(
                    "| # | Name | Type | Required | Description |"
                )
                doc_lines.append(
                    "|---|------|------|----------|-------------|"
                )
                for p in c["parameters"]:
                    required = "No" if p.get("optional") else "Yes"
                    desc = ""
                    if p.get("checked"):
                        desc = "Type-checked"
                    if p.get("default"):
                        desc += f" (default: {p['default']})"
                    doc_lines.append(
                        f"| {p['index']} | {p.get('name', '?')} | "
                        f"{p['type']} | {required} | {desc.strip()} |"
                    )
                doc_lines.append("")

            # Returns table
            if c["return_values"]:
                doc_lines.append("#### Returns")
                doc_lines.append("")
                doc_lines.append(f"Returns {c['num_returns']} value(s).")
                doc_lines.append("")
                doc_lines.append("| # | Type | Description |")
                doc_lines.append("|---|------|-------------|")
                ret_idx = 1
                for rv in c["return_values"]:
                    rtype = rv["type"]
                    desc = ""
                    if rtype == "table" and rv.get("fields"):
                        desc = "Table (see fields below)"
                    elif rtype == "nil":
                        desc = "nil on error"
                    doc_lines.append(
                        f"| {ret_idx} | {rtype} | {desc} |"
                    )
                    ret_idx += 1
                doc_lines.append("")

                # Table fields sub-table
                for rv in c["return_values"]:
                    if rv["type"] == "table" and rv.get("fields"):
                        doc_lines.append("#### Return Table Fields")
                        doc_lines.append("")
                        doc_lines.append("| Field | Type | Description |")
                        doc_lines.append("|-------|------|-------------|")
                        for field in rv["fields"]:
                            doc_lines.append(
                                f"| {field['name']} | {field['type']} | |"
                            )
                        doc_lines.append("")

            # Validations
            if c["validations"]:
                doc_lines.append("#### Validations (from binary)")
                doc_lines.append("")
                for v in c["validations"]:
                    doc_lines.append(f"- **{v['type']}**: {v['detail'][:120]}")
                doc_lines.append("")

            # Error returns
            if c["error_returns"]:
                doc_lines.append("#### Error Conditions")
                doc_lines.append("")
                for e in c["error_returns"]:
                    doc_lines.append(
                        f"- Returns `{e['returns']}` when: {e['condition'][:120]}"
                    )
                doc_lines.append("")

            # Game state
            if c["game_state_reads"] or c["game_state_writes"]:
                doc_lines.append("#### Game State Access")
                doc_lines.append("")
                if c["game_state_reads"]:
                    doc_lines.append(
                        f"- **Reads**: {', '.join(c['game_state_reads'])}"
                    )
                if c["game_state_writes"]:
                    doc_lines.append(
                        f"- **Writes**: {', '.join(c['game_state_writes'])}"
                    )
                if c["side_effects"]:
                    doc_lines.append(
                        f"- **Side effects**: {', '.join(c['side_effects'])}"
                    )
                doc_lines.append("")

            # Called functions
            if c["called_functions"]:
                doc_lines.append("#### Called Functions")
                doc_lines.append("")
                for fn in c["called_functions"][:20]:
                    doc_lines.append(f"- `{fn}`")
                if len(c["called_functions"]) > 20:
                    doc_lines.append(
                        f"- ... and {len(c['called_functions']) - 20} more"
                    )
                doc_lines.append("")

            doc_lines.append("---")
            doc_lines.append("")

    result = "\n".join(doc_lines)

    # Store the generated docs
    key = f"lua_api_docs:{system_filter}" if system_filter else "lua_api_docs:all"
    session.db.kv_set(key, result)
    session.db.commit()

    msg_info(
        f"Generated API docs: {len(contracts)} functions, "
        f"{len(doc_lines)} lines"
    )
    return result


# ===================================================================
# Retrieval helpers
# ===================================================================

def get_lua_contracts(session, system=None):
    """Retrieve stored contracts, optionally filtered by system.

    Args:
        session: PluginSession
        system: Optional system filter (e.g. "Housing")

    Returns:
        List of contract dicts.
    """
    contracts = session.db.kv_get("lua_contracts")
    if not contracts:
        return []

    if system:
        contracts = [
            c for c in contracts
            if c.get("system", "").lower() == system.lower()
        ]

    return contracts


def get_missing_lua_functions(session):
    """Return Lua functions present in the binary but not in TrinityCore.

    Returns:
        List of contract dicts for functions missing from TC.
    """
    report = session.db.kv_get("lua_tc_comparison")
    if not report:
        msg_warn("No TC comparison data. Run compare_with_tc_lua first.")
        return []

    missing_names = set(report.get("missing_in_tc", []))
    if not missing_names:
        return []

    contracts = session.db.kv_get("lua_contracts") or []
    return [c for c in contracts if c["name"] in missing_names]


def get_lua_completeness_score(session):
    """Compute an overall Lua API implementation completeness score.

    Scoring:
        - Base: % of binary Lua functions present in TC
        - Penalty: mismatches (wrong param count, wrong return count)
        - Bonus: functions with proper validations

    Returns:
        Dict with score breakdown.
    """
    report = session.db.kv_get("lua_tc_comparison")
    contracts = session.db.kv_get("lua_contracts")

    if not contracts:
        return {
            "overall_score": 0.0,
            "coverage_score": 0.0,
            "correctness_score": 0.0,
            "validation_score": 0.0,
            "total_binary_functions": 0,
            "total_tc_functions": 0,
            "matched": 0,
            "missing_from_tc": 0,
            "mismatches": 0,
        }

    total_binary = len(contracts)

    if not report:
        # No comparison done yet -- only contract data available
        return {
            "overall_score": 0.0,
            "coverage_score": 0.0,
            "correctness_score": 0.0,
            "validation_score": 0.0,
            "total_binary_functions": total_binary,
            "total_tc_functions": 0,
            "matched": 0,
            "missing_from_tc": total_binary,
            "mismatches": 0,
            "note": "Run compare_with_tc_lua() for full scoring",
        }

    total_tc = report.get("total_tc", 0)
    matched = report.get("matched", 0)
    missing_count = report.get("missing_in_tc_count", 0)
    mismatch_count = report.get("mismatch_count", 0)

    # Coverage: what fraction of binary functions does TC implement?
    if total_binary > 0:
        coverage_score = (matched / total_binary) * 100.0
    else:
        coverage_score = 100.0

    # Correctness: of matched functions, how many have no mismatches?
    if matched > 0:
        correctness_score = ((matched - mismatch_count) / matched) * 100.0
    else:
        correctness_score = 100.0

    # Validation: how many TC functions have proper validations?
    # (uses the has_validations flag from comparison)
    contracts_with_validations = sum(
        1 for c in contracts if c.get("validations")
    )
    if total_binary > 0:
        binary_validation_rate = (contracts_with_validations / total_binary) * 100.0
    else:
        binary_validation_rate = 0.0

    # Overall: weighted combination
    overall = (
        coverage_score * 0.50 +
        correctness_score * 0.30 +
        min(100.0, binary_validation_rate) * 0.20
    )

    # Per-system breakdown
    system_scores = {}
    by_system = {}
    for c in contracts:
        sys = c.get("system", "Unknown")
        by_system.setdefault(sys, []).append(c)

    missing_names = set(report.get("missing_in_tc", []))
    mismatch_names = set(m["name"] for m in report.get("mismatches", []))

    for sys, sys_contracts in by_system.items():
        sys_total = len(sys_contracts)
        sys_missing = sum(1 for c in sys_contracts if c["name"] in missing_names)
        sys_mismatch = sum(1 for c in sys_contracts if c["name"] in mismatch_names)
        sys_matched = sys_total - sys_missing

        if sys_total > 0:
            sys_coverage = (sys_matched / sys_total) * 100.0
        else:
            sys_coverage = 100.0

        if sys_matched > 0:
            sys_correct = ((sys_matched - sys_mismatch) / sys_matched) * 100.0
        else:
            sys_correct = 100.0

        system_scores[sys] = {
            "total": sys_total,
            "matched": sys_matched,
            "missing": sys_missing,
            "mismatches": sys_mismatch,
            "coverage": round(sys_coverage, 1),
            "correctness": round(sys_correct, 1),
        }

    result = {
        "overall_score": round(overall, 1),
        "coverage_score": round(coverage_score, 1),
        "correctness_score": round(correctness_score, 1),
        "validation_score": round(binary_validation_rate, 1),
        "total_binary_functions": total_binary,
        "total_tc_functions": total_tc,
        "matched": matched,
        "missing_from_tc": missing_count,
        "mismatches": mismatch_count,
        "system_scores": system_scores,
    }

    # Cache the score
    session.db.kv_set("lua_completeness_score", result)
    session.db.commit()

    msg_info(
        f"Lua completeness: {result['overall_score']}% overall "
        f"(coverage={result['coverage_score']}%, "
        f"correctness={result['correctness_score']}%, "
        f"validations={result['validation_score']}%)"
    )

    return result
