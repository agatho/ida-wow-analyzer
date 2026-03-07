"""
Data Flow Taint Analysis for CMSG Handlers

Tracks how user-controlled packet data flows through CMSG handlers in the
WoW x64 binary.  Every Read*() from a packet is a TAINT SOURCE.  Each tainted
value is followed through assignments, arithmetic, casts, function arguments,
and struct member writes.  If a tainted value reaches a dangerous operation
(SQL query parameter, object-creation size, teleport coordinate, array index,
pointer arithmetic) WITHOUT a validation check in between, the flow is flagged
as a potential exploit that TrinityCore must guard against.

Results are stored in the knowledge DB kv_store under key "taint_analysis".
"""

import json
import re
import time

import ida_funcs
import ida_name
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Taint source patterns -- every way a value can be read from a packet
# ---------------------------------------------------------------------------

_READ_TEMPLATE_RE = re.compile(
    r'(\w+)\s*=\s*.*?Read\s*<\s*(\w+)\s*>\s*\(',
)

_READ_BIT_RE = re.compile(
    r'(\w+)\s*=\s*.*?ReadBit\s*\(',
)

_READ_BITS_RE = re.compile(
    r'(\w+)\s*=\s*.*?ReadBits\s*\(\s*(\d+)\s*\)',
)

_READ_PACKED_GUID_RE = re.compile(
    r'(\w+)\s*=?\s*.*?ReadPackedGuid128\s*\(',
)

_READ_STRING_RE = re.compile(
    r'(\w+)\s*=\s*.*?Read(?:C?String|String)\s*\(',
)

_STREAM_EXTRACT_RE = re.compile(
    r'operator>>\s*\(\s*\w+\s*,\s*&?\s*(\w+)\s*\)'
    r'|>>\s*\(\s*\w+\s*,\s*[&*]?\s*(\w+)\s*\)'
    r'|>>\s*(\w+)',
)

_DIRECT_BUFFER_RE = re.compile(
    r'(\w+)\s*=\s*\*\s*\(\s*(\w+)\s*\*\s*\)\s*\(\s*\w+\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)',
)

# Catch-all for other read helpers (ReadFloat, ReadUInt32, etc.)
_READ_HELPER_RE = re.compile(
    r'(\w+)\s*=\s*.*?(?:Read(?:Float|Double|UInt8|UInt16|UInt32|UInt64|Int8|Int16|Int32|Int64))\s*\(',
)

# Handler packet parameter dereference: *(type*)(a2 + offset)  where a2 is
# the deserialized JAM struct passed to the handler
_PARAM_DEREF_RE = re.compile(
    r'(\w+)\s*=\s*\*\s*\(\s*(\w+)\s*\*?\s*\)\s*\(\s*(a[12])\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)',
)


# ---------------------------------------------------------------------------
# Sink patterns -- dangerous operations that consume values
# ---------------------------------------------------------------------------

_SINK_PATTERNS = {
    "sql_injection": [
        re.compile(r'(?:Format|format|sprintf|PQuery|DirectExecute|AsyncQuery|PrepareStatement'
                   r'|LoginDatabase|CharacterDatabase|WorldDatabase)\s*\([^)]*\b(\w+)\b',
                   re.IGNORECASE),
    ],
    "buffer_overflow": [
        # arr[tainted]
        re.compile(r'(\w+)\s*\[\s*(\w+)\s*\]'),
        # memcpy size
        re.compile(r'(?:memcpy|memmove|memset)\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)'),
    ],
    "object_creation": [
        re.compile(r'(?:new\s+\w+\s*\[\s*(\w+)\s*\]|malloc\s*\(\s*(\w+)\s*\)|'
                   r'alloc(?:a)?\s*\(\s*(\w+)\s*\)|resize\s*\(\s*(\w+)\s*\))'),
    ],
    "teleport": [
        re.compile(r'(?:TeleportTo|NearTeleportTo|Relocate|SetPosition|'
                   r'SummonCreature|SummonGameObject)\s*\([^)]*\b(\w+)\b',
                   re.IGNORECASE),
    ],
    "pointer_arith": [
        re.compile(r'\(\s*\w+\s*\*\s*\)\s*\(\s*\w+\s*[+\-]\s*(\w+)\s*\)'),
        re.compile(r'\w+\s*[+\-]\s*(\w+)\s*\*\s*(?:sizeof|0x[0-9A-Fa-f]+|\d+)'),
    ],
    "privilege_escalation": [
        re.compile(r'(?:SetLevel|SetSecurity|SetGMLevel|SetPermission|AddPermission|'
                   r'SetAccessLevel|SetFlag)\s*\([^)]*\b(\w+)\b', re.IGNORECASE),
    ],
    "resource_exhaustion": [
        # Loop counts
        re.compile(r'for\s*\([^;]*;\s*\w+\s*[<>=!]+\s*(\w+)\s*;'),
        re.compile(r'while\s*\(\s*\w+\s*[<>=!]+\s*(\w+)\s*\)'),
        # reserve/resize with tainted count
        re.compile(r'(?:reserve|resize)\s*\(\s*(\w+)\s*\)'),
    ],
    "type_confusion": [
        re.compile(r'(?:static_cast|reinterpret_cast|dynamic_cast)\s*<\s*\w+\s*\*?\s*>\s*\(\s*(\w+)\s*\)'),
        re.compile(r'(?:GetEntry|GetTypeId|GetObjectType)\s*\(\s*(\w+)\s*\)'),
    ],
}


# ---------------------------------------------------------------------------
# Validation / guard patterns -- these CLEAR taint for a variable
# ---------------------------------------------------------------------------

_VALIDATION_PATTERNS = [
    # Range check:  if (x > MAX) return;  /  if (x >= LIMIT) return;
    re.compile(
        r'if\s*\(\s*(\w+)\s*([><=!]+)\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\)\s*'
        r'(?:\{?\s*)?return\b',
    ),
    # Combined range: if (x < 0 || x > MAX) return;
    re.compile(
        r'if\s*\(\s*(\w+)\s*[<>]=?\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\|\|\s*'
        r'\1\s*[<>]=?\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\)\s*(?:\{?\s*)?return\b',
    ),
    # Null / zero check:  if (!x) return;
    re.compile(
        r'if\s*\(\s*!(\w+)\s*\)\s*(?:\{?\s*)?return\b',
    ),
    # Equality guard:  if (x == 0) return;
    re.compile(
        r'if\s*\(\s*(\w+)\s*==\s*(?:0x[0-9A-Fa-f]+|\d+|nullptr|NULL)\s*\)\s*'
        r'(?:\{?\s*)?return\b',
    ),
    # Enum validation:  if (x != A && x != B) return;
    re.compile(
        r'if\s*\(\s*(\w+)\s*!=\s*\S+\s*&&\s*\1\s*!=\s*\S+\s*\)\s*'
        r'(?:\{?\s*)?return\b',
    ),
    # Lookup validation:  if (!IsValid*(x)) return;
    re.compile(
        r'if\s*\(\s*!\s*(?:IsValid\w*|Get\w+Entry|sObjectMgr|sSpellMgr|'
        r'ObjectMgr|SpellMgr|FindEntry)\s*\(\s*(\w+)\s*\)\s*\)\s*'
        r'(?:\{?\s*)?return\b',
    ),
    # switch-with-default-return acts as enum whitelist
    re.compile(
        r'switch\s*\(\s*(\w+)\s*\)\s*\{.*?default\s*:\s*return\b',
        re.DOTALL,
    ),
]


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

_SEVERITY_HIGH = {"sql_injection", "buffer_overflow", "pointer_arith", "teleport"}
_SEVERITY_MEDIUM = {"object_creation", "resource_exhaustion", "type_confusion"}
_SEVERITY_LOW = {"privilege_escalation"}


def _classify_severity(category, has_validation):
    """Return 'high', 'medium', or 'low' for a given sink category."""
    if has_validation:
        # Partial validation drops severity by one level
        if category in _SEVERITY_HIGH:
            return "medium"
        return "low"
    if category in _SEVERITY_HIGH:
        return "high"
    if category in _SEVERITY_MEDIUM:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Suggested fix templates
# ---------------------------------------------------------------------------

_FIX_TEMPLATES = {
    "sql_injection": "Use PreparedStatement with parameter binding instead of string formatting",
    "buffer_overflow": "Add range check: if ({var} >= MAX_{container}) return;",
    "object_creation": "Clamp allocation size: size = std::min({var}, MAX_ALLOC);",
    "teleport": "Validate coordinates against map bounds before teleport",
    "pointer_arith": "Add bounds check before pointer arithmetic with {var}",
    "privilege_escalation": "Verify caller has permission before setting {var}",
    "resource_exhaustion": "Cap loop/allocation count: if ({var} > MAX_COUNT) return;",
    "type_confusion": "Validate type ID {var} against known enum range",
}


# ===================================================================
# Public API
# ===================================================================

def analyze_taint_flows(session, system_filter=None):
    """Main entry point -- analyse every CMSG handler for taint flows.

    Args:
        session: PluginSession with .db (KnowledgeDB)
        system_filter: optional substring to filter by tc_name/jam_type

    Returns:
        Count of unguarded taint flows found.
    """
    db = session.db

    query = ("SELECT * FROM opcodes "
             "WHERE direction = 'CMSG' AND handler_ea IS NOT NULL")
    if system_filter:
        query += (f" AND (tc_name LIKE '%{system_filter}%' "
                  f"OR jam_type LIKE '%{system_filter}%')")
    handlers = db.fetchall(query)

    msg_info(f"Taint analysis: scanning {len(handlers)} CMSG handlers"
             f"{f' (filter: {system_filter})' if system_filter else ''}...")

    all_flows = []
    handlers_with_flows = 0
    handlers_processed = 0

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"handler_0x{ea:X}"
        jam_type = handler["jam_type"]

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue
        handlers_processed += 1

        # Step 1 -- identify taint sources
        sources = _identify_taint_sources(pseudocode, jam_type, db)
        if not sources:
            continue

        # Step 2 -- propagate taint through the pseudocode
        tainted_vars = _propagate_taint(pseudocode, sources)

        # Step 3 -- identify sinks
        sinks = _identify_sinks(pseudocode)
        if not sinks:
            continue

        # Step 4 -- match tainted variables to sinks, check for guards
        handler_flows = []
        for sink in sinks:
            for var_in_sink in sink["variables"]:
                if var_in_sink not in tainted_vars:
                    continue

                tinfo = tainted_vars[var_in_sink]
                has_validation = _check_validation_between(
                    pseudocode, tinfo["source_line"], sink["line"], var_in_sink
                )

                severity = _classify_severity(sink["category"], has_validation)

                chain = list(tinfo["chain"])
                chain.append(sink["operation"])

                fix_template = _FIX_TEMPLATES.get(sink["category"], "Add validation for {var}")
                suggested_fix = fix_template.replace("{var}", var_in_sink)
                if "{container}" in suggested_fix:
                    suggested_fix = suggested_fix.replace(
                        "{container}", sink.get("container", "ARRAY"))

                flow = {
                    "handler": tc_name,
                    "handler_ea": ea,
                    "severity": severity,
                    "source": {
                        "variable": tinfo["origin_var"],
                        "type": tinfo["origin_type"],
                        "read_call": tinfo["read_call"],
                        "line": tinfo["source_line"],
                    },
                    "sink": {
                        "category": sink["category"],
                        "operation": sink["operation"],
                        "line": sink["line"],
                    },
                    "taint_chain": chain,
                    "has_validation": has_validation,
                    "suggested_fix": suggested_fix,
                    "tc_has_check": None,
                }
                handler_flows.append(flow)

        if handler_flows:
            handlers_with_flows += 1
            all_flows.extend(handler_flows)

        if handlers_processed % 100 == 0:
            msg_info(f"  ... processed {handlers_processed} handlers, "
                     f"{len(all_flows)} taint flows so far")

    # Build report and persist
    report = _build_taint_report(all_flows)
    db.kv_set("taint_analysis", report)
    db.commit()

    unguarded = sum(1 for f in all_flows if not f["has_validation"])
    msg_info(f"Taint analysis complete: {handlers_processed} handlers processed, "
             f"{len(all_flows)} total flows, {unguarded} unguarded")
    msg_info(f"  High severity unguarded: "
             f"{sum(1 for f in all_flows if f['severity'] == 'high' and not f['has_validation'])}")
    msg_info(f"  Medium severity unguarded: "
             f"{sum(1 for f in all_flows if f['severity'] == 'medium' and not f['has_validation'])}")
    msg_info(f"  Low severity unguarded: "
             f"{sum(1 for f in all_flows if f['severity'] == 'low' and not f['has_validation'])}")

    return unguarded


# ===================================================================
# Step 1 -- Identify taint sources
# ===================================================================

def _identify_taint_sources(pseudocode, jam_type=None, db=None):
    """Find every point where data is read from the packet.

    Returns a list of dicts:
        {
            "label": "taint_0",
            "variable": "v12",
            "type": "uint32",
            "read_call": "Read<uint32>()",
            "line": 15,
        }
    """
    sources = []
    taint_idx = 0
    lines = pseudocode.split("\n")

    for line_no, line in enumerate(lines):
        stripped = line.strip()

        # Read<T>()
        m = _READ_TEMPLATE_RE.search(stripped)
        if m:
            sources.append({
                "label": f"taint_{taint_idx}",
                "variable": m.group(1),
                "type": m.group(2),
                "read_call": f"Read<{m.group(2)}>()",
                "line": line_no,
            })
            taint_idx += 1
            continue

        # ReadBit()
        m = _READ_BIT_RE.search(stripped)
        if m:
            sources.append({
                "label": f"taint_{taint_idx}",
                "variable": m.group(1),
                "type": "bit",
                "read_call": "ReadBit()",
                "line": line_no,
            })
            taint_idx += 1
            continue

        # ReadBits(n)
        m = _READ_BITS_RE.search(stripped)
        if m:
            sources.append({
                "label": f"taint_{taint_idx}",
                "variable": m.group(1),
                "type": f"bits({m.group(2)})",
                "read_call": f"ReadBits({m.group(2)})",
                "line": line_no,
            })
            taint_idx += 1
            continue

        # ReadPackedGuid128()
        m = _READ_PACKED_GUID_RE.search(stripped)
        if m:
            sources.append({
                "label": f"taint_{taint_idx}",
                "variable": m.group(1),
                "type": "ObjectGuid",
                "read_call": "ReadPackedGuid128()",
                "line": line_no,
            })
            taint_idx += 1
            continue

        # ReadString / ReadCString
        m = _READ_STRING_RE.search(stripped)
        if m:
            sources.append({
                "label": f"taint_{taint_idx}",
                "variable": m.group(1),
                "type": "string",
                "read_call": "ReadString()",
                "line": line_no,
            })
            taint_idx += 1
            continue

        # Read helper variants (ReadFloat, ReadUInt32, etc.)
        m = _READ_HELPER_RE.search(stripped)
        if m:
            # Determine the type from the function name
            helper_m = re.search(r'Read(\w+)\s*\(', stripped)
            rtype = helper_m.group(1).lower() if helper_m else "unknown"
            sources.append({
                "label": f"taint_{taint_idx}",
                "variable": m.group(1),
                "type": rtype,
                "read_call": f"Read{helper_m.group(1) if helper_m else '?'}()",
                "line": line_no,
            })
            taint_idx += 1
            continue

        # operator>> stream extraction
        m = _STREAM_EXTRACT_RE.search(stripped)
        if m:
            var = m.group(1) or m.group(2) or m.group(3)
            if var:
                sources.append({
                    "label": f"taint_{taint_idx}",
                    "variable": var,
                    "type": "stream_extracted",
                    "read_call": f"operator>>({var})",
                    "line": line_no,
                })
                taint_idx += 1
                continue

        # Direct buffer access: *(type*)(packet_ptr + offset)
        m = _DIRECT_BUFFER_RE.search(stripped)
        if m:
            sources.append({
                "label": f"taint_{taint_idx}",
                "variable": m.group(1),
                "type": m.group(2),
                "read_call": f"*({m.group(2)}*)(pkt + {m.group(3)})",
                "line": line_no,
            })
            taint_idx += 1
            continue

        # Handler param dereference: *(type*)(a2 + offset)
        m = _PARAM_DEREF_RE.search(stripped)
        if m and m.group(3) in ("a1", "a2"):
            sources.append({
                "label": f"taint_{taint_idx}",
                "variable": m.group(1),
                "type": m.group(2),
                "read_call": f"*({m.group(2)}*)({m.group(3)} + {m.group(4)})",
                "line": line_no,
            })
            taint_idx += 1
            continue

    # If a JAM type is known, treat its deserialized fields as taint sources
    # on the first line (they arrive pre-parsed into the handler's packet arg).
    if jam_type and db:
        jam_fields = _get_jam_fields(jam_type, db)
        for field in jam_fields:
            sources.append({
                "label": f"taint_{taint_idx}",
                "variable": field["name"],
                "type": field.get("type", "unknown"),
                "read_call": f"JAM:{jam_type}.{field['name']}",
                "line": 0,
            })
            taint_idx += 1

    return sources


def _get_jam_fields(jam_type, db):
    """Retrieve the field list for a JAM message type from the DB."""
    row = db.fetchone("SELECT fields_json FROM jam_types WHERE name = ?",
                      (jam_type,))
    if not row or not row["fields_json"]:
        return []
    try:
        return json.loads(row["fields_json"])
    except (json.JSONDecodeError, TypeError):
        return []


# ===================================================================
# Step 2 -- Propagate taint through pseudocode
# ===================================================================

# Assignment patterns used during propagation
_SIMPLE_ASSIGN_RE = re.compile(r'^(\w+)\s*=\s*(.+?)\s*;')
_CAST_ASSIGN_RE = re.compile(r'^(\w+)\s*=\s*\(\s*\w+\s*\*?\s*\)\s*(\w+)\s*;')
_ARITH_OPERAND_RE = re.compile(r'\b(\w+)\b')
_FUNC_CALL_RE = re.compile(r'(\w+)\s*\(([^)]*)\)')
_STRUCT_WRITE_RE = re.compile(r'(\w+)\s*->\s*(\w+)\s*=\s*(\w+)\s*;')
_ARRAY_INDEX_RE = re.compile(r'(\w+)\s*\[\s*(\w+)\s*\]')


def _propagate_taint(pseudocode, sources):
    """Track taint from sources through assignments and operations.

    Returns a dict keyed by variable name:
        {
            "v15": {
                "origin_var": "v12",
                "origin_type": "uint32",
                "read_call": "Read<uint32>()",
                "source_line": 15,
                "chain": ["v12 = Read<uint32>()", "v15 = v12 * 4"],
            },
            ...
        }
    """
    # Seed tainted set from sources
    tainted = {}
    for src in sources:
        tainted[src["variable"]] = {
            "origin_var": src["variable"],
            "origin_type": src["type"],
            "read_call": src["read_call"],
            "source_line": src["line"],
            "chain": [f"{src['variable']} = {src['read_call']}"],
        }

    lines = pseudocode.split("\n")

    # Scan for validation gates that CLEAR taint.  We collect them first so
    # that the propagation pass can respect them.
    cleared_after = {}  # var -> line after which it's cleared
    for line_no, line in enumerate(lines):
        stripped = line.strip()
        for pat in _VALIDATION_PATTERNS:
            m = pat.search(stripped)
            if m:
                cleared_var = m.group(1)
                # The variable is "safe" after this guard line
                if cleared_var not in cleared_after:
                    cleared_after[cleared_var] = line_no

    # Forward propagation pass
    for line_no, line in enumerate(lines):
        stripped = line.strip()

        # Skip empty / comment lines
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # Check struct member write: obj->field = tainted;
        m = _STRUCT_WRITE_RE.search(stripped)
        if m:
            obj_var, field_name, rhs_var = m.group(1), m.group(2), m.group(3)
            if _is_tainted(rhs_var, tainted, cleared_after, line_no):
                composite = f"{obj_var}->{field_name}"
                src_info = tainted[rhs_var]
                tainted[composite] = {
                    "origin_var": src_info["origin_var"],
                    "origin_type": src_info["origin_type"],
                    "read_call": src_info["read_call"],
                    "source_line": src_info["source_line"],
                    "chain": list(src_info["chain"]) + [f"{composite} = {rhs_var}"],
                }
            continue

        # Simple or arithmetic assignment: lhs = expr;
        m = _SIMPLE_ASSIGN_RE.search(stripped)
        if m:
            lhs = m.group(1)
            rhs_expr = m.group(2)

            # Check if ANY token on the RHS is tainted
            rhs_tokens = set(_ARITH_OPERAND_RE.findall(rhs_expr))
            tainted_rhs = [t for t in rhs_tokens
                           if _is_tainted(t, tainted, cleared_after, line_no)]

            if tainted_rhs:
                # Inherit taint from the first tainted operand
                donor = tainted_rhs[0]
                src_info = tainted[donor]
                tainted[lhs] = {
                    "origin_var": src_info["origin_var"],
                    "origin_type": src_info["origin_type"],
                    "read_call": src_info["read_call"],
                    "source_line": src_info["source_line"],
                    "chain": list(src_info["chain"]) + [f"{lhs} = {rhs_expr.strip()[:80]}"],
                }

                # Function call on RHS: y = Foo(tainted) -> y is tainted (conservative)
                # Already handled above -- lhs inherits taint.
            continue

        # Function call as a statement (not assignment): Foo(tainted_arg)
        # We don't need to propagate here (no new variable), but sinks will
        # pick it up in _identify_sinks.

    return tainted


def _is_tainted(var, tainted, cleared_after, current_line):
    """Check if *var* is tainted at *current_line*, respecting clears."""
    if var not in tainted:
        return False
    if var in cleared_after and current_line > cleared_after[var]:
        return False
    return True


# ===================================================================
# Step 3 -- Identify dangerous sinks
# ===================================================================

def _identify_sinks(pseudocode):
    """Scan pseudocode for dangerous operations and the variables they consume.

    Returns a list of dicts:
        {
            "category": "buffer_overflow",
            "operation": "items[v12]",
            "line": 42,
            "variables": ["v12"],
            "container": "items",  # optional
        }
    """
    sinks = []
    lines = pseudocode.split("\n")

    for line_no, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        for category, patterns in _SINK_PATTERNS.items():
            for pat in patterns:
                for m in pat.finditer(stripped):
                    # Collect all captured groups (some patterns have multiple)
                    captured_vars = [g for g in m.groups() if g and _is_identifier(g)]
                    if not captured_vars:
                        continue

                    operation = stripped[:120]

                    sink_entry = {
                        "category": category,
                        "operation": operation,
                        "line": line_no,
                        "variables": captured_vars,
                    }

                    # For buffer_overflow array access, record the container
                    if category == "buffer_overflow":
                        arr_m = _ARRAY_INDEX_RE.search(stripped)
                        if arr_m:
                            sink_entry["container"] = arr_m.group(1)
                            sink_entry["operation"] = f"{arr_m.group(1)}[{arr_m.group(2)}]"

                    sinks.append(sink_entry)
                    break  # one match per pattern per line is enough

    return sinks


def _is_identifier(s):
    """Return True if s looks like a C variable name (not a number/keyword)."""
    if not s:
        return False
    # Filter out pure numbers
    if re.match(r'^(?:0x[0-9A-Fa-f]+|\d+)$', s):
        return False
    # Filter out common C keywords
    if s in ("return", "if", "else", "for", "while", "do", "switch", "case",
             "break", "continue", "void", "int", "unsigned", "char", "float",
             "double", "true", "false", "nullptr", "NULL", "sizeof",
             "this", "const", "static"):
        return False
    return bool(re.match(r'^[a-zA-Z_]\w*$', s))


# ===================================================================
# Step 4 -- Check for validation between source and sink
# ===================================================================

def _check_validation_between(pseudocode, source_line, sink_line, taint_var):
    """Scan lines between source_line and sink_line for validation of taint_var.

    Returns True if a validation check exists that would guard against bad values.
    """
    lines = pseudocode.split("\n")
    start = max(0, source_line)
    end = min(len(lines), sink_line)

    if start >= end:
        return False

    region = "\n".join(lines[start:end])

    for pat in _VALIDATION_PATTERNS:
        m = pat.search(region)
        if m and m.group(1) == taint_var:
            return True

    # Also check for broader patterns that don't capture the exact variable
    # but are clearly guarding: e.g.  if (x < 0 || x >= count) { ... return; }
    guard_re = re.compile(
        r'if\s*\([^)]*\b' + re.escape(taint_var) + r'\b[^)]*\)\s*'
        r'(?:\{[^}]*)?return\b',
        re.DOTALL,
    )
    if guard_re.search(region):
        return True

    return False


# ===================================================================
# Step 5 -- Build the final report
# ===================================================================

def _build_taint_report(flows):
    """Assemble the complete taint analysis report from individual flows.

    Returns a JSON-serialisable dict suitable for kv_set storage.
    """
    high = [f for f in flows if f["severity"] == "high" and not f["has_validation"]]
    medium = [f for f in flows if f["severity"] == "medium" and not f["has_validation"]]
    low = [f for f in flows if f["severity"] == "low" and not f["has_validation"]]
    guarded = [f for f in flows if f["has_validation"]]

    # Group by handler for readability
    by_handler = {}
    for f in flows:
        h = f["handler"]
        if h not in by_handler:
            by_handler[h] = []
        by_handler[h].append(f)

    # Per-handler summary
    handler_summaries = []
    for handler_name, hflows in sorted(by_handler.items()):
        handler_summaries.append({
            "handler": handler_name,
            "handler_ea": hflows[0]["handler_ea"],
            "total_flows": len(hflows),
            "unguarded": sum(1 for f in hflows if not f["has_validation"]),
            "high_severity": sum(1 for f in hflows
                                 if f["severity"] == "high" and not f["has_validation"]),
            "categories": list(set(f["sink"]["category"] for f in hflows)),
        })

    # Sort handler summaries by unguarded high-severity count (most dangerous first)
    handler_summaries.sort(key=lambda h: (-h["high_severity"], -h["unguarded"]))

    # Sink category distribution
    category_counts = {}
    for f in flows:
        cat = f["sink"]["category"]
        if cat not in category_counts:
            category_counts[cat] = {"total": 0, "unguarded": 0}
        category_counts[cat]["total"] += 1
        if not f["has_validation"]:
            category_counts[cat]["unguarded"] += 1

    return {
        "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_flows": len(flows),
            "unguarded_high": len(high),
            "unguarded_medium": len(medium),
            "unguarded_low": len(low),
            "guarded": len(guarded),
            "handlers_with_issues": len([h for h in handler_summaries if h["unguarded"] > 0]),
        },
        "category_distribution": category_counts,
        "handler_summaries": handler_summaries,
        "flows": flows,
    }


# ===================================================================
# Report retrieval helpers
# ===================================================================

def get_taint_report(session):
    """Retrieve the stored taint analysis report from the knowledge DB.

    Returns the full report dict, or None if no analysis has been run.
    """
    return session.db.kv_get("taint_analysis")


def get_high_severity_flows(session):
    """Return only the high-severity unguarded flows.

    Returns a list of flow dicts, or an empty list if no report exists.
    """
    report = get_taint_report(session)
    if not report:
        return []
    return [f for f in report.get("flows", [])
            if f["severity"] == "high" and not f["has_validation"]]


def export_security_audit(session):
    """Export the taint analysis results as a Markdown security audit report.

    Returns the report as a string.  Also stores it in kv_store as
    'taint_analysis_markdown'.
    """
    report = get_taint_report(session)
    if not report:
        msg_warn("No taint analysis report found -- run analyze_taint_flows() first")
        return "# Security Audit Report\n\nNo taint analysis data available.\n"

    summary = report["summary"]
    lines = [
        "# WoW Binary Security Audit -- Data Flow Taint Analysis",
        "",
        f"**Generated:** {report['analysis_time']}",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total taint flows analysed | {summary['total_flows']} |",
        f"| Unguarded HIGH severity | {summary['unguarded_high']} |",
        f"| Unguarded MEDIUM severity | {summary['unguarded_medium']} |",
        f"| Unguarded LOW severity | {summary['unguarded_low']} |",
        f"| Properly guarded flows | {summary['guarded']} |",
        f"| Handlers with issues | {summary['handlers_with_issues']} |",
        "",
    ]

    # Category breakdown
    cat_dist = report.get("category_distribution", {})
    if cat_dist:
        lines.append("## Sink Category Distribution")
        lines.append("")
        lines.append("| Category | Total | Unguarded |")
        lines.append("|----------|-------|-----------|")
        for cat, counts in sorted(cat_dist.items(), key=lambda x: -x[1]["unguarded"]):
            lines.append(f"| {cat} | {counts['total']} | {counts['unguarded']} |")
        lines.append("")

    # High-severity flows detail
    high_flows = [f for f in report.get("flows", [])
                  if f["severity"] == "high" and not f["has_validation"]]
    if high_flows:
        lines.append("## HIGH Severity Unguarded Flows")
        lines.append("")

        for i, flow in enumerate(high_flows, 1):
            lines.append(f"### {i}. {flow['handler']}")
            lines.append("")
            lines.append(f"- **Handler EA:** `0x{flow['handler_ea']:X}`")
            lines.append(f"- **Source:** `{flow['source']['read_call']}` "
                         f"-> `{flow['source']['variable']}` "
                         f"(line {flow['source']['line']})")
            lines.append(f"- **Sink:** `{flow['sink']['category']}` -- "
                         f"`{flow['sink']['operation'][:100]}` "
                         f"(line {flow['sink']['line']})")
            lines.append(f"- **Taint chain:**")
            for step in flow["taint_chain"]:
                lines.append(f"  - `{step[:120]}`")
            lines.append(f"- **Suggested fix:** {flow['suggested_fix']}")
            lines.append("")

    # Medium severity summary
    med_flows = [f for f in report.get("flows", [])
                 if f["severity"] == "medium" and not f["has_validation"]]
    if med_flows:
        lines.append("## MEDIUM Severity Unguarded Flows")
        lines.append("")
        lines.append("| # | Handler | Source | Sink Category | Operation |")
        lines.append("|---|---------|--------|---------------|-----------|")
        for i, flow in enumerate(med_flows, 1):
            op = flow["sink"]["operation"][:60].replace("|", "\\|")
            lines.append(
                f"| {i} | {flow['handler']} | "
                f"`{flow['source']['read_call']}` | "
                f"{flow['sink']['category']} | `{op}` |"
            )
        lines.append("")

    # Handler risk ranking
    handler_sums = report.get("handler_summaries", [])
    risky = [h for h in handler_sums if h["unguarded"] > 0]
    if risky:
        lines.append("## Handler Risk Ranking")
        lines.append("")
        lines.append("| Handler | Unguarded | High | Categories |")
        lines.append("|---------|-----------|------|------------|")
        for h in risky[:50]:
            cats = ", ".join(h["categories"][:4])
            lines.append(
                f"| {h['handler']} | {h['unguarded']} | "
                f"{h['high_severity']} | {cats} |"
            )
        lines.append("")

    lines.append("---")
    lines.append("*Report generated by TC WoW Analyzer -- taint_analysis module*")
    lines.append("")

    md_text = "\n".join(lines)

    # Persist the markdown
    session.db.kv_set("taint_analysis_markdown", md_text)
    session.db.commit()

    msg_info(f"Security audit report exported ({len(lines)} lines)")
    return md_text
