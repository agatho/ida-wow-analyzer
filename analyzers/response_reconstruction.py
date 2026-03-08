"""
Response Packet Reconstruction
Traces SMSG response packet construction within CMSG handler functions.
For each handler, identifies which SMSG opcodes are built, which fields
are populated, in what order, with what values/conditions, and classifies
response paths (success, error, broadcast, conditional).

Generates complete TrinityCore C++ handler code and SMSG packet structs
from reconstructed response data.
"""

import json
import re
import time
from collections import defaultdict

import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Write-type detection patterns applied to decompiled pseudocode
# ---------------------------------------------------------------------------

# Packet object allocation / construction
_RE_PKT_ALLOC = re.compile(
    r'(\w+)\s*=\s*(?:operator_new|(?:\(\w+\s*\*\))?(?:__\w*alloc|_?\w*new))\s*\('
    r'\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\)',
)
_RE_PKT_STACK = re.compile(
    r'(?:WorldPacket|Packet|ByteBuffer)\s+(\w+)\s*(?:\(|;)',
)

# Opcode assignment to packet variable
_RE_OPCODE_ASSIGN = re.compile(
    r'\*\s*\(?\s*(?:_WORD|_DWORD|uint16|unsigned\s+__int16)\s*\*?\)?\s*'
    r'\(?\s*(\w+)\s*(?:\+\s*(?:0x[0-9A-Fa-f]+|\d+))?\s*\)?\s*=\s*'
    r'(0x[0-9A-Fa-f]+|\d+)',
)
_RE_OPCODE_MEMBER = re.compile(
    r'(\w+)->(?:opcode|m_opcode|header)\s*=\s*(0x[0-9A-Fa-f]+|\d+)',
)
_RE_OPCODE_CTOR = re.compile(
    r'(\w+)\s*=\s*\w+\(\s*(0x[0-9A-Fa-f]+|\d+)\s*(?:,\s*\d+)?\s*\)',
)

# Field write patterns on a packet variable
_WRITE_PATTERNS = [
    # Direct memory writes: *(type*)(pkt + offset) = value
    {
        "regex": re.compile(
            r'\*\s*\(?\s*(?:_DWORD|_QWORD|_WORD|_BYTE|'
            r'uint32|uint64|uint16|uint8|unsigned\s+(?:int|__int64|__int16|__int8)|'
            r'int|__int64|float|double)\s*\*?\)?\s*'
            r'\(?\s*{pkt_var}\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*=\s*'
            r'(.+?)\s*;'
        ),
        "extract": lambda m, offset_base: {
            "offset": _parse_int(m.group(1)),
            "source": m.group(2).strip(),
        },
        "type_detect": lambda m: _detect_type_from_cast(m.group(0)),
    },
    # Method-style writes: pkt->Write<type>(value) or Write*(pkt, value)
    {
        "regex": re.compile(
            r'{pkt_var}\s*->\s*Write\s*<\s*(\w+)\s*>\s*\(\s*(.+?)\s*\)',
        ),
        "extract": lambda m, offset_base: {
            "source": m.group(2).strip(),
        },
        "type_detect": lambda m: m.group(1).lower(),
    },
    # WriteBit / WriteBits
    {
        "regex": re.compile(
            r'(?:{pkt_var}\s*->\s*)?WriteBits?\s*\(\s*(?:{pkt_var}\s*,\s*)?'
            r'(.+?)\s*(?:,\s*(\d+)\s*)?\)',
        ),
        "extract": lambda m, offset_base: {
            "source": m.group(1).strip(),
            "bit_count": int(m.group(2)) if m.group(2) else 1,
        },
        "type_detect": lambda m: "bits",
    },
    # WritePackedGuid128 / WritePackedGuid
    {
        "regex": re.compile(
            r'(?:{pkt_var}\s*->\s*)?WritePackedGuid(?:128)?\s*\(\s*'
            r'(?:{pkt_var}\s*,\s*)?(.+?)\s*\)',
        ),
        "extract": lambda m, offset_base: {
            "source": m.group(1).strip(),
        },
        "type_detect": lambda m: "packed_guid",
    },
    # WriteString / WriteCString
    {
        "regex": re.compile(
            r'(?:{pkt_var}\s*->\s*)?Write(?:C?)String\s*\(\s*'
            r'(?:{pkt_var}\s*,\s*)?(.+?)\s*\)',
        ),
        "extract": lambda m, offset_base: {
            "source": m.group(1).strip(),
        },
        "type_detect": lambda m: "string" if "WriteString" in m.group(0) else "cstring",
    },
    # WriteFloat
    {
        "regex": re.compile(
            r'(?:{pkt_var}\s*->\s*)?WriteFloat\s*\(\s*'
            r'(?:{pkt_var}\s*,\s*)?(.+?)\s*\)',
        ),
        "extract": lambda m, offset_base: {
            "source": m.group(1).strip(),
        },
        "type_detect": lambda m: "float",
    },
    # Stream operator: *pkt << value  or  pkt << value
    {
        "regex": re.compile(
            r'(?:\*\s*)?{pkt_var}\s*<<\s*(.+?)\s*;',
        ),
        "extract": lambda m, offset_base: {
            "source": m.group(1).strip(),
        },
        "type_detect": lambda m: _infer_type_from_source(m.group(1).strip()),
    },
]

# Send patterns
_RE_SEND_PACKET = re.compile(
    r'(?:SendPacket|Send)\s*\(\s*(?:&?\s*)?(\w+)',
)
_RE_SEND_TO_SET = re.compile(
    r'(?:SendMessageToSet|BroadcastPacket|SendToAll|SendPacketToAll)\s*\(\s*'
    r'(?:&?\s*)?(\w+)',
)

# Call instruction patterns for tracing helper functions
_RE_FUNC_CALL = re.compile(
    r'(\w+)\s*\(\s*([^)]*)\s*\)',
)

# Conditional block detection
_RE_IF_BLOCK = re.compile(
    r'if\s*\(\s*(.+?)\s*\)\s*\{?',
)
_RE_ELSE_BLOCK = re.compile(
    r'\}\s*else\s*\{?',
)

# Type detection from cast expressions
_TYPE_CAST_MAP = {
    "_BYTE": "uint8",
    "_WORD": "uint16",
    "_DWORD": "uint32",
    "_QWORD": "uint64",
    "uint8": "uint8",
    "uint16": "uint16",
    "uint32": "uint32",
    "uint64": "uint64",
    "unsigned int": "uint32",
    "unsigned __int64": "uint64",
    "unsigned __int16": "uint16",
    "unsigned __int8": "uint8",
    "int": "int32",
    "__int64": "int64",
    "float": "float",
    "double": "double",
}

# C++ type → default initializer
_CPP_DEFAULTS = {
    "uint8": " = 0",
    "uint16": " = 0",
    "uint32": " = 0",
    "uint64": " = 0",
    "int8": " = 0",
    "int16": " = 0",
    "int32": " = 0",
    "int64": " = 0",
    "float": " = 0.0f",
    "double": " = 0.0",
    "ObjectGuid": "",
    "packed_guid": "",
    "string": "",
    "cstring": "",
    "bits": " = 0",
    "Position": "",
}

# Source-value patterns that hint at field names
_SOURCE_NAME_HINTS = {
    re.compile(r'GetGUID', re.I): "Guid",
    re.compile(r'GetEntry', re.I): "Entry",
    re.compile(r'GetLevel', re.I): "Level",
    re.compile(r'GetMap', re.I): "MapID",
    re.compile(r'GetPosition', re.I): "Position",
    re.compile(r'GetName', re.I): "Name",
    re.compile(r'result|Result', re.I): "Result",
    re.compile(r'error|Error', re.I): "Error",
    re.compile(r'count|Count', re.I): "Count",
    re.compile(r'status|Status', re.I): "Status",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _parse_int(val):
    """Parse an integer from a string that may be hex or decimal."""
    try:
        return int(val, 0)
    except (ValueError, TypeError):
        return 0


def _detect_type_from_cast(expr):
    """Detect the C++ type from a cast expression in pseudocode."""
    for pattern, typ in _TYPE_CAST_MAP.items():
        if pattern in expr:
            return typ
    return "uint32"


def _infer_type_from_source(source):
    """Infer a field type from the source expression."""
    if "GUID" in source.upper() or "guid" in source.lower():
        return "packed_guid"
    if "float" in source.lower() or source.startswith("*(float"):
        return "float"
    if "string" in source.lower() or "String" in source:
        return "string"
    return "uint32"


def _guess_field_name(field_index, field_type, source):
    """Attempt to guess a readable field name from source expression."""
    for pattern, name in _SOURCE_NAME_HINTS.items():
        if pattern.search(source):
            return name
    if field_type == "packed_guid":
        return f"Guid_{field_index}"
    if field_type == "float":
        return f"field_{field_index}"
    return f"field_{field_index}"


def _compile_write_patterns(pkt_var):
    """Compile write-detection regexes with a specific packet variable name."""
    compiled = []
    escaped = re.escape(pkt_var)
    for pat in _WRITE_PATTERNS:
        raw = pat["regex"].pattern.replace("{pkt_var}", escaped)
        compiled.append({
            "regex": re.compile(raw),
            "extract": pat["extract"],
            "type_detect": pat["type_detect"],
        })
    return compiled


def _opcode_name_from_index(db, index_val):
    """Look up a known opcode name from the DB by internal_index or wire_opcode."""
    row = db.fetchone(
        "SELECT tc_name, direction, internal_index FROM opcodes "
        "WHERE internal_index = ? AND direction = 'SMSG'",
        (index_val,),
    )
    if row and row["tc_name"]:
        return row["tc_name"], row["internal_index"]

    # Try wire_opcode
    row = db.fetchone(
        "SELECT tc_name, direction, internal_index FROM opcodes "
        "WHERE wire_opcode = ? AND direction = 'SMSG'",
        (index_val,),
    )
    if row and row["tc_name"]:
        return row["tc_name"], row["internal_index"]

    return None, index_val


def _camel_to_upper_snake(name):
    """Convert CamelCase to UPPER_SNAKE_CASE."""
    s = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', name)
    return s.upper()


def _opcode_to_class_name(opcode_name):
    """Convert SMSG_SOME_THING to SomeThing."""
    parts = opcode_name.split("_")
    if parts and parts[0] in ("SMSG", "CMSG"):
        parts = parts[1:]
    return "".join(p.capitalize() for p in parts)


def _get_handler_name_from_tc_name(tc_name):
    """Convert CMSG_HOUSING_DECOR_PLACE → HandleHousingDecorPlace."""
    parts = tc_name.split("_")
    if parts and parts[0] in ("CMSG", "SMSG"):
        parts = parts[1:]
    return "Handle" + "".join(p.capitalize() for p in parts)


# ---------------------------------------------------------------------------
# Core tracing logic
# ---------------------------------------------------------------------------

def _identify_packet_variables(pseudocode):
    """Identify variables that represent packet objects in the pseudocode.

    Returns a list of (variable_name, line_index) tuples.
    """
    pkt_vars = []
    lines = pseudocode.split("\n")

    for i, line in enumerate(lines):
        # Stack-allocated packet objects
        m = _RE_PKT_STACK.search(line)
        if m:
            pkt_vars.append((m.group(1), i))
            continue

        # Heap-allocated packet objects
        m = _RE_PKT_ALLOC.search(line)
        if m:
            pkt_vars.append((m.group(1), i))
            continue

    return pkt_vars


def _identify_response_opcode(pseudocode_block, packet_var):
    """Determine the SMSG opcode assigned to a packet variable.

    Returns the integer opcode value or None.
    """
    escaped = re.escape(packet_var)

    # Pattern 1: *(uint16*)(pkt) = 0x1234  or  *(uint16*)(pkt + 0) = 0x1234
    for m in _RE_OPCODE_ASSIGN.finditer(pseudocode_block):
        if m.group(1) == packet_var:
            return _parse_int(m.group(2))

    # Pattern 2: pkt->opcode = 0x1234
    for m in _RE_OPCODE_MEMBER.finditer(pseudocode_block):
        if m.group(1) == packet_var:
            return _parse_int(m.group(2))

    # Pattern 3: pkt = SomeConstructor(0x1234)  (opcode in constructor arg)
    for m in _RE_OPCODE_CTOR.finditer(pseudocode_block):
        if m.group(1) == packet_var:
            val = _parse_int(m.group(2))
            # Sanity check: opcodes are usually in a reasonable range
            if 0 < val < 0xFFFF:
                return val

    # Pattern 4: look for any assignment of a constant to the var within
    # the first few lines after allocation
    pkt_assign_re = re.compile(
        rf'\*\s*\(?\s*\w+\s*\*?\)?\s*\(?\s*{escaped}\s*\)?\s*=\s*'
        r'(0x[0-9A-Fa-f]+|\d+)\s*;'
    )
    for m in pkt_assign_re.finditer(pseudocode_block):
        val = _parse_int(m.group(1))
        if 0 < val < 0xFFFF:
            return val

    return None


def _extract_packet_fields(pseudocode_block, packet_var):
    """Extract ordered field writes for a single packet variable.

    Returns a list of field dicts: {index, type, name, source, offset?, bit_count?}
    """
    fields = []
    compiled = _compile_write_patterns(packet_var)
    field_index = 0

    lines = pseudocode_block.split("\n")
    for line in lines:
        for pat in compiled:
            m = pat["regex"].search(line)
            if m:
                field_type = pat["type_detect"](m)
                extracted = pat["extract"](m, 0)
                source = extracted.get("source", "")

                field = {
                    "index": field_index,
                    "type": field_type,
                    "name": _guess_field_name(field_index, field_type, source),
                    "source": source,
                }
                if "offset" in extracted:
                    field["offset"] = extracted["offset"]
                if "bit_count" in extracted:
                    field["bit_count"] = extracted["bit_count"]

                fields.append(field)
                field_index += 1
                break  # one match per line

    return fields


def _classify_response_path(pseudocode, send_line_idx, packet_var, condition_stack):
    """Classify how a response packet is sent.

    Returns a dict with path_type and condition.
    """
    lines = pseudocode.split("\n")

    # Check for broadcast-style sends
    send_line = lines[send_line_idx] if send_line_idx < len(lines) else ""
    if _RE_SEND_TO_SET.search(send_line):
        return {
            "path_type": "broadcast",
            "condition": condition_stack[-1] if condition_stack else None,
        }

    # Check what condition we're inside
    if not condition_stack:
        return {
            "path_type": "success_response",
            "condition": None,
        }

    condition = condition_stack[-1]
    cond_lower = condition.lower()

    # Error indicators
    error_indicators = [
        "!", "!= 0", "error", "fail", "invalid", "null", "nullptr",
        "< 0", "!has", "!is", "!can", "!get", "return",
    ]
    for indicator in error_indicators:
        if indicator in cond_lower:
            return {
                "path_type": "error_response",
                "condition": condition,
            }

    return {
        "path_type": "conditional",
        "condition": condition,
    }


def _find_send_sites(pseudocode, packet_var):
    """Find all locations where a packet variable is sent.

    Returns a list of (line_index, send_type) tuples.
    send_type is 'direct' or 'broadcast'.
    """
    sites = []
    lines = pseudocode.split("\n")
    escaped = re.escape(packet_var)

    for i, line in enumerate(lines):
        # Direct send
        if re.search(rf'SendPacket\s*\(\s*(?:&?\s*)?{escaped}', line):
            sites.append((i, "direct"))
        elif re.search(rf'Send\s*\(\s*(?:&?\s*)?{escaped}', line):
            sites.append((i, "direct"))
        # Broadcast send
        if re.search(
            rf'(?:SendMessageToSet|BroadcastPacket|SendToAll|SendPacketToAll)'
            rf'\s*\(\s*(?:&?\s*)?{escaped}', line
        ):
            sites.append((i, "broadcast"))

    return sites


def _build_condition_stack(pseudocode, up_to_line):
    """Build a stack of active conditions at a given line index.

    Walks the pseudocode from top to up_to_line, tracking if/else nesting.
    Returns list of condition strings (innermost last).
    """
    lines = pseudocode.split("\n")
    conditions = []
    brace_depth = 0
    cond_at_depth = {}

    for i in range(min(up_to_line + 1, len(lines))):
        line = lines[i].strip()

        # Track conditions
        m = _RE_IF_BLOCK.match(line)
        if m:
            cond_at_depth[brace_depth] = m.group(1).strip()

        m = _RE_ELSE_BLOCK.match(line)
        if m and brace_depth in cond_at_depth:
            cond_at_depth[brace_depth] = "!" + cond_at_depth[brace_depth]

        # Track brace depth
        brace_depth += line.count("{")
        brace_depth -= line.count("}")

        # Clean up conditions for braces that closed
        closed = [d for d in cond_at_depth if d >= brace_depth]
        for d in closed:
            if d > 0:  # don't remove function-level
                del cond_at_depth[d]

    conditions = [cond_at_depth[d] for d in sorted(cond_at_depth.keys()) if d > 0]
    return conditions


def _trace_response_construction(pseudocode, handler_name, handler_ea, db):
    """Parse pseudocode for all SMSG packet constructions.

    Returns a list of response dicts.
    """
    responses = []
    lines = pseudocode.split("\n")

    # Phase 1: find all packet variable candidates
    pkt_vars = _identify_packet_variables(pseudocode)

    # Also look for variables that have opcode assignments even if we
    # didn't catch them with the allocation pattern
    for m in _RE_OPCODE_ASSIGN.finditer(pseudocode):
        var = m.group(1)
        if not any(v == var for v, _ in pkt_vars):
            # Find the line index
            for i, line in enumerate(lines):
                if var in line and m.group(2) in line:
                    pkt_vars.append((var, i))
                    break

    if not pkt_vars:
        return responses

    # Phase 2: for each packet variable, trace its lifecycle
    for pkt_var, alloc_line in pkt_vars:
        # Determine the opcode
        # Search from allocation line to end of function (or next allocation)
        search_end = len(lines)
        for other_var, other_line in pkt_vars:
            if other_var != pkt_var and other_line > alloc_line:
                search_end = min(search_end, other_line)

        block_text = "\n".join(lines[alloc_line:search_end])

        opcode_val = _identify_response_opcode(block_text, pkt_var)
        if opcode_val is None:
            continue

        # Look up opcode name
        smsg_name, smsg_index = _opcode_name_from_index(db, opcode_val)
        if smsg_name is None:
            smsg_name = f"SMSG_UNKNOWN_0x{opcode_val:04X}"

        # Extract fields
        fields = _extract_packet_fields(block_text, pkt_var)

        # Find send sites
        send_sites = _find_send_sites(pseudocode, pkt_var)

        if not send_sites:
            # Packet constructed but never sent directly -- might be passed
            # to a helper. Still record it.
            send_sites = [(search_end - 1, "unknown")]

        # Classify each send site
        for send_line, send_type in send_sites:
            condition_stack = _build_condition_stack(pseudocode, send_line)

            if send_type == "broadcast":
                path_info = {
                    "path_type": "broadcast",
                    "condition": condition_stack[-1] if condition_stack else None,
                }
            else:
                path_info = _classify_response_path(
                    pseudocode, send_line, pkt_var, condition_stack
                )

            response = {
                "smsg_opcode": smsg_name,
                "smsg_index": smsg_index,
                "path_type": path_info["path_type"],
                "condition": path_info["condition"],
                "fields": fields,
                "pkt_var": pkt_var,
                "alloc_line": alloc_line,
                "send_line": send_line,
            }
            responses.append(response)

    return responses


def _trace_helper_calls(pseudocode, handler_ea, db):
    """Trace one level of function calls from the handler to find
    response constructions in helper functions.

    Returns additional response dicts found in callees.
    """
    helper_responses = []

    func = ida_funcs.get_func(handler_ea)
    if not func:
        return helper_responses

    # Collect direct call targets
    callee_eas = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN):
                continue
            target_func = ida_funcs.get_func(xref.to)
            if target_func and target_func.start_ea != func.start_ea:
                callee_eas.add(target_func.start_ea)

    # Decompile each callee and look for packet construction
    for callee_ea in callee_eas:
        callee_name = ida_name.get_name(callee_ea) or f"sub_{callee_ea:X}"

        # Skip very common utility functions
        if callee_name.startswith("sub_") and len(callee_name) < 10:
            continue
        if any(skip in callee_name.lower() for skip in
               ("operator", "memcpy", "memset", "strlen", "printf", "assert")):
            continue

        callee_code = get_decompiled_text(callee_ea, db=db)
        if not callee_code:
            continue

        responses = _trace_response_construction(
            callee_code, callee_name, callee_ea, db
        )
        for r in responses:
            r["from_helper"] = callee_name
            r["helper_ea"] = callee_ea
            helper_responses.append(r)

    return helper_responses


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def reconstruct_responses(session, system_filter=None):
    """Main entry point: reconstruct SMSG response packets from CMSG handlers.

    For each CMSG handler with a known handler_ea, decompiles the handler,
    traces all SMSG packet constructions, extracts field-by-field data,
    tracks conditional response paths, and stores results.

    Args:
        session: PluginSession
        system_filter: Only analyze handlers matching this pattern (e.g. 'housing')

    Returns:
        Number of response packets reconstructed.
    """
    db = session.db
    total_responses = 0
    handler_count = 0

    query = ("SELECT * FROM opcodes "
             "WHERE handler_ea IS NOT NULL "
             "AND (direction = 'CMSG' OR direction = 'unknown')")
    if system_filter:
        query += f" AND (tc_name LIKE '%{system_filter}%' OR jam_type LIKE '%{system_filter}%')"
    handlers = db.fetchall(query)

    msg_info(f"Reconstructing response packets from {len(handlers)} CMSG handlers...")

    all_results = []

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"handler_0x{ea:X}"
        jam_type = handler["jam_type"] or ""
        internal_index = handler["internal_index"]

        pseudocode = get_decompiled_text(ea, db=db)
        if not pseudocode:
            continue

        handler_name = _get_handler_name_from_tc_name(tc_name) if tc_name else f"Handler_0x{ea:X}"

        # Trace direct response constructions
        responses = _trace_response_construction(pseudocode, handler_name, ea, db)

        # Trace one level of helper calls
        helper_responses = _trace_helper_calls(pseudocode, ea, db)
        responses.extend(helper_responses)

        if not responses:
            continue

        # Clean up transient fields before storage
        clean_responses = []
        for r in responses:
            clean = {
                "smsg_opcode": r["smsg_opcode"],
                "smsg_index": r["smsg_index"],
                "path_type": r["path_type"],
                "condition": r["condition"],
                "fields": r["fields"],
            }
            if r.get("from_helper"):
                clean["from_helper"] = r["from_helper"]
                clean["helper_ea"] = r["helper_ea"]
            clean_responses.append(clean)

        result_entry = {
            "cmsg_handler": handler_name,
            "cmsg_opcode": tc_name,
            "handler_ea": ea,
            "responses": clean_responses,
        }
        all_results.append(result_entry)
        total_responses += len(clean_responses)
        handler_count += 1

        if handler_count % 50 == 0:
            msg_info(f"  Processed {handler_count} handlers, "
                     f"{total_responses} responses so far...")

    # Store in kv_store
    db.kv_set("response_packets", all_results)
    db.commit()

    msg_info(f"Reconstructed {total_responses} response packets "
             f"from {handler_count} CMSG handlers")

    # Print summary of top findings
    for entry in all_results[:20]:
        smsg_names = list(set(r["smsg_opcode"] for r in entry["responses"]))
        msg(f"  {entry['cmsg_opcode']} -> {', '.join(smsg_names)}")

    return total_responses


def get_response_packets(session, cmsg_name=None):
    """Retrieve reconstructed response packet data.

    Args:
        session: PluginSession
        cmsg_name: If provided, return only data for this CMSG handler.
                   Matches against cmsg_opcode or cmsg_handler fields.

    Returns:
        List of response entries, or a single entry if cmsg_name is given.
    """
    all_data = session.db.kv_get("response_packets") or []

    if cmsg_name is None:
        return all_data

    cmsg_upper = cmsg_name.upper()
    for entry in all_data:
        if (entry.get("cmsg_opcode", "").upper() == cmsg_upper or
                entry.get("cmsg_handler", "").upper() == cmsg_upper or
                cmsg_upper in entry.get("cmsg_opcode", "").upper() or
                cmsg_upper in entry.get("cmsg_handler", "").upper()):
            return entry

    return None


def get_handler_response_map(session):
    """Get a compact CMSG -> SMSG mapping for all handlers.

    Returns a dict: { cmsg_opcode: [smsg_opcode, ...] }
    """
    all_data = session.db.kv_get("response_packets") or []
    result = {}

    for entry in all_data:
        cmsg = entry.get("cmsg_opcode", "unknown")
        smsg_list = list(set(
            r["smsg_opcode"] for r in entry.get("responses", [])
        ))
        if smsg_list:
            result[cmsg] = smsg_list

    return result


# ---------------------------------------------------------------------------
# C++ Code Generation
# ---------------------------------------------------------------------------

def generate_response_handler_cpp(session, cmsg_name):
    """Generate complete TrinityCore handler C++ code for a CMSG handler,
    including all response paths discovered from the binary.

    Args:
        session: PluginSession
        cmsg_name: CMSG opcode name (e.g. "CMSG_HOUSING_DECOR_PLACE")

    Returns:
        C++ handler function source as a string.
    """
    entry = get_response_packets(session, cmsg_name)
    if not entry:
        return f"// No response data found for {cmsg_name}\n"

    cmsg_handler = entry.get("cmsg_handler", "HandleUnknown")
    cmsg_opcode = entry.get("cmsg_opcode", cmsg_name)
    responses = entry.get("responses", [])

    # Derive the packet class name from the CMSG opcode
    cmsg_class = _opcode_to_class_name(cmsg_opcode)

    # Determine the namespace from the opcode name
    # e.g. CMSG_HOUSING_DECOR_PLACE -> Housing
    parts = cmsg_opcode.split("_")
    if len(parts) >= 2 and parts[0] == "CMSG":
        namespace = parts[1].capitalize()
    else:
        namespace = "Misc"

    lines = []
    lines.append(
        f"void WorldSession::{cmsg_handler}"
        f"(WorldPackets::{namespace}::{cmsg_class}& packet)"
    )
    lines.append("{")

    # Group responses by path type
    error_responses = [r for r in responses if r["path_type"] == "error_response"]
    success_responses = [r for r in responses if r["path_type"] == "success_response"]
    broadcast_responses = [r for r in responses if r["path_type"] == "broadcast"]
    conditional_responses = [r for r in responses if r["path_type"] == "conditional"]

    # Emit error paths first (early returns)
    for i, resp in enumerate(error_responses):
        condition = resp.get("condition") or "/* validation check */"
        smsg_class = _opcode_to_class_name(resp["smsg_opcode"])

        lines.append(f"    // Error response (path {i + 1})")
        lines.append(f"    if ({condition})")
        lines.append("    {")
        lines.append(f"        WorldPackets::{namespace}::{smsg_class} result;")

        for field in resp.get("fields", []):
            field_name = field["name"]
            source = field["source"]
            lines.append(f"        result.{field_name} = {source};")

        lines.append("        SendPacket(result.Write());")
        lines.append("        return;")
        lines.append("    }")
        lines.append("")

    # Emit handler logic placeholder
    lines.append("    // ... handler logic ...")
    lines.append("")

    # Emit success responses
    for i, resp in enumerate(success_responses):
        smsg_class = _opcode_to_class_name(resp["smsg_opcode"])

        lines.append(f"    // Success response (path {len(error_responses) + i + 1})")
        lines.append(f"    WorldPackets::{namespace}::{smsg_class} result;")

        for field in resp.get("fields", []):
            field_name = field["name"]
            source = field["source"]
            lines.append(f"    result.{field_name} = {source};")

        lines.append("    SendPacket(result.Write());")
        lines.append("")

    # Emit broadcast responses
    for i, resp in enumerate(broadcast_responses):
        smsg_class = _opcode_to_class_name(resp["smsg_opcode"])
        condition = resp.get("condition")

        lines.append(f"    // Broadcast response")
        if condition:
            lines.append(f"    // Condition: {condition}")
        lines.append(f"    WorldPackets::{namespace}::{smsg_class} broadcastPkt;")

        for field in resp.get("fields", []):
            field_name = field["name"]
            source = field["source"]
            lines.append(f"    broadcastPkt.{field_name} = {source};")

        lines.append("    _player->SendMessageToSet(broadcastPkt.Write(), true);")
        lines.append("")

    # Emit conditional responses
    for i, resp in enumerate(conditional_responses):
        smsg_class = _opcode_to_class_name(resp["smsg_opcode"])
        condition = resp.get("condition") or "/* condition */"

        lines.append(f"    // Conditional response")
        lines.append(f"    if ({condition})")
        lines.append("    {")
        lines.append(f"        WorldPackets::{namespace}::{smsg_class} condPkt;")

        for field in resp.get("fields", []):
            field_name = field["name"]
            source = field["source"]
            lines.append(f"        condPkt.{field_name} = {source};")

        lines.append("        SendPacket(condPkt.Write());")
        lines.append("    }")
        lines.append("")

    lines.append("}")
    return "\n".join(lines) + "\n"


def generate_smsg_struct_cpp(session, smsg_name):
    """Generate a TrinityCore SMSG packet struct definition from
    reconstructed response data.

    Args:
        session: PluginSession
        smsg_name: SMSG opcode name (e.g. "SMSG_HOUSING_DECOR_PLACE_RESULT")

    Returns:
        C++ struct definition as a string.
    """
    all_data = session.db.kv_get("response_packets") or []
    smsg_upper = smsg_name.upper()

    # Find the response entry that contains this SMSG
    best_fields = []
    found_opcode = None

    for entry in all_data:
        for resp in entry.get("responses", []):
            if resp.get("smsg_opcode", "").upper() == smsg_upper:
                found_opcode = resp["smsg_opcode"]
                # Take the response with the most fields (usually the
                # success path has all fields)
                if len(resp.get("fields", [])) > len(best_fields):
                    best_fields = resp["fields"]

    if not found_opcode:
        return f"// SMSG '{smsg_name}' not found in reconstructed responses\n"

    class_name = _opcode_to_class_name(found_opcode)

    lines = []
    lines.append(f"class {class_name} final : public ServerPacket")
    lines.append("{")
    lines.append("public:")
    lines.append(f"    {class_name}() : ServerPacket({found_opcode}) {{ }}")
    lines.append("")
    lines.append("    WorldPacket const* Write() override;")

    if best_fields:
        lines.append("")
        # Deduplicate fields by name (same field may appear in multiple paths)
        seen_names = set()
        for field in best_fields:
            fname = field["name"]
            if fname in seen_names:
                continue
            seen_names.add(fname)

            ftype = field["type"]
            # Map internal types to C++ types
            cpp_type = _field_type_to_cpp(ftype)
            default = _CPP_DEFAULTS.get(ftype, _CPP_DEFAULTS.get(cpp_type, " = 0"))
            lines.append(f"    {cpp_type} {fname}{default};")

    lines.append("};")

    # Also generate the Write() method
    lines.append("")
    lines.append(f"WorldPacket const* {class_name}::Write()")
    lines.append("{")

    if best_fields:
        seen_names = set()
        for field in best_fields:
            fname = field["name"]
            if fname in seen_names:
                continue
            seen_names.add(fname)

            ftype = field["type"]
            if ftype == "packed_guid":
                lines.append(f"    _worldPacket.WritePackedGuid({fname});")
            elif ftype == "bits":
                bit_count = field.get("bit_count", 1)
                lines.append(f"    _worldPacket.WriteBits({fname}, {bit_count});")
            elif ftype == "string":
                lines.append(f"    _worldPacket.WriteBits({fname}.size(), 11);")
                lines.append(f"    _worldPacket.FlushBits();")
                lines.append(f"    _worldPacket.WriteString({fname});")
            elif ftype == "cstring":
                lines.append(f"    _worldPacket << {fname};")
            else:
                lines.append(f"    _worldPacket << {fname};")

    lines.append("")
    lines.append("    return &_worldPacket;")
    lines.append("}")

    return "\n".join(lines) + "\n"


def _field_type_to_cpp(ftype):
    """Convert internal field type to TrinityCore C++ type."""
    mapping = {
        "uint8": "uint8",
        "uint16": "uint16",
        "uint32": "uint32",
        "uint64": "uint64",
        "int8": "int8",
        "int16": "int16",
        "int32": "int32",
        "int64": "int64",
        "float": "float",
        "double": "double",
        "packed_guid": "ObjectGuid",
        "string": "std::string",
        "cstring": "std::string",
        "bits": "uint32",
    }
    return mapping.get(ftype, "uint32")
