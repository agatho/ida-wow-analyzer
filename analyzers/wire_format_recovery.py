"""
Bit-Level Wire Format Recovery (Feature #3)
Traces through decompiled handler pseudocode to recover the exact
bit-level serialization order of WoW packets.

WoW packets use aggressive bit-packing:
  - ReadBit() / WriteBit()                — single boolean bits
  - ReadBits(n) / WriteBits(value, n)     — n-bit integers
  - ReadPackedGuid128() / WritePackedGuid128() — variable-length GUID
  - ReadString(len) / WriteString()       — length-prefixed strings
  - Read<uint32>() etc.                   — standard typed reads
  - FlushBits()                           — byte-align after bit ops
  - Optional fields gated by bit flags
  - Dynamic arrays with ReadBits(n) size prefix
"""

import json
import re
import textwrap

import ida_funcs
import ida_name
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Read / Write call classification
# ---------------------------------------------------------------------------

# Template typed reads:  Read<uint32>(), Read<float>(), Read<int16>(), etc.
_TEMPLATE_READ_RE = re.compile(
    r'Read\s*<\s*(u?int(?:8|16|32|64)_t|u?int(?:8|16|32|64)|float|double)\s*>',
    re.IGNORECASE,
)
_TEMPLATE_WRITE_RE = re.compile(
    r'Write\s*<\s*(u?int(?:8|16|32|64)_t|u?int(?:8|16|32|64)|float|double)\s*>',
    re.IGNORECASE,
)

# Named read helpers
_NAMED_READ_RE = re.compile(
    r'(Read(?:UInt8|UInt16|UInt32|UInt64|Int8|Int16|Int32|Int64|Float|Double'
    r'|ObjectGuid|CString))\s*\(',
    re.IGNORECASE,
)

_NAMED_WRITE_RE = re.compile(
    r'(Write(?:UInt8|UInt16|UInt32|UInt64|Int8|Int16|Int32|Int64|Float|Double'
    r'|ObjectGuid|CString))\s*\(',
    re.IGNORECASE,
)

# Bit operations
_READ_BIT_RE = re.compile(r'ReadBit\s*\(\s*\)', re.IGNORECASE)
_WRITE_BIT_RE = re.compile(r'WriteBit\s*\(', re.IGNORECASE)
_READ_BITS_RE = re.compile(
    r'ReadBits\s*\(\s*(?:(\w+)\s*,\s*)?(\d+)\s*\)', re.IGNORECASE
)
_WRITE_BITS_RE = re.compile(
    r'WriteBits\s*\(\s*[^,]+,\s*(\d+)\s*\)', re.IGNORECASE
)

# Packed GUID
_READ_PACKED_GUID_RE = re.compile(
    r'ReadPackedGuid(?:128)?\s*\(', re.IGNORECASE
)
_WRITE_PACKED_GUID_RE = re.compile(
    r'WritePackedGuid(?:128)?\s*\(', re.IGNORECASE
)

# String operations
_READ_STRING_RE = re.compile(
    r'ReadString\s*\(\s*(\w+)\s*\)', re.IGNORECASE
)
_WRITE_STRING_RE = re.compile(
    r'WriteString\s*\(', re.IGNORECASE
)

# FlushBits
_FLUSH_BITS_RE = re.compile(r'FlushBits\s*\(', re.IGNORECASE)
_RESET_BITPOS_RE = re.compile(r'ResetBitPos\s*\(', re.IGNORECASE)

# ByteBuffer stream operator reads:  data >> someVar;
_STREAM_READ_RE = re.compile(
    r'>>\s+(\w+)\s*;', re.IGNORECASE
)
_STREAM_WRITE_RE = re.compile(
    r'<<\s+(\w+)\s*;', re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Type metadata — size in bits
# ---------------------------------------------------------------------------

_TYPE_INFO = {
    "uint8":        {"bit_size": 8,   "byte_size": 1},
    "uint8_t":      {"bit_size": 8,   "byte_size": 1},
    "int8":         {"bit_size": 8,   "byte_size": 1},
    "int8_t":       {"bit_size": 8,   "byte_size": 1},
    "uint16":       {"bit_size": 16,  "byte_size": 2},
    "uint16_t":     {"bit_size": 16,  "byte_size": 2},
    "int16":        {"bit_size": 16,  "byte_size": 2},
    "int16_t":      {"bit_size": 16,  "byte_size": 2},
    "uint32":       {"bit_size": 32,  "byte_size": 4},
    "uint32_t":     {"bit_size": 32,  "byte_size": 4},
    "int32":        {"bit_size": 32,  "byte_size": 4},
    "int32_t":      {"bit_size": 32,  "byte_size": 4},
    "uint64":       {"bit_size": 64,  "byte_size": 8},
    "uint64_t":     {"bit_size": 64,  "byte_size": 8},
    "int64":        {"bit_size": 64,  "byte_size": 8},
    "int64_t":      {"bit_size": 64,  "byte_size": 8},
    "float":        {"bit_size": 32,  "byte_size": 4},
    "double":       {"bit_size": 64,  "byte_size": 8},
    "bit":          {"bit_size": 1,   "byte_size": 0},
    "packed_guid":  {"bit_size": 128, "byte_size": 16},
    "string":       {"bit_size": 0,   "byte_size": 0},
    "ObjectGuid":   {"bit_size": 128, "byte_size": 16},
}

# Map named Read/Write helpers to canonical type names
_NAMED_CALL_TO_TYPE = {
    "readuint8":       "uint8",
    "readuint16":      "uint16",
    "readuint32":      "uint32",
    "readuint64":      "uint64",
    "readint8":        "int8",
    "readint16":       "int16",
    "readint32":       "int32",
    "readint64":       "int64",
    "readfloat":       "float",
    "readdouble":      "double",
    "readobjectguid":  "ObjectGuid",
    "readcstring":     "string",
    "writeuint8":      "uint8",
    "writeuint16":     "uint16",
    "writeuint32":     "uint32",
    "writeuint64":     "uint64",
    "writeint8":       "int8",
    "writeint16":      "int16",
    "writeint32":       "int32",
    "writeint64":      "int64",
    "writefloat":      "float",
    "writedouble":     "double",
    "writeobjectguid": "ObjectGuid",
    "writecstring":    "string",
}

# Normalize C type aliases produced by Hex-Rays
_TYPE_NORMALIZE = {
    "uint8_t":  "uint8",
    "uint16_t": "uint16",
    "uint32_t": "uint32",
    "uint64_t": "uint64",
    "int8_t":   "int8",
    "int16_t":  "int16",
    "int32_t":  "int32",
    "int64_t":  "int64",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_type(raw_type):
    """Normalize a raw type string to a canonical name."""
    t = raw_type.strip().lower()
    return _TYPE_NORMALIZE.get(t, raw_type.strip().lower())


def _bit_size_for(field_type, explicit_bits=None):
    """Return the bit size for a field type, or explicit_bits for 'bits'."""
    if field_type == "bits" and explicit_bits is not None:
        return int(explicit_bits)
    info = _TYPE_INFO.get(field_type)
    if info:
        return info["bit_size"]
    return 0


def _byte_offset_from_bits(total_bits):
    """Approximate byte offset from a cumulative bit count."""
    return total_bits // 8


def _make_field(index, name, field_type, bit_size, cumulative_bits,
                is_optional=False, condition="", is_array=False,
                array_size_field="", raw_call=""):
    """Create a field descriptor dict."""
    return {
        "index": index,
        "name": name,
        "type": field_type,
        "bit_size": bit_size,
        "byte_offset": _byte_offset_from_bits(cumulative_bits),
        "is_optional": is_optional,
        "condition": condition,
        "is_array": is_array,
        "array_size_field": array_size_field,
        "raw_call": raw_call.strip(),
    }


# ---------------------------------------------------------------------------
# Condition / scope tracking
# ---------------------------------------------------------------------------

_IF_CONDITION_RE = re.compile(
    r'^\s*if\s*\(\s*(.+?)\s*\)\s*$'
)
_IF_BRACE_RE = re.compile(
    r'^\s*if\s*\(\s*(.+?)\s*\)\s*\{'
)
_FOR_LOOP_RE = re.compile(
    r'for\s*\(\s*\w[\w\s]*=\s*0\s*;'
    r'\s*\w+\s*<\s*(\w+)\s*;'
    r'\s*\+\+\w+\s*\)',
    re.IGNORECASE,
)
_WHILE_LOOP_RE = re.compile(
    r'while\s*\(\s*\w+\s*<\s*(\w+)\s*\)',
    re.IGNORECASE,
)


class _ScopeTracker:
    """Tracks nested if/for/while scopes to determine optional and array context."""

    def __init__(self):
        # Stack of (scope_type, detail) where scope_type is 'if' | 'for' | 'while'
        self._stack = []
        # Map from brace depth where scope was opened to (scope_type, detail)
        self._depth_map = {}
        self._brace_depth = 0

    def process_line(self, line):
        """Update scope tracking for a line of pseudocode."""
        stripped = line.strip()

        # Count braces to track nesting
        opens = stripped.count("{")
        closes = stripped.count("}")

        # Check for new scope openers BEFORE updating depth
        if_match = _IF_BRACE_RE.search(stripped) or _IF_CONDITION_RE.search(stripped)
        for_match = _FOR_LOOP_RE.search(stripped)
        while_match = _WHILE_LOOP_RE.search(stripped)

        if for_match and "{" in stripped:
            scope_info = ("for", for_match.group(1))
            self._depth_map[self._brace_depth + 1] = scope_info
            self._stack.append(scope_info)
        elif while_match and "{" in stripped:
            scope_info = ("while", while_match.group(1))
            self._depth_map[self._brace_depth + 1] = scope_info
            self._stack.append(scope_info)
        elif if_match and "{" in stripped:
            cond = if_match.group(1)
            scope_info = ("if", cond)
            self._depth_map[self._brace_depth + 1] = scope_info
            self._stack.append(scope_info)

        # Update depth
        self._brace_depth += opens

        # Pop scopes for closing braces
        for _ in range(closes):
            self._brace_depth -= 1
            if self._brace_depth + 1 in self._depth_map:
                popped = self._depth_map.pop(self._brace_depth + 1)
                if self._stack and self._stack[-1] == popped:
                    self._stack.pop()

    @property
    def is_optional(self):
        """True if we are inside an 'if' scope (field is conditional)."""
        return any(s[0] == "if" for s in self._stack)

    @property
    def condition(self):
        """Return the innermost 'if' condition expression, or ''."""
        for s in reversed(self._stack):
            if s[0] == "if":
                return s[1]
        return ""

    @property
    def is_array(self):
        """True if we are inside a for/while loop."""
        return any(s[0] in ("for", "while") for s in self._stack)

    @property
    def array_size_field(self):
        """Return the loop bound variable, or ''."""
        for s in reversed(self._stack):
            if s[0] in ("for", "while"):
                return s[1]
        return ""


# ---------------------------------------------------------------------------
# Core tracing
# ---------------------------------------------------------------------------

def _parse_read_call(line):
    """Parse a single line of pseudocode for a Read/Write serialization call.

    Returns a dict with keys:
        type, bit_size, name_hint, is_bit_op, raw_call
    or None if the line contains no recognized serialization call.
    """
    stripped = line.strip()

    # 1. ReadBit()
    m = _READ_BIT_RE.search(stripped)
    if m:
        # Try to find assignment target: var = ReadBit()
        assign = re.match(r'\s*(\w+)\s*=.*ReadBit', stripped)
        name_hint = assign.group(1) if assign else ""
        return {
            "type": "bit",
            "bit_size": 1,
            "name_hint": name_hint,
            "is_bit_op": True,
            "raw_call": stripped,
        }

    # 2. WriteBit()
    m = _WRITE_BIT_RE.search(stripped)
    if m:
        arg = re.search(r'WriteBit\s*\(\s*(\w+)', stripped)
        name_hint = arg.group(1) if arg else ""
        return {
            "type": "bit",
            "bit_size": 1,
            "name_hint": name_hint,
            "is_bit_op": True,
            "raw_call": stripped,
        }

    # 3. ReadBits(var, N) or ReadBits(N)
    m = _READ_BITS_RE.search(stripped)
    if m:
        name_hint = m.group(1) or ""
        bit_count = int(m.group(2))
        # Try to find assignment target
        if not name_hint:
            assign = re.match(r'\s*(\w+)\s*=.*ReadBits', stripped)
            name_hint = assign.group(1) if assign else ""
        return {
            "type": "bits",
            "bit_size": bit_count,
            "name_hint": name_hint,
            "is_bit_op": True,
            "raw_call": stripped,
        }

    # 4. WriteBits(value, N)
    m = _WRITE_BITS_RE.search(stripped)
    if m:
        bit_count = int(m.group(1))
        arg = re.search(r'WriteBits\s*\(\s*(\w+)', stripped)
        name_hint = arg.group(1) if arg else ""
        return {
            "type": "bits",
            "bit_size": bit_count,
            "name_hint": name_hint,
            "is_bit_op": True,
            "raw_call": stripped,
        }

    # 5. ReadPackedGuid128 / WritePackedGuid128
    m = _READ_PACKED_GUID_RE.search(stripped)
    if not m:
        m = _WRITE_PACKED_GUID_RE.search(stripped)
    if m:
        arg = re.search(r'Packed(?:Guid|Guid128)\s*\(\s*(\w+)', stripped)
        name_hint = arg.group(1) if arg else ""
        return {
            "type": "packed_guid",
            "bit_size": 128,
            "name_hint": name_hint,
            "is_bit_op": False,
            "raw_call": stripped,
        }

    # 6. ReadString(len) / WriteString()
    m = _READ_STRING_RE.search(stripped)
    if m:
        len_var = m.group(1)
        assign = re.match(r'\s*(\w+)\s*=.*ReadString', stripped)
        name_hint = assign.group(1) if assign else ""
        return {
            "type": "string",
            "bit_size": 0,
            "name_hint": name_hint,
            "is_bit_op": False,
            "raw_call": stripped,
            "string_len_field": len_var,
        }
    m = _WRITE_STRING_RE.search(stripped)
    if m:
        arg = re.search(r'WriteString\s*\(\s*(\w+)', stripped)
        name_hint = arg.group(1) if arg else ""
        return {
            "type": "string",
            "bit_size": 0,
            "name_hint": name_hint,
            "is_bit_op": False,
            "raw_call": stripped,
        }

    # 7. FlushBits / ResetBitPos
    if _FLUSH_BITS_RE.search(stripped) or _RESET_BITPOS_RE.search(stripped):
        return {
            "type": "flush",
            "bit_size": 0,
            "name_hint": "",
            "is_bit_op": True,
            "raw_call": stripped,
        }

    # 8. Template Read<type>() / Write<type>()
    m = _TEMPLATE_READ_RE.search(stripped)
    if not m:
        m = _TEMPLATE_WRITE_RE.search(stripped)
    if m:
        raw_t = m.group(1)
        canon = _normalize_type(raw_t)
        bit_sz = _bit_size_for(canon)
        # Try to find assignment or struct offset for name
        assign = re.match(r'\s*(\w+)\s*=.*Read<', stripped)
        name_hint = assign.group(1) if assign else ""
        if not name_hint:
            # Check for struct member write: *(type*)(ptr + offset) = Read<>
            member = re.search(r'\*\s*\(\s*\w+\s*\*\s*\)\s*\(\s*\w+\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)', stripped)
            if member:
                name_hint = f"field_at_{member.group(1)}"
        return {
            "type": canon,
            "bit_size": bit_sz,
            "name_hint": name_hint,
            "is_bit_op": False,
            "raw_call": stripped,
        }

    # 9. Named read/write helpers: ReadUInt32(...), WriteFloat(...), etc.
    m = _NAMED_READ_RE.search(stripped)
    if not m:
        m = _NAMED_WRITE_RE.search(stripped)
    if m:
        func_name = m.group(1).lower()
        canon = _NAMED_CALL_TO_TYPE.get(func_name)
        if canon:
            bit_sz = _bit_size_for(canon)
            assign = re.match(r'\s*(\w+)\s*=', stripped)
            name_hint = assign.group(1) if assign else ""
            return {
                "type": canon,
                "bit_size": bit_sz,
                "name_hint": name_hint,
                "is_bit_op": False,
                "raw_call": stripped,
            }

    # 10. Stream operator reads/writes:  data >> var;  data << var;
    m = _STREAM_READ_RE.search(stripped)
    if m:
        name_hint = m.group(1)
        return {
            "type": "uint32",  # default; actual type unknown from stream op
            "bit_size": 32,
            "name_hint": name_hint,
            "is_bit_op": False,
            "raw_call": stripped,
            "type_uncertain": True,
        }
    m = _STREAM_WRITE_RE.search(stripped)
    if m:
        name_hint = m.group(1)
        return {
            "type": "uint32",
            "bit_size": 32,
            "name_hint": name_hint,
            "is_bit_op": False,
            "raw_call": stripped,
            "type_uncertain": True,
        }

    return None


def _trace_serialization(pseudocode, handler_ea):
    """Trace through pseudocode line-by-line to recover ordered field list.

    Tracks:
      - Cumulative bit position
      - Conditional (optional) scope from if-statements
      - Array scope from for/while loops
      - Bit vs byte alignment via FlushBits

    Returns a list of field descriptor dicts.
    """
    if not pseudocode:
        return []

    lines = pseudocode.split("\n")
    fields = []
    cumulative_bits = 0
    field_index = 0
    scope = _ScopeTracker()
    in_bit_region = False

    # Track which variable names were read as bit-count fields
    # so we can link array sizes and string lengths
    bit_count_vars = {}  # var_name -> field_index
    bit_flag_vars = {}   # var_name -> field_index

    for line in lines:
        # Update scope tracking
        scope.process_line(line)

        # Parse this line for a serialization call
        parsed = _parse_read_call(line)
        if parsed is None:
            continue

        field_type = parsed["type"]

        # FlushBits just aligns — emit alignment marker but don't add a field
        if field_type == "flush":
            if in_bit_region and (cumulative_bits % 8) != 0:
                # Pad to next byte boundary
                pad = 8 - (cumulative_bits % 8)
                cumulative_bits += pad
            in_bit_region = False
            continue

        bit_size = parsed["bit_size"]
        name_hint = parsed["name_hint"]
        is_bit_op = parsed.get("is_bit_op", False)

        # Track bit region state
        if is_bit_op:
            in_bit_region = True
        elif in_bit_region:
            # Transitioning from bit region to byte-aligned read without
            # explicit FlushBits — auto-align
            if (cumulative_bits % 8) != 0:
                pad = 8 - (cumulative_bits % 8)
                cumulative_bits += pad
            in_bit_region = False

        # Determine if this field is optional or part of an array
        is_optional = scope.is_optional
        condition = scope.condition
        is_array = scope.is_array
        array_size_field = scope.array_size_field

        # For array elements inside a loop, the cumulative offset is approximate
        # (represents the first element's position)

        # Generate name
        if name_hint and name_hint not in ("v", "a1", "a2", "a3", "result"):
            name = name_hint
        else:
            name = f"field_{field_index}"

        # Build field descriptor
        field = _make_field(
            index=field_index,
            name=name,
            field_type=field_type,
            bit_size=bit_size,
            cumulative_bits=cumulative_bits,
            is_optional=is_optional,
            condition=condition,
            is_array=is_array,
            array_size_field=array_size_field,
            raw_call=parsed.get("raw_call", ""),
        )

        # Carry string_len_field forward if present
        if "string_len_field" in parsed:
            field["string_len_field"] = parsed["string_len_field"]
        if parsed.get("type_uncertain"):
            field["type_uncertain"] = True

        fields.append(field)

        # Track bit-count and flag variables for cross-referencing
        if field_type == "bit":
            if name_hint:
                bit_flag_vars[name_hint] = field_index
        elif field_type == "bits":
            if name_hint:
                bit_count_vars[name_hint] = field_index

        # Advance cumulative position
        if bit_size > 0:
            cumulative_bits += bit_size
        elif field_type == "string":
            # Strings are variable-length; advance by 0 (unknown)
            pass
        elif field_type == "packed_guid":
            # PackedGuid128 is variable but max 18 bytes;
            # use 128 bits (16 bytes) as estimate
            cumulative_bits += 128

        field_index += 1

    # Post-pass: link array size fields and optional conditions to earlier fields
    _link_cross_references(fields, bit_count_vars, bit_flag_vars)

    return fields


def _link_cross_references(fields, bit_count_vars, bit_flag_vars):
    """Post-pass to resolve cross-references between fields.

    - If a field's array_size_field matches a bits/uint32 field, record the link.
    - If a field's condition mentions a bit flag variable, record the link.
    """
    name_to_idx = {}
    for f in fields:
        name_to_idx[f["name"]] = f["index"]

    for f in fields:
        # Link array size to the earlier field that holds the count
        if f["is_array"] and f["array_size_field"]:
            size_var = f["array_size_field"]
            if size_var in bit_count_vars:
                f["array_size_field_index"] = bit_count_vars[size_var]
            elif size_var in name_to_idx:
                f["array_size_field_index"] = name_to_idx[size_var]

        # Link optional condition to the bit flag field
        if f["is_optional"] and f["condition"]:
            for var_name, flag_idx in bit_flag_vars.items():
                if var_name in f["condition"]:
                    f["condition_field_index"] = flag_idx
                    break


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_wire_formats(session, system_filter=None):
    """Main entry point: recover wire formats for all opcodes with handlers.

    Args:
        session: PluginSession with .db access
        system_filter: Optional string filter (e.g. 'housing') to limit
                       analysis to opcodes whose tc_name contains this string

    Returns:
        Number of wire formats successfully recovered.
    """
    db = session.db

    query = "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL"
    params = ()
    if system_filter:
        query += " AND (tc_name LIKE ? OR jam_type LIKE ?)"
        params = (f"%{system_filter}%", f"%{system_filter}%")

    handlers = db.fetchall(query, params)
    if not handlers:
        msg_warn("No opcode handlers found in database")
        return 0

    msg_info(f"Recovering wire formats for {len(handlers)} handlers"
             f"{(' (filter: ' + system_filter + ')') if system_filter else ''}...")

    all_formats = {}
    recovered = 0
    failed = 0
    skipped = 0

    for i, handler in enumerate(handlers):
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"opcode_0x{handler['internal_index']:X}"
        direction = handler["direction"]

        # Decompile the handler (pass db so cached pseudocode is used)
        pseudocode = get_decompiled_text(ea, db=db)
        if not pseudocode:
            skipped += 1
            continue

        # Trace serialization
        fields = _trace_serialization(pseudocode, ea)
        if not fields:
            skipped += 1
            continue

        # Compute summary stats
        total_bits = 0
        bit_fields = 0
        byte_fields = 0
        optional_count = 0
        array_count = 0
        for f in fields:
            total_bits += f["bit_size"]
            if f["type"] in ("bit", "bits"):
                bit_fields += 1
            else:
                byte_fields += 1
            if f["is_optional"]:
                optional_count += 1
            if f["is_array"]:
                array_count += 1

        fmt = {
            "opcode_name": tc_name,
            "direction": direction,
            "handler_ea": ea,
            "handler_ea_hex": ea_str(ea),
            "field_count": len(fields),
            "total_bits": total_bits,
            "estimated_min_bytes": total_bits // 8,
            "bit_fields": bit_fields,
            "byte_fields": byte_fields,
            "optional_fields": optional_count,
            "array_fields": array_count,
            "fields": fields,
        }

        all_formats[tc_name] = fmt
        recovered += 1

        # Also update the jam_types table if this opcode has a linked JAM type
        jam_type = handler.get("jam_type")
        if jam_type:
            db.upsert_jam_type(
                name=jam_type,
                field_count=len(fields),
                fields_json=json.dumps(fields),
                wire_size=total_bits // 8,
                status="wire_format_recovered",
            )

        # Progress
        if (i + 1) % 100 == 0:
            db.commit()
            msg_info(f"  Progress: {i + 1}/{len(handlers)} "
                     f"({recovered} recovered, {skipped} skipped)")

    # Store all formats in kv_store
    db.kv_set("wire_formats", all_formats)
    db.commit()

    msg_info(f"Wire format recovery complete: {recovered} recovered, "
             f"{skipped} skipped, {failed} failed "
             f"(out of {len(handlers)} handlers)")
    return recovered


# ---------------------------------------------------------------------------
# Single opcode retrieval
# ---------------------------------------------------------------------------

def get_wire_format(session, opcode_name):
    """Retrieve the wire format for a single opcode by name.

    Returns the format dict, or None if not found.
    """
    db = session.db
    all_formats = db.kv_get("wire_formats")
    if not all_formats:
        msg_warn("No wire formats in database. Run analyze_wire_formats first.")
        return None

    fmt = all_formats.get(opcode_name)
    if not fmt:
        # Try case-insensitive lookup
        for key, val in all_formats.items():
            if key.lower() == opcode_name.lower():
                return val
        msg_warn(f"Wire format for '{opcode_name}' not found")
        return None

    return fmt


# ---------------------------------------------------------------------------
# C++ code generation
# ---------------------------------------------------------------------------

# Type mapping for C++ struct members
_TYPE_TO_CPP = {
    "uint8":        "uint8",
    "uint16":       "uint16",
    "uint32":       "uint32",
    "uint64":       "uint64",
    "int8":         "int8",
    "int16":        "int16",
    "int32":        "int32",
    "int64":        "int64",
    "float":        "float",
    "double":       "double",
    "bit":          "bool",
    "bits":         "uint32",
    "packed_guid":  "ObjectGuid",
    "ObjectGuid":   "ObjectGuid",
    "string":       "std::string",
}

_TYPE_TO_CPP_DEFAULT = {
    "uint8":        " = 0",
    "uint16":       " = 0",
    "uint32":       " = 0",
    "uint64":       " = 0",
    "int8":         " = 0",
    "int16":        " = 0",
    "int32":        " = 0",
    "int64":        " = 0",
    "float":        " = 0.0f",
    "double":       " = 0.0",
    "bit":          " = false",
    "bits":         " = 0",
    "packed_guid":  "",
    "ObjectGuid":   "",
    "string":       "",
}


def _opcode_name_to_class(opcode_name):
    """Convert CMSG_HOUSE_DECOR_PLACE -> HouseDecorPlace."""
    # Strip direction prefix
    for prefix in ("CMSG_", "SMSG_", "MSG_"):
        if opcode_name.upper().startswith(prefix):
            opcode_name = opcode_name[len(prefix):]
            break
    # UPPER_SNAKE_CASE -> CamelCase
    return "".join(part.capitalize() for part in opcode_name.split("_"))


def _field_to_cpp_name(field):
    """Generate a C++ member name from a field descriptor."""
    name = field["name"]
    # Clean up common decompiler artifacts
    if name.startswith("field_at_"):
        return name.replace("field_at_", "Field")
    if name.startswith("field_"):
        return f"Field{name[6:]}"
    # Capitalize first letter
    if name and name[0].islower():
        return name[0].upper() + name[1:]
    return name


def export_wire_format_cpp(session, opcode_name):
    """Generate C++ packet struct with exact Read/Write methods
    matching the binary's serialization order.

    Returns a string containing the complete C++ code:
    - Struct definition with all fields
    - Read() or Write() method implementation
    """
    fmt = get_wire_format(session, opcode_name)
    if not fmt:
        return f"// Wire format for '{opcode_name}' not found\n"

    fields = fmt.get("fields", [])
    direction = fmt.get("direction", "CMSG")
    class_name = _opcode_name_to_class(opcode_name)

    is_client = direction == "CMSG"
    base_class = "ClientPacket" if is_client else "ServerPacket"

    lines = []

    # ── Header comment ──
    lines.append(f"// Auto-generated from binary wire format recovery")
    lines.append(f"// Opcode: {opcode_name}")
    lines.append(f"// Direction: {direction}")
    lines.append(f"// Handler: {fmt.get('handler_ea_hex', 'unknown')}")
    lines.append(f"// Fields: {len(fields)}, "
                 f"Estimated min size: {fmt.get('estimated_min_bytes', '?')} bytes")
    lines.append(f"")

    # ── Struct definition ──
    lines.append(f"class {class_name} final : public {base_class}")
    lines.append(f"{{")
    lines.append(f"public:")

    if is_client:
        lines.append(f"    {class_name}(WorldPacket&& packet) : "
                     f"{base_class}({opcode_name}, std::move(packet)) {{ }}")
        lines.append(f"")
        lines.append(f"    void Read() override;")
    else:
        lines.append(f"    {class_name}() : {base_class}({opcode_name}) {{ }}")
        lines.append(f"")
        lines.append(f"    WorldPacket const* Write() override;")

    # ── Member declarations ──
    if fields:
        lines.append(f"")

        # Separate bit flags from regular fields for cleaner output
        for field in fields:
            cpp_type = _TYPE_TO_CPP.get(field["type"], "uint32")
            cpp_name = _field_to_cpp_name(field)
            default = _TYPE_TO_CPP_DEFAULT.get(field["type"], " = 0")

            # Array fields get a vector type
            if field["is_array"] and field["type"] != "bit":
                lines.append(f"    std::vector<{cpp_type}> {cpp_name};")
            else:
                lines.append(f"    {cpp_type} {cpp_name}{default};")

    lines.append(f"}};")
    lines.append(f"")

    # ── Read() / Write() method ──
    if is_client:
        lines.extend(_generate_read_method(class_name, fields))
    else:
        lines.extend(_generate_write_method(class_name, opcode_name, fields))

    return "\n".join(lines) + "\n"


def _generate_read_method(class_name, fields):
    """Generate the Read() method body preserving exact serialization order."""
    lines = []
    lines.append(f"void {class_name}::Read()")
    lines.append(f"{{")

    in_bit_region = False
    indent = "    "
    current_indent = indent
    scope_stack = []  # track open scopes for proper indentation

    for i, field in enumerate(fields):
        ftype = field["type"]
        cpp_name = _field_to_cpp_name(field)

        # Handle scope changes for optional fields
        if field["is_optional"] and field["condition"]:
            # Check if this is a new condition scope
            cond = field["condition"]
            if not scope_stack or scope_stack[-1] != cond:
                # Find the bit flag field referenced in the condition
                cond_cpp = _condition_to_cpp(cond, fields)
                lines.append(f"{current_indent}if ({cond_cpp})")
                lines.append(f"{current_indent}{{")
                scope_stack.append(cond)
                current_indent = indent * (len(scope_stack) + 1)

        # Handle array wrapper
        if field["is_array"] and field["array_size_field"]:
            size_field = field["array_size_field"]
            size_cpp = _field_to_cpp_name_by_var(size_field, fields)
            lines.append(f"{current_indent}{cpp_name}.resize({size_cpp});")
            lines.append(f"{current_indent}for (uint32 i = 0; i < {size_cpp}; ++i)")
            lines.append(f"{current_indent}{{")
            array_indent = current_indent + indent
        else:
            array_indent = None

        use_indent = array_indent if array_indent else current_indent
        element_ref = f"{cpp_name}[i]" if array_indent else cpp_name

        # Emit the actual read call
        if ftype == "bit":
            lines.append(f"{use_indent}{element_ref} = _worldPacket.ReadBit();")
            in_bit_region = True
        elif ftype == "bits":
            lines.append(f"{use_indent}{element_ref} = _worldPacket.ReadBits({field['bit_size']});")
            in_bit_region = True
        elif ftype == "packed_guid":
            if in_bit_region:
                lines.append(f"{use_indent}_worldPacket.ResetBitPos();")
                in_bit_region = False
            lines.append(f"{use_indent}_worldPacket >> {element_ref};")
        elif ftype == "string":
            if in_bit_region:
                lines.append(f"{use_indent}_worldPacket.ResetBitPos();")
                in_bit_region = False
            len_field = field.get("string_len_field", "")
            if len_field:
                len_cpp = _field_to_cpp_name_by_var(len_field, fields)
                lines.append(f"{use_indent}{element_ref} = "
                             f"_worldPacket.ReadString({len_cpp});")
            else:
                lines.append(f"{use_indent}_worldPacket >> {element_ref};")
        else:
            # Standard typed reads (uint8, uint16, uint32, float, etc.)
            if in_bit_region:
                lines.append(f"{use_indent}_worldPacket.ResetBitPos();")
                in_bit_region = False
            lines.append(f"{use_indent}_worldPacket >> {element_ref};")

        # Close array scope
        if array_indent:
            lines.append(f"{current_indent}}}")

        # Close optional scopes when next field has a different condition
        # or is not optional
        next_field = fields[i + 1] if i + 1 < len(fields) else None
        if scope_stack:
            next_cond = (next_field["condition"]
                         if next_field and next_field["is_optional"]
                         else "")
            while scope_stack and scope_stack[-1] != next_cond:
                scope_stack.pop()
                current_indent = indent * (len(scope_stack) + 1)
                lines.append(f"{current_indent}}}")

    # Close any remaining scopes
    while scope_stack:
        scope_stack.pop()
        current_indent = indent * (len(scope_stack) + 1)
        lines.append(f"{current_indent}}}")

    lines.append(f"}}")
    return lines


def _generate_write_method(class_name, opcode_name, fields):
    """Generate the Write() method body preserving exact serialization order."""
    lines = []
    lines.append(f"WorldPacket const* {class_name}::Write()")
    lines.append(f"{{")

    in_bit_region = False
    indent = "    "
    current_indent = indent
    scope_stack = []

    for i, field in enumerate(fields):
        ftype = field["type"]
        cpp_name = _field_to_cpp_name(field)

        # Handle optional scope
        if field["is_optional"] and field["condition"]:
            cond = field["condition"]
            if not scope_stack or scope_stack[-1] != cond:
                cond_cpp = _condition_to_cpp(cond, fields)
                lines.append(f"{current_indent}if ({cond_cpp})")
                lines.append(f"{current_indent}{{")
                scope_stack.append(cond)
                current_indent = indent * (len(scope_stack) + 1)

        # Handle array wrapper
        if field["is_array"] and field["array_size_field"]:
            size_field = field["array_size_field"]
            size_cpp = _field_to_cpp_name_by_var(size_field, fields)
            lines.append(f"{current_indent}for (uint32 i = 0; i < {size_cpp}; ++i)")
            lines.append(f"{current_indent}{{")
            array_indent = current_indent + indent
        else:
            array_indent = None

        use_indent = array_indent if array_indent else current_indent
        element_ref = f"{cpp_name}[i]" if array_indent else cpp_name

        # Emit write call
        if ftype == "bit":
            lines.append(f"{use_indent}_worldPacket.WriteBit({element_ref});")
            in_bit_region = True
        elif ftype == "bits":
            lines.append(f"{use_indent}_worldPacket.WriteBits({element_ref}, "
                         f"{field['bit_size']});")
            in_bit_region = True
        elif ftype == "packed_guid":
            if in_bit_region:
                lines.append(f"{use_indent}_worldPacket.FlushBits();")
                in_bit_region = False
            lines.append(f"{use_indent}_worldPacket << {element_ref};")
        elif ftype == "string":
            if in_bit_region:
                lines.append(f"{use_indent}_worldPacket.FlushBits();")
                in_bit_region = False
            lines.append(f"{use_indent}_worldPacket.WriteString({element_ref});")
        else:
            if in_bit_region:
                lines.append(f"{use_indent}_worldPacket.FlushBits();")
                in_bit_region = False
            lines.append(f"{use_indent}_worldPacket << {element_ref};")

        # Close array scope
        if array_indent:
            lines.append(f"{current_indent}}}")

        # Close optional scopes
        next_field = fields[i + 1] if i + 1 < len(fields) else None
        if scope_stack:
            next_cond = (next_field["condition"]
                         if next_field and next_field["is_optional"]
                         else "")
            while scope_stack and scope_stack[-1] != next_cond:
                scope_stack.pop()
                current_indent = indent * (len(scope_stack) + 1)
                lines.append(f"{current_indent}}}")

    # Flush any trailing bits
    if in_bit_region:
        lines.append(f"{current_indent}_worldPacket.FlushBits();")

    # Close remaining scopes
    while scope_stack:
        scope_stack.pop()
        current_indent = indent * (len(scope_stack) + 1)
        lines.append(f"{current_indent}}}")

    lines.append(f"")
    lines.append(f"{indent}return &_worldPacket;")
    lines.append(f"}}")
    return lines


def _condition_to_cpp(condition_expr, fields):
    """Convert a decompiler condition expression to readable C++.

    Tries to replace variable names with the C++ field names from the format.
    """
    result = condition_expr
    for f in fields:
        if f["name"] in result and f["type"] == "bit":
            cpp_name = _field_to_cpp_name(f)
            result = result.replace(f["name"], cpp_name)
    return result


def _field_to_cpp_name_by_var(var_name, fields):
    """Find the C++ name for a field by its decompiler variable name."""
    for f in fields:
        if f["name"] == var_name:
            return _field_to_cpp_name(f)
    # Fall back to the variable name itself, capitalized
    if var_name and var_name[0].islower():
        return var_name[0].upper() + var_name[1:]
    return var_name


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def export_all_formats_json(session):
    """Export all recovered wire formats as a JSON blob.

    Returns a JSON string, or stores to kv_store and returns the dict.
    """
    db = session.db
    all_formats = db.kv_get("wire_formats")
    if not all_formats:
        msg_warn("No wire formats in database. Run analyze_wire_formats first.")
        return "{}"

    # Build export structure with summary
    export = {
        "meta": {
            "format_count": len(all_formats),
            "total_fields": sum(f.get("field_count", 0)
                                for f in all_formats.values()),
            "cmsg_count": sum(1 for f in all_formats.values()
                              if f.get("direction") == "CMSG"),
            "smsg_count": sum(1 for f in all_formats.values()
                              if f.get("direction") == "SMSG"),
        },
        "formats": all_formats,
    }

    result_json = json.dumps(export, indent=2)

    # Also store the export timestamp
    import time
    db.kv_set("wire_formats_export_time", time.time())
    db.commit()

    msg_info(f"Exported {len(all_formats)} wire formats as JSON "
             f"({len(result_json)} bytes)")
    return result_json
