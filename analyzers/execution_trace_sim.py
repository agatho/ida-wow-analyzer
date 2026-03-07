"""
Lightweight Symbolic Execution Trace Simulator for CMSG Handlers

Parses Hex-Rays decompiled pseudocode into an AST-like structure and
simulates execution with symbolic inputs to produce complete I/O
specifications.  Each handler yields a set of *paths*, where every path
records:

  - Preconditions  (accumulated branch constraints)
  - Inputs         (packet fields read, with symbolic type/constraint info)
  - Effects        (state writes, DB ops, function calls with side effects)
  - Outputs        (SMSG packets constructed and sent)
  - Return value   (concrete or symbolic)

This is NOT a full binary symbolic engine.  It operates entirely on the
text output of Hex-Rays, which makes it fast (~ms per handler) and
portable across IDB versions.

Results are stored in the knowledge DB under key ``execution_traces``.
"""

import json
import re
import time
import collections
import copy

import ida_funcs
import ida_name
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ===================================================================
#  Constants & limits
# ===================================================================

MAX_PATHS_PER_HANDLER = 64
MAX_NESTING_DEPTH = 20
MAX_LOOP_UNROLL = 1          # execute loop body once symbolically
MAX_STMT_COUNT = 4000        # safety limit for very large handlers
_COMPLEXITY_PATH_WEIGHT = 1.0
_COMPLEXITY_DEPTH_WEIGHT = 0.6
_COMPLEXITY_EFFECT_WEIGHT = 0.4


# ===================================================================
#  AST node types
# ===================================================================

class NodeType:
    BLOCK       = "block"
    IF          = "if"
    SWITCH      = "switch"
    CASE        = "case"
    WHILE       = "while"
    FOR         = "for"
    DO_WHILE    = "do_while"
    RETURN      = "return"
    ASSIGN      = "assignment"
    CALL        = "function_call"
    EXPR_STMT   = "expr_stmt"
    BREAK       = "break"
    CONTINUE    = "continue"
    GOTO        = "goto"
    LABEL       = "label"


class ExprType:
    VARIABLE    = "variable"
    CONSTANT    = "constant"
    BINARY_OP   = "binary_op"
    UNARY_OP    = "unary_op"
    FIELD       = "field_access"
    ARRAY_IDX   = "array_index"
    CALL        = "call"
    CAST        = "cast"
    DEREF       = "deref"
    ADDR_OF     = "addr_of"
    TERNARY     = "ternary"
    STRING_LIT  = "string_literal"
    RAW         = "raw"          # unparsed sub-expression


# ===================================================================
#  Symbolic value model
# ===================================================================

class SymKind:
    CONCRETE  = "concrete"
    SYMBOLIC  = "symbolic"
    CONSTRAINED = "constrained"   # symbolic + range/equality constraints
    TOP       = "top"             # fully unknown


class SymbolicValue:
    """Lightweight symbolic value representation."""

    __slots__ = ("kind", "name", "concrete", "type_hint", "constraints",
                 "origin", "origin_line")

    def __init__(self, kind=SymKind.TOP, name=None, concrete=None,
                 type_hint=None, constraints=None, origin=None,
                 origin_line=-1):
        self.kind = kind
        self.name = name
        self.concrete = concrete
        self.type_hint = type_hint
        self.constraints = constraints or []
        self.origin = origin            # "packet_read", "param", "local", etc.
        self.origin_line = origin_line

    def copy(self):
        return SymbolicValue(
            kind=self.kind, name=self.name, concrete=self.concrete,
            type_hint=self.type_hint,
            constraints=list(self.constraints),
            origin=self.origin, origin_line=self.origin_line,
        )

    def add_constraint(self, constraint_str):
        c = self.copy()
        c.kind = SymKind.CONSTRAINED
        c.constraints.append(constraint_str)
        return c

    def to_dict(self):
        d = {"kind": self.kind}
        if self.name:
            d["name"] = self.name
        if self.concrete is not None:
            d["concrete"] = self.concrete
        if self.type_hint:
            d["type_hint"] = self.type_hint
        if self.constraints:
            d["constraints"] = self.constraints
        if self.origin:
            d["origin"] = self.origin
        return d

    def __repr__(self):
        if self.kind == SymKind.CONCRETE:
            return f"Concrete({self.concrete})"
        if self.kind == SymKind.SYMBOLIC:
            return f"Sym({self.name})"
        if self.kind == SymKind.CONSTRAINED:
            return f"Sym({self.name}|{','.join(self.constraints)})"
        return "Top"


# ===================================================================
#  Symbolic execution state
# ===================================================================

class SymState:
    """Mutable symbolic execution state for one path."""

    __slots__ = ("variables", "memory", "packet_pos", "return_value",
                 "side_effects", "path_conditions", "halted",
                 "halt_reason")

    def __init__(self):
        self.variables = {}          # name -> SymbolicValue
        self.memory = {}             # (base, offset) -> SymbolicValue
        self.packet_pos = 0          # how many bytes read from packet so far
        self.return_value = None     # SymbolicValue or None
        self.side_effects = []       # list of effect dicts
        self.path_conditions = []    # list of condition strings
        self.halted = False
        self.halt_reason = None

    def fork(self):
        """Create an independent copy of this state."""
        s = SymState()
        s.variables = {k: v.copy() for k, v in self.variables.items()}
        s.memory = {k: v.copy() for k, v in self.memory.items()}
        s.packet_pos = self.packet_pos
        s.return_value = self.return_value
        s.side_effects = list(self.side_effects)
        s.path_conditions = list(self.path_conditions)
        s.halted = self.halted
        s.halt_reason = self.halt_reason
        return s

    def set_var(self, name, sym_val):
        self.variables[name] = sym_val

    def get_var(self, name):
        return self.variables.get(name)

    def set_mem(self, base, offset, sym_val):
        self.memory[(base, offset)] = sym_val

    def get_mem(self, base, offset):
        return self.memory.get((base, offset))

    def add_effect(self, effect_type, **kwargs):
        eff = {"type": effect_type}
        eff.update(kwargs)
        self.side_effects.append(eff)

    def add_condition(self, cond_str):
        self.path_conditions.append(cond_str)


# ===================================================================
#  Regex-based pseudocode parser
# ===================================================================

# --- Statement-level patterns ---

_RE_FUNC_DECL = re.compile(
    r'^(?:(?:__int64|int|void|bool|unsigned|char|short|long|float|double|'
    r'__int\d+|_BYTE|_WORD|_DWORD|_QWORD|signed)\s*\*?\s+)*'
    r'(?:__fastcall\s+|__cdecl\s+)?'
    r'(\w+)\s*\(([^)]*)\)\s*$'
)

_RE_IF = re.compile(
    r'^if\s*\(\s*(.+?)\s*\)\s*$'
)

_RE_IF_SINGLE = re.compile(
    r'^if\s*\(\s*(.+?)\s*\)\s+(.+;)\s*$'
)

_RE_ELSE_IF = re.compile(
    r'^else\s+if\s*\(\s*(.+?)\s*\)\s*$'
)

_RE_ELSE = re.compile(
    r'^else\s*$'
)

_RE_SWITCH = re.compile(
    r'^switch\s*\(\s*(.+?)\s*\)\s*$'
)

_RE_CASE = re.compile(
    r'^case\s+(0x[0-9A-Fa-f]+|\-?\d+|[A-Z_]\w*)\s*:\s*(.*)$'
)

_RE_DEFAULT = re.compile(
    r'^default\s*:\s*(.*)$'
)

_RE_RETURN = re.compile(
    r'^return\s*(.*?)\s*;\s*$'
)

_RE_WHILE = re.compile(
    r'^while\s*\(\s*(.+?)\s*\)\s*$'
)

_RE_FOR = re.compile(
    r'^for\s*\(\s*(.*?)\s*;\s*(.*?)\s*;\s*(.*?)\s*\)\s*$'
)

_RE_DO = re.compile(
    r'^do\s*$'
)

_RE_DO_WHILE = re.compile(
    r'^while\s*\(\s*(.+?)\s*\)\s*;\s*$'
)

_RE_BREAK = re.compile(r'^break\s*;\s*$')
_RE_CONTINUE = re.compile(r'^continue\s*;\s*$')

_RE_GOTO = re.compile(r'^goto\s+(\w+)\s*;\s*$')
_RE_LABEL = re.compile(r'^(\w+)\s*:\s*$')

_RE_ASSIGN = re.compile(
    r'^(\*?\s*[\w\.\[\]\-\>]+(?:\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+))?)\s*'
    r'([+\-\*/%&\|\^]?=)\s*(.+?)\s*;\s*$'
)

_RE_FUNC_CALL_STMT = re.compile(
    r'^([\w:]+)\s*\((.*)?\)\s*;\s*$'
)

_RE_OPEN_BRACE = re.compile(r'^\{\s*$')
_RE_CLOSE_BRACE = re.compile(r'^\}\s*$')

# --- Expression-level patterns ---

_RE_READ_TEMPLATE = re.compile(
    r'Read\s*<\s*(\w+)\s*>\s*\('
)

_RE_READ_HELPER = re.compile(
    r'Read(Float|Double|UInt8|UInt16|UInt32|UInt64|Int8|Int16|Int32|Int64'
    r'|Bit|String|CString|PackedGuid128)\s*\('
)

_RE_READ_BITS = re.compile(
    r'ReadBits\s*\(\s*(\d+)\s*\)'
)

_RE_STREAM_EXTRACT = re.compile(
    r'operator>>\s*\([^,]+,\s*&?\s*(\w+)\s*\)'
    r'|>>\s*\(\s*\w+\s*,\s*[&*]?\s*(\w+)\s*\)'
    r'|>>\s*(\w+)'
)

_RE_SEND_PACKET = re.compile(
    r'(\w*[Ss]end\w*[Pp]acket\w*)\s*\(\s*([^)]*)\)'
)

_RE_SMSG_NAME = re.compile(r'(SMSG_\w+)')

_RE_DB_CALL = re.compile(
    r'\b(Execute|PExecute|Query|PQuery|PrepareStatement|'
    r'SetData|SaveToDB|DeleteFromDB|InsertIntoDB|'
    r'DirectExecute|AsyncQuery|CommitTransaction)\b',
    re.IGNORECASE
)

_RE_STATE_WRITE = re.compile(
    r'\*\s*\(\s*(\w+)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*='
)

_RE_MEMBER_WRITE = re.compile(
    r'(\w+)\s*->\s*(\w+)\s*\(\s*(.*?)\s*\)\s*;'
)

_RE_SET_CALL = re.compile(
    r'(\w+)\s*->\s*(Set\w+)\s*\(\s*(.*?)\s*\)'
)

_RE_FIELD_ACCESS = re.compile(
    r'(\w+)\s*->\s*(\w+)'
)

_RE_DEREF_OFFSET = re.compile(
    r'\*\s*\(\s*(\w+)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
)

_RE_CAST = re.compile(
    r'\(\s*(\w+\s*\*?)\s*\)\s*(\w+)'
)

_RE_CONSTANT = re.compile(
    r'^(0x[0-9A-Fa-f]+|\-?\d+(?:\.\d+)?)[uUlLfF]*$'
)

_RE_STRING_LIT = re.compile(r'^"(.*)"$')

_RE_TERNARY = re.compile(
    r'(.+?)\s*\?\s*(.+?)\s*:\s*(.+)'
)

# Known side-effect function categories
_SIDE_EFFECT_FUNCTIONS = {
    "send_packet": re.compile(
        r'^(Send\w*Packet|SendPacket|SendDirectMessage|'
        r'SendMessageToSet|BroadcastPacket)', re.IGNORECASE
    ),
    "db_operation": re.compile(
        r'^(Execute|PExecute|Query|PQuery|DirectExecute|AsyncQuery|'
        r'SaveToDB|DeleteFromDB|CommitTransaction)', re.IGNORECASE
    ),
    "state_write": re.compile(
        r'^(Set\w+|Update\w+|Remove\w+|Add\w+|Clear\w+|Reset\w+|'
        r'Modify\w+|Apply\w+|Toggle\w+)', re.IGNORECASE
    ),
    "teleport": re.compile(
        r'^(TeleportTo|NearTeleportTo|Relocate|SendNewWorld)',
        re.IGNORECASE
    ),
    "object_mgmt": re.compile(
        r'^(Create\w+|Destroy\w+|Spawn\w+|Despawn\w+|SummonCreature|'
        r'SummonGameObject)', re.IGNORECASE
    ),
    "combat": re.compile(
        r'^(CastSpell|CastCustomSpell|DealDamage|Kill|AttackerStateUpdate|'
        r'CalcDamage)', re.IGNORECASE
    ),
    "event": re.compile(
        r'^(TriggerEvent|FireEvent|Emit|Signal|Notify\w+)', re.IGNORECASE
    ),
}


# ===================================================================
#  Pseudocode tokenizer / line-level parser
# ===================================================================

def _strip_comments(text):
    """Strip C-style and line comments from pseudocode."""
    # Remove block comments
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    # Remove line comments
    text = re.sub(r'//[^\n]*', '', text)
    return text


def _find_matching_brace(lines, start_idx):
    """Find the line index of the closing brace that matches the opening
    brace on or after ``start_idx``.  Returns -1 on failure."""
    depth = 0
    for i in range(start_idx, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth <= 0:
            return i
    return -1


def _find_block_after(lines, idx):
    """Given a control-flow line at *idx*, find the body extent.

    Returns ``(body_start, body_end)`` where *body_end* is exclusive.
    If the body is a brace-delimited block, *body_start* is the line
    after the opening brace and *body_end* is the line of the closing
    brace.  For single-statement bodies, ``body_end = body_start + 1``.
    """
    # Check if the opening brace is on the same line
    if '{' in lines[idx]:
        close = _find_matching_brace(lines, idx)
        if close >= 0:
            return (idx + 1, close)
    # Next line might be the opening brace
    next_idx = idx + 1
    if next_idx < len(lines) and '{' in lines[next_idx]:
        close = _find_matching_brace(lines, next_idx)
        if close >= 0:
            return (next_idx + 1, close)
    # Single-statement body
    if next_idx < len(lines):
        return (next_idx, next_idx + 1)
    return (idx + 1, idx + 1)


# ===================================================================
#  AST construction from pseudocode lines
# ===================================================================

def _parse_pseudocode(text):
    """Parse Hex-Rays pseudocode text into a list of AST-like statement
    nodes.  This is intentionally simplified — it handles the subset of
    constructs that Hex-Rays commonly emits for game handler functions.

    Returns a list of statement dicts.
    """
    text = _strip_comments(text)
    lines = text.split('\n')
    stmts, _ = _parse_block(lines, 0, len(lines), 0)
    return stmts


def _parse_block(lines, start, end, depth):
    """Parse lines[start:end] into a list of statement nodes.

    Returns ``(stmts, next_idx)`` where *next_idx* is the first line
    after the parsed block.
    """
    stmts = []
    i = start
    stmt_count = 0

    while i < end and stmt_count < MAX_STMT_COUNT:
        if i >= len(lines):
            break
        line = lines[i].strip()
        stmt_count += 1

        # Skip empty and brace-only lines
        if not line or line == '{' or line == '}':
            i += 1
            continue

        # ---------- return ----------
        m = _RE_RETURN.match(line)
        if m:
            stmts.append({
                "type": NodeType.RETURN,
                "value_expr": m.group(1).strip(),
                "line": i,
            })
            i += 1
            continue

        # ---------- break ----------
        if _RE_BREAK.match(line):
            stmts.append({"type": NodeType.BREAK, "line": i})
            i += 1
            continue

        # ---------- continue ----------
        if _RE_CONTINUE.match(line):
            stmts.append({"type": NodeType.CONTINUE, "line": i})
            i += 1
            continue

        # ---------- goto ----------
        m = _RE_GOTO.match(line)
        if m:
            stmts.append({
                "type": NodeType.GOTO,
                "label": m.group(1),
                "line": i,
            })
            i += 1
            continue

        # ---------- label ----------
        m = _RE_LABEL.match(line)
        if m and not _RE_CASE.match(line) and not _RE_DEFAULT.match(line):
            stmts.append({
                "type": NodeType.LABEL,
                "label": m.group(1),
                "line": i,
            })
            i += 1
            continue

        # ---------- single-line if ----------
        m = _RE_IF_SINGLE.match(line)
        if m:
            cond = m.group(1)
            body_text = m.group(2).strip()
            body_stmts = _parse_single_stmt(body_text, i)
            node = {
                "type": NodeType.IF,
                "condition": cond,
                "body": body_stmts,
                "else_body": None,
                "elif_chain": [],
                "line": i,
            }
            # Check for else on next line
            i += 1
            i, node = _parse_else_chain(lines, i, end, node, depth)
            stmts.append(node)
            continue

        # ---------- if ----------
        m = _RE_IF.match(line)
        if m:
            cond = m.group(1)
            body_start, body_end = _find_block_after(lines, i)
            body_stmts, _ = _parse_block(lines, body_start, body_end,
                                         depth + 1)
            node = {
                "type": NodeType.IF,
                "condition": cond,
                "body": body_stmts,
                "else_body": None,
                "elif_chain": [],
                "line": i,
            }
            i = body_end + 1
            i, node = _parse_else_chain(lines, i, end, node, depth)
            stmts.append(node)
            continue

        # ---------- switch ----------
        m = _RE_SWITCH.match(line)
        if m:
            switch_expr = m.group(1)
            body_start, body_end = _find_block_after(lines, i)
            cases = _parse_switch_cases(lines, body_start, body_end, depth)
            stmts.append({
                "type": NodeType.SWITCH,
                "expr": switch_expr,
                "cases": cases,
                "line": i,
            })
            i = body_end + 1
            continue

        # ---------- while ----------
        m = _RE_WHILE.match(line)
        if m:
            cond = m.group(1)
            body_start, body_end = _find_block_after(lines, i)
            body_stmts, _ = _parse_block(lines, body_start, body_end,
                                         depth + 1)
            stmts.append({
                "type": NodeType.WHILE,
                "condition": cond,
                "body": body_stmts,
                "line": i,
            })
            i = body_end + 1
            continue

        # ---------- for ----------
        m = _RE_FOR.match(line)
        if m:
            init, cond, incr = m.group(1), m.group(2), m.group(3)
            body_start, body_end = _find_block_after(lines, i)
            body_stmts, _ = _parse_block(lines, body_start, body_end,
                                         depth + 1)
            stmts.append({
                "type": NodeType.FOR,
                "init": init,
                "condition": cond,
                "increment": incr,
                "body": body_stmts,
                "line": i,
            })
            i = body_end + 1
            continue

        # ---------- do-while ----------
        m = _RE_DO.match(line)
        if m:
            body_start, body_end = _find_block_after(lines, i)
            body_stmts, _ = _parse_block(lines, body_start, body_end,
                                         depth + 1)
            # Look for while (...); after close brace
            while_line_idx = body_end + 1
            do_cond = "true"
            if while_line_idx < end:
                wm = _RE_DO_WHILE.match(lines[while_line_idx].strip())
                if wm:
                    do_cond = wm.group(1)
                    while_line_idx += 1
            stmts.append({
                "type": NodeType.DO_WHILE,
                "condition": do_cond,
                "body": body_stmts,
                "line": i,
            })
            i = while_line_idx
            continue

        # ---------- assignment ----------
        m = _RE_ASSIGN.match(line)
        if m:
            lhs = m.group(1).strip()
            op = m.group(2)
            rhs = m.group(3).strip()
            stmts.append({
                "type": NodeType.ASSIGN,
                "lhs": lhs,
                "operator": op,
                "rhs": rhs,
                "line": i,
            })
            i += 1
            continue

        # ---------- function call statement ----------
        m = _RE_FUNC_CALL_STMT.match(line)
        if m:
            func_name = m.group(1)
            args_text = m.group(2) or ""
            stmts.append({
                "type": NodeType.CALL,
                "function": func_name,
                "args_text": args_text.strip(),
                "line": i,
            })
            i += 1
            continue

        # ---------- fallthrough: expression statement ----------
        stmts.append({
            "type": NodeType.EXPR_STMT,
            "text": line,
            "line": i,
        })
        i += 1

    return stmts, i


def _parse_single_stmt(text, line_num):
    """Parse a single inline statement (e.g. the body of a single-line
    ``if``)."""
    text = text.strip().rstrip(';').strip()
    m = re.match(r'^return\s*(.*)', text)
    if m:
        return [{"type": NodeType.RETURN, "value_expr": m.group(1).strip(),
                 "line": line_num}]
    m = _RE_ASSIGN.match(text + ';')
    if m:
        return [{"type": NodeType.ASSIGN, "lhs": m.group(1).strip(),
                 "operator": m.group(2), "rhs": m.group(3).strip(),
                 "line": line_num}]
    m = _RE_FUNC_CALL_STMT.match(text + ';')
    if m:
        return [{"type": NodeType.CALL, "function": m.group(1),
                 "args_text": (m.group(2) or "").strip(), "line": line_num}]
    return [{"type": NodeType.EXPR_STMT, "text": text, "line": line_num}]


def _parse_else_chain(lines, i, end, if_node, depth):
    """Parse optional ``else if`` / ``else`` clauses following an ``if``
    block.  Mutates *if_node* in-place and returns
    ``(next_line_idx, if_node)``."""
    while i < end and i < len(lines):
        stripped = lines[i].strip()

        # else if
        m = _RE_ELSE_IF.match(stripped)
        if m:
            cond = m.group(1)
            body_start, body_end = _find_block_after(lines, i)
            body_stmts, _ = _parse_block(lines, body_start, body_end,
                                         depth + 1)
            if_node["elif_chain"].append({
                "condition": cond,
                "body": body_stmts,
                "line": i,
            })
            i = body_end + 1
            continue

        # else
        m = _RE_ELSE.match(stripped)
        if m:
            body_start, body_end = _find_block_after(lines, i)
            body_stmts, _ = _parse_block(lines, body_start, body_end,
                                         depth + 1)
            if_node["else_body"] = body_stmts
            i = body_end + 1
            break

        # Check for "} else if" or "} else" on the same line as closing brace
        if stripped.startswith('}'):
            remainder = stripped[1:].strip()
            m2 = re.match(r'^else\s+if\s*\(\s*(.+?)\s*\)\s*$', remainder)
            if m2:
                cond = m2.group(1)
                body_start, body_end = _find_block_after(lines, i)
                body_stmts, _ = _parse_block(lines, body_start, body_end,
                                             depth + 1)
                if_node["elif_chain"].append({
                    "condition": cond,
                    "body": body_stmts,
                    "line": i,
                })
                i = body_end + 1
                continue

            m2 = re.match(r'^else\s*$', remainder)
            if m2:
                body_start, body_end = _find_block_after(lines, i)
                body_stmts, _ = _parse_block(lines, body_start, body_end,
                                             depth + 1)
                if_node["else_body"] = body_stmts
                i = body_end + 1
                break

        # No more else clauses
        break

    return i, if_node


def _parse_switch_cases(lines, start, end, depth):
    """Parse ``case`` / ``default`` labels inside a switch body.

    Returns a list of case dicts, each with ``value``, ``is_default``,
    ``body`` (list of stmts).
    """
    cases = []
    i = start

    while i < end and i < len(lines):
        stripped = lines[i].strip()

        # case N:
        m = _RE_CASE.match(stripped)
        if m:
            value = m.group(1)
            trailing = m.group(2).strip() if m.group(2) else ""
            # Collect body lines until next case/default/break/close brace
            body_start = i + 1
            body_end = _find_case_end(lines, body_start, end)
            body_stmts, _ = _parse_block(lines, body_start, body_end,
                                         depth + 1)
            # If trailing text is a statement, prepend it
            if trailing and trailing != '{':
                pre = _parse_single_stmt(trailing, i)
                body_stmts = pre + body_stmts
            cases.append({
                "value": value,
                "is_default": False,
                "body": body_stmts,
                "line": i,
            })
            i = body_end
            continue

        # default:
        m = _RE_DEFAULT.match(stripped)
        if m:
            trailing = m.group(1).strip() if m.group(1) else ""
            body_start = i + 1
            body_end = _find_case_end(lines, body_start, end)
            body_stmts, _ = _parse_block(lines, body_start, body_end,
                                         depth + 1)
            if trailing and trailing != '{':
                pre = _parse_single_stmt(trailing, i)
                body_stmts = pre + body_stmts
            cases.append({
                "value": "default",
                "is_default": True,
                "body": body_stmts,
                "line": i,
            })
            i = body_end
            continue

        i += 1

    return cases


def _find_case_end(lines, start, end):
    """Find where the current ``case`` body ends: at the next ``case``,
    ``default``, or ``break`` statement at the same brace depth."""
    depth = 0
    for i in range(start, end):
        stripped = lines[i].strip()
        depth += stripped.count('{') - stripped.count('}')
        if depth < 0:
            return i
        if depth == 0:
            if _RE_CASE.match(stripped) or _RE_DEFAULT.match(stripped):
                return i
            if _RE_BREAK.match(stripped):
                return i + 1   # include break in body
    return end


# ===================================================================
#  Expression analysis helpers
# ===================================================================

def _classify_expr_reads(expr_text):
    """Identify packet read operations in an expression string.

    Returns a list of ``(var_name, read_type, bit_width)`` tuples.
    """
    reads = []

    for m in _RE_READ_TEMPLATE.finditer(expr_text):
        type_name = m.group(1)
        reads.append((None, type_name, _type_to_bits(type_name)))

    for m in _RE_READ_HELPER.finditer(expr_text):
        suffix = m.group(1)
        reads.append((None, suffix, _suffix_to_bits(suffix)))

    for m in _RE_READ_BITS.finditer(expr_text):
        bits = int(m.group(1))
        reads.append((None, f"bits{bits}", bits))

    for m in _RE_STREAM_EXTRACT.finditer(expr_text):
        var = m.group(1) or m.group(2) or m.group(3)
        if var:
            reads.append((var, "stream_extract", 0))

    return reads


def _type_to_bits(type_name):
    """Estimate bit width from a C++ type name."""
    mapping = {
        "uint8": 8, "int8": 8, "char": 8, "bool": 8,
        "uint16": 16, "int16": 16, "short": 16,
        "uint32": 32, "int32": 32, "int": 32, "float": 32,
        "uint64": 64, "int64": 64, "double": 64,
        "_BYTE": 8, "_WORD": 16, "_DWORD": 32, "_QWORD": 64,
        "unsigned __int8": 8, "unsigned __int16": 16,
        "unsigned __int32": 32, "unsigned __int64": 64,
        "__int8": 8, "__int16": 16, "__int32": 32, "__int64": 64,
        "ObjectGuid": 128,
    }
    for key, val in mapping.items():
        if key.lower() in type_name.lower():
            return val
    return 32  # default assumption


def _suffix_to_bits(suffix):
    """Map a Read helper suffix to bit width."""
    mapping = {
        "UInt8": 8, "Int8": 8, "UInt16": 16, "Int16": 16,
        "UInt32": 32, "Int32": 32, "UInt64": 64, "Int64": 64,
        "Float": 32, "Double": 64, "Bit": 1,
        "String": 0, "CString": 0, "PackedGuid128": 128,
    }
    return mapping.get(suffix, 32)


def _classify_side_effect(func_name, args_text, line_num):
    """Classify a function call as a side-effect category.

    Returns a dict describing the effect, or None if the call is
    considered pure/uninteresting.
    """
    for category, pattern in _SIDE_EFFECT_FUNCTIONS.items():
        if pattern.match(func_name):
            effect = {
                "type": category,
                "function": func_name,
                "args": args_text,
                "line": line_num,
            }
            # Try to extract SMSG name for send_packet
            if category == "send_packet":
                sm = _RE_SMSG_NAME.search(args_text)
                if sm:
                    effect["packet_name"] = sm.group(1)
            return effect

    # Check for member call side effects: obj->SetFoo(bar)
    sm = _RE_SET_CALL.search(f"{func_name}({args_text})")
    if sm:
        return {
            "type": "state_write",
            "function": func_name,
            "target": sm.group(1),
            "operation": sm.group(2),
            "args": sm.group(3),
            "line": line_num,
        }

    return None


def _is_error_return(value_expr):
    """Heuristic: does a return value indicate an error path?"""
    if not value_expr:
        return False
    v = value_expr.strip()
    # Numeric non-zero returns from void-like handlers are often errors
    if re.match(r'^[1-9]\d*$', v):
        return True
    if re.match(r'^0x[1-9A-Fa-f][0-9A-Fa-f]*$', v):
        return True
    # Named error codes
    if re.search(r'(?i)(err|fail|invalid|denied|not_found|bad)', v):
        return True
    return False


# ===================================================================
#  Symbolic executor
# ===================================================================

class PathCollector:
    """Collects completed execution paths up to the configured limit."""

    def __init__(self, max_paths=MAX_PATHS_PER_HANDLER):
        self.paths = []
        self.max_paths = max_paths
        self._next_id = 0
        self.max_depth_seen = 0

    @property
    def full(self):
        return len(self.paths) >= self.max_paths

    def add_path(self, state, depth):
        if self.full:
            return
        if depth > self.max_depth_seen:
            self.max_depth_seen = depth
        pid = self._next_id
        self._next_id += 1

        # Build path record
        inputs = []
        for eff in state.side_effects:
            if eff["type"] == "packet_read":
                inputs.append({
                    "field": eff.get("variable", f"field_{eff.get('offset', '?')}"),
                    "type": eff.get("read_type", "unknown"),
                    "bits": eff.get("bits", 0),
                    "constraint": _constraints_for_var(
                        state, eff.get("variable")),
                })

        effects = [e for e in state.side_effects
                   if e["type"] != "packet_read"]

        outputs = [e for e in state.side_effects
                   if e["type"] == "send_packet"]

        ret_val = None
        if state.return_value is not None:
            if isinstance(state.return_value, SymbolicValue):
                ret_val = str(state.return_value)
            else:
                ret_val = str(state.return_value)

        self.paths.append({
            "id": pid,
            "conditions": list(state.path_conditions),
            "inputs": inputs,
            "effects": [_effect_to_dict(e) for e in effects],
            "outputs": [_effect_to_dict(e) for e in outputs],
            "return_value": ret_val,
            "depth": depth,
        })


def _constraints_for_var(state, var_name):
    """Collect accumulated constraints for a variable from the state."""
    if not var_name:
        return None
    sv = state.get_var(var_name)
    if sv and sv.constraints:
        return " AND ".join(sv.constraints)
    # Check path conditions that reference this variable
    relevant = [c for c in state.path_conditions if var_name in c]
    if relevant:
        return " AND ".join(relevant)
    return None


def _effect_to_dict(eff):
    """Normalise a side-effect dict for JSON storage."""
    d = dict(eff)
    # Drop internal fields
    d.pop("_sym", None)
    return d


def _exec_block(stmts, state, collector, depth):
    """Symbolically execute a list of AST statements on *state*.

    Forks state at branches and collects completed paths into
    *collector*.  Returns ``True`` if the block terminates
    (return/break), ``False`` otherwise.
    """
    if collector.full or state.halted:
        return False

    for stmt in stmts:
        if collector.full or state.halted:
            return False

        stype = stmt["type"]

        # ------ return ------
        if stype == NodeType.RETURN:
            val_expr = stmt.get("value_expr", "")
            _process_expr_effects(val_expr, state, stmt.get("line", -1))
            state.return_value = val_expr if val_expr else None
            collector.add_path(state, depth)
            return True

        # ------ break / continue / goto ------
        if stype in (NodeType.BREAK, NodeType.CONTINUE, NodeType.GOTO):
            return True

        # ------ label ------
        if stype == NodeType.LABEL:
            continue

        # ------ assignment ------
        if stype == NodeType.ASSIGN:
            _exec_assignment(stmt, state, depth)
            continue

        # ------ function call ------
        if stype == NodeType.CALL:
            _exec_call(stmt, state, depth)
            continue

        # ------ expression statement ------
        if stype == NodeType.EXPR_STMT:
            _process_expr_effects(stmt.get("text", ""), state,
                                  stmt.get("line", -1))
            continue

        # ------ if ------
        if stype == NodeType.IF:
            terminated = _exec_if(stmt, state, collector, depth)
            if terminated:
                return True
            continue

        # ------ switch ------
        if stype == NodeType.SWITCH:
            terminated = _exec_switch(stmt, state, collector, depth)
            if terminated:
                return True
            continue

        # ------ while / for / do-while (execute body once) ------
        if stype in (NodeType.WHILE, NodeType.FOR, NodeType.DO_WHILE):
            _exec_loop(stmt, state, collector, depth)
            continue

    return False


def _exec_assignment(stmt, state, depth):
    """Process an assignment statement, tracking packet reads and memory
    writes."""
    lhs = stmt["lhs"]
    rhs = stmt["rhs"]
    op = stmt.get("operator", "=")
    line = stmt.get("line", -1)

    # Detect packet reads in RHS
    reads = _classify_expr_reads(rhs)
    if reads:
        for _var, read_type, bits in reads:
            sym = SymbolicValue(
                kind=SymKind.SYMBOLIC,
                name=lhs,
                type_hint=read_type,
                origin="packet_read",
                origin_line=line,
            )
            state.set_var(lhs, sym)
            state.add_effect(
                "packet_read",
                variable=lhs,
                read_type=read_type,
                bits=bits,
                offset=state.packet_pos,
                line=line,
            )
            state.packet_pos += max(bits // 8, 1)
        return

    # Detect state writes (struct member)
    m = _RE_STATE_WRITE.match(lhs + " =")
    if m:
        state.add_effect(
            "state_write",
            target=m.group(2),
            offset=m.group(3),
            cast_type=m.group(1),
            line=line,
        )

    # Track the symbolic value
    rhs_sym = _resolve_expr(rhs, state, line)
    if op == "=":
        state.set_var(lhs, rhs_sym)
    else:
        # Compound assignment: preserve constraints from lhs
        old = state.get_var(lhs)
        if old:
            merged = old.copy()
            merged.kind = SymKind.SYMBOLIC
            merged.name = f"({lhs} {op} {rhs})"
            state.set_var(lhs, merged)
        else:
            state.set_var(lhs, rhs_sym)

    # Check for side effects in RHS expression
    _process_expr_effects(rhs, state, line)


def _exec_call(stmt, state, depth):
    """Process a standalone function call statement."""
    func_name = stmt["function"]
    args_text = stmt.get("args_text", "")
    line = stmt.get("line", -1)

    effect = _classify_side_effect(func_name, args_text, line)
    if effect:
        state.side_effects.append(effect)

    # Check for packet reads in args
    reads = _classify_expr_reads(args_text)
    for _var, read_type, bits in reads:
        state.add_effect(
            "packet_read",
            variable=f"arg_of_{func_name}",
            read_type=read_type,
            bits=bits,
            offset=state.packet_pos,
            line=line,
        )
        state.packet_pos += max(bits // 8, 1)

    # Check for send_packet patterns
    sm = _RE_SEND_PACKET.search(f"{func_name}({args_text})")
    if sm:
        pkt_name = None
        nm = _RE_SMSG_NAME.search(args_text)
        if nm:
            pkt_name = nm.group(1)
        state.add_effect(
            "send_packet",
            function=sm.group(1),
            packet_name=pkt_name,
            args=sm.group(2),
            line=line,
        )

    # DB operations
    if _RE_DB_CALL.search(func_name):
        state.add_effect(
            "db_operation",
            function=func_name,
            args=args_text,
            line=line,
        )


def _exec_if(stmt, state, collector, depth):
    """Fork execution at an ``if`` statement.

    Creates two (or more) paths: one per branch of the if/elif/else
    chain.  Returns ``True`` if ALL branches terminate (return/break)
    — meaning code after the if is dead.
    """
    cond = stmt["condition"]
    body = stmt.get("body", [])
    elif_chain = stmt.get("elif_chain", [])
    else_body = stmt.get("else_body")

    all_branches_terminate = True
    branches_executed = 0

    # --- True branch ---
    if not collector.full:
        true_state = state.fork()
        true_state.add_condition(cond)
        _apply_condition_constraints(true_state, cond, True)
        terminated = _exec_block(body, true_state, collector, depth + 1)
        if not terminated:
            all_branches_terminate = False
        branches_executed += 1

    # --- Elif branches ---
    accumulated_negations = [cond]
    for elif_branch in elif_chain:
        if collector.full:
            break
        elif_cond = elif_branch["condition"]
        elif_state = state.fork()
        for neg in accumulated_negations:
            elif_state.add_condition(f"NOT ({neg})")
        elif_state.add_condition(elif_cond)
        _apply_condition_constraints(elif_state, elif_cond, True)
        terminated = _exec_block(elif_branch["body"], elif_state,
                                 collector, depth + 1)
        if not terminated:
            all_branches_terminate = False
        accumulated_negations.append(elif_cond)
        branches_executed += 1

    # --- Else branch ---
    if else_body is not None:
        if not collector.full:
            else_state = state.fork()
            for neg in accumulated_negations:
                else_state.add_condition(f"NOT ({neg})")
            terminated = _exec_block(else_body, else_state, collector,
                                     depth + 1)
            if not terminated:
                all_branches_terminate = False
            branches_executed += 1
    else:
        # No else: the false path falls through
        all_branches_terminate = False
        # Apply negated conditions to the current state for fall-through
        for neg in accumulated_negations:
            state.add_condition(f"NOT ({neg})")
            _apply_condition_constraints(state, neg, False)

    return all_branches_terminate and else_body is not None


def _exec_switch(stmt, state, collector, depth):
    """Fork execution at a ``switch`` statement.

    One path per case/default.  Returns ``True`` if all cases terminate.
    """
    switch_expr = stmt["expr"]
    cases = stmt.get("cases", [])

    if not cases:
        return False

    all_terminate = True
    has_default = False
    case_values = []

    for case in cases:
        if collector.full:
            break

        value = case["value"]
        is_default = case["is_default"]
        body = case.get("body", [])

        case_state = state.fork()

        if is_default:
            has_default = True
            for cv in case_values:
                case_state.add_condition(f"{switch_expr} != {cv}")
        else:
            case_state.add_condition(f"{switch_expr} == {value}")
            case_values.append(value)
            # Apply constraint to the switch variable
            var_name = switch_expr.strip()
            sv = case_state.get_var(var_name)
            if sv:
                case_state.set_var(
                    var_name,
                    sv.add_constraint(f"== {value}")
                )

        terminated = _exec_block(body, case_state, collector, depth + 1)
        if not terminated:
            all_terminate = False

    # If no default, there is an implicit fall-through path
    if not has_default:
        all_terminate = False
        for cv in case_values:
            state.add_condition(f"{switch_expr} != {cv}")

    return all_terminate and has_default


def _exec_loop(stmt, state, collector, depth):
    """Execute a loop body exactly once with a symbolic iteration count.

    We do NOT unroll loops — we execute the body once to discover what
    effects a single iteration has, then record a symbolic note about
    repetition.
    """
    cond = stmt.get("condition", "true")
    body = stmt.get("body", [])
    stype = stmt["type"]
    line = stmt.get("line", -1)

    # Record that we entered a loop
    state.add_effect(
        "loop_entered",
        loop_type=stype,
        condition=cond,
        iterations="symbolic(N)",
        line=line,
    )

    # For do-while, body executes at least once unconditionally
    # For while/for, assume condition is true for first iteration
    if stype in (NodeType.WHILE, NodeType.FOR):
        state.add_condition(f"loop_cond: {cond}")

    # Execute init for `for` loops
    if stype == NodeType.FOR:
        init = stmt.get("init", "")
        if init:
            _process_expr_effects(init, state, line)

    # Execute body once
    loop_state = state.fork()
    _exec_block(body, loop_state, collector, depth + 1)

    # Merge any non-terminating side effects back into the main state
    # (the loop body may have added effects that happen on each iteration)
    for eff in loop_state.side_effects:
        if eff not in state.side_effects:
            state.side_effects.append(eff)

    # Update variables that were modified in the loop
    for var_name, sv in loop_state.variables.items():
        old = state.get_var(var_name)
        if old is None or old.kind != sv.kind or old.concrete != sv.concrete:
            # Variable was modified in the loop — mark as symbolic
            modified = sv.copy()
            modified.kind = SymKind.SYMBOLIC
            modified.name = f"{var_name}_after_loop"
            state.set_var(var_name, modified)


def _resolve_expr(expr_text, state, line):
    """Resolve an expression string to a SymbolicValue.

    This is a best-effort resolution — it handles common patterns but
    falls back to ``TOP`` for complex expressions.
    """
    expr_text = expr_text.strip()

    # Constant
    m = _RE_CONSTANT.match(expr_text)
    if m:
        try:
            val = int(m.group(1), 0)
        except ValueError:
            val = float(m.group(1))
        return SymbolicValue(kind=SymKind.CONCRETE, concrete=val,
                             origin="constant", origin_line=line)

    # String literal
    m = _RE_STRING_LIT.match(expr_text)
    if m:
        return SymbolicValue(kind=SymKind.CONCRETE, concrete=m.group(1),
                             type_hint="string", origin="constant",
                             origin_line=line)

    # Variable reference
    if re.match(r'^[a-zA-Z_]\w*$', expr_text):
        existing = state.get_var(expr_text)
        if existing:
            return existing.copy()
        return SymbolicValue(kind=SymKind.SYMBOLIC, name=expr_text,
                             origin="local", origin_line=line)

    # Packet read
    reads = _classify_expr_reads(expr_text)
    if reads:
        _var, read_type, bits = reads[0]
        return SymbolicValue(kind=SymKind.SYMBOLIC, name=f"pkt_{read_type}",
                             type_hint=read_type, origin="packet_read",
                             origin_line=line)

    # Dereference with offset: *(type*)(base + offset)
    m = _RE_DEREF_OFFSET.search(expr_text)
    if m:
        cast_type = m.group(1)
        base = m.group(2)
        offset = m.group(3)
        mem_val = state.get_mem(base, offset)
        if mem_val:
            return mem_val.copy()
        return SymbolicValue(kind=SymKind.SYMBOLIC,
                             name=f"*({base}+{offset})",
                             type_hint=cast_type, origin="memory_read",
                             origin_line=line)

    # Field access: obj->field
    m = _RE_FIELD_ACCESS.search(expr_text)
    if m:
        obj = m.group(1)
        field = m.group(2)
        return SymbolicValue(kind=SymKind.SYMBOLIC,
                             name=f"{obj}.{field}",
                             origin="field_access", origin_line=line)

    # Fallback — unparsed expression
    return SymbolicValue(kind=SymKind.TOP, name=expr_text,
                         origin="complex_expr", origin_line=line)


def _process_expr_effects(expr_text, state, line):
    """Scan an expression string for side-effectful operations and
    record them in *state*."""
    if not expr_text:
        return

    # Send packet
    for m in _RE_SEND_PACKET.finditer(expr_text):
        pkt_name = None
        nm = _RE_SMSG_NAME.search(m.group(2))
        if nm:
            pkt_name = nm.group(1)
        state.add_effect(
            "send_packet",
            function=m.group(1),
            packet_name=pkt_name,
            args=m.group(2),
            line=line,
        )

    # DB operations
    for m in _RE_DB_CALL.finditer(expr_text):
        state.add_effect(
            "db_operation",
            function=m.group(1),
            line=line,
        )

    # State writes via dereference
    for m in _RE_STATE_WRITE.finditer(expr_text):
        state.add_effect(
            "state_write",
            cast_type=m.group(1),
            target=m.group(2),
            offset=m.group(3),
            line=line,
        )

    # Member set calls: obj->SetFoo(...)
    for m in _RE_SET_CALL.finditer(expr_text):
        state.add_effect(
            "state_write",
            target=m.group(1),
            operation=m.group(2),
            args=m.group(3),
            line=line,
        )

    # Packet reads
    reads = _classify_expr_reads(expr_text)
    for _var, read_type, bits in reads:
        state.add_effect(
            "packet_read",
            read_type=read_type,
            bits=bits,
            offset=state.packet_pos,
            line=line,
        )
        state.packet_pos += max(bits // 8, 1)


def _apply_condition_constraints(state, cond_text, is_true):
    """Extract variable constraints from a branch condition and apply
    them to the symbolic state.

    For example, ``x > 10`` on the true branch constrains *x* to be
    ``> 10``.  On the false branch, *x* is ``<= 10``.
    """
    cond = cond_text.strip()

    # Simple comparison: var OP const
    m = re.match(
        r'^(\w+)\s*([<>=!]+)\s*(0x[0-9A-Fa-f]+|\-?\d+)\s*$', cond
    )
    if m:
        var_name = m.group(1)
        op = m.group(2)
        value = m.group(3)
        sv = state.get_var(var_name)
        if sv is None:
            sv = SymbolicValue(kind=SymKind.SYMBOLIC, name=var_name)

        if is_true:
            state.set_var(var_name, sv.add_constraint(f"{op} {value}"))
        else:
            neg_op = _negate_op(op)
            if neg_op:
                state.set_var(var_name,
                              sv.add_constraint(f"{neg_op} {value}"))
        return

    # Null check: !var
    m = re.match(r'^!\s*(\w+)\s*$', cond)
    if m:
        var_name = m.group(1)
        sv = state.get_var(var_name) or SymbolicValue(
            kind=SymKind.SYMBOLIC, name=var_name)
        if is_true:
            state.set_var(var_name, sv.add_constraint("== 0"))
        else:
            state.set_var(var_name, sv.add_constraint("!= 0"))
        return

    # Truthiness: if (var) - bare variable
    m = re.match(r'^(\w+)\s*$', cond)
    if m:
        var_name = m.group(1)
        sv = state.get_var(var_name) or SymbolicValue(
            kind=SymKind.SYMBOLIC, name=var_name)
        if is_true:
            state.set_var(var_name, sv.add_constraint("!= 0"))
        else:
            state.set_var(var_name, sv.add_constraint("== 0"))
        return

    # Equality: var == const
    m = re.match(
        r'^(\w+)\s*==\s*(0x[0-9A-Fa-f]+|\-?\d+|nullptr|NULL)\s*$', cond
    )
    if m:
        var_name = m.group(1)
        value = m.group(2)
        sv = state.get_var(var_name) or SymbolicValue(
            kind=SymKind.SYMBOLIC, name=var_name)
        if is_true:
            state.set_var(var_name, sv.add_constraint(f"== {value}"))
        else:
            state.set_var(var_name, sv.add_constraint(f"!= {value}"))
        return

    # Inequality: var != const
    m = re.match(
        r'^(\w+)\s*!=\s*(0x[0-9A-Fa-f]+|\-?\d+|nullptr|NULL)\s*$', cond
    )
    if m:
        var_name = m.group(1)
        value = m.group(2)
        sv = state.get_var(var_name) or SymbolicValue(
            kind=SymKind.SYMBOLIC, name=var_name)
        if is_true:
            state.set_var(var_name, sv.add_constraint(f"!= {value}"))
        else:
            state.set_var(var_name, sv.add_constraint(f"== {value}"))
        return

    # Flag check: var & MASK
    m = re.match(
        r'^(\w+)\s*&\s*(0x[0-9A-Fa-f]+|\d+)\s*$', cond
    )
    if m:
        var_name = m.group(1)
        mask = m.group(2)
        sv = state.get_var(var_name) or SymbolicValue(
            kind=SymKind.SYMBOLIC, name=var_name)
        if is_true:
            state.set_var(var_name,
                          sv.add_constraint(f"has_flag({mask})"))
        else:
            state.set_var(var_name,
                          sv.add_constraint(f"no_flag({mask})"))
        return

    # Function call predicate: HasPermission(x), IsAlive(), etc.
    m = re.match(r'^!?\s*(\w+)\s*\(', cond)
    if m:
        # Don't try to constrain — just record the condition text
        return


def _negate_op(op):
    """Return the negated comparison operator."""
    negations = {
        "==": "!=", "!=": "==",
        "<": ">=", ">=": "<",
        ">": "<=", "<=": ">",
    }
    return negations.get(op)


# ===================================================================
#  Handler discovery
# ===================================================================

def _get_cmsg_handlers(db):
    """Retrieve all known CMSG handlers from the knowledge DB.

    Returns list of dicts with keys: handler_ea, tc_name, opcode_value,
    jam_type.
    """
    query = ("SELECT * FROM opcodes "
             "WHERE handler_ea IS NOT NULL AND direction = 'CMSG'")
    rows = db.fetchall(query)
    if not rows:
        return []
    return rows


# ===================================================================
#  Cross-path analysis
# ===================================================================

def _analyze_cross_paths(paths):
    """Perform cross-path analysis on a list of completed paths.

    Returns:
      - uncovered_input_ranges: fields/ranges not exercised by any path
      - dead_paths: path IDs whose conditions are contradictory
      - coverage_metric: rough estimate of input space coverage
    """
    uncovered = []
    dead_paths = []

    # Collect all input fields across all paths
    all_fields = collections.defaultdict(list)
    for path in paths:
        for inp in path.get("inputs", []):
            field = inp.get("field", "unknown")
            constraint = inp.get("constraint")
            all_fields[field].append({
                "path_id": path["id"],
                "constraint": constraint,
            })

    # Check for dead paths: contradictory conditions
    for path in paths:
        conditions = path.get("conditions", [])
        if _has_contradiction(conditions):
            dead_paths.append(path["id"])

    # Check for uncovered input ranges
    for field, entries in all_fields.items():
        constraints = [e["constraint"] for e in entries if e["constraint"]]
        if not constraints:
            # Field read but never constrained — full range uncovered
            uncovered.append({
                "field": field,
                "range": "unrestricted",
                "note": "field read but no path constrains it",
            })
        else:
            # Check for obvious gaps in numeric constraints
            gaps = _find_constraint_gaps(field, constraints)
            uncovered.extend(gaps)

    # Coverage metric
    total_fields = len(all_fields)
    constrained_fields = sum(
        1 for f, entries in all_fields.items()
        if any(e["constraint"] for e in entries)
    )
    coverage = (constrained_fields / max(total_fields, 1)) * 100.0

    return uncovered, dead_paths, round(coverage, 1)


def _has_contradiction(conditions):
    """Lightweight check for obviously contradictory conditions.

    Detects patterns like ``x == 5 AND x != 5``, or
    ``x > 10 AND NOT (x > 10)``.
    """
    positive = set()
    negative = set()

    for cond in conditions:
        cond_str = str(cond).strip()
        if cond_str.startswith("NOT (") and cond_str.endswith(")"):
            inner = cond_str[5:-1].strip()
            negative.add(inner)
        else:
            positive.add(cond_str)

    # Direct contradiction: same expression in both positive and negative
    if positive & negative:
        return True

    # Check for var == A and var == B (A != B)
    equalities = collections.defaultdict(set)
    for cond in positive:
        m = re.match(r'^(\w+)\s*==\s*(.+)$', cond)
        if m:
            equalities[m.group(1)].add(m.group(2))

    for var, values in equalities.items():
        if len(values) > 1:
            return True

    return False


def _find_constraint_gaps(field, constraints):
    """Find obvious gaps in numeric constraints for a field.

    Returns a list of uncovered range dicts.
    """
    gaps = []

    # Extract numeric bounds
    upper_bounds = []
    lower_bounds = []
    equalities = set()

    for c in constraints:
        m = re.search(r'([<>]=?)\s*(0x[0-9A-Fa-f]+|\-?\d+)', c)
        if m:
            op = m.group(1)
            try:
                val = int(m.group(2), 0)
            except ValueError:
                continue
            if op in ('<', '<='):
                upper_bounds.append(val)
            elif op in ('>', '>='):
                lower_bounds.append(val)

        m = re.search(r'==\s*(0x[0-9A-Fa-f]+|\-?\d+)', c)
        if m:
            try:
                equalities.add(int(m.group(1), 0))
            except ValueError:
                pass

    # If we have both upper and lower bounds, check for a gap
    if upper_bounds and lower_bounds:
        max_lower = max(lower_bounds)
        min_upper = min(upper_bounds)
        if max_lower >= min_upper:
            gaps.append({
                "field": field,
                "range": f"[{max_lower}, {min_upper}]",
                "note": "bounds overlap or cross — possible dead range",
            })

    # Check if 0 is uncovered (common oversight)
    if lower_bounds and not equalities:
        min_lower = min(lower_bounds)
        if min_lower > 0:
            gaps.append({
                "field": field,
                "range": f"[0, {min_lower})",
                "note": "values below lower bound not covered",
            })

    return gaps


# ===================================================================
#  Complexity scoring
# ===================================================================

def _compute_complexity(paths, max_depth):
    """Compute a handler complexity score from its paths.

    Factors:
      - Number of paths
      - Maximum nesting depth
      - Diversity of side effect types
    """
    path_count = len(paths)
    if path_count == 0:
        return 0.0

    # Collect unique effect types
    effect_types = set()
    for path in paths:
        for eff in path.get("effects", []):
            effect_types.add(eff.get("type", "unknown"))
        for out in path.get("outputs", []):
            effect_types.add("send_packet")

    score = (
        path_count * _COMPLEXITY_PATH_WEIGHT
        + max_depth * _COMPLEXITY_DEPTH_WEIGHT
        + len(effect_types) * _COMPLEXITY_EFFECT_WEIGHT
    )
    return round(score, 2)


# ===================================================================
#  Test case generation
# ===================================================================

def _generate_test_case(handler_name, handler_ea, path):
    """Generate a C++ TEST_F for a single execution path.

    This is more precise than the behavioral_spec test generator because
    it uses the full symbolic constraint information.
    """
    pid = path["id"]
    conditions = path.get("conditions", [])
    inputs = path.get("inputs", [])
    effects = path.get("effects", [])
    outputs = path.get("outputs", [])
    ret_val = path.get("return_value")

    sanitized_name = re.sub(r'[^A-Za-z0-9_]', '_', handler_name)
    func_name = _opcode_to_handler(handler_name)

    lines = []
    lines.append(f"// Handler: {handler_name} @ {ea_str(handler_ea)}")
    lines.append(f"// Path {pid}: {_path_summary(path)}")
    lines.append(f"TEST_F({sanitized_name}Test, Path{pid})")
    lines.append("{")

    # Preconditions
    lines.append("    // --- Preconditions ---")
    for cond in conditions:
        lines.append(f"    // REQUIRE: {cond}")
    lines.append("")

    # Construct packet with symbolic inputs
    lines.append("    // --- Construct CMSG ---")
    lines.append(f"    WorldPacket data(/* {handler_name} */);")
    for inp in inputs:
        field = inp.get("field", "unknown")
        ftype = inp.get("type", "uint32")
        constraint = inp.get("constraint")
        if constraint:
            lines.append(f"    // {field}: {ftype} where {constraint}")
        else:
            lines.append(f"    // {field}: {ftype}")
        lines.append(f"    data << {_type_to_cpp(ftype)}(/* {field} */);")
    lines.append("")

    # Execute
    lines.append("    // --- Execute ---")
    lines.append(f"    _session->{func_name}(data);")
    lines.append("")

    # Assert effects
    lines.append("    // --- Assert Effects ---")
    for eff in effects:
        etype = eff.get("type", "unknown")
        if etype == "state_write":
            op = eff.get("operation", "")
            target = eff.get("target", "")
            lines.append(f"    // EXPECT: {target}->{op}() was called")
        elif etype == "db_operation":
            func = eff.get("function", "")
            lines.append(f"    // EXPECT: DB {func}() was executed")
        elif etype == "combat":
            func = eff.get("function", "")
            lines.append(f"    // EXPECT: Combat action {func}() occurred")

    # Assert outputs
    for out in outputs:
        pkt_name = out.get("packet_name", "unknown")
        lines.append(f"    EXPECT_TRUE(WasSent(\"{pkt_name}\"));")

    # Assert return
    if ret_val is not None:
        if _is_error_return(str(ret_val)):
            lines.append(f"    // Binary returns error: {ret_val}")
            lines.append(f"    EXPECT_NE(GetHandlerResult(), 0);")
        else:
            lines.append(f"    // Binary returns: {ret_val}")

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _opcode_to_handler(opcode_name):
    """Convert ``CMSG_FOO_BAR`` to ``HandleFooBar``."""
    name = opcode_name
    if name.startswith("CMSG_"):
        name = name[5:]
    parts = name.split("_")
    camel = "".join(p.capitalize() for p in parts if p)
    return f"Handle{camel}"


def _type_to_cpp(type_name):
    """Map a read type to a C++ type for test generation."""
    mapping = {
        "UInt8": "uint8", "Int8": "int8_t",
        "UInt16": "uint16", "Int16": "int16_t",
        "UInt32": "uint32", "Int32": "int32_t",
        "UInt64": "uint64", "Int64": "int64_t",
        "Float": "float", "Double": "double",
        "Bit": "bool", "PackedGuid128": "ObjectGuid",
        "uint8": "uint8", "uint16": "uint16",
        "uint32": "uint32", "uint64": "uint64",
        "int8": "int8_t", "int16": "int16_t",
        "int32": "int32_t", "int64": "int64_t",
    }
    return mapping.get(type_name, "uint32")


def _path_summary(path):
    """One-line summary of a path for comments."""
    conditions = path.get("conditions", [])
    ret_val = path.get("return_value")
    outputs = path.get("outputs", [])

    parts = []
    if conditions:
        conds_short = conditions[:3]
        parts.append(" AND ".join(str(c) for c in conds_short))
        if len(conditions) > 3:
            parts.append(f"... (+{len(conditions)-3} more)")

    if ret_val is not None:
        parts.append(f"-> return {ret_val}")
    elif outputs:
        pkt_names = [o.get("packet_name", "?") for o in outputs]
        parts.append(f"-> sends {', '.join(pkt_names)}")
    else:
        parts.append("-> void return")

    return " | ".join(parts) if parts else "unconditional path"


# ===================================================================
#  Main entry point
# ===================================================================

def simulate_execution(session):
    """Perform symbolic execution trace simulation on all CMSG handlers.

    Parses each handler's decompiled pseudocode, builds an AST,
    explores execution paths with symbolic inputs, and produces
    complete I/O specifications.

    Args:
        session: PluginSession with ``.db`` (KnowledgeDB).

    Returns:
        Count of handlers successfully simulated.
    """
    db = session.db
    handlers = _get_cmsg_handlers(db)
    if not handlers:
        msg_warn("No CMSG handlers found. Run opcode analysis first.")
        return 0

    msg_info(f"Execution trace simulation: {len(handlers)} CMSG handlers")

    t0 = time.time()
    handler_traces = []
    generated_tests = []
    complexity_ranking = []
    total_paths = 0
    simulated_count = 0
    skipped = 0

    for idx, handler in enumerate(handlers):
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"handler_{ea_str(ea)}"
        opcode_value = handler.get("opcode_value", 0)

        # Decompile
        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            skipped += 1
            continue

        # Parse into AST
        try:
            ast_stmts = _parse_pseudocode(pseudocode)
        except Exception as exc:
            msg_warn(f"  Parse error in {tc_name}: {exc}")
            skipped += 1
            continue

        if not ast_stmts:
            skipped += 1
            continue

        # Symbolic execution
        collector = PathCollector(MAX_PATHS_PER_HANDLER)
        initial_state = SymState()

        # Set up handler parameters as symbolic
        # Typical handler: void Handler(WorldPacket& packet)
        # a1 = this (WorldSession*), a2 = packet
        initial_state.set_var("a1", SymbolicValue(
            kind=SymKind.SYMBOLIC, name="this_session",
            type_hint="WorldSession*", origin="param",
        ))
        initial_state.set_var("a2", SymbolicValue(
            kind=SymKind.SYMBOLIC, name="packet",
            type_hint="WorldPacket*", origin="param",
        ))
        initial_state.set_var("this", SymbolicValue(
            kind=SymKind.SYMBOLIC, name="this_session",
            type_hint="WorldSession*", origin="param",
        ))

        try:
            _exec_block(ast_stmts, initial_state, collector, 0)
        except Exception as exc:
            msg_warn(f"  Execution error in {tc_name}: {exc}")
            skipped += 1
            continue

        paths = collector.paths
        if not paths:
            # Handler with no discovered paths — add implicit void return
            collector.add_path(initial_state, 0)
            paths = collector.paths

        # Cross-path analysis
        uncovered, dead, coverage = _analyze_cross_paths(paths)

        # Complexity
        max_depth = collector.max_depth_seen
        complexity = _compute_complexity(paths, max_depth)

        trace = {
            "handler": tc_name,
            "opcode": opcode_value,
            "handler_ea": f"0x{ea:X}",
            "path_count": len(paths),
            "complexity_score": complexity,
            "max_depth": max_depth,
            "paths": paths,
            "uncovered_input_ranges": uncovered,
            "dead_paths": dead,
            "coverage_pct": coverage,
        }
        handler_traces.append(trace)

        # Store per-handler trace
        db.kv_set(f"execution_trace:{tc_name}", trace)

        # Generate test cases
        for path in paths:
            test_code = _generate_test_case(tc_name, ea, path)
            generated_tests.append({
                "handler": tc_name,
                "path_id": path["id"],
                "test_code": test_code,
            })

        complexity_ranking.append({
            "handler": tc_name,
            "score": complexity,
            "path_count": len(paths),
            "max_depth": max_depth,
        })

        total_paths += len(paths)
        simulated_count += 1

        if (idx + 1) % 50 == 0:
            elapsed = time.time() - t0
            msg_info(f"  Processed {idx + 1}/{len(handlers)} handlers, "
                     f"{total_paths} paths, {elapsed:.1f}s elapsed")
            db.commit()

    # Sort complexity ranking
    complexity_ranking.sort(key=lambda x: x["score"], reverse=True)

    # Build summary
    avg_paths = round(total_paths / max(simulated_count, 1), 2)

    summary = {
        "handler_traces": handler_traces,
        "generated_tests": generated_tests,
        "complexity_ranking": complexity_ranking,
        "total_handlers": simulated_count,
        "total_paths": total_paths,
        "avg_paths_per_handler": avg_paths,
        "skipped_handlers": skipped,
        "elapsed_seconds": round(time.time() - t0, 2),
        "generated_at": time.time(),
    }

    db.kv_set("execution_traces", summary)
    db.commit()

    elapsed = time.time() - t0
    msg_info(
        f"Execution trace simulation complete: "
        f"{simulated_count} handlers, {total_paths} paths "
        f"(avg {avg_paths}/handler), {skipped} skipped, "
        f"{len(generated_tests)} test cases generated, "
        f"{elapsed:.1f}s elapsed"
    )

    # Log top-10 most complex handlers
    if complexity_ranking:
        msg_info("Top-10 most complex handlers:")
        for entry in complexity_ranking[:10]:
            msg(f"  {entry['handler']}: score={entry['score']}, "
                f"paths={entry['path_count']}, depth={entry['max_depth']}")

    return simulated_count


# ===================================================================
#  Retrieval API
# ===================================================================

def get_execution_traces(session):
    """Retrieve stored execution trace simulation results.

    Args:
        session: PluginSession with ``.db``.

    Returns:
        dict with full simulation results, or None if not yet run.
    """
    return session.db.kv_get("execution_traces")


def get_handler_trace(session, handler_name):
    """Retrieve the execution trace for a single handler.

    Args:
        session: PluginSession
        handler_name: TC opcode name (e.g. ``CMSG_HOUSING_DECOR_PLACE``)

    Returns:
        dict with handler trace data, or None.
    """
    return session.db.kv_get(f"execution_trace:{handler_name}")


def get_complexity_ranking(session, top_n=None):
    """Retrieve the complexity ranking of all analysed handlers.

    Args:
        session: PluginSession
        top_n: If given, return only the top N most complex handlers.

    Returns:
        List of dicts sorted by complexity score descending.
    """
    data = session.db.kv_get("execution_traces")
    if not data:
        return []
    ranking = data.get("complexity_ranking", [])
    if top_n:
        return ranking[:top_n]
    return ranking


def get_generated_tests(session, handler_name=None):
    """Retrieve generated test cases.

    Args:
        session: PluginSession
        handler_name: If given, return tests for this handler only.

    Returns:
        List of test case dicts.
    """
    data = session.db.kv_get("execution_traces")
    if not data:
        return []
    tests = data.get("generated_tests", [])
    if handler_name:
        return [t for t in tests if t["handler"] == handler_name]
    return tests


def get_uncovered_inputs(session, handler_name=None):
    """Retrieve input ranges not covered by any execution path.

    Args:
        session: PluginSession
        handler_name: If given, return for this handler only.

    Returns:
        List of uncovered range dicts.
    """
    if handler_name:
        trace = get_handler_trace(session, handler_name)
        if trace:
            return trace.get("uncovered_input_ranges", [])
        return []

    data = session.db.kv_get("execution_traces")
    if not data:
        return []

    result = []
    for trace in data.get("handler_traces", []):
        for u in trace.get("uncovered_input_ranges", []):
            entry = dict(u)
            entry["handler"] = trace["handler"]
            result.append(entry)
    return result


def get_dead_paths(session, handler_name=None):
    """Retrieve paths with contradictory conditions.

    Args:
        session: PluginSession
        handler_name: If given, return for this handler only.

    Returns:
        List of dicts with handler name and dead path IDs.
    """
    if handler_name:
        trace = get_handler_trace(session, handler_name)
        if trace and trace.get("dead_paths"):
            return [{"handler": handler_name,
                      "dead_paths": trace["dead_paths"]}]
        return []

    data = session.db.kv_get("execution_traces")
    if not data:
        return []

    result = []
    for trace in data.get("handler_traces", []):
        dead = trace.get("dead_paths", [])
        if dead:
            result.append({
                "handler": trace["handler"],
                "dead_paths": dead,
            })
    return result


def format_trace_report(session, handler_name):
    """Generate a human-readable execution trace report for a handler.

    Args:
        session: PluginSession
        handler_name: TC opcode name

    Returns:
        Formatted string report.
    """
    trace = get_handler_trace(session, handler_name)
    if not trace:
        return f"No execution trace found for '{handler_name}'"

    lines = []
    lines.append(f"## Execution Trace: {handler_name}")
    lines.append(f"Binary address: {trace['handler_ea']}")
    lines.append(f"Paths: {trace['path_count']}  |  "
                 f"Complexity: {trace['complexity_score']}  |  "
                 f"Max depth: {trace['max_depth']}  |  "
                 f"Coverage: {trace.get('coverage_pct', '?')}%")
    lines.append("")

    for path in trace.get("paths", []):
        pid = path["id"]
        conditions = path.get("conditions", [])
        inputs = path.get("inputs", [])
        effects = path.get("effects", [])
        outputs = path.get("outputs", [])
        ret_val = path.get("return_value")

        lines.append(f"### Path {pid}")

        if conditions:
            lines.append("  Preconditions:")
            for c in conditions:
                lines.append(f"    - {c}")

        if inputs:
            lines.append("  Inputs (packet reads):")
            for inp in inputs:
                constraint = inp.get("constraint", "")
                constraint_str = f" WHERE {constraint}" if constraint else ""
                lines.append(
                    f"    - {inp['field']}: {inp['type']}"
                    f" ({inp.get('bits', '?')} bits){constraint_str}"
                )

        if effects:
            lines.append("  Effects:")
            for eff in effects:
                etype = eff.get("type", "?")
                if etype == "state_write":
                    target = eff.get("target", "?")
                    op = eff.get("operation", "write")
                    lines.append(f"    - [{etype}] {target}.{op}")
                elif etype == "db_operation":
                    func = eff.get("function", "?")
                    lines.append(f"    - [{etype}] {func}()")
                elif etype == "loop_entered":
                    lines.append(
                        f"    - [{etype}] {eff.get('loop_type', '?')} "
                        f"cond={eff.get('condition', '?')} "
                        f"iter={eff.get('iterations', '?')}"
                    )
                else:
                    func = eff.get("function", eff.get("operation", "?"))
                    lines.append(f"    - [{etype}] {func}")

        if outputs:
            lines.append("  Outputs (packets sent):")
            for out in outputs:
                pkt = out.get("packet_name", out.get("function", "?"))
                lines.append(f"    - {pkt}")

        if ret_val is not None:
            is_err = _is_error_return(str(ret_val))
            label = " (ERROR)" if is_err else ""
            lines.append(f"  Return: {ret_val}{label}")

        lines.append("")

    # Uncovered inputs
    uncovered = trace.get("uncovered_input_ranges", [])
    if uncovered:
        lines.append("### Uncovered Input Ranges")
        for u in uncovered:
            lines.append(
                f"  - {u['field']}: {u['range']} — {u.get('note', '')}"
            )
        lines.append("")

    # Dead paths
    dead = trace.get("dead_paths", [])
    if dead:
        lines.append(f"### Dead Paths (contradictory conditions): {dead}")
        lines.append("")

    return "\n".join(lines)
