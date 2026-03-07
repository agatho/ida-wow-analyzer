"""
Handler Behavioral Specification Generator
Enumerates every execution path through a decompiled handler, recording
conditions, negated conditions, outcomes, and side effects on each path.

Produces a formal, machine-verifiable specification:
  "Given input where field_A > 10 AND field_B == 0, handler returns error
   0x17 and sends no response."

Feed the same inputs to a TrinityCore handler and verify identical outputs.
"""

import json
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
# Regex patterns for pseudocode analysis
# ---------------------------------------------------------------------------

# if ( <condition> )
_RE_IF = re.compile(
    r'^(\s*)if\s*\(\s*(.+?)\s*\)\s*$', re.MULTILINE
)

# else if ( <condition> )
_RE_ELSE_IF = re.compile(
    r'^(\s*)else\s+if\s*\(\s*(.+?)\s*\)\s*$', re.MULTILINE
)

# else
_RE_ELSE = re.compile(
    r'^(\s*)else\s*$', re.MULTILINE
)

# switch ( <expr> )
_RE_SWITCH = re.compile(
    r'^(\s*)switch\s*\(\s*(.+?)\s*\)\s*$', re.MULTILINE
)

# case <value>:
_RE_CASE = re.compile(
    r'^\s*case\s+(0x[0-9A-Fa-f]+|\d+|[A-Z_]\w*)\s*:', re.MULTILINE
)

# default:
_RE_DEFAULT = re.compile(r'^\s*default\s*:', re.MULTILINE)

# return <value>;
_RE_RETURN = re.compile(
    r'^\s*return\s*(.*?)\s*;\s*$', re.MULTILINE
)

# goto <label>;
_RE_GOTO = re.compile(
    r'^\s*goto\s+(\w+)\s*;', re.MULTILINE
)

# <label>:  (not case/default)
_RE_LABEL = re.compile(
    r'^(\w+)\s*:\s*$', re.MULTILINE
)

# SendPacket / send packet calls
_RE_SEND_PACKET = re.compile(
    r'(\w*[Ss]end\w*[Pp]acket\w*)\s*\(\s*([^)]*)\)', re.MULTILINE
)

# Generic function call: identifier(...)
_RE_FUNC_CALL = re.compile(
    r'\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*;', re.MULTILINE
)

# Ternary: cond ? a : b
_RE_TERNARY = re.compile(
    r'(.+?)\s*\?\s*(.+?)\s*:\s*(.+)'
)

# Pointer dereference member access: *(type *)(ptr + offset)
_RE_DEREF = re.compile(
    r'\*\s*\(\s*\w+\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
)

# Database-related function names
_DB_FUNCTIONS = re.compile(
    r'\b(Execute|PExecute|Query|PQuery|PrepareStatement|'
    r'SetData|SaveToDB|DeleteFromDB|InsertIntoDB|'
    r'DirectExecute|AsyncQuery|CommitTransaction)\b',
    re.IGNORECASE
)

# State mutation: *(ptr + offset) = value
_RE_STATE_WRITE = re.compile(
    r'\*\s*\(\s*\w+\s*\*\s*\)\s*\(\s*\w+\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\)\s*='
)

# Logging calls
_RE_LOG_CALL = re.compile(
    r'\b(TC_LOG_\w+|sLog|LOG_\w+|printf|OutputDebugString)\s*\(', re.IGNORECASE
)

# Event / signal triggers
_RE_EVENT_TRIGGER = re.compile(
    r'\b(TriggerEvent|FireEvent|SendEvent|OnEvent|Emit|Signal|Notify)\w*\s*\(',
    re.IGNORECASE
)

# SMSG opcode name extraction from SendPacket argument
_RE_SMSG_NAME = re.compile(r'(SMSG_\w+)')


# ---------------------------------------------------------------------------
# Condition classification
# ---------------------------------------------------------------------------

_CONDITION_CLASSIFIERS = [
    ("null_check",       re.compile(r'^!?\s*\w+\s*$')),
    ("null_check",       re.compile(r'\w+\s*[!=]=\s*0\b')),
    ("null_check",       re.compile(r'\w+\s*[!=]=\s*(?:nullptr|NULL)\b')),
    ("range_check",      re.compile(r'\w+\s*[<>]=?\s*(?:0x[0-9A-Fa-f]+|\d+)')),
    ("flag_check",       re.compile(r'\w+\s*&\s*(?:0x[0-9A-Fa-f]+|\d+)')),
    ("state_check",      re.compile(r'\w+\s*==\s*(?:0x[0-9A-Fa-f]+|\d+)')),
    ("permission_check", re.compile(r'(?:Has|Can|Is|Check)\w*\s*\(')),
    ("equality_check",   re.compile(r'\w+\s*[!=]=\s*\w+')),
]

MAX_NESTING_DEPTH = 15
MAX_PATHS_PER_HANDLER = 256


# ===================================================================
# Public API
# ===================================================================


def generate_behavioral_specs(session, system_filter=None):
    """Main entry point: generate behavioral specs for all CMSG handlers.

    Args:
        session: PluginSession with .db and .cfg
        system_filter: Optional string to filter handler names (e.g. 'Housing')

    Returns:
        Number of handler specs generated.
    """
    db = session.db

    query = ("SELECT * FROM opcodes "
             "WHERE handler_ea IS NOT NULL AND direction = 'CMSG'")
    if system_filter:
        query += f" AND tc_name LIKE '%{system_filter}%'"

    handlers = db.fetchall(query)
    if not handlers:
        msg_warn("No CMSG handlers found. Run opcode analysis first.")
        return 0

    msg_info(f"Generating behavioral specs for {len(handlers)} CMSG handlers...")

    count = 0
    total_paths = 0
    all_specs = {}

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"handler_0x{ea:X}"

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        paths = _enumerate_paths(pseudocode, tc_name, ea)
        if not paths:
            continue

        paths = _simplify_paths(paths)

        spec = {
            "handler": tc_name,
            "handler_ea": f"0x{ea:X}",
            "path_count": len(paths),
            "paths": paths,
            "generated_at": time.time(),
        }

        # Store per-handler spec
        db.kv_set(f"behavioral_spec:{tc_name}", spec)
        all_specs[tc_name] = spec
        total_paths += len(paths)
        count += 1

        if count % 50 == 0:
            db.commit()
            msg_info(f"  Processed {count} handlers, "
                     f"{total_paths} paths so far...")

    # Store summary
    summary = {
        "handler_count": count,
        "total_paths": total_paths,
        "average_paths": round(total_paths / max(count, 1), 1),
        "handlers": sorted(all_specs.keys()),
        "generated_at": time.time(),
    }
    db.kv_set("behavioral_specs", summary)
    db.commit()

    msg_info(f"Generated behavioral specs: {count} handlers, "
             f"{total_paths} execution paths "
             f"(avg {summary['average_paths']} paths/handler)")
    return count


def get_behavioral_specs(session, handler_name=None):
    """Retrieve stored behavioral specs.

    Args:
        session: PluginSession
        handler_name: If given, return spec for this handler only.
                      Otherwise return the summary.

    Returns:
        dict with spec data, or None if not found.
    """
    db = session.db
    if handler_name:
        return db.kv_get(f"behavioral_spec:{handler_name}")
    return db.kv_get("behavioral_specs")


def get_spec_coverage(session):
    """How many handlers have full behavioral specs.

    Returns:
        dict with coverage statistics.
    """
    db = session.db

    total_cmsg = db.fetchone(
        "SELECT COUNT(*) as cnt FROM opcodes "
        "WHERE handler_ea IS NOT NULL AND direction = 'CMSG'")
    total_cmsg = total_cmsg["cnt"] if total_cmsg else 0

    spec_summary = db.kv_get("behavioral_specs")
    specced = spec_summary["handler_count"] if spec_summary else 0

    coverage_pct = round((specced / max(total_cmsg, 1)) * 100, 1)

    return {
        "total_cmsg_handlers": total_cmsg,
        "handlers_with_specs": specced,
        "coverage_percent": coverage_pct,
        "total_paths": spec_summary["total_paths"] if spec_summary else 0,
    }


def generate_spec_document(session, handler_name):
    """Generate a human-readable specification document for a handler.

    Args:
        session: PluginSession
        handler_name: TC opcode name (e.g. 'CMSG_HOUSING_DECOR_PLACE')

    Returns:
        String with formatted specification text.
    """
    spec = get_behavioral_specs(session, handler_name)
    if not spec:
        return f"No behavioral spec found for '{handler_name}'"

    func_name = _opcode_to_handler(handler_name)
    lines = [
        f"## {func_name} Behavioral Specification",
        f"",
        f"Handler: {handler_name}",
        f"Binary address: {spec['handler_ea']}",
        f"Execution paths: {spec['path_count']}",
        f"",
    ]

    for path in spec["paths"]:
        pid = path["path_id"]
        depth = path.get("depth", 0)
        outcome = path.get("outcome", {})
        outcome_type = outcome.get("type", "unknown")
        outcome_desc = _format_outcome(outcome)

        lines.append(f"### Path {pid + 1}: {_path_label(outcome)}")
        lines.append("")

        # Conditions
        conditions = path.get("conditions", [])
        neg_conditions = path.get("negated_conditions", [])

        if conditions or neg_conditions:
            lines.append("**Conditions:**")
            for cond in conditions:
                ctype = cond.get("type", "")
                expr = cond.get("expr", "")
                type_tag = f" [{ctype}]" if ctype else ""
                lines.append(f"  - {expr}{type_tag}")
            for cond in neg_conditions:
                expr = cond.get("expr", "")
                lines.append(f"  - NOT ({expr})")
            lines.append("")

        # Outcome
        lines.append(f"**Outcome:** {outcome_desc}")
        lines.append("")

        # Side effects
        side_effects = path.get("side_effects", [])
        if side_effects:
            lines.append("**Side Effects:**")
            for se in side_effects:
                se_type = se.get("type", "unknown")
                if se_type == "send_packet":
                    target = se.get("target", "unknown")
                    lines.append(f"  - Sends {target}")
                elif se_type == "function_call":
                    func = se.get("function", "unknown")
                    lines.append(f"  - Calls {func}()")
                elif se_type == "db_write":
                    op = se.get("operation", "unknown")
                    lines.append(f"  - Database: {op}")
                elif se_type == "state_mutation":
                    lines.append(f"  - Mutates state: {se.get('detail', '')}")
                elif se_type == "event_trigger":
                    lines.append(f"  - Triggers event: {se.get('function', '')}")
                elif se_type == "log":
                    lines.append(f"  - Logs: {se.get('function', '')}")
                else:
                    lines.append(f"  - {se_type}: {se.get('detail', '')}")
            lines.append("")

        lines.append(f"*Nesting depth: {depth}*")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def generate_test_from_spec(session, handler_name):
    """Generate C++ test cases from a handler's behavioral spec.

    One test per execution path, setting up conditions to exercise
    that specific path and asserting the expected outcome.

    Args:
        session: PluginSession
        handler_name: TC opcode name

    Returns:
        String with C++ test code.
    """
    spec = get_behavioral_specs(session, handler_name)
    if not spec:
        return f"// No behavioral spec found for '{handler_name}'\n"

    func_name = _opcode_to_handler(handler_name)
    sanitized = _sanitize(handler_name)

    lines = [
        f"// Auto-generated behavioral tests for {handler_name}",
        f"// {spec['path_count']} execution paths",
        f"// Generated by TC WoW Analyzer - Behavioral Spec Engine",
        f"",
        f'#include "TestFramework.h"',
        f'#include "WorldPacket.h"',
        f'#include "WorldSession.h"',
        f"",
        f"class {sanitized}Test : public PacketHandlerTest {{}};",
        f"",
    ]

    for path in spec["paths"]:
        pid = path["path_id"]
        outcome = path.get("outcome", {})
        outcome_type = outcome.get("type", "unknown")
        label = _path_label(outcome)
        sanitized_label = _sanitize(label)

        test_name = f"Path{pid}_{sanitized_label}"
        conditions = path.get("conditions", [])
        neg_conditions = path.get("negated_conditions", [])
        side_effects = path.get("side_effects", [])

        lines.append(f"// Path {pid + 1}: {label}")
        for cond in conditions:
            lines.append(f"//   Condition: {cond.get('expr', '')}")
        for cond in neg_conditions:
            lines.append(f"//   Negated:   {cond.get('expr', '')}")

        lines.append(f"TEST_F({sanitized}Test, {test_name})")
        lines.append("{")

        # Set up conditions
        lines.append("    // --- Setup: establish conditions for this path ---")
        for cond in conditions:
            ctype = cond.get("type", "")
            expr = cond.get("expr", "")
            if ctype == "null_check":
                lines.append(f"    // Ensure: {expr}")
                lines.append(f"    // SetupNullGuard({expr});")
            elif ctype == "range_check":
                lines.append(f"    // Ensure range: {expr}")
            elif ctype == "state_check":
                lines.append(f"    // Set state: {expr}")
            elif ctype == "permission_check":
                lines.append(f"    // Grant permission: {expr}")
            else:
                lines.append(f"    // Arrange: {expr}")

        lines.append("")
        lines.append(f"    WorldPacket packet(/* {handler_name} opcode */);")
        lines.append(f"    // TODO: populate packet fields to satisfy conditions")
        lines.append("")
        lines.append(f"    _session->{func_name}(packet);")
        lines.append("")

        # Assert outcome
        lines.append("    // --- Assert expected outcome ---")
        if outcome_type == "error_return":
            ret_val = outcome.get("return_value", "error")
            lines.append(f"    // Binary returns {ret_val}")
            lines.append(f"    EXPECT_NE(GetHandlerResult(), RESULT_OK);")
        elif outcome_type == "success":
            lines.append(f"    EXPECT_EQ(GetHandlerResult(), RESULT_OK);")
        elif outcome_type == "send_response":
            target = outcome.get("response_packet", "unknown")
            lines.append(f"    // Should send {target}")
            lines.append(f"    EXPECT_TRUE(WasSent(\"{target}\"));")
        elif outcome_type == "call_handler":
            called = outcome.get("function", "unknown")
            lines.append(f"    // Should delegate to {called}")
            lines.append(f"    EXPECT_TRUE(WasCalled(\"{called}\"));")

        # Assert side effects
        for se in side_effects:
            se_type = se.get("type", "")
            if se_type == "send_packet":
                target = se.get("target", "unknown")
                lines.append(f"    EXPECT_TRUE(WasSent(\"{target}\"));")
            elif se_type == "function_call":
                func = se.get("function", "unknown")
                lines.append(f"    EXPECT_TRUE(WasCalled(\"{func}\"));")

        lines.append("}")
        lines.append("")

    return "\n".join(lines)


def verify_spec_against_tc(session, handler_name):
    """Compare a binary behavioral spec against TC handler source.

    Parses the TC handler's execution paths and compares path count,
    conditions, and outcomes with the binary spec.

    Args:
        session: PluginSession
        handler_name: TC opcode name

    Returns:
        dict with comparison results, or None if comparison not possible.
    """
    db = session.db
    cfg = session.cfg
    tc_dir = cfg.tc_source_dir

    if not tc_dir:
        msg_warn("TrinityCore source not configured - cannot verify spec")
        return None

    binary_spec = get_behavioral_specs(session, handler_name)
    if not binary_spec:
        msg_warn(f"No binary spec for {handler_name}")
        return None

    func_name = _opcode_to_handler(handler_name)
    tc_source = _find_tc_handler_source(tc_dir, func_name)
    if not tc_source:
        msg_warn(f"TC handler source not found for {func_name}")
        return None

    # Enumerate TC's execution paths using the same algorithm
    tc_paths = _enumerate_paths(tc_source, handler_name, 0)
    tc_paths = _simplify_paths(tc_paths)

    binary_paths = binary_spec.get("paths", [])

    # Compare
    binary_error_paths = [p for p in binary_paths
                          if p.get("outcome", {}).get("type") == "error_return"]
    tc_error_paths = [p for p in tc_paths
                      if p.get("outcome", {}).get("type") == "error_return"]

    binary_success_paths = [p for p in binary_paths
                            if p.get("outcome", {}).get("type") == "success"]
    tc_success_paths = [p for p in tc_paths
                        if p.get("outcome", {}).get("type") == "success"]

    binary_send_paths = [p for p in binary_paths
                         if p.get("outcome", {}).get("type") == "send_response"]
    tc_send_paths = [p for p in tc_paths
                     if p.get("outcome", {}).get("type") == "send_response"]

    # Find paths in binary but missing from TC
    missing_in_tc = []
    extra_in_tc = []

    # Heuristic: compare error return values
    binary_error_vals = set()
    for p in binary_error_paths:
        rv = p.get("outcome", {}).get("return_value")
        if rv:
            binary_error_vals.add(rv)

    tc_error_vals = set()
    for p in tc_error_paths:
        rv = p.get("outcome", {}).get("return_value")
        if rv:
            tc_error_vals.add(rv)

    missing_error_codes = binary_error_vals - tc_error_vals
    extra_error_codes = tc_error_vals - binary_error_vals

    for code in missing_error_codes:
        matching = [p for p in binary_error_paths
                    if p.get("outcome", {}).get("return_value") == code]
        for p in matching:
            missing_in_tc.append({
                "path_id": p["path_id"],
                "type": "error_return",
                "return_value": code,
                "conditions": p.get("conditions", []),
            })

    for code in extra_error_codes:
        matching = [p for p in tc_error_paths
                    if p.get("outcome", {}).get("return_value") == code]
        for p in matching:
            extra_in_tc.append({
                "path_id": p["path_id"],
                "type": "error_return",
                "return_value": code,
                "conditions": p.get("conditions", []),
            })

    # Side effect comparison: packet sends
    binary_sends = set()
    for p in binary_paths:
        for se in p.get("side_effects", []):
            if se.get("type") == "send_packet":
                binary_sends.add(se.get("target", ""))

    tc_sends = set()
    for p in tc_paths:
        for se in p.get("side_effects", []):
            if se.get("type") == "send_packet":
                tc_sends.add(se.get("target", ""))

    missing_sends = binary_sends - tc_sends
    extra_sends = tc_sends - binary_sends

    result = {
        "handler": handler_name,
        "binary_path_count": len(binary_paths),
        "tc_path_count": len(tc_paths),
        "binary_error_paths": len(binary_error_paths),
        "tc_error_paths": len(tc_error_paths),
        "binary_success_paths": len(binary_success_paths),
        "tc_success_paths": len(tc_success_paths),
        "missing_in_tc": missing_in_tc,
        "extra_in_tc": extra_in_tc,
        "missing_error_codes": sorted(missing_error_codes),
        "extra_error_codes": sorted(extra_error_codes),
        "missing_sends": sorted(missing_sends),
        "extra_sends": sorted(extra_sends),
        "conformance_issues": len(missing_in_tc) + len(missing_error_codes) + len(missing_sends),
    }

    # Store verification result
    db.kv_set(f"spec_verification:{handler_name}", result)
    db.commit()

    if result["conformance_issues"] > 0:
        msg_warn(f"{handler_name}: {result['conformance_issues']} conformance "
                 f"issues (binary {len(binary_paths)} paths vs "
                 f"TC {len(tc_paths)} paths)")
    else:
        msg_info(f"{handler_name}: spec verification passed "
                 f"({len(binary_paths)} paths)")

    return result


# ===================================================================
# Core path enumeration
# ===================================================================


def _enumerate_paths(pseudocode, handler_name, handler_ea):
    """Enumerate all execution paths through pseudocode.

    Parses the if-then-else tree, switch statements, and early returns,
    building a list of paths where each path records:
      - conditions (must be true)
      - negated_conditions (must be false)
      - outcome (return value, send, or call)
      - side_effects (packets sent, functions called, mutations)
      - depth (nesting level)

    Args:
        pseudocode: Decompiled C text
        handler_name: For labeling
        handler_ea: For reference

    Returns:
        List of path dicts.
    """
    lines = pseudocode.split("\n")
    all_paths = []
    path_counter = [0]

    def _walk(start_line, end_line, parent_conditions, parent_negated,
              depth, side_effects_so_far):
        """Recursively walk lines, forking at branch points."""
        if depth > MAX_NESTING_DEPTH:
            return
        if path_counter[0] >= MAX_PATHS_PER_HANDLER:
            return

        i = start_line
        current_conditions = list(parent_conditions)
        current_negated = list(parent_negated)
        current_side_effects = list(side_effects_so_far)

        while i < end_line:
            if path_counter[0] >= MAX_PATHS_PER_HANDLER:
                return

            line = lines[i]
            stripped = line.strip()

            # --- return statement terminates this path ---
            ret_match = re.match(r'return\s*(.*?)\s*;', stripped)
            if ret_match and not stripped.startswith("if") and not stripped.startswith("else"):
                ret_val = ret_match.group(1).strip()
                outcome = _classify_return(ret_val, i)
                # Collect side effects from any inline expression
                inline_se = _extract_side_effects_line(stripped, i)
                all_paths.append(_make_path(
                    path_counter, current_conditions, current_negated,
                    outcome, current_side_effects + inline_se, depth
                ))
                return

            # --- switch statement ---
            switch_m = re.match(r'\s*switch\s*\(\s*(.+?)\s*\)\s*', stripped)
            if switch_m:
                switch_expr = switch_m.group(1)
                switch_block_start, switch_block_end = _find_brace_block(
                    lines, i)
                if switch_block_start < 0:
                    i += 1
                    continue

                cases = _extract_cases(lines, switch_block_start,
                                       switch_block_end)
                has_default = False

                for case_info in cases:
                    case_val = case_info["value"]
                    case_start = case_info["start"]
                    case_end = case_info["end"]
                    is_default = case_info["is_default"]

                    if is_default:
                        has_default = True
                        conds = list(current_conditions)
                        negs = list(current_negated)
                        # Default negates all explicit cases
                        for other_case in cases:
                            if not other_case["is_default"]:
                                negs.append({
                                    "expr": f"{switch_expr} == {other_case['value']}",
                                    "line": i,
                                })
                    else:
                        conds = list(current_conditions) + [{
                            "expr": f"{switch_expr} == {case_val}",
                            "line": i,
                            "type": "state_check",
                        }]
                        negs = list(current_negated)

                    # Collect side effects within the case block
                    case_se = _extract_side_effects_block(
                        lines, case_start, case_end)

                    # Check for return within the case
                    case_has_return = False
                    for ci in range(case_start, case_end):
                        cs = lines[ci].strip()
                        rm = re.match(r'return\s*(.*?)\s*;', cs)
                        if rm and not cs.startswith("if"):
                            outcome = _classify_return(rm.group(1).strip(), ci)
                            all_paths.append(_make_path(
                                path_counter, conds, negs,
                                outcome,
                                current_side_effects + case_se,
                                depth + 1
                            ))
                            case_has_return = True
                            break

                    if not case_has_return:
                        # Walk into case body for nested branches
                        _walk(case_start, case_end, conds, negs,
                              depth + 1,
                              current_side_effects + case_se)

                # If no default case, there is an implicit fall-through path
                if not has_default and cases:
                    all_neg = list(current_negated)
                    for c in cases:
                        if not c["is_default"]:
                            all_neg.append({
                                "expr": f"{switch_expr} == {c['value']}",
                                "line": i,
                            })
                    _walk(switch_block_end + 1, end_line,
                          current_conditions, all_neg,
                          depth, current_side_effects)

                # After switch, no fall-through past it in normal flow
                return

            # --- if / else if / else chains ---
            if_m = re.match(r'\s*if\s*\(\s*(.+?)\s*\)\s*$', stripped)
            if not if_m:
                # Single-line if: if (...) return ...;
                if_m = re.match(
                    r'\s*if\s*\(\s*(.+?)\s*\)\s*\{?\s*$', stripped)
                if not if_m:
                    # Check for single-line if-return
                    sl_m = re.match(
                        r'\s*if\s*\(\s*(.+?)\s*\)\s+(return\s+.*?;)', stripped)
                    if sl_m:
                        cond_expr = sl_m.group(1)
                        ret_stmt = sl_m.group(2)
                        ret_val_m = re.match(r'return\s*(.*?)\s*;', ret_stmt)
                        ret_val = ret_val_m.group(1) if ret_val_m else ""

                        parsed_cond = _parse_condition(cond_expr, i)

                        # Path where condition is true -> return
                        true_conds = current_conditions + [parsed_cond]
                        outcome = _classify_return(ret_val, i)
                        inline_se = _extract_side_effects_line(stripped, i)
                        all_paths.append(_make_path(
                            path_counter, true_conds, current_negated,
                            outcome,
                            current_side_effects + inline_se,
                            depth + 1
                        ))

                        # Continue with condition negated
                        current_negated = current_negated + [{
                            "expr": cond_expr,
                            "line": i,
                        }]
                        i += 1
                        continue

                    # Not an if statement — collect side effects and move on
                    line_se = _extract_side_effects_line(stripped, i)
                    current_side_effects.extend(line_se)
                    i += 1
                    continue

            if if_m:
                cond_expr = if_m.group(1)
                parsed_cond = _parse_condition(cond_expr, i)

                # Find the if block extent
                if_block_start, if_block_end = _find_brace_block(lines, i)
                if if_block_start < 0:
                    # Single statement if (no braces, not single-line return)
                    if_block_start = i + 1
                    if_block_end = i + 2

                # Check for else / else-if chain
                chain = _extract_if_else_chain(lines, i, if_block_start,
                                               if_block_end, end_line)

                # Process each branch in the chain
                accumulated_negations = list(current_negated)

                for branch in chain:
                    branch_type = branch["type"]
                    branch_start = branch["body_start"]
                    branch_end = branch["body_end"]

                    if branch_type == "if" or branch_type == "else_if":
                        branch_cond = _parse_condition(
                            branch["condition"], branch["line"])
                        branch_conditions = current_conditions + [branch_cond]
                        branch_negated = list(accumulated_negations)

                        # Extract side effects within the block
                        block_se = _extract_side_effects_block(
                            lines, branch_start, branch_end)

                        # Check for immediate return in the block
                        has_explicit_return = _block_has_return(
                            lines, branch_start, branch_end)

                        if has_explicit_return:
                            # Walk into the block which will find the return
                            _walk(branch_start, branch_end,
                                  branch_conditions, branch_negated,
                                  depth + 1,
                                  current_side_effects)
                        else:
                            # Block doesn't return — walk it, then the code
                            # after the chain will also be walked with this
                            # branch's conditions
                            _walk(branch_start, branch_end,
                                  branch_conditions, branch_negated,
                                  depth + 1,
                                  current_side_effects)

                        # Negate this branch's condition for subsequent branches
                        accumulated_negations = accumulated_negations + [{
                            "expr": branch["condition"],
                            "line": branch["line"],
                        }]

                    elif branch_type == "else":
                        # All previous conditions were false
                        branch_conditions = list(current_conditions)
                        branch_negated = list(accumulated_negations)

                        _walk(branch_start, branch_end,
                              branch_conditions, branch_negated,
                              depth + 1,
                              current_side_effects)

                # Find the end of the entire if-else chain
                chain_end = chain[-1]["body_end"] if chain else if_block_end

                # If there's no else branch, code after the chain is also
                # reachable with all conditions negated
                has_else = any(b["type"] == "else" for b in chain)
                if not has_else:
                    # Check if all branches return (making post-chain dead code)
                    all_return = all(
                        _block_has_return(lines, b["body_start"], b["body_end"])
                        for b in chain
                    )
                    if not all_return:
                        # Continue past the chain with accumulated negations
                        _walk(chain_end, end_line,
                              current_conditions, accumulated_negations,
                              depth,
                              current_side_effects)
                    else:
                        # Fall-through path after chain where all branches
                        # returned: this path has all conditions negated
                        _walk(chain_end, end_line,
                              current_conditions, accumulated_negations,
                              depth,
                              current_side_effects)
                else:
                    # Has else — all paths go through the chain
                    # Code after the chain is reachable from any non-returning
                    # branch, but we've already walked those
                    pass

                return  # Chain fully handled by recursion

            # Non-branching line — collect side effects
            line_se = _extract_side_effects_line(stripped, i)
            current_side_effects.extend(line_se)
            i += 1

        # Reached end of block without explicit return → implicit void return
        if path_counter[0] < MAX_PATHS_PER_HANDLER:
            outcome = {
                "type": "success",
                "return_value": None,
                "line": end_line - 1,
            }
            all_paths.append(_make_path(
                path_counter, current_conditions, current_negated,
                outcome, current_side_effects, depth
            ))

    # Find function body boundaries (skip declaration line)
    func_body_start = 0
    func_body_end = len(lines)

    # Skip to the opening brace of the function
    for idx, line in enumerate(lines):
        if "{" in line:
            func_body_start = idx + 1
            break

    # Find matching closing brace
    brace_depth = 1
    for idx in range(func_body_start, len(lines)):
        brace_depth += lines[idx].count("{") - lines[idx].count("}")
        if brace_depth <= 0:
            func_body_end = idx
            break

    _walk(func_body_start, func_body_end, [], [], 0, [])

    return all_paths


def _parse_condition(expr, line_num):
    """Parse a condition expression into structured form.

    Args:
        expr: The condition text (e.g. "*(a1+0x48) == 0")
        line_num: Source line index

    Returns:
        dict with expr, line, type.
    """
    cond = {
        "expr": expr.strip(),
        "line": line_num,
        "type": "unknown",
    }

    text = expr.strip()

    for ctype, pattern in _CONDITION_CLASSIFIERS:
        if pattern.search(text):
            cond["type"] = ctype
            break

    return cond


def _extract_side_effects(code_block):
    """Find all side effects in a block of code text.

    Side effects include:
      - SendPacket calls
      - Database operations
      - State mutations (struct member writes)
      - Event triggers
      - Logging calls
      - Other function calls of interest

    Args:
        code_block: String of pseudocode

    Returns:
        List of side effect dicts.
    """
    effects = []
    seen = set()

    for line_num, line in enumerate(code_block.split("\n")):
        stripped = line.strip()
        line_effects = _extract_side_effects_line(stripped, line_num)
        for eff in line_effects:
            key = (eff["type"], eff.get("function", ""),
                   eff.get("target", ""), eff.get("operation", ""))
            if key not in seen:
                seen.add(key)
                effects.append(eff)

    return effects


def _extract_side_effects_line(line, line_num):
    """Extract side effects from a single line of pseudocode."""
    effects = []
    if not line:
        return effects

    # SendPacket
    for m in _RE_SEND_PACKET.finditer(line):
        func_name = m.group(1)
        args = m.group(2)
        target = "unknown"
        smsg_m = _RE_SMSG_NAME.search(args)
        if smsg_m:
            target = smsg_m.group(1)
        effects.append({
            "type": "send_packet",
            "function": func_name,
            "target": target,
            "line": line_num,
        })

    # Database operations
    for m in _DB_FUNCTIONS.finditer(line):
        effects.append({
            "type": "db_write",
            "operation": m.group(1),
            "line": line_num,
            "detail": line.strip()[:120],
        })

    # State mutations: writing to struct member via pointer
    if _RE_STATE_WRITE.search(line):
        effects.append({
            "type": "state_mutation",
            "line": line_num,
            "detail": line.strip()[:120],
        })

    # Event triggers
    for m in _RE_EVENT_TRIGGER.finditer(line):
        effects.append({
            "type": "event_trigger",
            "function": m.group(0).rstrip("("),
            "line": line_num,
        })

    # Logging (lower priority)
    if _RE_LOG_CALL.search(line):
        log_m = _RE_LOG_CALL.search(line)
        effects.append({
            "type": "log",
            "function": log_m.group(1),
            "line": line_num,
        })

    # General function calls (exclude already captured and control flow)
    _skip_funcs = {
        "if", "else", "for", "while", "switch", "return", "sizeof",
        "static_cast", "dynamic_cast", "reinterpret_cast", "const_cast",
        "LODWORD", "HIDWORD", "LOWORD", "HIWORD", "LOBYTE", "HIBYTE",
        "BYTE1", "BYTE2", "BYTE3", "COERCE_FLOAT", "COERCE_DOUBLE",
    }
    # Only record "interesting" function calls that aren't already captured
    if not effects:
        for m in _RE_FUNC_CALL.finditer(line):
            fname = m.group(1)
            if fname in _skip_funcs:
                continue
            if fname.startswith("_") or len(fname) < 3:
                continue
            # Skip getters / simple accessors
            if fname.startswith("Get") or fname.startswith("get"):
                continue
            effects.append({
                "type": "function_call",
                "function": fname,
                "line": line_num,
            })

    return effects


def _extract_side_effects_block(lines, start, end):
    """Extract side effects from a range of lines."""
    effects = []
    seen = set()
    for i in range(start, min(end, len(lines))):
        stripped = lines[i].strip()
        line_effects = _extract_side_effects_line(stripped, i)
        for eff in line_effects:
            key = (eff["type"], eff.get("function", ""),
                   eff.get("target", ""), eff.get("operation", ""))
            if key not in seen:
                seen.add(key)
                effects.append(eff)
    return effects


def _simplify_paths(paths):
    """Merge redundant paths and remove impossible ones.

    - Remove paths with contradictory conditions (A and NOT A)
    - Merge paths identical except for irrelevant conditions
    - Sort: error paths first, then by condition count

    Args:
        paths: List of path dicts

    Returns:
        Simplified list.
    """
    if not paths:
        return []

    # Phase 1: Remove contradictory paths
    valid_paths = []
    for path in paths:
        if _has_contradiction(path):
            continue
        valid_paths.append(path)

    # Phase 2: Merge paths with identical outcomes and compatible conditions
    merged = []
    used = set()

    for i, p1 in enumerate(valid_paths):
        if i in used:
            continue

        outcome1 = p1.get("outcome", {})
        best = p1

        for j, p2 in enumerate(valid_paths):
            if j <= i or j in used:
                continue
            outcome2 = p2.get("outcome", {})

            # Same outcome type and value
            if (outcome1.get("type") == outcome2.get("type") and
                    outcome1.get("return_value") == outcome2.get("return_value")):
                # Same side effects
                se1 = [(s["type"], s.get("target", ""), s.get("function", ""))
                       for s in p1.get("side_effects", [])]
                se2 = [(s["type"], s.get("target", ""), s.get("function", ""))
                       for s in p2.get("side_effects", [])]
                if set(se1) == set(se2):
                    # Merge: keep the one with fewer conditions
                    cond_count1 = len(p1.get("conditions", [])) + len(
                        p1.get("negated_conditions", []))
                    cond_count2 = len(p2.get("conditions", [])) + len(
                        p2.get("negated_conditions", []))
                    if cond_count2 < cond_count1:
                        best = p2
                    used.add(j)

        merged.append(best)
        used.add(i)

    # Phase 3: Sort — error paths first, then by condition count
    def sort_key(p):
        outcome_type = p.get("outcome", {}).get("type", "")
        type_order = {
            "error_return": 0,
            "send_response": 1,
            "call_handler": 2,
            "success": 3,
        }
        order = type_order.get(outcome_type, 4)
        cond_count = len(p.get("conditions", [])) + len(
            p.get("negated_conditions", []))
        return (order, cond_count)

    merged.sort(key=sort_key)

    # Re-number path IDs
    for idx, path in enumerate(merged):
        path["path_id"] = idx

    return merged


# ===================================================================
# Internal helpers
# ===================================================================


def _make_path(counter, conditions, negated, outcome, side_effects, depth):
    """Create a path dict and increment the counter."""
    path = {
        "path_id": counter[0],
        "conditions": list(conditions),
        "negated_conditions": list(negated),
        "outcome": outcome,
        "side_effects": list(side_effects),
        "depth": depth,
    }
    counter[0] += 1
    return path


def _classify_return(ret_val, line_num):
    """Classify a return value into an outcome type."""
    if not ret_val or ret_val in ("", "void"):
        return {
            "type": "success",
            "return_value": None,
            "line": line_num,
        }

    # Non-zero integer return is typically an error
    try:
        int_val = int(ret_val, 0)
        if int_val == 0:
            return {
                "type": "success",
                "return_value": "0",
                "line": line_num,
            }
        else:
            return {
                "type": "error_return",
                "return_value": ret_val,
                "line": line_num,
            }
    except (ValueError, TypeError):
        pass

    # Named constant that looks like an error
    if re.match(r'^[A-Z_]+ERR|^ERROR|^FAIL|^INVALID', ret_val, re.IGNORECASE):
        return {
            "type": "error_return",
            "return_value": ret_val,
            "line": line_num,
        }

    # Return value that is a function call (delegation)
    if "(" in ret_val:
        return {
            "type": "call_handler",
            "function": ret_val.split("(")[0].strip(),
            "return_value": ret_val,
            "line": line_num,
        }

    # Numeric-looking hex
    if ret_val.startswith("0x"):
        return {
            "type": "error_return",
            "return_value": ret_val,
            "line": line_num,
        }

    # Default: treat as success with a value
    return {
        "type": "success",
        "return_value": ret_val,
        "line": line_num,
    }


def _find_brace_block(lines, start_idx):
    """Find the brace-delimited block starting at or near start_idx.

    Returns (body_start, body_end) where body_start is the line after '{'
    and body_end is the line of the matching '}'.
    Returns (-1, -1) if no block found.
    """
    # Find opening brace
    brace_line = -1
    for i in range(start_idx, min(start_idx + 3, len(lines))):
        if "{" in lines[i]:
            brace_line = i
            break

    if brace_line < 0:
        return (-1, -1)

    body_start = brace_line + 1
    depth = 0
    for i in range(brace_line, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0:
            return (body_start, i)

    return (body_start, len(lines))


def _extract_cases(lines, block_start, block_end):
    """Extract case labels and their line ranges from a switch block."""
    cases = []

    for i in range(block_start, block_end):
        stripped = lines[i].strip()

        case_m = re.match(
            r'case\s+(0x[0-9A-Fa-f]+|\d+|[A-Z_]\w*)\s*:', stripped)
        default_m = re.match(r'default\s*:', stripped)

        if case_m:
            cases.append({
                "value": case_m.group(1),
                "start": i + 1,
                "end": block_end,  # will be narrowed below
                "is_default": False,
                "is_fallthrough": False,
            })
        elif default_m:
            cases.append({
                "value": "default",
                "start": i + 1,
                "end": block_end,
                "is_default": True,
                "is_fallthrough": False,
            })

    # Narrow each case's end to the next case/default label or break
    for idx in range(len(cases)):
        if idx + 1 < len(cases):
            cases[idx]["end"] = cases[idx + 1]["start"] - 1

        # Check for break within the case
        for j in range(cases[idx]["start"], cases[idx]["end"]):
            if j >= len(lines):
                break
            s = lines[j].strip()
            if s == "break;" or s.startswith("break;"):
                cases[idx]["end"] = j
                break

        # Detect fallthrough: no break and no return before next case
        has_break = False
        has_return = False
        for j in range(cases[idx]["start"], cases[idx]["end"]):
            if j >= len(lines):
                break
            s = lines[j].strip()
            if s.startswith("break"):
                has_break = True
            if s.startswith("return"):
                has_return = True
        cases[idx]["is_fallthrough"] = not has_break and not has_return

    return cases


def _extract_if_else_chain(lines, if_line, if_block_start, if_block_end,
                           scope_end):
    """Extract a complete if / else-if / else chain.

    Returns a list of branch descriptors:
    [
        {"type": "if", "condition": "...", "line": N,
         "body_start": N, "body_end": M},
        {"type": "else_if", "condition": "...", "line": N, ...},
        {"type": "else", "condition": None, "line": N, ...},
    ]
    """
    chain = []

    # The initial if
    if_m = re.match(r'\s*if\s*\(\s*(.+?)\s*\)\s*\{?\s*$', lines[if_line].strip())
    if not if_m:
        # Try single-line match
        if_m = re.match(r'\s*if\s*\(\s*(.+?)\s*\)', lines[if_line].strip())
    if not if_m:
        return chain

    chain.append({
        "type": "if",
        "condition": if_m.group(1),
        "line": if_line,
        "body_start": if_block_start,
        "body_end": if_block_end,
    })

    # Look for else-if / else after the if block
    cursor = if_block_end
    # Skip the closing brace line
    if cursor < len(lines) and "}" in lines[cursor]:
        cursor += 1

    while cursor < scope_end and cursor < len(lines):
        stripped = lines[cursor].strip()

        # } else if (...)
        elif_m = re.match(
            r'(?:\}\s*)?else\s+if\s*\(\s*(.+?)\s*\)\s*\{?\s*$', stripped)
        if elif_m:
            block_start, block_end = _find_brace_block(lines, cursor)
            if block_start < 0:
                block_start = cursor + 1
                block_end = cursor + 2

            chain.append({
                "type": "else_if",
                "condition": elif_m.group(1),
                "line": cursor,
                "body_start": block_start,
                "body_end": block_end,
            })
            cursor = block_end
            if cursor < len(lines) and "}" in lines[cursor]:
                cursor += 1
            continue

        # } else {
        else_m = re.match(r'(?:\}\s*)?else\s*\{?\s*$', stripped)
        if else_m:
            block_start, block_end = _find_brace_block(lines, cursor)
            if block_start < 0:
                block_start = cursor + 1
                block_end = cursor + 2

            chain.append({
                "type": "else",
                "condition": None,
                "line": cursor,
                "body_start": block_start,
                "body_end": block_end,
            })
            break  # else is always last

        # Check for } else on same line as closing brace
        if stripped.startswith("}") and "else" in stripped:
            # Combined closing brace + else
            elif_combined = re.match(
                r'\}\s*else\s+if\s*\(\s*(.+?)\s*\)\s*\{?\s*$', stripped)
            if elif_combined:
                block_start, block_end = _find_brace_block(lines, cursor)
                if block_start < 0:
                    block_start = cursor + 1
                    block_end = cursor + 2
                chain.append({
                    "type": "else_if",
                    "condition": elif_combined.group(1),
                    "line": cursor,
                    "body_start": block_start,
                    "body_end": block_end,
                })
                cursor = block_end
                if cursor < len(lines) and "}" in lines[cursor]:
                    cursor += 1
                continue

            else_combined = re.match(r'\}\s*else\s*\{?\s*$', stripped)
            if else_combined:
                block_start, block_end = _find_brace_block(lines, cursor)
                if block_start < 0:
                    block_start = cursor + 1
                    block_end = cursor + 2
                chain.append({
                    "type": "else",
                    "condition": None,
                    "line": cursor,
                    "body_start": block_start,
                    "body_end": block_end,
                })
                break

        # Not part of the chain — stop
        break

    return chain


def _block_has_return(lines, start, end):
    """Check whether a block of lines contains a return statement
    at its top level (not nested in sub-blocks)."""
    depth = 0
    for i in range(start, min(end, len(lines))):
        line = lines[i]
        depth += line.count("{") - line.count("}")
        stripped = line.strip()
        if depth <= 0 and re.match(r'return\s', stripped):
            return True
        # Single-line if-return at top level
        if depth <= 0 and re.match(r'if\s*\(.+\)\s*return\s', stripped):
            # This is a conditional return, not guaranteed
            pass
    # Check last line specifically
    if start < len(lines) and end - 1 < len(lines) and end > start:
        last = lines[min(end - 1, len(lines) - 1)].strip()
        if last.startswith("return"):
            return True
    return False


def _has_contradiction(path):
    """Check if a path has contradictory conditions (A and NOT A)."""
    cond_exprs = set()
    for c in path.get("conditions", []):
        cond_exprs.add(c.get("expr", ""))

    for nc in path.get("negated_conditions", []):
        neg_expr = nc.get("expr", "")
        if neg_expr in cond_exprs:
            return True

    return False


def _path_label(outcome):
    """Create a short human-readable label for a path outcome."""
    otype = outcome.get("type", "unknown")
    if otype == "error_return":
        rv = outcome.get("return_value", "?")
        return f"Error return ({rv})"
    elif otype == "success":
        rv = outcome.get("return_value")
        if rv and rv != "0":
            return f"Success (returns {rv})"
        return "Success"
    elif otype == "send_response":
        pkt = outcome.get("response_packet", "?")
        return f"Send response ({pkt})"
    elif otype == "call_handler":
        func = outcome.get("function", "?")
        return f"Delegate to {func}"
    return "Unknown outcome"


def _format_outcome(outcome):
    """Format an outcome for display."""
    otype = outcome.get("type", "unknown")
    line = outcome.get("line", "?")

    if otype == "error_return":
        rv = outcome.get("return_value", "?")
        return f"Returns error {rv} (line {line})"
    elif otype == "success":
        rv = outcome.get("return_value")
        if rv:
            return f"Returns {rv} — success (line {line})"
        return f"Returns void — success (line {line})"
    elif otype == "send_response":
        pkt = outcome.get("response_packet", "?")
        return f"Sends {pkt} (line {line})"
    elif otype == "call_handler":
        func = outcome.get("function", "?")
        return f"Delegates to {func}() (line {line})"
    return f"Unknown outcome at line {line}"


def _opcode_to_handler(opcode_name):
    """Convert CMSG_FOO_BAR to HandleFooBar."""
    prefix_end = opcode_name.find("_")
    if prefix_end < 0:
        return opcode_name
    base = opcode_name[prefix_end + 1:]
    parts = base.split("_")
    return "Handle" + "".join(p.capitalize() for p in parts)


def _sanitize(name):
    """Sanitize a name for use as a C++ identifier."""
    return re.sub(r'[^A-Za-z0-9_]', '_', name)


def _find_tc_handler_source(tc_dir, func_name):
    """Find and extract TC handler function source code."""
    handlers_dir = os.path.join(tc_dir, "src", "server", "game", "Handlers")
    if not os.path.isdir(handlers_dir):
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
            rf'void\s+\w+::{re.escape(func_name)}\s*\([^)]*\)\s*\{{',
            re.MULTILINE
        )
        match = pattern.search(content)
        if not match:
            continue

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
