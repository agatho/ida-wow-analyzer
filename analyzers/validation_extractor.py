"""
Validation Rule Extractor
Parses decompiled handler pseudocode to extract server-side validation
patterns: range checks, null checks, permission checks, state guards.

Compares extracted validations against TrinityCore handler source to
find missing checks — a direct code quality improvement tool.
"""

import json
import re

import ida_funcs
import ida_hexrays
import ida_name

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# Patterns that indicate validation/guard checks in pseudocode
VALIDATION_PATTERNS = [
    # Range checks: if (x > MAX || x < 0) return ERROR;
    {
        "name": "range_check",
        "regex": re.compile(
            r'if\s*\(\s*(\w+)\s*([><=!]+)\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
            r'.*?return\s+(0x[0-9A-Fa-f]+|\d+|[A-Z_]+)',
            re.DOTALL
        ),
        "description": "Range/boundary check",
    },
    # Null/zero checks: if (!ptr) return;  or if (val == 0) return;
    {
        "name": "null_check",
        "regex": re.compile(
            r'if\s*\(\s*!(\w+)\s*\).*?return',
            re.DOTALL
        ),
        "description": "Null/zero guard",
    },
    # Equality checks against constants: if (state != EXPECTED) return;
    {
        "name": "state_guard",
        "regex": re.compile(
            r'if\s*\(\s*\*?\(?\s*\w+\s*\+?\s*(?:0x[0-9A-Fa-f]+|\d+)?\s*\)?\s*'
            r'([!=]=)\s*(0x[0-9A-Fa-f]+|\d+)\s*\).*?return',
            re.DOTALL
        ),
        "description": "State/flag guard",
    },
    # Function call checks: if (!HasPermission(...)) return;
    {
        "name": "permission_check",
        "regex": re.compile(
            r'if\s*\(\s*!?\s*(\w+)\s*\([^)]*\)\s*([!=<>]=?)\s*'
            r'(0x[0-9A-Fa-f]+|\d+)?\s*\).*?return',
            re.DOTALL
        ),
        "description": "Function-based permission/capability check",
    },
    # Combat/busy checks: if (IsInCombat()) return;
    {
        "name": "busy_check",
        "regex": re.compile(
            r'if\s*\(\s*\w+(?:->|\.)\s*(IsInCombat|IsDead|IsFlying|IsMounted|'
            r'HasUnitState|IsInFlight|IsCharmed|HasAura)\s*\(',
            re.IGNORECASE
        ),
        "description": "Player state/busy check",
    },
]

# Return value patterns that indicate error codes
ERROR_RETURN_PATTERN = re.compile(
    r'return\s+(0x[0-9A-Fa-f]+|\d+|[A-Z][A-Z_]+\d*)\s*;'
)


def extract_validations(session, handler_ea=None, system_filter=None):
    """Extract validation rules from handler functions.

    Args:
        session: PluginSession
        handler_ea: Specific handler address (None = all handlers)
        system_filter: Only analyze handlers in this system (e.g. 'housing')

    Returns number of validation rules extracted.
    """
    db = session.db
    count = 0

    if handler_ea:
        handlers = [{"handler_ea": handler_ea, "tc_name": "manual",
                      "direction": "CMSG", "internal_index": 0}]
    else:
        query = "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL"
        if system_filter:
            query += f" AND tc_name LIKE '%{system_filter}%'"
        handlers = db.fetchall(query)

    msg_info(f"Extracting validations from {len(handlers)} handlers...")
    total_rules = 0

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"] or f"handler_0x{ea:X}"

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        rules = _extract_rules_from_pseudocode(pseudocode, ea)
        if not rules:
            continue

        # Store rules in knowledge DB
        db.execute(
            """INSERT OR REPLACE INTO kv_store (key, value, updated_at)
               VALUES (?, ?, ?)""",
            (f"validations:{tc_name}",
             json.dumps(rules),
             __import__("time").time())
        )
        total_rules += len(rules)
        count += 1

        if count % 50 == 0:
            db.commit()
            msg_info(f"  Processed {count} handlers, {total_rules} rules so far...")

    db.commit()
    msg_info(f"Extracted {total_rules} validation rules from {count} handlers")
    return total_rules


def _extract_rules_from_pseudocode(pseudocode, handler_ea):
    """Parse pseudocode for validation patterns."""
    rules = []
    lines = pseudocode.split("\n")

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("if"):
            continue

        # Get surrounding context (the if block)
        block = _get_if_block(lines, i)

        for pattern in VALIDATION_PATTERNS:
            match = pattern["regex"].search(block)
            if match:
                # Extract the return value if present
                error_match = ERROR_RETURN_PATTERN.search(block)
                error_code = error_match.group(1) if error_match else None

                rule = {
                    "type": pattern["name"],
                    "description": pattern["description"],
                    "condition": stripped[:200],
                    "error_code": error_code,
                    "line_index": i,
                    "handler_ea": handler_ea,
                    "raw_block": block[:500],
                }

                # Try to extract the variable/field being checked
                if match.groups():
                    rule["checked_value"] = match.group(1)
                    if len(match.groups()) > 1:
                        rule["comparand"] = match.group(2)

                rules.append(rule)
                break  # one pattern per if-statement

    return rules


def _get_if_block(lines, start_idx):
    """Extract the full if-block starting at line index."""
    block_lines = [lines[start_idx]]
    brace_depth = lines[start_idx].count("{") - lines[start_idx].count("}")

    for j in range(start_idx + 1, min(start_idx + 10, len(lines))):
        block_lines.append(lines[j])
        brace_depth += lines[j].count("{") - lines[j].count("}")
        if brace_depth <= 0 and ("return" in lines[j] or "}" in lines[j]):
            break

    return "\n".join(block_lines)


def compare_validations_with_tc(session, tc_handler_path=None):
    """Compare extracted binary validations against TC handler source.

    Returns a list of missing validations per handler.
    """
    db = session.db
    cfg = session.cfg
    tc_dir = cfg.tc_source_dir

    if not tc_dir:
        msg_warn("TrinityCore source not configured — cannot compare validations")
        return []

    missing_report = []

    # Get all handlers with extracted validations
    rows = db.fetchall(
        "SELECT key, value FROM kv_store WHERE key LIKE 'validations:%'")

    for row in rows:
        handler_name = row["key"].replace("validations:", "")
        binary_rules = json.loads(row["value"])

        # Find the corresponding TC handler source
        tc_source = _find_tc_handler_source(tc_dir, handler_name)
        if not tc_source:
            continue

        # Check which binary validations are missing from TC
        tc_checks = _extract_tc_checks(tc_source)
        missing = []

        for rule in binary_rules:
            if not _is_check_present_in_tc(rule, tc_checks):
                missing.append(rule)

        if missing:
            missing_report.append({
                "handler": handler_name,
                "binary_total": len(binary_rules),
                "tc_total": len(tc_checks),
                "missing_count": len(missing),
                "missing": missing,
            })

    # Store report
    db.kv_set("validation_comparison_report", {
        "handlers_compared": len(rows),
        "handlers_with_gaps": len(missing_report),
        "items": missing_report,
    })
    db.commit()

    total_missing = sum(r["missing_count"] for r in missing_report)
    msg_info(f"Validation comparison: {total_missing} missing checks "
             f"across {len(missing_report)} handlers")
    return missing_report


def _find_tc_handler_source(tc_dir, handler_name):
    """Find TC handler source code by searching Handlers directory."""
    handlers_dir = os.path.join(tc_dir, "src", "server", "game", "Handlers")
    if not os.path.isdir(handlers_dir):
        return None

    # Convert opcode name to handler function name
    # CMSG_HOUSING_DECOR_PLACE → HandleHousingDecorPlace
    func_name = None
    if handler_name.startswith("CMSG_") or handler_name.startswith("SMSG_"):
        parts = handler_name.split("_")[1:]  # remove CMSG/SMSG
        func_name = "Handle" + "".join(p.capitalize() for p in parts)
    else:
        func_name = handler_name

    import os
    for fname in os.listdir(handlers_dir):
        if not fname.endswith(".cpp"):
            continue
        filepath = os.path.join(handlers_dir, fname)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if func_name and func_name in content:
                # Extract the function body
                start = content.index(func_name)
                # Find the opening brace
                brace_pos = content.index("{", start)
                depth = 1
                pos = brace_pos + 1
                while depth > 0 and pos < len(content):
                    if content[pos] == "{":
                        depth += 1
                    elif content[pos] == "}":
                        depth -= 1
                    pos += 1
                return content[start:pos]
        except (ValueError, IOError):
            continue
    return None


def _extract_tc_checks(tc_source):
    """Extract validation-like checks from TC source code."""
    checks = []
    for line in tc_source.split("\n"):
        stripped = line.strip()
        if stripped.startswith("if") and "return" in stripped:
            checks.append(stripped)
        elif stripped.startswith("if") and "SendPacket" not in stripped:
            checks.append(stripped)
    return checks


def _is_check_present_in_tc(binary_rule, tc_checks):
    """Heuristic: is a binary validation rule present in TC source?

    Matches by checking if similar comparison patterns exist.
    """
    rule_type = binary_rule["type"]
    checked = binary_rule.get("checked_value", "")
    comparand = binary_rule.get("comparand", "")

    for tc_check in tc_checks:
        tc_lower = tc_check.lower()

        # For null checks, look for similar null guard
        if rule_type == "null_check" and ("!" in tc_check or "nullptr" in tc_check):
            return True

        # For range checks, look for similar comparison
        if rule_type == "range_check" and comparand:
            if comparand in tc_check:
                return True

        # For busy checks, look for same function name
        if rule_type == "busy_check" and checked:
            if checked.lower() in tc_lower:
                return True

        # For state guards, look for similar enum comparison
        if rule_type == "state_guard":
            error_code = binary_rule.get("error_code", "")
            if error_code and error_code in tc_check:
                return True

    return False


import os
