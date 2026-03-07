"""
Conformance Scoring Engine
Compares TrinityCore handler implementations against the binary's actual
behavior by analyzing structural similarity: call graph shape, branch
count, validation patterns, and serialization sequence.

Produces a per-handler and per-system conformance score (0-100%).
"""

import json
import os
import re

import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


def analyze_conformance(session, system_filter=None):
    """Score conformance of TC handlers against binary handlers.

    Args:
        session: PluginSession
        system_filter: Only score handlers matching this pattern (e.g. 'Housing')

    Returns total number of handlers scored.
    """
    db = session.db
    cfg = session.cfg
    tc_dir = cfg.tc_source_dir

    if not tc_dir:
        msg_warn("TrinityCore source not configured — conformance scoring requires it")
        return 0

    # Get all handlers that have both a binary EA and a TC name
    query = ("SELECT * FROM opcodes WHERE handler_ea IS NOT NULL "
             "AND tc_name IS NOT NULL")
    if system_filter:
        query += f" AND tc_name LIKE '%{system_filter}%'"

    handlers = db.fetchall(query)
    if not handlers:
        msg_warn("No matched handlers found. Run opcode analysis first.")
        return 0

    msg_info(f"Scoring conformance for {len(handlers)} handlers...")

    scores = []
    system_totals = {}

    for handler in handlers:
        ea = handler["handler_ea"]
        tc_name = handler["tc_name"]

        # Analyze binary handler
        binary_profile = _profile_binary_handler(ea)
        if not binary_profile:
            continue

        # Analyze TC handler
        tc_profile = _profile_tc_handler(tc_dir, tc_name)
        if not tc_profile:
            continue

        # Compare profiles and compute score
        score = _compute_conformance_score(binary_profile, tc_profile)

        score_entry = {
            "tc_name": tc_name,
            "handler_ea": ea,
            "score": score["total"],
            "details": score,
            "binary_profile": binary_profile,
            "tc_profile": tc_profile,
        }
        scores.append(score_entry)

        # Aggregate by system
        system = _extract_system(tc_name)
        if system not in system_totals:
            system_totals[system] = {"scores": [], "count": 0}
        system_totals[system]["scores"].append(score["total"])
        system_totals[system]["count"] += 1

    # Compute system averages
    system_scores = {}
    for system, data in system_totals.items():
        if data["scores"]:
            avg = sum(data["scores"]) / len(data["scores"])
            system_scores[system] = {
                "average_score": round(avg, 1),
                "handler_count": data["count"],
                "min_score": min(data["scores"]),
                "max_score": max(data["scores"]),
            }

    # Sort by score (worst first — most need attention)
    scores.sort(key=lambda s: s["score"])

    # Store report
    report = {
        "total_handlers": len(scores),
        "average_score": round(
            sum(s["score"] for s in scores) / max(len(scores), 1), 1),
        "system_scores": system_scores,
        "handlers": [
            {
                "tc_name": s["tc_name"],
                "handler_ea": f"0x{s['handler_ea']:X}",
                "score": s["score"],
                "call_score": s["details"]["call_score"],
                "branch_score": s["details"]["branch_score"],
                "validation_score": s["details"]["validation_score"],
                "size_score": s["details"]["size_score"],
                "missing": s["details"].get("missing", []),
            }
            for s in scores
        ],
    }

    db.kv_set("conformance_report", report)
    db.commit()

    msg_info(f"Conformance scoring complete: {len(scores)} handlers, "
             f"average {report['average_score']}%")
    for sys_name, sys_data in sorted(system_scores.items(),
                                      key=lambda x: x[1]["average_score"]):
        msg_info(f"  {sys_name}: {sys_data['average_score']}% "
                 f"({sys_data['handler_count']} handlers)")

    return len(scores)


def _profile_binary_handler(ea):
    """Build a structural profile of a binary handler function."""
    func = ida_funcs.get_func(ea)
    if not func:
        return None

    profile = {
        "size": func.size(),
        "callees": [],
        "callee_count": 0,
        "branch_count": 0,
        "return_count": 0,
        "validation_count": 0,
    }

    # Count callees
    callee_set = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                target_func = ida_funcs.get_func(xref.to)
                if target_func and target_func.start_ea != func.start_ea:
                    callee_name = ida_name.get_name(target_func.start_ea)
                    callee_set.add(target_func.start_ea)
                    if callee_name and not callee_name.startswith("sub_"):
                        profile["callees"].append(callee_name)

    profile["callee_count"] = len(callee_set)

    # Decompile for structural analysis
    pseudocode = get_decompiled_text(ea)
    if pseudocode:
        profile["branch_count"] = pseudocode.count("if (")
        profile["return_count"] = pseudocode.count("return")
        # Count early returns (likely validations)
        lines = pseudocode.split("\n")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("if") and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if next_line.startswith("return"):
                    profile["validation_count"] += 1

    return profile


def _profile_tc_handler(tc_dir, tc_name):
    """Build a structural profile of a TC handler from source."""
    handlers_dir = os.path.join(tc_dir, "src", "server", "game", "Handlers")
    if not os.path.isdir(handlers_dir):
        return None

    # Convert opcode name to handler function name
    func_name = _opcode_to_handler_name(tc_name)

    for fname in os.listdir(handlers_dir):
        if not fname.endswith(".cpp"):
            continue
        filepath = os.path.join(handlers_dir, fname)
        source = _extract_function_body(filepath, func_name)
        if source:
            return _profile_from_source(source)

    return None


def _extract_function_body(filepath, func_name):
    """Extract a function body from a C++ source file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except IOError:
        return None

    # Find function definition
    pattern = re.compile(
        rf'void\s+\w+::{re.escape(func_name)}\s*\([^)]*\)\s*\{{',
        re.MULTILINE
    )
    match = pattern.search(content)
    if not match:
        return None

    # Extract body by brace matching
    start = match.start()
    brace_pos = content.index("{", match.start())
    depth = 1
    pos = brace_pos + 1
    while depth > 0 and pos < len(content):
        if content[pos] == "{":
            depth += 1
        elif content[pos] == "}":
            depth -= 1
        pos += 1

    return content[start:pos]


def _profile_from_source(source):
    """Build a profile from C++ source code."""
    profile = {
        "size": len(source),
        "callees": [],
        "callee_count": 0,
        "branch_count": 0,
        "return_count": 0,
        "validation_count": 0,
    }

    # Count function calls (simplified: word followed by '(')
    call_pattern = re.compile(r'\b([A-Z]\w+|[a-z]\w+)\s*\(')
    calls = set(m.group(1) for m in call_pattern.finditer(source))
    # Filter out keywords
    keywords = {"if", "for", "while", "switch", "return", "sizeof", "static_cast",
                "dynamic_cast", "reinterpret_cast", "const_cast"}
    calls -= keywords
    profile["callees"] = sorted(calls)
    profile["callee_count"] = len(calls)

    profile["branch_count"] = source.count("if (") + source.count("if(")
    profile["return_count"] = source.count("return")

    # Count early-return validations
    lines = source.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("if") and i + 1 < len(lines):
            next_stripped = lines[i + 1].strip()
            if next_stripped.startswith("return") or "return" in stripped:
                profile["validation_count"] += 1

    return profile


def _compute_conformance_score(binary, tc):
    """Compute conformance score between binary and TC profiles.

    Scoring dimensions (each 0-100, weighted):
      - Call similarity (30%): How many binary callees appear in TC
      - Branch similarity (20%): Similar branching complexity
      - Validation coverage (30%): TC has same number of guard checks
      - Size similarity (20%): Similar function size (proxy for completeness)
    """
    # Call similarity: what fraction of binary callees are in TC
    if binary["callee_count"] > 0:
        # Match by name substring (binary names may be mangled)
        matched_calls = 0
        for bin_callee in binary["callees"]:
            bin_lower = bin_callee.lower()
            for tc_callee in tc["callees"]:
                if (bin_lower in tc_callee.lower() or
                        tc_callee.lower() in bin_lower):
                    matched_calls += 1
                    break
        call_score = min(100, (matched_calls / binary["callee_count"]) * 100)
    else:
        call_score = 50  # unknown

    # Branch similarity: penalize if TC has significantly fewer branches
    if binary["branch_count"] > 0:
        ratio = tc["branch_count"] / binary["branch_count"]
        branch_score = min(100, ratio * 100)
    else:
        branch_score = 100 if tc["branch_count"] == 0 else 50

    # Validation coverage: TC should have at least as many guard checks
    if binary["validation_count"] > 0:
        ratio = tc["validation_count"] / binary["validation_count"]
        validation_score = min(100, ratio * 100)
    else:
        validation_score = 100

    # Size similarity: similar line count suggests similar completeness
    if binary["size"] > 0:
        # TC source is typically 2-4x verbose vs decompiled pseudocode
        normalized_tc_size = tc["size"] / 3.0
        ratio = min(normalized_tc_size, binary["size"]) / max(normalized_tc_size, binary["size"])
        size_score = ratio * 100
    else:
        size_score = 50

    # Weighted total
    total = (
        call_score * 0.30 +
        branch_score * 0.20 +
        validation_score * 0.30 +
        size_score * 0.20
    )

    # Build missing items list
    missing = []
    if validation_score < 80:
        missing.append(f"Missing ~{binary['validation_count'] - tc['validation_count']} "
                       f"validation checks")
    if call_score < 70:
        missing.append(f"Missing ~{binary['callee_count'] - len(tc['callees'])} "
                       f"function calls")
    if branch_score < 60:
        missing.append(f"Missing ~{binary['branch_count'] - tc['branch_count']} "
                       f"branch conditions")

    return {
        "total": round(total, 1),
        "call_score": round(call_score, 1),
        "branch_score": round(branch_score, 1),
        "validation_score": round(validation_score, 1),
        "size_score": round(size_score, 1),
        "missing": missing,
    }


def _opcode_to_handler_name(opcode_name):
    """Convert CMSG_FOO_BAR to HandleFooBar."""
    prefix_end = opcode_name.find("_")
    if prefix_end < 0:
        return opcode_name
    base = opcode_name[prefix_end + 1:]
    parts = base.split("_")
    return "Handle" + "".join(p.capitalize() for p in parts)


def _extract_system(tc_name):
    """Extract game system from opcode name."""
    name_upper = tc_name.upper()
    systems = {
        "HOUSING": "Housing", "HOUSE": "Housing", "DECOR": "Housing",
        "NEIGHBORHOOD": "Housing", "INTERIOR": "Housing",
        "QUEST": "Quest", "SPELL": "Combat", "AURA": "Combat",
        "GUILD": "Social", "CHAT": "Social", "MAIL": "Social",
        "BATTLEGROUND": "PvP", "ARENA": "PvP",
        "AUCTION": "Auction", "TRADE": "Crafting",
        "TALENT": "Talent", "PET": "Pet",
        "ACHIEVEMENT": "Achievement", "LOOT": "Loot",
        "MOVEMENT": "Movement", "ITEM": "Item",
        "CHARACTER": "Character", "PLAYER": "Character",
    }
    for keyword, system in systems.items():
        if keyword in name_upper:
            return system
    return "Other"


def get_conformance_report(session):
    """Retrieve the stored conformance report."""
    return session.db.kv_get("conformance_report") or {}
