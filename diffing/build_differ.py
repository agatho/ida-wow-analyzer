"""
Cross-Build Diffing Engine
Compares function signatures between two WoW builds to track
how opcodes, handlers, and structures migrate across patches.

Strategies:
  1. Exact match — identical bytes
  2. Signature match — same prologue/epilogue pattern
  3. String reference match — same string constants referenced
  4. Callgraph match — same callee set
  5. SimHash match — similar instruction sequences
"""

import json
import os
import time

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


def diff_builds(session, old_build_dir, new_build_dir=None):
    """Diff two builds and store results in the knowledge DB.

    Args:
        session: PluginSession (uses current IDB as "new" build)
        old_build_dir: Path to previous build's extraction directory
        new_build_dir: Path to new build's extraction (default: current)
    """
    db = session.db
    cfg = session.cfg

    old_build = _detect_build_number(old_build_dir)
    new_build = cfg.build_number

    msg_info(f"Diffing build {old_build} → {new_build}")
    start = time.time()

    # Load old build data
    old_functions = _load_functions(old_build_dir, old_build)
    if not old_functions:
        msg_error(f"No function data found in {old_build_dir}")
        return 0

    msg_info(f"Old build: {len(old_functions)} functions")

    # Load new build data from current DB
    new_functions = {}
    for row in db.fetchall("SELECT * FROM functions WHERE name IS NOT NULL"):
        new_functions[row["name"]] = {
            "ea": row["ea"],
            "rva": row["rva"],
            "name": row["name"],
            "size": row["size"],
        }

    msg_info(f"New build: {len(new_functions)} functions")

    # Strategy 1: Exact name match
    matched = 0
    for name, old_func in old_functions.items():
        if name in new_functions:
            new_func = new_functions[name]
            confidence = 1.0 if old_func.get("size") == new_func.get("size") else 0.9

            db.execute(
                """INSERT OR REPLACE INTO diffing
                   (old_ea, new_ea, match_type, confidence,
                    old_build, new_build)
                   VALUES (?, ?, 'name_match', ?, ?, ?)""",
                (old_func["ea"], new_func["ea"], confidence,
                 old_build, new_build))
            matched += 1

            if matched % 1000 == 0:
                db.commit()

    db.commit()

    # Strategy 2: SimHash similarity (if available)
    simhash_matches = _diff_simhash(session, old_build_dir, old_build,
                                     new_build)
    total = matched + simhash_matches

    elapsed = time.time() - start
    msg_info(f"Diff complete: {total} matches ({matched} name, "
             f"{simhash_matches} simhash) in {elapsed:.1f}s")

    db.kv_set("last_diff", {
        "old_build": old_build,
        "new_build": new_build,
        "name_matches": matched,
        "simhash_matches": simhash_matches,
        "total": total,
        "elapsed_seconds": elapsed,
    })
    db.commit()

    return total


def _load_functions(build_dir, build_number):
    """Load function data from a build's extraction directory."""
    functions = {}

    # Try wow_functions_XXXXX.json
    for candidate in [
        os.path.join(build_dir, f"wow_functions_{build_number}.json"),
        os.path.join(build_dir, "wow_functions.json"),
    ]:
        if os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8") as f:
                data = json.load(f)
            for func in data.get("functions", []):
                name = func.get("name")
                if name:
                    rva = func.get("rva")
                    if isinstance(rva, str):
                        rva = int(rva, 16)
                    functions[name] = {
                        "ea": rva,  # use RVA as ea for old builds
                        "rva": rva,
                        "name": name,
                        "size": func.get("size", 0),
                    }
            break

    return functions


def _diff_simhash(session, old_build_dir, old_build, new_build):
    """Compare functions using SimHash similarity scores."""
    db = session.db

    old_simhash_file = None
    for candidate in [
        os.path.join(old_build_dir, f"wow_simhash_{old_build}.json"),
        os.path.join(old_build_dir, "wow_simhash.json"),
        os.path.join(old_build_dir, "wow_simhash_prev.json"),
    ]:
        if os.path.isfile(candidate):
            old_simhash_file = candidate
            break

    if not old_simhash_file:
        return 0

    try:
        with open(old_simhash_file, "r", encoding="utf-8") as f:
            old_hashes = json.load(f)
    except Exception:
        return 0

    # Load current build's simhashes if available
    new_simhash_file = None
    cfg = session.cfg
    ext_dir = cfg.extraction_dir
    if ext_dir:
        for candidate in [
            os.path.join(ext_dir, f"wow_simhash_{new_build}.json"),
            os.path.join(ext_dir, "wow_simhash.json"),
        ]:
            if os.path.isfile(candidate):
                new_simhash_file = candidate
                break

    if not new_simhash_file:
        return 0

    try:
        with open(new_simhash_file, "r", encoding="utf-8") as f:
            new_hashes = json.load(f)
    except Exception:
        return 0

    # Build lookup: hash → [functions]
    old_hash_map = {}
    old_funcs = old_hashes if isinstance(old_hashes, list) else old_hashes.get("functions", [])
    for func in old_funcs:
        h = func.get("simhash", func.get("hash"))
        if h:
            old_hash_map.setdefault(h, []).append(func)

    # Match new functions against old by hash
    matched = 0
    new_funcs = new_hashes if isinstance(new_hashes, list) else new_hashes.get("functions", [])
    for func in new_funcs:
        h = func.get("simhash", func.get("hash"))
        if h and h in old_hash_map:
            old_matches = old_hash_map[h]
            if len(old_matches) == 1:  # unique match
                old_func = old_matches[0]
                old_rva = old_func.get("rva")
                new_rva = func.get("rva")
                if old_rva and new_rva:
                    if isinstance(old_rva, str):
                        old_rva = int(old_rva, 16)
                    if isinstance(new_rva, str):
                        new_rva = int(new_rva, 16)

                    # Don't overwrite higher-confidence matches
                    existing = db.fetchone(
                        "SELECT confidence FROM diffing "
                        "WHERE new_ea = ?",
                        (session.cfg.rva_to_ea(new_rva),))
                    if not existing or existing["confidence"] < 0.8:
                        db.execute(
                            """INSERT OR REPLACE INTO diffing
                               (old_ea, new_ea, match_type, confidence,
                                old_build, new_build)
                               VALUES (?, ?, 'simhash', 0.8, ?, ?)""",
                            (old_rva,
                             session.cfg.rva_to_ea(new_rva),
                             old_build, session.cfg.build_number))
                        matched += 1

    db.commit()
    return matched


def _detect_build_number(build_dir):
    """Detect build number from directory contents."""
    import re
    for fname in os.listdir(build_dir):
        m = re.search(r'_(\d{5,6})\.(json|txt)', fname)
        if m:
            return int(m.group(1))
    return 0


def get_diff_report(session):
    """Generate a human-readable diff report."""
    db = session.db
    last_diff = db.kv_get("last_diff")
    if not last_diff:
        return "No diff data available. Run diff_builds() first.\n"

    lines = [
        f"Build Diff Report: {last_diff['old_build']} → "
        f"{last_diff['new_build']}",
        f"{'=' * 60}",
        f"Name matches:    {last_diff['name_matches']}",
        f"SimHash matches: {last_diff['simhash_matches']}",
        f"Total matches:   {last_diff['total']}",
        f"Time:            {last_diff['elapsed_seconds']:.1f}s",
        "",
    ]

    # Show unmatched functions (new in this build)
    unmatched = db.fetchall(
        """SELECT f.ea, f.name, f.system FROM functions f
           WHERE f.name IS NOT NULL
             AND f.ea NOT IN (SELECT new_ea FROM diffing)
           ORDER BY f.system, f.name
           LIMIT 50""")

    if unmatched:
        lines.append(f"New/unmatched functions ({len(unmatched)} shown):")
        for row in unmatched:
            sys = row["system"] or "unknown"
            lines.append(f"  [{sys}] {row['name']} @ 0x{row['ea']:X}")

    return "\n".join(lines) + "\n"
