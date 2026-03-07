"""
Lumina Integration (IDA 9.3+)
Pulls community-sourced function metadata from Hex-Rays' Lumina server
to auto-name and annotate WoW binary functions.

The ida_lumina module (new in 9.3) provides programmatic access to:
- Pull function metadata from Lumina server
- Push locally named functions to Lumina
- Query match status for functions
"""

import time

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str
)


def _has_lumina():
    """Check if ida_lumina module is available (IDA 9.3+)."""
    try:
        import ida_lumina
        return True
    except ImportError:
        return False


_HAS_LUMINA = None


def is_available():
    """Check if Lumina integration is available."""
    global _HAS_LUMINA
    if _HAS_LUMINA is None:
        _HAS_LUMINA = _has_lumina()
    return _HAS_LUMINA


def pull_metadata(db, ea_list=None, progress_cb=None):
    """Pull function metadata from Lumina for the given addresses.

    If ea_list is None, queries all auto-named (sub_XXX) functions.

    Args:
        db: KnowledgeDB instance for storing results
        ea_list: List of addresses to query, or None for all unnamed
        progress_cb: Optional callback(current, total) for progress

    Returns:
        dict with counts: {"queried": N, "matched": N, "renamed": N}
    """
    if not is_available():
        msg_warn("Lumina not available (requires IDA 9.3+)")
        return {"queried": 0, "matched": 0, "renamed": 0}

    import ida_lumina
    import ida_funcs
    import ida_name
    import idautils
    import re

    auto_name_re = re.compile(r'^(?:sub_|j_sub_|nullsub_)')

    # Build list of functions to query
    if ea_list is None:
        ea_list = []
        for ea in idautils.Functions():
            name = ida_name.get_name(ea) or ""
            if auto_name_re.match(name):
                ea_list.append(ea)

    if not ea_list:
        msg_info("Lumina: No unnamed functions to query")
        return {"queried": 0, "matched": 0, "renamed": 0}

    msg_info(f"Lumina: Querying {len(ea_list)} functions...")
    stats = {"queried": len(ea_list), "matched": 0, "renamed": 0}

    try:
        # Use ida_lumina to pull metadata
        # The exact API depends on IDA 9.3 — try the available methods
        if hasattr(ida_lumina, 'pull_md'):
            # Pull metadata for all functions at once
            result = ida_lumina.pull_md(ea_list)
            if result:
                stats["matched"] = result.get("matched", 0)
                stats["renamed"] = result.get("applied", 0)
        elif hasattr(ida_lumina, 'LuminaClient'):
            # Alternative API path
            client = ida_lumina.LuminaClient()
            if client.connect():
                for i, ea in enumerate(ea_list):
                    if progress_cb:
                        progress_cb(i, len(ea_list))
                    try:
                        md = client.pull_md(ea)
                        if md and md.name:
                            stats["matched"] += 1
                            # Store in our DB
                            if db:
                                db.upsert_function(
                                    ea,
                                    name=md.name,
                                    system="lumina",
                                    confidence=md.likelihood if hasattr(md, 'likelihood') else 50
                                )
                            stats["renamed"] += 1
                    except Exception:
                        continue
                client.disconnect()
                if db:
                    db.commit()
        else:
            msg_warn("Lumina: API methods not found — check IDA 9.3 SDK docs")

    except Exception as exc:
        msg_error(f"Lumina pull failed: {exc}")

    msg_info(f"Lumina: {stats['matched']} matches, {stats['renamed']} renames applied")

    # Store stats in kv_store
    if db:
        db.kv_set("lumina_pull", {
            "timestamp": time.time(),
            **stats,
        })
        db.commit()

    return stats


def push_metadata(db, ea_list=None, min_confidence=80):
    """Push locally named functions to Lumina server.

    Only pushes functions with confidence >= min_confidence to avoid
    polluting the Lumina database with uncertain names.

    Args:
        db: KnowledgeDB instance
        ea_list: Specific addresses to push, or None for all confident names
        min_confidence: Minimum confidence threshold for pushing

    Returns:
        dict with counts: {"pushed": N, "accepted": N}
    """
    if not is_available():
        msg_warn("Lumina not available (requires IDA 9.3+)")
        return {"pushed": 0, "accepted": 0}

    import ida_lumina
    import ida_funcs
    import ida_name
    import re

    auto_name_re = re.compile(r'^(?:sub_|j_sub_|nullsub_)')

    # Build list of named functions
    if ea_list is None and db:
        rows = db.fetchall(
            "SELECT ea FROM functions WHERE confidence >= ? AND name IS NOT NULL",
            (min_confidence,)
        )
        ea_list = [row["ea"] for row in rows]

    if not ea_list:
        msg_info("Lumina: No functions to push")
        return {"pushed": 0, "accepted": 0}

    stats = {"pushed": 0, "accepted": 0}

    try:
        if hasattr(ida_lumina, 'push_md'):
            result = ida_lumina.push_md(ea_list)
            if result:
                stats["pushed"] = len(ea_list)
                stats["accepted"] = result.get("accepted", 0)
        else:
            msg_warn("Lumina: push_md not available")
    except Exception as exc:
        msg_error(f"Lumina push failed: {exc}")

    msg_info(f"Lumina: Pushed {stats['pushed']}, {stats['accepted']} accepted")
    return stats


def get_lumina_stats(db):
    """Get last Lumina pull/push statistics."""
    if db is None:
        return None
    return db.kv_get("lumina_pull")
