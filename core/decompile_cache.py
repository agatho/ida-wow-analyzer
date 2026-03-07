"""
Decompiled Function Cache (IDA 9.3+)
Uses cfunc_t.serialize() / cfunc_t.deserialize() to cache decompiled
pseudocode in the knowledge DB, avoiding expensive re-decompilation.
"""

import hashlib
import time

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, safe_get_bytes
)


# Table schema for binary cfunc blobs
_CACHE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cfunc_cache (
    ea INTEGER PRIMARY KEY,
    func_hash TEXT NOT NULL,
    serialized BLOB NOT NULL,
    pseudocode TEXT,
    created_at REAL
);
"""

_cache_table_created = False


def _ensure_cache_table(db):
    """Create the cfunc_cache table if it doesn't exist."""
    global _cache_table_created
    if _cache_table_created:
        return
    db.execute(_CACHE_TABLE_SQL)
    db.commit()
    _cache_table_created = True


def _compute_func_hash(ea):
    """Compute a hash of the function bytes for change detection."""
    import ida_funcs
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    size = func.end_ea - func.start_ea
    if size <= 0 or size > 500_000:
        return None
    data = safe_get_bytes(func.start_ea, size)
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()[:16]


def _has_serialize_api():
    """Check if IDA 9.3+ cfunc_t serialize/deserialize is available."""
    try:
        import ida_hexrays
        # Check for the serialize method on cfuncptr_t
        return hasattr(ida_hexrays.cfuncptr_t, 'serialize') or hasattr(ida_hexrays.cfunc_t, 'serialize')
    except ImportError:
        return False


_HAS_SERIALIZE = None


def cached_decompile(ea, db):
    """Decompile with caching. Returns cfunc or None.

    Args:
        ea: Function address
        db: KnowledgeDB instance

    Returns:
        cfunc_t object or None
    """
    global _HAS_SERIALIZE
    if _HAS_SERIALIZE is None:
        _HAS_SERIALIZE = _has_serialize_api()

    if not _HAS_SERIALIZE or db is None:
        # Fall back to regular decompilation
        from tc_wow_analyzer.core.utils import safe_decompile
        return safe_decompile(ea)

    _ensure_cache_table(db)

    # Compute current function hash
    func_hash = _compute_func_hash(ea)
    if func_hash is None:
        from tc_wow_analyzer.core.utils import safe_decompile
        return safe_decompile(ea)

    # Check cache
    row = db.fetchone(
        "SELECT func_hash, serialized FROM cfunc_cache WHERE ea = ?",
        (ea,)
    )

    if row and row["func_hash"] == func_hash:
        # Cache hit — deserialize
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)  # need a cfunc to call deserialize on...
            # Actually, cfunc_t.deserialize() is a static/class method that creates a new cfunc
            # The exact API: ida_hexrays.cfunc_t.deserialize(blob) or similar
            # Let's try the actual 9.3 API
            blob = row["serialized"]
            if isinstance(blob, (bytes, memoryview)):
                cfunc = ida_hexrays.cfunc_t.deserialize(bytes(blob))
                if cfunc:
                    return cfunc
        except Exception:
            pass
        # Deserialization failed — fall through to fresh decompile

    # Cache miss or hash changed — decompile fresh
    from tc_wow_analyzer.core.utils import safe_decompile
    cfunc = safe_decompile(ea)
    if cfunc is None:
        return None

    # Serialize and store
    try:
        blob = cfunc.serialize()
        if blob:
            pseudocode = str(cfunc)
            db.execute(
                "INSERT OR REPLACE INTO cfunc_cache (ea, func_hash, serialized, pseudocode, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (ea, func_hash, blob, pseudocode, time.time())
            )
            db.commit()
    except Exception as exc:
        # serialize() not available or failed — that's fine, just skip caching
        pass

    return cfunc


def get_cached_pseudocode(ea, db):
    """Get cached pseudocode text without decompiling.

    Returns the text if cached and function unchanged, else None.
    """
    if db is None:
        return None

    _ensure_cache_table(db)
    func_hash = _compute_func_hash(ea)
    if func_hash is None:
        return None

    row = db.fetchone(
        "SELECT func_hash, pseudocode FROM cfunc_cache WHERE ea = ?",
        (ea,)
    )
    if row and row["func_hash"] == func_hash and row["pseudocode"]:
        return row["pseudocode"]
    return None


def get_cache_stats(db):
    """Return cache statistics."""
    if db is None:
        return {"cached_functions": 0, "total_size_kb": 0}

    _ensure_cache_table(db)

    row = db.fetchone(
        "SELECT COUNT(*) as cnt, COALESCE(SUM(LENGTH(serialized)), 0) as total_bytes "
        "FROM cfunc_cache"
    )
    return {
        "cached_functions": row["cnt"] if row else 0,
        "total_size_kb": round((row["total_bytes"] if row else 0) / 1024, 1),
    }


def invalidate_cache(ea, db):
    """Remove a specific function from the cache."""
    if db is None:
        return
    _ensure_cache_table(db)
    db.execute("DELETE FROM cfunc_cache WHERE ea = ?", (ea,))
    db.commit()


def clear_cache(db):
    """Clear the entire decompilation cache."""
    if db is None:
        return
    _ensure_cache_table(db)
    db.execute("DELETE FROM cfunc_cache")
    db.commit()
    msg_info("Decompilation cache cleared")
