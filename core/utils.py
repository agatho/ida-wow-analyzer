"""
Utility functions for the TC WoW Analyzer plugin.
Address math, pattern helpers, IDA thread safety wrappers,
crash-safe decompilation with skip lists.
"""

import json
import os
import time
import datetime

import ida_kernwin
import ida_auto
import ida_loader
import idaapi


# ---------------------------------------------------------------------------
# Central log file — written next to the IDB as tc_wow_analyzer.log
# ---------------------------------------------------------------------------
_log_file = None
_log_path = None


def _init_log_file():
    """Open (or reopen) the log file next to the current IDB."""
    global _log_file, _log_path
    if _log_file is not None:
        return _log_file
    try:
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not idb_path:
            return None
        _log_path = os.path.splitext(idb_path)[0] + ".tc_wow_analyzer.log"
        _log_file = open(_log_path, "a", encoding="utf-8", buffering=1)
        _log_file.write(f"\n{'=' * 72}\n")
        _log_file.write(f"  TC WoW Analyzer session started "
                        f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        _log_file.write(f"{'=' * 72}\n")
    except Exception:
        _log_file = None
    return _log_file


def _write_log(level, text):
    """Append a timestamped line to the central log file."""
    f = _init_log_file()
    if f is None:
        return
    try:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        f.write(f"{ts}  {level:5s}  {text}\n")
    except Exception:
        pass


def close_log():
    """Flush and close the log file (called on shutdown)."""
    global _log_file
    if _log_file is not None:
        try:
            _log_file.write(f"\n--- session ended "
                            f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            _log_file.close()
        except Exception:
            pass
        _log_file = None


def ea_str(ea):
    """Format an address as a hex string: 0x7FF725A3B160"""
    return f"0x{ea:X}"


def rva_str(rva):
    """Format an RVA as a hex string: 0x5DC5A0"""
    return f"0x{rva:X}"


def get_func_name_safe(ea):
    """Get function name at ea, or hex address if unnamed."""
    import ida_funcs
    import ida_name
    name = ida_name.get_name(ea)
    if name and not name.startswith("sub_"):
        return name
    func = ida_funcs.get_func(ea)
    if func:
        return ida_name.get_name(func.start_ea) or ea_str(func.start_ea)
    return ea_str(ea)


# ---------------------------------------------------------------------------
#  Crash-safe decompilation
# ---------------------------------------------------------------------------
#
#  IDA's Hex-Rays decompiler can hard-crash (segfault / access violation) on
#  certain malformed or obfuscated functions.  A Python try/except cannot
#  catch this — the entire IDA process terminates.
#
#  Strategy:
#    1. Before calling decompile(), write the address to a "canary" file
#       next to the IDB.  This is a simple JSON file that survives crashes.
#    2. After decompile() returns successfully, remove the canary.
#    3. If IDA crashed, on next startup the canary file still exists.
#       We read it, add the address to the skip list, and delete it.
#    4. Before decompiling any address, check the skip list first.
#
#  The skip list is PER-BUILD: it stores a binary fingerprint (image base +
#  text section size + entry point) so the list auto-invalidates when a new
#  binary is loaded.  Addresses from a different build are discarded.
#
#  The skip list is stored in:
#    - Memory: _decompile_skiplist (set of ints)
#    - Disk:   <idb_base>.tc_wow_skiplist.json  (per-build, survives crashes)
#    - Canary: <idb_base>.tc_wow_decompile_canary  (crash detection)
#

_decompile_skiplist: set = set()
_skiplist_path: str = ""
_canary_path: str = ""
_skiplist_loaded: bool = False
_binary_fingerprint: str = ""


def _get_idb_base():
    """Return IDB path without extension, or empty string."""
    try:
        import ida_loader
        idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if idb:
            return os.path.splitext(idb)[0]
    except Exception:
        pass
    return ""


def _compute_binary_fingerprint():
    """Compute a fingerprint for the current binary.

    Uses image_base + text_section_size + entry_point so the skip list
    auto-invalidates when a different build is loaded into the same IDB.
    """
    try:
        import ida_ida
        import ida_segment
        import ida_entry

        image_base = ida_ida.inf_get_min_ea()
        entry = ida_entry.get_entry(ida_entry.get_entry_ordinal(0)) if ida_entry.get_entry_qty() > 0 else 0

        # Get .text segment size as part of fingerprint
        text_size = 0
        seg = ida_segment.get_first_seg()
        while seg:
            if ida_segment.get_segm_name(seg) in (".text", "CODE"):
                text_size = seg.size()
                break
            seg = ida_segment.get_next_seg(seg.start_ea)

        return f"{image_base:X}_{text_size:X}_{entry:X}"
    except Exception:
        return "unknown"


def _ensure_skiplist_loaded():
    """Load the skip list and check for crash canary on first use."""
    global _decompile_skiplist, _skiplist_path, _canary_path, _skiplist_loaded
    global _binary_fingerprint
    if _skiplist_loaded:
        return

    base = _get_idb_base()
    if not base:
        _skiplist_loaded = True
        return

    _skiplist_path = base + ".tc_wow_skiplist.json"
    _canary_path = base + ".tc_wow_decompile_canary"
    _binary_fingerprint = _compute_binary_fingerprint()

    # Load existing skip list — validate build fingerprint
    if os.path.isfile(_skiplist_path):
        try:
            with open(_skiplist_path, "r") as f:
                data = json.load(f)
            stored_fp = data.get("binary_fingerprint", "")
            if stored_fp == _binary_fingerprint:
                _decompile_skiplist = set(data.get("addresses", []))
            else:
                # Different build — discard old skip list
                msg("Skip list from different build — resetting")
                _decompile_skiplist = set()
        except Exception:
            _decompile_skiplist = set()

    # Check crash canary — if it exists, the previous decompile crashed IDA
    if os.path.isfile(_canary_path):
        try:
            with open(_canary_path, "r") as f:
                canary = json.load(f)
            crash_ea = canary.get("ea", 0)
            if crash_ea:
                _decompile_skiplist.add(crash_ea)
                _save_skiplist()
                msg_warn(f"Decompiler crash detected at {ea_str(crash_ea)} "
                         f"— added to skip list ({len(_decompile_skiplist)} total)")
        except Exception:
            pass
        # Remove the canary regardless
        try:
            os.remove(_canary_path)
        except OSError:
            pass

    _skiplist_loaded = True

    if _decompile_skiplist:
        msg(f"Decompiler skip list: {len(_decompile_skiplist)} addresses "
            f"(build {_binary_fingerprint})")


def _save_skiplist():
    """Persist the skip list to disk with the build fingerprint."""
    if not _skiplist_path:
        return
    try:
        with open(_skiplist_path, "w") as f:
            json.dump({
                "binary_fingerprint": _binary_fingerprint,
                "addresses": sorted(_decompile_skiplist),
                "updated": time.time(),
                "count": len(_decompile_skiplist),
            }, f, indent=2)
    except Exception:
        pass


def _set_canary(ea):
    """Write crash canary before decompiling."""
    if not _canary_path:
        return
    try:
        with open(_canary_path, "w") as f:
            json.dump({"ea": ea, "time": time.time()}, f)
    except Exception:
        pass


def _clear_canary():
    """Remove crash canary after successful decompile."""
    if not _canary_path:
        return
    try:
        if os.path.isfile(_canary_path):
            os.remove(_canary_path)
    except OSError:
        pass


def is_decompile_skipped(ea):
    """Check if an address is in the decompiler skip list."""
    _ensure_skiplist_loaded()
    return ea in _decompile_skiplist


def add_to_skiplist(ea):
    """Manually add an address to the decompiler skip list."""
    _ensure_skiplist_loaded()
    _decompile_skiplist.add(ea)
    _save_skiplist()


def get_skiplist_count():
    """Return number of addresses in the skip list."""
    _ensure_skiplist_loaded()
    return len(_decompile_skiplist)


_MAX_FUNC_SIZE = 200_000  # bytes — skip functions larger than this

# When True, safe_decompile returns None for uncached functions instead
# of calling the decompiler.  Set by batch runner to prevent GUI crashes.
_decompile_cache_only = False


def safe_decompile(ea):
    """Decompile a function with crash protection.

    Returns the cfunc object on success, None if:
      - The address is in the skip list (previous crash)
      - The function is too large (>200KB, likely to hang/OOM)
      - Cache-only mode is active and function isn't cached
      - Hex-Rays raises a Python exception
      - The decompiler returns None

    If IDA hard-crashes during decompile(), the canary file ensures
    this address is auto-skipped on the next run.
    """
    _ensure_skiplist_loaded()

    if ea in _decompile_skiplist:
        return None

    # In cache-only mode, don't call the decompiler at all
    if _decompile_cache_only:
        return None

    # Guard: skip oversized functions that may hang the decompiler
    import ida_funcs
    func = ida_funcs.get_func(ea)
    if func and (func.end_ea - func.start_ea) > _MAX_FUNC_SIZE:
        msg_warn(f"Skipping oversized function at {ea_str(ea)} "
                 f"({(func.end_ea - func.start_ea) // 1024}KB)")
        _decompile_skiplist.add(ea)
        _save_skiplist()
        return None

    _set_canary(ea)
    try:
        import ida_hexrays
        cfunc = ida_hexrays.decompile(ea)
        _clear_canary()
        return cfunc
    except Exception:
        _clear_canary()
        # Soft failure (Python exception, not a crash) — still add to skip list
        # to avoid retrying expensive failures
        _decompile_skiplist.add(ea)
        _save_skiplist()
        return None


def get_decompiled_text(ea, db=None):
    """Decompile a function and return the pseudocode as text.
    Returns None on failure. Uses crash-safe decompilation.

    If *db* is provided, checks the cfunc serialization cache first
    (IDA 9.3+ only) to avoid redundant decompilation.
    """
    # Try cache-only lookup first (no decompilation needed)
    if db is not None:
        try:
            from tc_wow_analyzer.core.decompile_cache import get_cached_pseudocode
            cached = get_cached_pseudocode(ea, db)
            if cached:
                return cached
        except ImportError:
            pass

    cfunc = safe_decompile(ea)
    if cfunc:
        text = str(cfunc)
        # Cache the result for next time
        if db is not None:
            try:
                from tc_wow_analyzer.core.decompile_cache import (
                    _ensure_cache_table, _compute_func_hash
                )
                _ensure_cache_table(db)
                func_hash = _compute_func_hash(ea)
                if func_hash:
                    try:
                        blob = cfunc.serialize()
                    except (AttributeError, Exception):
                        blob = None
                    db.execute(
                        "INSERT OR REPLACE INTO cfunc_cache "
                        "(ea, func_hash, serialized, pseudocode, created_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (ea, func_hash, blob, text, time.time())
                    )
                    db.commit()
            except Exception:
                pass
        return text
    return None


# ---------------------------------------------------------------------------
#  Safe memory reads
# ---------------------------------------------------------------------------

def safe_get_bytes(ea, size, default=None):
    """Read bytes from the database, returning *default* on failure."""
    try:
        import ida_bytes
        data = ida_bytes.get_bytes(ea, size)
        return data if data is not None else default
    except Exception:
        return default


def safe_get_qword(ea, default=0):
    """Read a 64-bit value, returning *default* on failure."""
    try:
        import ida_bytes
        return ida_bytes.get_qword(ea)
    except Exception:
        return default


def safe_get_dword(ea, default=0):
    """Read a 32-bit value, returning *default* on failure."""
    try:
        import ida_bytes
        return ida_bytes.get_dword(ea)
    except Exception:
        return default


def is_valid_ea(ea):
    """Check if an address is mapped in the IDB."""
    try:
        import ida_bytes
        return ida_bytes.is_mapped(ea)
    except Exception:
        return False


# ---------------------------------------------------------------------------
#  IDB auto-save
# ---------------------------------------------------------------------------

_last_autosave = 0.0
_AUTOSAVE_INTERVAL = 300  # seconds (5 minutes)


def maybe_autosave_idb():
    """Save the IDB if more than 5 minutes have passed since last save.

    Call this periodically during long batch runs. Uses execute_sync
    to ensure the save happens on the main thread.
    """
    global _last_autosave
    now = time.time()
    if now - _last_autosave < _AUTOSAVE_INTERVAL:
        return
    _last_autosave = now
    try:
        import ida_loader
        def _do_save():
            ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)
            return 1
        idaapi.execute_sync(_do_save, idaapi.MFF_WRITE)
        msg("IDB auto-saved")
    except Exception as e:
        msg_warn(f"IDB auto-save failed: {e}")


def wait_for_analysis():
    """Wait for IDA auto-analysis to complete."""
    ida_auto.auto_wait()


def run_on_main_thread(func, *args):
    """Execute a function on IDA's main thread and return the result.
    Use this when calling IDA API from background threads."""
    result = [None]
    exc = [None]

    def wrapper():
        try:
            result[0] = func(*args)
        except Exception as e:
            exc[0] = e
        return 1

    idaapi.execute_sync(wrapper, idaapi.MFF_FAST)
    if exc[0]:
        raise exc[0]
    return result[0]


def ask_yes_no(question, default=True):
    """Ask the user a yes/no question via IDA dialog."""
    return ida_kernwin.ask_yn(
        1 if default else 0,
        f"TC WoW Analyzer\n\n{question}"
    ) == 1


def msg(text):
    """Print a message to IDA output window with plugin prefix."""
    print(f"[TC-WoW] {text}")
    _write_log("INFO", text)
    _post_activity(text, "info")


def msg_info(text):
    """Print an info message."""
    print(f"[TC-WoW] INFO: {text}")
    _write_log("INFO", text)
    _post_activity(text, "info")


def msg_warn(text):
    """Print a warning."""
    print(f"[TC-WoW] WARNING: {text}")
    _write_log("WARN", text)
    _post_activity(text, "warn")


def msg_error(text):
    """Print an error."""
    print(f"[TC-WoW] ERROR: {text}")
    _write_log("ERROR", text)
    _post_activity(text, "error")


def _post_activity(text, level):
    """Forward message to the activity manager (if initialized)."""
    try:
        from tc_wow_analyzer.core.activity import ActivityManager
        ActivityManager.get().post(text, level=level)
    except Exception:
        pass
