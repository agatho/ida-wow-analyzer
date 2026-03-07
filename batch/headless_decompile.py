"""
Headless Decompilation Orchestrator
====================================
Runs mass decompilation in idat64 (headless IDA) with automatic crash recovery.

When the decompiler crashes on a bad function, idat64 terminates — but the
canary file survives.  This orchestrator detects the crash, adds the address
to the skip list, and relaunches idat64 automatically.  After all functions
are either decompiled or skipped, the IDB is ready for GUI use.

Usage from plugin (automatic):
    The plugin calls `launch_headless_decompile()` which saves the IDB,
    spawns this orchestrator, and optionally closes the GUI.

Usage standalone:
    python headless_decompile.py --idb "C:/dumps/wow_dump.i64" \
                                 --ida "C:/Program Files/IDA Pro/idat64.exe"

The orchestrator is a NORMAL Python script (not IDAPython). It runs outside
IDA and manages idat64 subprocess launches.
"""

import argparse
import json
import os
import subprocess
import sys
import time


def _find_idat64(ida_dir=None):
    """Locate idat64 executable."""
    candidates = []
    if ida_dir:
        candidates.append(os.path.join(ida_dir, "idat64.exe"))
        candidates.append(os.path.join(ida_dir, "idat64"))

    # Common install locations
    for base in [
        os.environ.get("IDADIR", ""),
        r"C:\Program Files\IDA Pro",
        r"C:\Program Files\IDA Pro 9.3",
        r"C:\Program Files\IDA Pro 9.2",
        os.path.expanduser("~/ida"),
    ]:
        if base:
            candidates.append(os.path.join(base, "idat64.exe"))
            candidates.append(os.path.join(base, "idat64"))

    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _read_canary(idb_base):
    """Read the crash canary file if it exists."""
    canary_path = idb_base + ".tc_wow_decompile_canary"
    if not os.path.isfile(canary_path):
        return None
    try:
        with open(canary_path, "r") as f:
            data = json.load(f)
        return data.get("ea", 0)
    except Exception:
        return None


def _read_skiplist(idb_base):
    """Read the current skip list."""
    path = idb_base + ".tc_wow_skiplist.json"
    if not os.path.isfile(path):
        return set(), ""
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return set(data.get("addresses", [])), data.get("binary_fingerprint", "")
    except Exception:
        return set(), ""


def _save_skiplist(idb_base, addresses, fingerprint):
    """Save the skip list."""
    path = idb_base + ".tc_wow_skiplist.json"
    try:
        with open(path, "w") as f:
            json.dump({
                "binary_fingerprint": fingerprint,
                "addresses": sorted(addresses),
                "updated": time.time(),
                "count": len(addresses),
            }, f, indent=2)
    except Exception as e:
        print(f"[Orchestrator] WARNING: Could not save skip list: {e}")


def _remove_canary(idb_base):
    """Remove the crash canary."""
    canary_path = idb_base + ".tc_wow_decompile_canary"
    try:
        if os.path.isfile(canary_path):
            os.remove(canary_path)
    except OSError:
        pass


def _create_decompile_script(script_path):
    """Create the IDAPython script that idat64 will run."""
    script = '''"""
IDAPython script for headless mass decompilation.
Invoked by the orchestrator via idat64 -A -S"this_script.py"
Decompiles all functions, skipping those in the skip list.
On completion (or if all remaining are skipped), exits cleanly.
"""
import sys
import time
import idaapi
import ida_auto
import ida_funcs
import idautils

# Wait for auto-analysis
ida_auto.auto_wait()

# Initialize the plugin's skip list (loads canary, etc.)
try:
    from tc_wow_analyzer.core.utils import (
        safe_decompile, _ensure_skiplist_loaded, is_decompile_skipped,
        maybe_autosave_idb, msg
    )
except ImportError:
    # Fallback if plugin not on path
    plugins_dir = idaapi.get_user_idadir() + "/plugins"
    if plugins_dir not in sys.path:
        sys.path.insert(0, plugins_dir)
    from tc_wow_analyzer.core.utils import (
        safe_decompile, _ensure_skiplist_loaded, is_decompile_skipped,
        maybe_autosave_idb, msg
    )

_ensure_skiplist_loaded()

# Also try to use decompile cache
db = None
try:
    from tc_wow_analyzer.core.config import cfg
    from tc_wow_analyzer.core.db import KnowledgeDB
    db_path = cfg.db_path
    if db_path:
        db = KnowledgeDB(db_path)
        db.open()
except Exception:
    db = None

start = time.time()
total = 0
decompiled = 0
skipped = 0
cached = 0

# Check cache for already-decompiled functions
if db:
    try:
        from tc_wow_analyzer.core.decompile_cache import (
            _ensure_cache_table, _compute_func_hash
        )
        _ensure_cache_table(db)
    except Exception:
        pass

for ea in idautils.Functions():
    total += 1

    if is_decompile_skipped(ea):
        skipped += 1
        continue

    # Check cache
    if db:
        try:
            func_hash = _compute_func_hash(ea)
            if func_hash:
                row = db.fetchone(
                    "SELECT func_hash FROM cfunc_cache WHERE ea = ?", (ea,))
                if row and row["func_hash"] == func_hash:
                    cached += 1
                    continue
        except Exception:
            pass

    # This is where the crash can happen — canary is set inside safe_decompile
    cfunc = safe_decompile(ea)
    if cfunc:
        decompiled += 1
        # Cache the result
        if db:
            try:
                func_hash = _compute_func_hash(ea)
                text = str(cfunc)
                try:
                    blob = cfunc.serialize()
                except (AttributeError, Exception):
                    blob = None
                if func_hash:
                    db.execute(
                        "INSERT OR REPLACE INTO cfunc_cache "
                        "(ea, func_hash, serialized, pseudocode, created_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (ea, func_hash, blob, text, time.time()))
            except Exception:
                pass

    # Periodic progress & save
    if total % 1000 == 0:
        elapsed = time.time() - start
        print(f"[Headless] Progress: {total} functions checked, "
              f"{decompiled} decompiled, {skipped} skipped, "
              f"{cached} cached ({elapsed:.0f}s)")
        maybe_autosave_idb()
        if db:
            try:
                db.commit()
            except Exception:
                pass

# Final save
if db:
    try:
        db.commit()
        db.close()
    except Exception:
        pass

elapsed = time.time() - start
print(f"[Headless] DONE: {total} functions, {decompiled} decompiled, "
      f"{skipped} skipped, {cached} cached in {elapsed:.0f}s")

# Save IDB
import idc
idc.save_database(idc.get_idb_path(), 0)
print("[Headless] IDB saved.")

# Clean exit
idc.qexit(0)
'''
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script)


def run_orchestrator(idb_path, idat_path, max_crashes=200, reopen_ida=False,
                     ida_gui_path=None):
    """Run the headless decompilation with crash recovery loop.

    Args:
        idb_path: Path to the .i64/.idb file
        idat_path: Path to idat64 executable
        max_crashes: Maximum number of crash-recoveries before giving up
        reopen_ida: If True, launch ida64 GUI after completion
        ida_gui_path: Path to ida64 GUI executable (auto-detected if None)

    Returns:
        dict with stats: total_crashes, skip_list_size, success
    """
    if not os.path.isfile(idb_path):
        print(f"[Orchestrator] ERROR: IDB not found: {idb_path}")
        return {"success": False, "total_crashes": 0, "skip_list_size": 0}

    if not os.path.isfile(idat_path):
        print(f"[Orchestrator] ERROR: idat64 not found: {idat_path}")
        return {"success": False, "total_crashes": 0, "skip_list_size": 0}

    idb_base = os.path.splitext(idb_path)[0]

    # Create the temporary decompile script
    script_path = idb_base + ".tc_wow_headless_decompile.py"
    _create_decompile_script(script_path)

    crash_count = 0
    start_time = time.time()

    print(f"[Orchestrator] Starting headless decompilation")
    print(f"[Orchestrator] IDB: {idb_path}")
    print(f"[Orchestrator] idat64: {idat_path}")
    print(f"[Orchestrator] Max crash recoveries: {max_crashes}")
    print()

    while crash_count < max_crashes:
        # Read current skip list
        skiplist, fingerprint = _read_skiplist(idb_base)

        print(f"[Orchestrator] === Run #{crash_count + 1} "
              f"(skip list: {len(skiplist)} addresses) ===")

        # Launch idat64
        cmd = [
            idat_path,
            "-A",                          # Autonomous mode (no dialogs)
            f'-S"{script_path}"',          # Run our script
            idb_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                timeout=7200,  # 2 hour timeout per run
                capture_output=False,
                text=True,
            )
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            print("[Orchestrator] WARNING: idat64 timed out after 2 hours")
            exit_code = -1
        except Exception as e:
            print(f"[Orchestrator] ERROR launching idat64: {e}")
            exit_code = -1

        # Check if it was a crash or clean exit
        if exit_code == 0:
            print(f"[Orchestrator] Clean exit — decompilation complete!")
            break

        # Crash detected — check canary
        crash_ea = _read_canary(idb_base)
        if crash_ea:
            crash_count += 1
            skiplist.add(crash_ea)
            _save_skiplist(idb_base, skiplist, fingerprint)
            _remove_canary(idb_base)
            print(f"[Orchestrator] Crash #{crash_count} at 0x{crash_ea:X} — "
                  f"added to skip list ({len(skiplist)} total)")
        else:
            # Non-decompiler crash (maybe out of memory, etc.)
            crash_count += 1
            print(f"[Orchestrator] Crash #{crash_count} — "
                  f"no canary found (non-decompiler crash?)")
            if crash_count >= 3 and not crash_ea:
                print("[Orchestrator] 3 consecutive non-decompiler crashes — aborting")
                break

        # Brief pause before retry
        time.sleep(2)

    # Cleanup temp script
    try:
        os.remove(script_path)
    except OSError:
        pass

    elapsed = time.time() - start_time
    final_skiplist, _ = _read_skiplist(idb_base)
    success = crash_count < max_crashes

    print()
    print(f"[Orchestrator] {'SUCCESS' if success else 'ABORTED'}")
    print(f"[Orchestrator] Total crashes recovered: {crash_count}")
    print(f"[Orchestrator] Skip list size: {len(final_skiplist)}")
    print(f"[Orchestrator] Total time: {elapsed / 60:.1f} minutes")

    # Optionally reopen IDA GUI
    if reopen_ida and success:
        gui_path = ida_gui_path
        if not gui_path:
            # Derive from idat64 path
            idat_dir = os.path.dirname(idat_path)
            for name in ("ida64.exe", "ida64"):
                candidate = os.path.join(idat_dir, name)
                if os.path.isfile(candidate):
                    gui_path = candidate
                    break

        if gui_path:
            print(f"[Orchestrator] Reopening IDA GUI: {gui_path}")
            subprocess.Popen([gui_path, idb_path])
        else:
            print("[Orchestrator] Could not find ida64 — please reopen IDA manually")

    return {
        "success": success,
        "total_crashes": crash_count,
        "skip_list_size": len(final_skiplist),
        "elapsed_s": round(elapsed, 1),
    }


def launch_headless_decompile(session, reopen_after=True):
    """Launch headless decompilation from within the IDA GUI plugin.

    This function:
    1. Saves the current IDB
    2. Finds idat64 next to the current ida64
    3. Spawns the orchestrator as an external process
    4. Optionally closes the current IDA instance

    The orchestrator runs idat64 in a loop, handling crashes automatically.
    When done, it can reopen ida64 with the enriched IDB.

    Args:
        session: PluginSession
        reopen_after: Reopen IDA GUI after headless decompilation completes

    Returns:
        True if orchestrator was launched successfully
    """
    import ida_loader
    import ida_kernwin

    # Get paths
    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    if not idb_path:
        msg_error("No IDB loaded")
        return False

    # Find idat64 next to current IDA installation
    ida_dir = os.path.dirname(sys.executable)
    idat_path = None
    for name in ("idat64.exe", "idat64"):
        candidate = os.path.join(ida_dir, name)
        if os.path.isfile(candidate):
            idat_path = candidate
            break

    if not idat_path:
        idat_path = _find_idat64()

    if not idat_path:
        msg_error("Cannot find idat64 — please configure ida_path in settings")
        return False

    # Confirm with user
    from tc_wow_analyzer.core.utils import ask_yes_no
    if not ask_yes_no(
        "Run mass decompilation in headless mode?\n\n"
        "This will:\n"
        "  1. Save the current IDB\n"
        "  2. Close IDA\n"
        "  3. Run idat64 with automatic crash recovery\n"
        "  4. Reopen IDA when done\n\n"
        "Crashes are handled automatically — no manual intervention needed.\n"
        "This may take 30-60 minutes for large binaries."
    ):
        return False

    # Save IDB first
    msg("Saving IDB before headless decompilation...")
    ida_loader.save_database(idb_path, 0)

    # Find ida64 GUI for reopening
    ida_gui_path = None
    for name in ("ida64.exe", "ida64"):
        candidate = os.path.join(ida_dir, name)
        if os.path.isfile(candidate) and "idat" not in name:
            ida_gui_path = candidate
            break

    # Build orchestrator command
    orchestrator_script = os.path.abspath(__file__)
    cmd = [
        sys.executable,  # Python interpreter
        orchestrator_script,
        "--idb", idb_path,
        "--ida", idat_path,
        "--max-crashes", "200",
    ]
    if reopen_after and ida_gui_path:
        cmd.extend(["--reopen", "--ida-gui", ida_gui_path])

    msg(f"Launching headless decompilation orchestrator...")
    msg(f"  idat64: {idat_path}")
    msg(f"  IDB: {idb_path}")

    # Launch as detached process (survives IDA closing)
    try:
        if sys.platform == "win32":
            # DETACHED_PROCESS flag on Windows
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            DETACHED_PROCESS = 0x00000008
            subprocess.Popen(
                cmd,
                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                close_fds=True,
            )
        else:
            subprocess.Popen(
                cmd,
                start_new_session=True,
                close_fds=True,
            )
    except Exception as e:
        msg_error(f"Failed to launch orchestrator: {e}")
        return False

    msg("Orchestrator launched. Closing IDA in 3 seconds...")
    msg("IDA will reopen automatically when decompilation is complete.")

    # Schedule IDA close after a brief delay
    def _close_ida():
        import idc
        idc.qexit(0)
        return -1  # don't repeat

    idaapi.register_timer(3000, _close_ida)
    return True


# ---------------------------------------------------------------------------
# CLI entry point — used when orchestrator is run as a standalone script
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Headless decompilation orchestrator with crash recovery"
    )
    parser.add_argument("--idb", required=True, help="Path to .i64/.idb file")
    parser.add_argument("--ida", required=True, help="Path to idat64 executable")
    parser.add_argument("--max-crashes", type=int, default=200,
                        help="Max crash recoveries (default: 200)")
    parser.add_argument("--reopen", action="store_true",
                        help="Reopen IDA GUI after completion")
    parser.add_argument("--ida-gui", default=None,
                        help="Path to ida64 GUI executable")

    args = parser.parse_args()
    result = run_orchestrator(
        idb_path=args.idb,
        idat_path=args.ida,
        max_crashes=args.max_crashes,
        reopen_ida=args.reopen,
        ida_gui_path=args.ida_gui,
    )
    sys.exit(0 if result["success"] else 1)
