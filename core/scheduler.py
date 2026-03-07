"""
Scheduled Task Scheduler for TC WoW Analyzer.

Provides a timer-based scheduler that can run LLM auto-naming (and other
heavy tasks) during configurable time windows — e.g. 23:00-05:00 nightly
when the PC is otherwise idle.

The scheduler runs a lightweight watchdog thread that wakes every 60 seconds
to check whether the current time falls within any configured window.  When
a window opens, it kicks off the selected tasks (LLM decompilation by default)
and stops when the window closes or all work is done.

Configuration is stored in the plugin config under the "scheduler" key and
persisted to tc_wow_config.json:

    "scheduler": {
        "enabled": true,
        "windows": [
            {"start": "23:00", "end": "05:00", "days": [0,1,2,3,4,5,6]}
        ],
        "tasks": ["llm_semantic_decompiler"],
        "apply_to_idb": true,
        "rate_limit": 2.0,
        "max_per_session": 0,
        "pause_on_user_activity": true,
        "activity_idle_minutes": 5
    }

Usage from IDA:
    from tc_wow_analyzer.core.scheduler import (
        start_scheduler, stop_scheduler, get_scheduler_status,
        configure_schedule, is_in_window
    )
    start_scheduler(session)   # begins watchdog
    stop_scheduler()           # stops everything
    get_scheduler_status()     # returns status dict
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import idaapi

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


# ---------------------------------------------------------------------------
#  Schedule configuration
# ---------------------------------------------------------------------------

@dataclass
class TimeWindow:
    """A daily time window during which scheduled tasks may run."""
    start: str = "23:00"  # HH:MM in local time
    end: str = "05:00"    # HH:MM — can cross midnight
    days: List[int] = field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6])
    # 0=Monday, 6=Sunday  (matching datetime.weekday())

    def is_active_now(self) -> bool:
        """Check whether the current local time is within this window."""
        now = datetime.now()
        if now.weekday() not in self.days:
            return False

        start_h, start_m = map(int, self.start.split(":"))
        end_h, end_m = map(int, self.end.split(":"))

        start_mins = start_h * 60 + start_m
        end_mins = end_h * 60 + end_m
        now_mins = now.hour * 60 + now.minute

        if start_mins <= end_mins:
            # Same-day window (e.g. 09:00–17:00)
            return start_mins <= now_mins < end_mins
        else:
            # Crosses midnight (e.g. 23:00–05:00)
            return now_mins >= start_mins or now_mins < end_mins

    def minutes_until_start(self) -> int:
        """Minutes until this window next opens (0 if currently active)."""
        if self.is_active_now():
            return 0

        now = datetime.now()
        start_h, start_m = map(int, self.start.split(":"))

        # Build the next start datetime
        target = now.replace(hour=start_h, minute=start_m, second=0,
                             microsecond=0)
        if target <= now:
            target += timedelta(days=1)

        # Advance to a valid day
        for _ in range(8):
            if target.weekday() in self.days:
                break
            target += timedelta(days=1)

        diff = target - now
        return max(0, int(diff.total_seconds() / 60))

    def minutes_until_end(self) -> int:
        """Minutes until this window closes (0 if not active)."""
        if not self.is_active_now():
            return 0

        now = datetime.now()
        end_h, end_m = map(int, self.end.split(":"))

        target = now.replace(hour=end_h, minute=end_m, second=0,
                             microsecond=0)
        if target <= now:
            target += timedelta(days=1)

        diff = target - now
        return max(0, int(diff.total_seconds() / 60))

    def to_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "days": self.days}

    @classmethod
    def from_dict(cls, d: dict) -> "TimeWindow":
        return cls(
            start=d.get("start", "23:00"),
            end=d.get("end", "05:00"),
            days=d.get("days", [0, 1, 2, 3, 4, 5, 6]),
        )


@dataclass
class SchedulerConfig:
    """Full scheduler configuration."""
    enabled: bool = False
    windows: List[TimeWindow] = field(default_factory=lambda: [
        TimeWindow("23:00", "05:00")
    ])
    tasks: List[str] = field(default_factory=lambda: [
        "llm_semantic_decompiler"
    ])
    apply_to_idb: bool = True
    rate_limit: float = 2.0       # seconds between LLM calls
    max_per_session: int = 0      # 0 = unlimited
    pause_on_user_activity: bool = True
    activity_idle_minutes: int = 5  # resume after N minutes idle

    def to_dict(self) -> dict:
        d = asdict(self)
        d["windows"] = [w.to_dict() for w in self.windows]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SchedulerConfig":
        windows = [TimeWindow.from_dict(w) for w in d.get("windows", [])]
        if not windows:
            windows = [TimeWindow()]
        return cls(
            enabled=d.get("enabled", False),
            windows=windows,
            tasks=d.get("tasks", ["llm_semantic_decompiler"]),
            apply_to_idb=d.get("apply_to_idb", True),
            rate_limit=d.get("rate_limit", 2.0),
            max_per_session=d.get("max_per_session", 0),
            pause_on_user_activity=d.get("pause_on_user_activity", True),
            activity_idle_minutes=d.get("activity_idle_minutes", 5),
        )

    def is_any_window_active(self) -> bool:
        return any(w.is_active_now() for w in self.windows)

    def next_window_info(self) -> dict:
        """Get info about the next upcoming window."""
        if self.is_any_window_active():
            active = [w for w in self.windows if w.is_active_now()][0]
            return {
                "active": True,
                "window": active.to_dict(),
                "minutes_remaining": active.minutes_until_end(),
            }
        # Find the soonest start
        best = None
        best_mins = float("inf")
        for w in self.windows:
            m = w.minutes_until_start()
            if m < best_mins:
                best_mins = m
                best = w
        return {
            "active": False,
            "window": best.to_dict() if best else None,
            "minutes_until_start": int(best_mins) if best else -1,
        }


# ---------------------------------------------------------------------------
#  Scheduler state
# ---------------------------------------------------------------------------

class _SchedulerState:
    """Thread-safe scheduler state."""
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.working = False        # currently executing tasks
        self.paused = False         # paused due to user activity
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.session = None
        self.config = SchedulerConfig()
        # Stats
        self.handlers_processed = 0
        self.errors = 0
        self.last_run_start: Optional[float] = None
        self.last_run_end: Optional[float] = None
        self.last_handler_name: str = ""
        self.total_sessions = 0
        # User activity tracking
        self.last_user_activity: float = 0.0


_state = _SchedulerState()


# ---------------------------------------------------------------------------
#  User activity detection
# ---------------------------------------------------------------------------

class _ActivityHook(idaapi.UI_Hooks):
    """Tracks user activity in IDA to pause scheduled work."""

    def screen_ea_changed(self, ea, prev_ea):
        _state.last_user_activity = time.time()

    def current_widget_changed(self, widget, prev_widget):
        _state.last_user_activity = time.time()


_activity_hook = None


def _install_activity_hook():
    global _activity_hook
    if _activity_hook is None:
        _activity_hook = _ActivityHook()
        _activity_hook.hook()


def _remove_activity_hook():
    global _activity_hook
    if _activity_hook is not None:
        _activity_hook.unhook()
        _activity_hook = None


def _is_user_idle() -> bool:
    """Check if user has been idle for the configured threshold."""
    if not _state.config.pause_on_user_activity:
        return True  # feature disabled, always "idle"
    idle_threshold = _state.config.activity_idle_minutes * 60
    return (time.time() - _state.last_user_activity) >= idle_threshold


# ---------------------------------------------------------------------------
#  Watchdog thread
# ---------------------------------------------------------------------------

def _watchdog_loop():
    """Main scheduler loop — runs in a daemon thread.

    Wakes every 60 seconds.  When inside a configured time window and the
    user is idle, launches the selected tasks.  Stops working when the
    window closes, the user becomes active, or stop_scheduler() is called.
    """
    msg_info("Scheduler watchdog started")
    _state.total_sessions = 0

    while not _state.stop_event.is_set():
        try:
            _watchdog_tick()
        except Exception as e:
            msg_error(f"Scheduler watchdog error: {e}")
            import traceback
            traceback.print_exc()

        # Sleep 60 seconds in 1-second increments (responsive to stop)
        for _ in range(60):
            if _state.stop_event.is_set():
                break
            time.sleep(1)

    with _state.lock:
        _state.running = False
        _state.working = False

    msg_info("Scheduler watchdog stopped")


def _watchdog_tick():
    """Single tick of the watchdog — check window and dispatch."""
    cfg = _state.config

    if not cfg.enabled:
        return

    in_window = cfg.is_any_window_active()

    with _state.lock:
        was_working = _state.working

    if in_window and not was_working:
        # Window just opened — should we start?
        if _is_user_idle():
            _start_work_session()
        else:
            with _state.lock:
                _state.paused = True

    elif in_window and was_working:
        # Window still open — check if user came back
        if cfg.pause_on_user_activity and not _is_user_idle():
            msg_info("Scheduler: user active, pausing...")
            with _state.lock:
                _state.paused = True
                _state.working = False
        # If paused but user went idle again, resume
        elif _state.paused and _is_user_idle():
            msg_info("Scheduler: user idle again, resuming...")
            _start_work_session()

    elif not in_window and was_working:
        # Window just closed
        msg_info("Scheduler: time window closed, stopping work")
        with _state.lock:
            _state.working = False
            _state.paused = False


def _start_work_session():
    """Begin executing scheduled tasks on IDA's main thread."""
    with _state.lock:
        _state.working = True
        _state.paused = False
        _state.last_run_start = time.time()
        _state.total_sessions += 1

    session_num = _state.total_sessions
    msg_info(f"Scheduler: starting work session #{session_num}")
    msg_info(f"  Tasks: {', '.join(_state.config.tasks)}")
    msg_info(f"  Rate limit: {_state.config.rate_limit}s")
    msg_info(f"  Apply to IDB: {_state.config.apply_to_idb}")

    # Execute on IDA's main thread (required for IDA API calls)
    def _run_on_main():
        try:
            _execute_scheduled_tasks()
        except Exception as e:
            msg_error(f"Scheduler work session error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            with _state.lock:
                _state.working = False
                _state.last_run_end = time.time()
        return 1

    idaapi.execute_sync(_run_on_main, idaapi.MFF_WRITE)


def _execute_scheduled_tasks():
    """Run the configured tasks within the time window.

    This runs on the IDA main thread.  It checks the time window and
    user activity between each handler to allow clean interruption.
    """
    session = _state.session
    if not session or not session.db:
        msg_error("Scheduler: no session available")
        return

    # Pre-load the LLM model before starting work
    if not _ensure_llm_ready(session):
        msg_error("Scheduler: LLM model could not be loaded, aborting session")
        return

    cfg = _state.config
    processed_this_session = 0

    for task_name in cfg.tasks:
        if _should_stop():
            break

        if task_name == "llm_semantic_decompiler":
            processed_this_session += _run_llm_decompiler_incremental(
                session, cfg)
        elif task_name == "handler_scaffolding":
            processed_this_session += _run_task_simple(
                session, task_name,
                "tc_wow_analyzer.analyzers.handler_scaffolding",
                "generate_all_scaffolds")
        else:
            processed_this_session += _run_task_simple(
                session, task_name, None, None)

    msg_info(f"Scheduler: session complete — {processed_this_session} items "
             f"processed this session")


def _ensure_llm_ready(session) -> bool:
    """Ensure the configured LLM provider is available and model is loaded.

    For local providers (LM Studio, Ollama), this triggers model loading
    so it's warmed up and ready when the first real request arrives.
    Returns True if the provider is ready, False otherwise.
    """
    try:
        from tc_wow_analyzer.core.llm_provider import get_or_discover_provider
        provider = get_or_discover_provider(session)
        msg_info(f"Scheduler: LLM provider = {provider.display_name}")

        # Trigger model loading (for local providers this actually loads
        # the model into GPU/RAM; for API providers it's a no-op)
        if not provider.ensure_model_loaded(timeout=180.0):
            return False

        msg_info("Scheduler: LLM model loaded and ready")
        return True
    except Exception as e:
        msg_error(f"Scheduler: LLM provider setup failed: {e}")
        return False


def _run_llm_decompiler_incremental(session, cfg: SchedulerConfig) -> int:
    """Run LLM decompiler one handler at a time, checking stop conditions
    between each handler for responsive interruption."""
    from tc_wow_analyzer.analyzers.llm_semantic_decompiler import (
        semantically_decompile_function, KV_KEY
    )

    db = session.db
    existing = db.kv_get(KV_KEY) or {}
    existing_results = existing.get("results", {})

    # Get all CMSG handlers not yet processed
    handlers = db.fetchall(
        "SELECT * FROM opcodes WHERE direction = 'CMSG' "
        "AND handler_ea IS NOT NULL ORDER BY internal_index"
    )

    if not handlers:
        msg_warn("Scheduler: no CMSG handlers found")
        return 0

    # Filter to unprocessed only
    todo = []
    for row in handlers:
        tc_name = row["tc_name"] or f"handler_{row['internal_index']:X}"
        prev = existing_results.get(tc_name)
        if prev and prev.get("clean_cpp") and prev.get("quality_score", 0) > 0:
            continue  # already done
        todo.append(row)

    if not todo:
        msg_info("Scheduler: all handlers already processed")
        return 0

    msg_info(f"Scheduler: {len(todo)} handlers remaining "
             f"(of {len(handlers)} total)")

    processed = 0
    errors = 0

    for i, row in enumerate(todo):
        # Check stop conditions before each handler
        if _should_stop():
            msg_info(f"Scheduler: stopping after {processed} handlers "
                     f"(window closed or user active)")
            break

        # Max per session check
        if cfg.max_per_session > 0 and processed >= cfg.max_per_session:
            msg_info(f"Scheduler: reached max_per_session={cfg.max_per_session}")
            break

        handler_ea = row["handler_ea"]
        tc_name = row["tc_name"] or f"handler_{row['internal_index']:X}"

        with _state.lock:
            _state.last_handler_name = tc_name

        msg(f"  Scheduler [{i+1}/{len(todo)}] {tc_name}")

        try:
            result = semantically_decompile_function(
                session, handler_ea,
                apply_to_idb_flag=cfg.apply_to_idb,
                rate_limit=cfg.rate_limit,
            )

            if result and not result.get("error"):
                processed += 1
                existing_results[tc_name] = result
                with _state.lock:
                    _state.handlers_processed += 1
            else:
                errors += 1
                with _state.lock:
                    _state.errors += 1
                if result:
                    existing_results[tc_name] = result

        except Exception as e:
            errors += 1
            msg_error(f"  Scheduler: error processing {tc_name}: {e}")
            with _state.lock:
                _state.errors += 1

        # Save every 5 handlers
        if (processed + errors) % 5 == 0 and (processed + errors) > 0:
            _save_llm_results(db, existing_results, processed)

        # Rate limit
        time.sleep(cfg.rate_limit)

    # Final save
    _save_llm_results(db, existing_results, processed)

    return processed


def _save_llm_results(db, results, handlers_processed):
    """Persist LLM results to kv_store."""
    from tc_wow_analyzer.analyzers.llm_semantic_decompiler import KV_KEY

    total_vars = sum(len(r.get("variable_map", {}))
                     for r in results.values() if isinstance(r, dict))
    total_consts = sum(len(r.get("constants_identified", {}))
                       for r in results.values() if isinstance(r, dict))

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "provider": "scheduler",
        "handlers_processed": len([r for r in results.values()
                                   if isinstance(r, dict) and r.get("clean_cpp")]),
        "total_variables_renamed": total_vars,
        "total_constants_identified": total_consts,
        "results": results,
    }
    db.kv_set(KV_KEY, report)
    db.commit()


def _run_task_simple(session, task_name, module_path, func_name) -> int:
    """Run a simple (non-incremental) task."""
    if not module_path or not func_name:
        msg_warn(f"Scheduler: task '{task_name}' not implemented for scheduling")
        return 0

    try:
        import importlib
        mod = importlib.import_module(module_path)
        func = getattr(mod, func_name)
        return func(session) or 0
    except Exception as e:
        msg_error(f"Scheduler: task '{task_name}' failed: {e}")
        return 0


def _should_stop() -> bool:
    """Check if the scheduler should stop working."""
    if _state.stop_event.is_set():
        return True
    if not _state.config.is_any_window_active():
        return True
    if _state.config.pause_on_user_activity and not _is_user_idle():
        return True
    return False


# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------

def load_config(session) -> SchedulerConfig:
    """Load scheduler config from the plugin config."""
    raw = session.cfg.get("scheduler") or {}
    if isinstance(raw, dict):
        return SchedulerConfig.from_dict(raw)
    return SchedulerConfig()


def save_config(session, config: SchedulerConfig):
    """Save scheduler config to the plugin config."""
    session.cfg.set("scheduler", config.to_dict())
    session.cfg.save()


def start_scheduler(session):
    """Start the scheduler watchdog thread.

    The scheduler will check every 60 seconds whether the current time
    falls within a configured window, and if so, begin processing.
    """
    with _state.lock:
        if _state.running:
            msg_warn("Scheduler already running")
            return

    _state.session = session
    _state.config = load_config(session)

    if not _state.config.enabled:
        msg_warn("Scheduler is disabled in config. "
                 "Use configure_schedule() or set scheduler.enabled=true")
        return

    _state.stop_event.clear()
    _state.running = True
    _state.last_user_activity = time.time()

    # Install activity tracking
    if _state.config.pause_on_user_activity:
        _install_activity_hook()

    # Start watchdog
    t = threading.Thread(target=_watchdog_loop, daemon=True,
                         name="tc_wow_scheduler")
    _state.thread = t
    t.start()

    next_info = _state.config.next_window_info()
    if next_info["active"]:
        msg_info(f"Scheduler started — window is ACTIVE "
                 f"({next_info['minutes_remaining']}min remaining)")
    else:
        msg_info(f"Scheduler started — next window in "
                 f"{next_info['minutes_until_start']}min "
                 f"({next_info['window']['start']}–{next_info['window']['end']})")


def stop_scheduler():
    """Stop the scheduler and any in-progress work."""
    _state.stop_event.set()
    _remove_activity_hook()

    if _state.thread and _state.thread.is_alive():
        _state.thread.join(timeout=5)

    with _state.lock:
        _state.running = False
        _state.working = False
        _state.thread = None

    msg_info("Scheduler stopped")


def get_scheduler_status() -> dict:
    """Get current scheduler status for display."""
    with _state.lock:
        cfg = _state.config
        next_info = cfg.next_window_info()

        return {
            "enabled": cfg.enabled,
            "running": _state.running,
            "working": _state.working,
            "paused": _state.paused,
            "windows": [w.to_dict() for w in cfg.windows],
            "tasks": cfg.tasks,
            "apply_to_idb": cfg.apply_to_idb,
            "rate_limit": cfg.rate_limit,
            "max_per_session": cfg.max_per_session,
            "pause_on_user_activity": cfg.pause_on_user_activity,
            "activity_idle_minutes": cfg.activity_idle_minutes,
            "next_window": next_info,
            "user_idle": _is_user_idle(),
            "stats": {
                "handlers_processed": _state.handlers_processed,
                "errors": _state.errors,
                "total_sessions": _state.total_sessions,
                "last_handler": _state.last_handler_name,
                "last_run_start": _state.last_run_start,
                "last_run_end": _state.last_run_end,
            },
        }


def is_in_window() -> bool:
    """Quick check: is a time window currently active?"""
    return _state.config.is_any_window_active()


def configure_schedule(session,
                       enabled: bool = True,
                       start: str = "23:00",
                       end: str = "05:00",
                       days: Optional[List[int]] = None,
                       tasks: Optional[List[str]] = None,
                       apply_to_idb: bool = True,
                       rate_limit: float = 2.0,
                       max_per_session: int = 0,
                       pause_on_activity: bool = True,
                       idle_minutes: int = 5):
    """Configure the scheduler with new settings.

    This is the user-friendly configuration entry point.  Can be called
    from the IDA Python console::

        from tc_wow_analyzer.core.scheduler import configure_schedule
        configure_schedule(session, start="23:00", end="05:00")
        # or for weekdays only:
        configure_schedule(session, start="22:00", end="06:00", days=[0,1,2,3,4])

    Args:
        session: PluginSession.
        enabled: Whether the scheduler is active.
        start: Window start time (HH:MM, local).
        end: Window end time (HH:MM, local).
        days: List of weekday numbers (0=Monday, 6=Sunday).
        tasks: List of task names to run.
        apply_to_idb: Apply LLM renames/comments to IDB.
        rate_limit: Seconds between LLM calls.
        max_per_session: Max handlers per session (0=unlimited).
        pause_on_activity: Pause when user is active in IDA.
        idle_minutes: Minutes of idle before resuming.
    """
    if days is None:
        days = [0, 1, 2, 3, 4, 5, 6]
    if tasks is None:
        tasks = ["llm_semantic_decompiler"]

    config = SchedulerConfig(
        enabled=enabled,
        windows=[TimeWindow(start, end, days)],
        tasks=tasks,
        apply_to_idb=apply_to_idb,
        rate_limit=rate_limit,
        max_per_session=max_per_session,
        pause_on_user_activity=pause_on_activity,
        activity_idle_minutes=idle_minutes,
    )

    save_config(session, config)
    _state.config = config

    msg_info(f"Scheduler configured: {start}–{end} "
             f"({'daily' if len(days) == 7 else f'{len(days)} days/week'})")
    msg_info(f"  Tasks: {', '.join(tasks)}")
    msg_info(f"  Rate limit: {rate_limit}s, apply to IDB: {apply_to_idb}")
    msg_info(f"  Pause on user activity: {pause_on_activity} "
             f"(idle threshold: {idle_minutes}min)")

    if enabled:
        msg_info("Scheduler is ENABLED — use start_scheduler(session) to begin")
    else:
        msg_info("Scheduler is DISABLED — set enabled=True to activate")


def add_window(session, start: str, end: str,
               days: Optional[List[int]] = None):
    """Add an additional time window to the schedule.

    Useful for having different windows on different days::

        configure_schedule(session, start="23:00", end="05:00", days=[0,1,2,3,4])
        add_window(session, start="10:00", end="18:00", days=[5,6])  # weekends
    """
    if days is None:
        days = [0, 1, 2, 3, 4, 5, 6]

    config = load_config(session)
    config.windows.append(TimeWindow(start, end, days))
    save_config(session, config)
    _state.config = config

    msg_info(f"Added window: {start}–{end} "
             f"(total: {len(config.windows)} windows)")


def run_now(session, max_handlers: int = 0):
    """Manually trigger a work session immediately, ignoring windows.

    Useful for testing or when you want to run a quick batch::

        from tc_wow_analyzer.core.scheduler import run_now
        run_now(session, max_handlers=10)  # process 10 handlers right now
    """
    _state.session = session
    _state.config = load_config(session)

    if max_handlers > 0:
        _state.config.max_per_session = max_handlers

    msg_info(f"Scheduler: manual run"
             + (f" (max {max_handlers} handlers)" if max_handlers else ""))

    with _state.lock:
        _state.working = True
        _state.last_run_start = time.time()
        _state.total_sessions += 1

    try:
        _execute_scheduled_tasks()
    finally:
        with _state.lock:
            _state.working = False
            _state.last_run_end = time.time()


def print_status():
    """Print scheduler status to IDA output window."""
    status = get_scheduler_status()

    msg("=== TC WoW Scheduler Status ===")
    msg(f"  Enabled: {status['enabled']}")
    msg(f"  Running: {status['running']}")
    msg(f"  Working: {status['working']}")
    msg(f"  Paused:  {status['paused']}")

    for i, w in enumerate(status["windows"]):
        msg(f"  Window {i+1}: {w['start']}–{w['end']} "
            f"(days: {w['days']})")

    nw = status["next_window"]
    if nw["active"]:
        msg(f"  Window is ACTIVE — {nw['minutes_remaining']}min remaining")
    else:
        msg(f"  Next window in {nw['minutes_until_start']}min")

    msg(f"  User idle: {status['user_idle']}")
    msg(f"  Tasks: {', '.join(status['tasks'])}")

    stats = status["stats"]
    msg(f"  Handlers processed: {stats['handlers_processed']}")
    msg(f"  Errors: {stats['errors']}")
    msg(f"  Sessions: {stats['total_sessions']}")
    if stats["last_handler"]:
        msg(f"  Last handler: {stats['last_handler']}")
    msg("=" * 35)
