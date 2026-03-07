"""
LLM Scheduler Configuration Dialog

Provides a GUI for configuring the overnight LLM auto-naming scheduler.
Users can set time windows, tasks, rate limits, and start/stop the scheduler.
"""

import ida_kernwin
import idaapi

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


class SchedulerDialog(ida_kernwin.Form):
    """Configuration dialog for the LLM auto-naming scheduler."""

    FORM_TEMPLATE = r"""STARTITEM 0
TC WoW Analyzer — LLM Scheduler

Schedule automatic LLM-powered analysis during idle hours.
The scheduler pauses when you use IDA and resumes when idle.

<##Time Window##Start time (HH\:MM)\::{iStartTime}>
<End time (HH\:MM)\::{iEndTime}>

<##Active Days##Monday\::{cMon}>
<Tuesday\::{cTue}>
<Wednesday\::{cWed}>
<Thursday\::{cThu}>
<Friday\::{cFri}>
<Saturday\::{cSat}>
<Sunday\::{cSun}>{cDaysGroup}>

<##Tasks to Run##LLM Semantic Decompiler (auto-naming)\::{cLLMDecomp}>
<Handler Scaffolding Generator\::{cScaffold}>{cTaskGroup}>

<##LLM Settings##Rate limit between calls (seconds)\::{iRateLimit}>
<Max handlers per night (0 = unlimited)\::{iMaxPerSession}>

<##Behavior##Apply renames and comments to IDB\::{cApplyIDB}>
<Pause when user is active in IDA\::{cPauseActivity}>
<Enable scheduler\::{cEnabled}>{cBehavGroup}>

<Idle threshold (minutes before resuming)\::{iIdleMinutes}>

"""

    def __init__(self, session):
        self._session = session

        # Load current config
        from tc_wow_analyzer.core.scheduler import load_config
        cfg = load_config(session)

        # Parse window
        w = cfg.windows[0] if cfg.windows else None
        start_time = w.start if w else "23:00"
        end_time = w.end if w else "05:00"
        active_days = w.days if w else [0, 1, 2, 3, 4, 5, 6]

        # Days bitmask
        days_val = 0
        for d in active_days:
            days_val |= (1 << d)

        # Tasks bitmask
        tasks_val = 0
        if "llm_semantic_decompiler" in cfg.tasks:
            tasks_val |= 1
        if "handler_scaffolding" in cfg.tasks:
            tasks_val |= 2

        # Behavior bitmask
        behav_val = 0
        if cfg.apply_to_idb:
            behav_val |= 1
        if cfg.pause_on_user_activity:
            behav_val |= 2
        if cfg.enabled:
            behav_val |= 4

        controls = {
            "iStartTime": ida_kernwin.Form.StringInput(
                value=start_time, swidth=10),
            "iEndTime": ida_kernwin.Form.StringInput(
                value=end_time, swidth=10),
            "cDaysGroup": ida_kernwin.Form.ChkGroupControl((
                "cMon", "cTue", "cWed", "cThu", "cFri", "cSat", "cSun",
            ), value=days_val),
            "cTaskGroup": ida_kernwin.Form.ChkGroupControl((
                "cLLMDecomp", "cScaffold",
            ), value=tasks_val),
            "iRateLimit": ida_kernwin.Form.StringInput(
                value=str(cfg.rate_limit), swidth=10),
            "iMaxPerSession": ida_kernwin.Form.StringInput(
                value=str(cfg.max_per_session), swidth=10),
            "cBehavGroup": ida_kernwin.Form.ChkGroupControl((
                "cApplyIDB", "cPauseActivity", "cEnabled",
            ), value=behav_val),
            "iIdleMinutes": ida_kernwin.Form.StringInput(
                value=str(cfg.activity_idle_minutes), swidth=10),
        }

        super().__init__(self.FORM_TEMPLATE, controls)

    def apply(self):
        """Read form values and apply to scheduler config."""
        from tc_wow_analyzer.core.scheduler import configure_schedule, add_window

        start_time = self.iStartTime.value.strip() or "23:00"
        end_time = self.iEndTime.value.strip() or "05:00"

        # Parse days
        days_val = self.cDaysGroup.value
        days = [d for d in range(7) if days_val & (1 << d)]
        if not days:
            days = [0, 1, 2, 3, 4, 5, 6]

        # Parse tasks
        tasks_val = self.cTaskGroup.value
        tasks = []
        if tasks_val & 1:
            tasks.append("llm_semantic_decompiler")
        if tasks_val & 2:
            tasks.append("handler_scaffolding")
        if not tasks:
            tasks = ["llm_semantic_decompiler"]

        # Parse rate limit
        try:
            rate_limit = float(self.iRateLimit.value.strip())
        except ValueError:
            rate_limit = 2.0

        # Parse max per session
        try:
            max_per_session = int(self.iMaxPerSession.value.strip())
        except ValueError:
            max_per_session = 0

        # Parse behavior
        behav_val = self.cBehavGroup.value
        apply_idb = bool(behav_val & 1)
        pause_activity = bool(behav_val & 2)
        enabled = bool(behav_val & 4)

        # Parse idle minutes
        try:
            idle_minutes = int(self.iIdleMinutes.value.strip())
        except ValueError:
            idle_minutes = 5

        configure_schedule(
            self._session,
            enabled=enabled,
            start=start_time,
            end=end_time,
            days=days,
            tasks=tasks,
            apply_to_idb=apply_idb,
            rate_limit=rate_limit,
            max_per_session=max_per_session,
            pause_on_activity=pause_activity,
            idle_minutes=idle_minutes,
        )

        return enabled


def show_scheduler_dialog(session):
    """Show the scheduler configuration dialog."""
    from tc_wow_analyzer.core.scheduler import (
        get_scheduler_status, start_scheduler, stop_scheduler, print_status
    )

    # Show current status first
    print_status()

    dlg = SchedulerDialog(session)
    dlg.Compile()

    ok = dlg.Execute()
    if ok == 1:
        enabled = dlg.apply()

        # Ask to start/stop scheduler
        status = get_scheduler_status()

        if enabled and not status["running"]:
            answer = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                "Scheduler is enabled.\n"
                "Start the scheduler now?\n\n"
                "It will automatically run during the configured time windows."
            )
            if answer == ida_kernwin.ASKBTN_YES:
                start_scheduler(session)

        elif not enabled and status["running"]:
            stop_scheduler()
            msg_info("Scheduler disabled and stopped")

        # Show updated status
        print_status()

    dlg.Free()


def show_scheduler_status(session):
    """Show scheduler status in a message box."""
    from tc_wow_analyzer.core.scheduler import get_scheduler_status

    status = get_scheduler_status()
    nw = status["next_window"]

    lines = [
        f"Enabled: {status['enabled']}",
        f"Running: {status['running']}",
        f"Working: {status['working']}",
        f"Paused:  {status['paused']}",
        "",
    ]

    for i, w in enumerate(status["windows"]):
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        day_str = ", ".join(day_names[d] for d in w["days"])
        lines.append(f"Window {i+1}: {w['start']}-{w['end']} ({day_str})")

    lines.append("")

    if nw["active"]:
        lines.append(f"Window ACTIVE - {nw['minutes_remaining']}min remaining")
    else:
        lines.append(f"Next window in {nw['minutes_until_start']}min")

    lines.extend([
        "",
        f"Tasks: {', '.join(status['tasks'])}",
        f"Rate limit: {status['rate_limit']}s",
        f"Handlers processed: {status['stats']['handlers_processed']}",
        f"Errors: {status['stats']['errors']}",
        f"Sessions completed: {status['stats']['total_sessions']}",
    ])

    if status["stats"]["last_handler"]:
        lines.append(f"Last handler: {status['stats']['last_handler']}")

    ida_kernwin.info("\n".join(lines))
