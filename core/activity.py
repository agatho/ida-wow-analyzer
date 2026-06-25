"""
Activity Manager
Central hub for tracking what the plugin is doing. All subsystems post
status updates here. The UI activity view reads from this to display
a live status window.
"""

import collections
import threading
import time


class ActivityEntry:
    """Single log entry."""
    __slots__ = ("timestamp", "level", "source", "text")

    def __init__(self, level, source, text):
        self.timestamp = time.time()
        self.level = level      # "info", "warn", "error", "task", "progress"
        self.source = source    # subsystem name e.g. "importer", "vtable_analyzer"
        self.text = text


class ActivityManager:
    """Singleton that collects plugin activity for the status window.

    Thread-safe — batch tasks may run on background threads.
    """

    _instance = None

    def __init__(self, max_entries=500):
        self._log = collections.deque(maxlen=max_entries)
        self._lock = threading.Lock()

        # Current task tracking
        self._current_task = ""
        self._task_progress = ""     # e.g. "3/12"
        self._task_detail = ""       # e.g. "analyzing vtables..."
        self._task_start = 0.0
        self._batch_name = ""
        self._batch_tasks = []
        self._batch_completed = []

        # Structured extraction tracking (the 70-analyzer pipeline). Distinct
        # from the generic batch fields so the status header can render a
        # per-analyzer table + a persistent FAILED list that survives the
        # bounded log deque.
        self._ext_active = False
        self._ext_total = 0
        self._ext_index = 0
        self._ext_current = ""
        self._ext_started = 0.0
        self._ext_done = []      # list of dicts: {name,status,items,elapsed}
        self._ext_failed = []    # names of FAILED/soft-failed analyzers (persistent)

        # Stats
        self._total_events = 0
        self._errors = 0
        self._warnings = 0

        # Callbacks for UI refresh
        self._on_update = []

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def post(self, text, level="info", source=""):
        with self._lock:
            self._log.append(ActivityEntry(level, source, text))
            self._total_events += 1
            if level == "error":
                self._errors += 1
            elif level == "warn":
                self._warnings += 1
        self._notify()

    def task_start(self, task_name, detail=""):
        with self._lock:
            self._current_task = task_name
            self._task_detail = detail
            self._task_start = time.time()
            self._task_progress = ""
            self._log.append(ActivityEntry(
                "task", task_name, f"Started: {task_name}"))
            self._total_events += 1
        self._notify()

    def task_progress(self, current, total, detail=""):
        with self._lock:
            self._task_progress = f"{current}/{total}"
            if detail:
                self._task_detail = detail
        self._notify()

    def task_end(self, task_name, result="", count=-1):
        with self._lock:
            elapsed = time.time() - self._task_start if self._task_start else 0
            summary = f"Done: {task_name}"
            if count >= 0:
                summary += f" ({count} items)"
            if elapsed > 0:
                summary += f" in {elapsed:.1f}s"
            if result:
                summary += f" — {result}"
            self._log.append(ActivityEntry("task", task_name, summary))
            self._total_events += 1
            self._current_task = ""
            self._task_progress = ""
            self._task_detail = ""
            self._task_start = 0.0
        self._notify()

    def batch_start(self, name, tasks):
        with self._lock:
            self._batch_name = name
            self._batch_tasks = list(tasks)
            self._batch_completed = []
            self._log.append(ActivityEntry(
                "task", "batch",
                f"Batch '{name}' started — {len(tasks)} tasks"))
            self._total_events += 1
        self._notify()

    def batch_task_done(self, task_name):
        with self._lock:
            self._batch_completed.append(task_name)
        self._notify()

    def batch_end(self):
        with self._lock:
            name = self._batch_name
            done = len(self._batch_completed)
            total = len(self._batch_tasks)
            self._log.append(ActivityEntry(
                "task", "batch",
                f"Batch '{name}' finished — {done}/{total} tasks completed"))
            self._total_events += 1
            self._batch_name = ""
            self._batch_tasks = []
            self._batch_completed = []
        self._notify()

    # ─── Structured extraction tracking ───────────────────────────

    def extraction_start(self, total):
        with self._lock:
            self._ext_active = True
            self._ext_total = total
            self._ext_index = 0
            self._ext_current = ""
            self._ext_started = time.time()
            self._ext_done = []
            self._ext_failed = []
            self._log.append(ActivityEntry(
                "task", "extraction", f"Extraction started — {total} analyzers"))
            self._total_events += 1
        self._notify()

    def extraction_step(self, index, name):
        with self._lock:
            self._ext_index = index
            self._ext_current = name
        self._notify()

    def extraction_done(self, name, status, items=-1, elapsed=0.0):
        with self._lock:
            self._ext_done.append({"name": name, "status": status,
                                   "items": items, "elapsed": elapsed})
            if status not in ("OK", "SKIPPED", "SKIPPED_ENV", "SKIPPED_FILTER"):
                if name not in self._ext_failed:
                    self._ext_failed.append(name)
            self._ext_current = ""
        self._notify()

    def extraction_end(self):
        with self._lock:
            done = len(self._ext_done)
            failed = len(self._ext_failed)
            self._log.append(ActivityEntry(
                "task", "extraction",
                f"Extraction finished — {done}/{self._ext_total} ran, {failed} failed"))
            self._total_events += 1
            self._ext_active = False
            self._ext_current = ""
        self._notify()

    def _extraction_lines(self):
        """Status lines for the structured extraction block (caller holds _lock)."""
        lines = []
        elapsed = time.time() - self._ext_started if self._ext_started else 0
        ok = sum(1 for d in self._ext_done if d["status"] == "OK")
        fail = len(self._ext_failed)
        skip = sum(1 for d in self._ext_done if str(d["status"]).startswith("SKIP"))
        items = sum(d["items"] for d in self._ext_done if isinstance(d["items"], int) and d["items"] > 0)
        head = f"EXTRACTION: [{self._ext_index}/{self._ext_total}]"
        if self._ext_current:
            head += f"  Running: {self._ext_current}"
        if elapsed > 1:
            head += f"  ({elapsed:.0f}s)"
        lines.append(head)
        lines.append(f"  {ok} OK · {fail} FAILED · {skip} skipped · {items} items")
        if self._ext_failed:
            lines.append("  FAILED: " + ", ".join(self._ext_failed[:12])
                         + (" …" if fail > 12 else ""))
        # recent completed (last 8)
        for d in self._ext_done[-8:]:
            mark = "ok " if d["status"] == "OK" else ("!! " if d["status"] not in
                   ("SKIPPED", "SKIPPED_ENV", "SKIPPED_FILTER") else ".. ")
            cnt = str(d["items"]) if isinstance(d["items"], int) and d["items"] >= 0 else d["status"]
            lines.append(f"  {mark}{d['name'][:30]:30s} {cnt:>8}  {d['elapsed']:.1f}s")
        lines.append("=" * 70)
        return lines

    def get_log(self, count=100):
        with self._lock:
            entries = list(self._log)
        return entries[-count:]

    def get_status_lines(self):
        """Return formatted lines for the activity viewer."""
        lines = []
        with self._lock:
            # Structured extraction header (the 70-analyzer pipeline)
            if self._ext_active:
                lines.extend(self._extraction_lines())
                lines.append("")

            # Header: current state
            if self._batch_name:
                done = len(self._batch_completed)
                total = len(self._batch_tasks)
                elapsed = time.time() - self._task_start if self._task_start else 0
                lines.append(
                    f"BATCH: {self._batch_name}  "
                    f"[{done}/{total} tasks]")
                lines.append("")

            if self._current_task:
                elapsed = time.time() - self._task_start if self._task_start else 0
                status = f"RUNNING: {self._current_task}"
                if self._task_progress:
                    status += f"  [{self._task_progress}]"
                if elapsed > 1:
                    status += f"  ({elapsed:.0f}s)"
                lines.append(status)
                if self._task_detail:
                    lines.append(f"  {self._task_detail}")
                lines.append("")
            elif not self._batch_name and not self._ext_active:
                lines.append("IDLE")
                lines.append("")

            # Stats bar
            lines.append(
                f"Events: {self._total_events}  "
                f"Warnings: {self._warnings}  "
                f"Errors: {self._errors}")
            lines.append("=" * 70)

            # Recent log (newest first)
            entries = list(self._log)

        for entry in reversed(entries[-200:]):
            ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
            level_tag = ""
            if entry.level == "error":
                level_tag = "ERROR "
            elif entry.level == "warn":
                level_tag = "WARN  "
            elif entry.level == "task":
                level_tag = "TASK  "
            elif entry.level == "progress":
                level_tag = "      "
            else:
                level_tag = "      "

            src = f"[{entry.source}] " if entry.source else ""
            lines.append(f"{ts}  {level_tag}{src}{entry.text}")

        return lines

    def register_callback(self, fn):
        self._on_update.append(fn)

    def unregister_callback(self, fn):
        try:
            self._on_update.remove(fn)
        except ValueError:
            pass

    def _notify(self):
        for fn in self._on_update:
            try:
                fn()
            except Exception:
                pass


# Module-level shortcut
activity = ActivityManager.get
