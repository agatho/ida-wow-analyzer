"""
Progress heartbeat for long, silent analyzer phases.

WHY THIS EXISTS
---------------
A headless `idat.exe` run on build 12.1.0.69382 was killed by Windows mid-run:

    Event 1002, Application Hang, AppHangB1
    "idat.exe hat aufgehoert mit Windows zu interagieren und wurde geschlossen."

The process was healthy — 100% of one core, still writing decompilation
results — but `compiler_artifacts` phase 5 had been iterating every function in
the database without printing a single line. Windows' hang detector treats a
process that stops servicing its message queue as frozen and terminates it. The
run lost analyzers 67-71 plus every remaining pipeline step.

`indirect_call_resolver` phase 5 has the same shape and had already produced a
22-minute silent stretch in an earlier run.

A heartbeat solves both problems at once: it emits progress the user can see,
and the act of logging pumps enough activity to keep the hang detector quiet.

Usage::

    from tc_wow_analyzer.core.heartbeat import Heartbeat

    hb = Heartbeat("Phase 5: unreachable markers", total=len(items))
    for item in items:
        hb.tick()
        ...
    hb.done()
"""

import time

from tc_wow_analyzer.core.utils import msg_info


class Heartbeat:
    """Emit a progress line at most every *interval* seconds.

    Cheap enough to call in a tight loop: the common path is one integer
    increment and one float comparison.
    """

    def __init__(self, label, total=0, interval=20.0, note=None):
        self.label = label
        self.total = total or 0
        self.interval = interval
        self.note = note
        self.count = 0
        self._start = time.time()
        self._last = self._start

    def tick(self, n=1, extra=None):
        """Advance by *n* and log if the interval has elapsed."""
        self.count += n
        now = time.time()
        if now - self._last < self.interval:
            return
        self._last = now
        self._emit(now, extra)

    def _emit(self, now, extra=None):
        elapsed = now - self._start
        rate = self.count / elapsed if elapsed > 0 else 0.0
        if self.total:
            pct = 100.0 * self.count / self.total
            eta = (self.total - self.count) / rate if rate > 0 else 0
            line = (f"  {self.label}: {self.count:,}/{self.total:,} "
                    f"({pct:.0f}%) {rate:.0f}/s, ETA {eta / 60:.0f}min")
        else:
            line = (f"  {self.label}: {self.count:,} in {elapsed:.0f}s "
                    f"({rate:.0f}/s)")
        if extra:
            line += f" — {extra}"
        elif self.note:
            line += f" — {self.note}"
        msg_info(line)

    def done(self, extra=None):
        """Emit a final line with the total time."""
        elapsed = time.time() - self._start
        line = f"  {self.label}: done {self.count:,} in {elapsed:.1f}s"
        if extra:
            line += f" — {extra}"
        msg_info(line)
        return self.count
