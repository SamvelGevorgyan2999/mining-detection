"""Process sampling with per-process CPU history.

``psutil`` only reports instantaneous CPU, but "sustained" is the whole point
of the mining signal, so the sampler keeps state between polls:

* ``cpu_usage``          core-saturation percent, capped at 100 (one fully
                         pinned core reads as 100%, matching how task managers
                         present a single busy thread)
* ``cpu_share``          the same figure divided by core count, i.e. how much
                         of the whole machine the process is eating
* ``cpu_average``        exponentially weighted mean across polls
* ``cpu_sustained_seconds``  time the process has stayed continuously above
                         the elevated-CPU threshold

Sampling is split into two phases because opening a process handle is by far
the most expensive part of a poll on a busy host:

``sample()``  touches every process but reads only CPU, reusing cached handles
              and immutable attributes.
``enrich()``  adds memory and thread counts, and re-verifies process identity,
              for the much smaller set of processes actually being reported.

Without that split a single poll on a 380-process Windows host takes longer
than the default collection interval.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import psutil

from ..config import Settings, settings as default_settings
from .. import intel

_EWMA_ALPHA = 0.4


@dataclass
class _ProcState:
    """Per-process state carried between polls.

    Name, path, command line, owner and parent never change for the life of a
    pid, so they are read once and reused.
    """

    handle: psutil.Process
    create_time: float = 0.0
    cpu_average: float = 0.0
    cpu_sustained_seconds: float = 0.0
    last_sample: float = field(default_factory=time.monotonic)
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    parent_pid: int = 0
    is_browser_renderer: bool = False
    static_loaded: bool = False


class ProcessSampler:
    """Stateful poller. Reuse one instance so CPU history accumulates."""

    def __init__(self, cfg: Settings | None = None) -> None:
        self.cfg = cfg or default_settings
        self.cpu_count = psutil.cpu_count(logical=True) or 1
        self._total_memory = float(psutil.virtual_memory().total) or 1.0
        self._state: dict[int, _ProcState] = {}

    def _state_for(self, pid: int) -> _ProcState | None:
        state = self._state.get(pid)
        if state is not None:
            return state
        try:
            handle = psutil.Process(pid)
            create_time = handle.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return None
        state = _ProcState(handle=handle, create_time=create_time)
        self._state[pid] = state
        return state

    def prime(self) -> None:
        """Establish CPU baselines so the next sample has real numbers."""
        now = time.monotonic()
        for pid in psutil.pids():
            state = self._state_for(pid)
            if state is None:
                continue
            try:
                state.handle.cpu_percent(None)
                state.last_sample = now
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    @staticmethod
    def _load_static(state: _ProcState) -> None:
        handle = state.handle
        with handle.oneshot():
            state.name = handle.name()
            try:
                state.exe = handle.exe() or ""
            except (psutil.AccessDenied, OSError):
                state.exe = ""
            try:
                state.cmdline = " ".join(handle.cmdline())
            except (psutil.AccessDenied, OSError):
                state.cmdline = ""
            try:
                state.username = handle.username() or ""
            except (psutil.AccessDenied, KeyError, OSError):
                state.username = ""
            try:
                state.parent_pid = handle.ppid()
            except (psutil.AccessDenied, OSError):
                state.parent_pid = 0
        state.is_browser_renderer = intel.is_browser_renderer(state.name, state.cmdline)
        state.static_loaded = True

    def sample(self) -> list[dict]:
        """Cheap full pass: CPU history plus cached immutable attributes."""
        now = time.monotonic()
        wall_now = time.time()
        live_pids = set(psutil.pids())
        results: list[dict] = []

        for pid in live_pids:
            state = self._state_for(pid)
            if state is None:
                continue
            try:
                raw_cpu = state.handle.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

            elapsed = max(0.0, now - state.last_sample)
            state.last_sample = now

            cpu_usage = min(100.0, raw_cpu)
            if state.cpu_average == 0.0:
                state.cpu_average = cpu_usage
            else:
                state.cpu_average = _EWMA_ALPHA * cpu_usage + (1 - _EWMA_ALPHA) * state.cpu_average

            if cpu_usage >= self.cfg.elevated_cpu_percent:
                state.cpu_sustained_seconds += elapsed
            else:
                state.cpu_sustained_seconds = 0.0

            if not state.static_loaded:
                try:
                    self._load_static(state)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # Windows books all unused CPU time to "System Idle Process", so
            # reporting it would put a permanent 100% row at the top of every
            # host view.
            if intel.is_idle_pseudo_process(state.name):
                continue

            results.append(
                {
                    "pid": pid,
                    "name": state.name,
                    "path": state.exe,
                    "command_line": state.cmdline,
                    "username": state.username,
                    "parent_pid": state.parent_pid,
                    "parent_name": "",
                    "cpu_usage": round(cpu_usage, 2),
                    "cpu_share": round(min(100.0, raw_cpu / self.cpu_count), 2),
                    "cpu_average": round(state.cpu_average, 2),
                    "cpu_sustained_seconds": round(state.cpu_sustained_seconds, 1),
                    "memory_usage": 0.0,
                    "memory_rss_mb": 0.0,
                    "gpu_usage": 0.0,
                    "thread_count": 0,
                    "lifetime_seconds": round(max(0.0, wall_now - state.create_time), 1),
                    "is_browser_renderer": state.is_browser_renderer,
                }
            )

        # Resolve parents from names already gathered rather than reopening
        # each parent process.
        names_by_pid = {pid: st.name for pid, st in self._state.items() if st.name}
        for row in results:
            row["parent_name"] = names_by_pid.get(row["parent_pid"], "")

        for stale in set(self._state) - live_pids:
            del self._state[stale]

        return results

    def enrich(self, rows: list[dict]) -> list[dict]:
        """Add memory and thread counts to the rows being reported.

        Also re-verifies identity: a pid can be reused between polls, and this
        is the point where a stale handle would produce a misattributed path,
        so the reported subset is confirmed rather than trusted.
        """
        verified: list[dict] = []
        for row in rows:
            state = self._state.get(row["pid"])
            if state is None:
                verified.append(row)
                continue
            try:
                handle = state.handle
                if handle.create_time() != state.create_time:
                    del self._state[row["pid"]]
                    continue  # pid reuse: drop rather than report the wrong process.
                with handle.oneshot():
                    rss = handle.memory_info().rss
                    row["memory_rss_mb"] = round(rss / (1024 * 1024), 1)
                    row["memory_usage"] = round(100.0 * rss / self._total_memory, 2)
                    row["thread_count"] = handle.num_threads()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            verified.append(row)
        return verified


def select_reportable(processes: list[dict], limit: int, cfg: Settings | None = None) -> list[dict]:
    """Trim the snapshot to processes worth sending upstream.

    Anything already interesting (busy, unknown path, miner-like name or
    command line) is always kept; the remainder fills the quota by CPU so the
    dashboard still shows normal activity for context.
    """
    cfg = cfg or default_settings
    must_keep: list[dict] = []
    remainder: list[dict] = []

    for proc in processes:
        interesting = (
            max(proc["cpu_usage"], proc["cpu_average"]) >= cfg.elevated_cpu_percent
            or proc.get("gpu_usage", 0.0) > 0.0
            or intel.matches_miner_binary(proc["name"], proc["path"])
            or intel.path_trust(proc["path"]) == "suspicious"
            or bool(intel.match_command_line(proc["command_line"]))
        )
        (must_keep if interesting else remainder).append(proc)

    remainder.sort(key=lambda p: -max(p["cpu_usage"], p["cpu_average"]))
    slots = max(0, limit - len(must_keep))
    return must_keep + remainder[:slots]


