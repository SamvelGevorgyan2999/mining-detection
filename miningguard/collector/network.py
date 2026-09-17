"""Outbound connection sampling, reverse resolution and DNS cache reading."""

from __future__ import annotations

import queue
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

import psutil

from .. import intel
from ..config import Settings, settings as default_settings

_PROTOCOL = {
    (socket.AF_INET, socket.SOCK_STREAM): "tcp",
    (socket.AF_INET6, socket.SOCK_STREAM): "tcp6",
    (socket.AF_INET, socket.SOCK_DGRAM): "udp",
    (socket.AF_INET6, socket.SOCK_DGRAM): "udp6",
}

_INTERESTING_STATES = {
    psutil.CONN_ESTABLISHED,
    psutil.CONN_SYN_SENT,
    psutil.CONN_SYN_RECV,
    psutil.CONN_CLOSE_WAIT,
    psutil.CONN_NONE,
}


_RESOLVER_THREADS = 4
_RESOLVER_QUEUE_LIMIT = 256


@dataclass
class _Endpoint:
    first_seen: float
    last_seen: float
    count: int = 1


class _ReverseResolver:
    """Non-blocking reverse DNS with a persistent cache.

    ``gethostbyaddr`` can stall for seconds per address and ignores socket
    timeouts, so resolving inline would make a poll take longer than the
    polling interval. Lookups run on daemon threads and callers read whatever
    is cached; a name that is not ready yet simply appears on the next poll.
    """

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._cache: dict[str, str] = {}
        self._failed: set[str] = set()
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()
        self._workers: list[threading.Thread] = []

    def _ensure_workers(self) -> None:
        if self._workers:
            return
        for index in range(_RESOLVER_THREADS):
            worker = threading.Thread(
                target=self._run, name=f"mg-rdns-{index}", daemon=True
            )
            worker.start()
            self._workers.append(worker)

    def _run(self) -> None:
        while True:
            ip = self._queue.get()
            try:
                hostname = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
            except (socket.herror, socket.gaierror, OSError):
                hostname = ""
            with self._lock:
                if hostname:
                    self._cache[ip] = hostname
                else:
                    self._failed.add(ip)
                self._pending.discard(ip)
            self._queue.task_done()

    def lookup(self, ip: str) -> str:
        """Return a cached hostname, queueing a lookup when there is none."""
        if not self.enabled or not ip:
            return ""
        with self._lock:
            cached = self._cache.get(ip)
            if cached is not None:
                return cached
            if ip in self._failed or ip in self._pending:
                return ""
            if len(self._pending) >= _RESOLVER_QUEUE_LIMIT:
                return ""
            self._pending.add(ip)
        self._ensure_workers()
        self._queue.put(ip)
        return ""

    def drain(self, timeout: float) -> None:
        """Wait briefly for queued lookups. Used by one-shot CLI scans."""
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            with self._lock:
                if not self._pending:
                    return
            time.sleep(0.1)

    def known_domains(self) -> list[str]:
        with self._lock:
            return sorted(set(self._cache.values()))


class NetworkSampler:
    """Tracks how long each remote endpoint has been in use.

    Connection age is the signal that separates a mining session from an
    ordinary API call, and neither psutil nor the OS exposes socket age
    portably, so it is measured across polls.
    """

    def __init__(self, cfg: Settings | None = None) -> None:
        self.cfg = cfg or default_settings
        self._endpoints: dict[tuple[int, str, int, str], _Endpoint] = {}
        self._resolver = _ReverseResolver(self.cfg.resolve_remote_hostnames)

    def sample(self) -> list[dict]:
        now = time.monotonic()
        connections = self._list_connections()
        seen: set[tuple[int, str, int, str]] = set()
        aggregated: dict[tuple[int, str, int, str], dict] = {}

        for conn in connections:
            if not conn.raddr:
                continue
            if conn.status and conn.status not in _INTERESTING_STATES:
                continue

            ip = conn.raddr.ip
            port = int(conn.raddr.port or 0)
            if not intel.is_routable(ip):
                continue

            protocol = _PROTOCOL.get((conn.family, conn.type), "tcp")
            pid = conn.pid or 0
            key = (pid, ip, port, protocol)
            seen.add(key)

            endpoint = self._endpoints.get(key)
            if endpoint is None:
                self._endpoints[key] = _Endpoint(first_seen=now, last_seen=now)
                endpoint = self._endpoints[key]
            else:
                if now - endpoint.last_seen > self.cfg.collector_interval * 3:
                    endpoint.count += 1  # Gap in observation: treat as a new session.
                endpoint.last_seen = now

            aggregated[key] = {
                "pid": pid,
                "process_name": self._process_name(pid),
                "destination_ip": ip,
                "destination_domain": self.reverse_lookup(ip),
                "destination_port": port,
                "protocol": protocol,
                "status": (conn.status or "").lower(),
                "duration_seconds": round(now - endpoint.first_seen, 1),
                "connection_count": endpoint.count,
            }

        for stale in set(self._endpoints) - seen:
            # Keep recently closed endpoints briefly so repeat connections to
            # the same destination are recognised as a pattern.
            if now - self._endpoints[stale].last_seen > self.cfg.collector_interval * 8:
                del self._endpoints[stale]

        return list(aggregated.values())

    def _list_connections(self) -> list:
        try:
            return psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, OSError):
            pass
        # Without elevation Windows exposes only per-process sockets.
        collected: list = []
        for proc in psutil.process_iter(["pid"]):
            try:
                connections = (
                    proc.net_connections(kind="inet")
                    if hasattr(proc, "net_connections")
                    else proc.connections(kind="inet")
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                continue
            for conn in connections:
                collected.append(conn._replace(pid=proc.pid))
        return collected

    def _process_name(self, pid: int) -> str:
        if not pid:
            return ""
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return ""

    def reverse_lookup(self, ip: str) -> str:
        return self._resolver.lookup(ip)

    def await_resolution(self, timeout: float = 3.0) -> None:
        self._resolver.drain(timeout)

    def observed_domains(self) -> list[str]:
        return self._resolver.known_domains()


_WINDOWS_DNS_RECORD = re.compile(r"^\s{4}(\S+)\s*$")


def collect_dns_cache(limit: int = 400) -> list[str]:
    """Read recently resolved names from the OS resolver cache.

    Windows exposes its cache through ``ipconfig /displaydns`` without
    elevation, which gives real DNS visibility. Linux and macOS resolver
    caches are not queryable this way; those platforms need either a resolver
    log or packet capture, so an empty list is returned and the engine simply
    scores fewer DNS signals.
    """
    if not sys.platform.startswith("win"):
        return []

    try:
        completed = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True,
            text=True,
            timeout=15,
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return []

    domains: list[str] = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped or ":" in stripped or "-" * 4 in stripped:
            continue
        match = _WINDOWS_DNS_RECORD.match(line.rstrip())
        if not match:
            continue
        candidate = match.group(1).lower().rstrip(".")
        if "." in candidate and not candidate.endswith(".in-addr.arpa"):
            domains.append(candidate)

    unique = sorted(set(domains))
    # Prioritise names the engine actually cares about when trimming.
    unique.sort(
        key=lambda d: (
            not intel.match_cryptojacking_domain(d),
            not intel.match_mining_domain(d),
            not intel.looks_like_dga(d),
            d,
        )
    )
    return unique[:limit]


