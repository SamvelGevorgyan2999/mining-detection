"""Optional per-process GPU utilisation via ``nvidia-smi``.

GPU mining leaves the CPU almost idle, so CPU-only telemetry misses it
entirely. There is no portable GPU accounting API, so this shells out to
``nvidia-smi`` when present and returns nothing otherwise.
"""

from __future__ import annotations

import shutil
import subprocess

_TIMEOUT = 15


def _nvidia_smi() -> str | None:
    return shutil.which("nvidia-smi")


def _run(args: list[str]) -> str:
    binary = _nvidia_smi()
    if not binary:
        return ""
    try:
        completed = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def sample_gpu_usage() -> dict[int, float]:
    """Map pid to GPU utilisation percent.

    ``nvidia-smi pmon`` reports per-process SM utilisation directly. When the
    driver does not support pmon (common on consumer Windows drivers in WDDM
    mode) the fallback derives a rough figure from the share of GPU memory a
    process holds multiplied by overall GPU utilisation.
    """
    usage = _sample_pmon()
    if usage:
        return usage
    return _sample_memory_share()


def _sample_pmon() -> dict[int, float]:
    output = _run(["pmon", "-c", "1"])
    usage: dict[int, float] = {}
    for line in output.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        sm = parts[3]
        if sm in {"-", "N/A"}:
            continue
        try:
            usage[pid] = max(usage.get(pid, 0.0), float(sm))
        except ValueError:
            continue
    return usage


def _sample_memory_share() -> dict[int, float]:
    apps = _run(
        ["--query-compute-apps=pid,used_gpu_memory", "--format=csv,noheader,nounits"]
    )
    if not apps.strip():
        return {}

    totals = _run(
        ["--query-gpu=utilization.gpu,memory.total", "--format=csv,noheader,nounits"]
    )
    gpu_util, gpu_memory_total = 0.0, 0.0
    for line in totals.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        try:
            gpu_util = max(gpu_util, float(parts[0]))
            gpu_memory_total = max(gpu_memory_total, float(parts[1]))
        except ValueError:
            continue
    if gpu_memory_total <= 0:
        return {}

    usage: dict[int, float] = {}
    for line in apps.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
            used = float(parts[1])
        except ValueError:
            continue
        share = min(1.0, used / gpu_memory_total)
        usage[pid] = round(gpu_util * share, 2)
    return usage


