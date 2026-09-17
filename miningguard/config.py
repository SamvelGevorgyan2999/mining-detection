from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
WEB_ROOT = PACKAGE_ROOT / "web"


def _load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file(PROJECT_ROOT / ".env")


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env_str(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env_str(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    return _env_str(name, "yes" if default else "no").lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str
    api_url: str
    api_host: str
    api_port: int
    api_token: str
    collector_interval: float
    collector_top_processes: int
    resolve_remote_hostnames: bool
    gpu_sampling: bool
    feed_path: str
    retention_days: int
    # Rule thresholds, kept here so the collector and the engine agree.
    sustained_cpu_percent: float
    sustained_cpu_seconds: float
    elevated_cpu_percent: float
    sustained_gpu_percent: float
    long_lived_connection_seconds: float
    browser_cpu_percent: float

    @classmethod
    def from_env(cls) -> "Settings":
        default_sqlite = f"sqlite+pysqlite:///{(PROJECT_ROOT / 'miningguard.db').as_posix()}"
        port = _env_int("MG_API_PORT", 8000)
        return cls(
            database_url=_env_str("MG_DATABASE_URL", default_sqlite),
            api_url=_env_str("MG_API_URL", f"http://127.0.0.1:{port}"),
            api_host=_env_str("MG_API_HOST", "127.0.0.1"),
            api_port=port,
            api_token=_env_str("MG_API_TOKEN", ""),
            collector_interval=_env_float("MG_COLLECTOR_INTERVAL", 15.0),
            collector_top_processes=_env_int("MG_COLLECTOR_TOP_PROCESSES", 40),
            resolve_remote_hostnames=_env_bool("MG_RESOLVE_HOSTNAMES", True),
            gpu_sampling=_env_bool("MG_GPU_SAMPLING", True),
            feed_path=_env_str("MG_FEED_PATH", ""),
            retention_days=_env_int("MG_RETENTION_DAYS", 14),
            sustained_cpu_percent=_env_float("MG_SUSTAINED_CPU_PERCENT", 80.0),
            sustained_cpu_seconds=_env_float("MG_SUSTAINED_CPU_SECONDS", 180.0),
            elevated_cpu_percent=_env_float("MG_ELEVATED_CPU_PERCENT", 55.0),
            sustained_gpu_percent=_env_float("MG_SUSTAINED_GPU_PERCENT", 75.0),
            long_lived_connection_seconds=_env_float("MG_LONG_LIVED_CONNECTION_SECONDS", 300.0),
            browser_cpu_percent=_env_float("MG_BROWSER_CPU_PERCENT", 45.0),
        )


settings = Settings.from_env()


