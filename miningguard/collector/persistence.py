"""Autostart enumeration.

A miner that survives a reboot is materially more suspicious than a
short-lived CPU spike, so persistence is collected as first-class evidence.
Everything here is read-only and degrades quietly when a source is not
readable at the current privilege level.
"""

from __future__ import annotations

import csv
import os
import re
import subprocess
import sys
from pathlib import Path

import psutil

_MAX_ITEMS = 400
_COMMAND_EXE = re.compile(r'^\s*"([^"]+)"|^\s*(\S+)')


def _extract_target(command: str) -> str:
    if not command:
        return ""
    match = _COMMAND_EXE.match(command)
    if not match:
        return ""
    return (match.group(1) or match.group(2) or "").strip()


def _item(mechanism: str, name: str, command: str, source: str, *, enabled: bool = True,
          target: str | None = None) -> dict:
    return {
        "mechanism": mechanism,
        "name": name[:255],
        "target_path": (target if target is not None else _extract_target(command))[:1024],
        "command": command[:2048],
        "source": source[:1024],
        "enabled": enabled,
    }


def _collect_windows() -> list[dict]:
    import winreg

    items: list[dict] = []

    run_keys = (
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM-Wow64"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM-Winlogon"),
    )

    for root, subkey, label in run_keys:
        try:
            with winreg.OpenKey(root, subkey) as handle:
                count = winreg.QueryInfoKey(handle)[1]
                for index in range(count):
                    try:
                        name, value, _ = winreg.EnumValue(handle, index)
                    except OSError:
                        continue
                    if not isinstance(value, str) or not value.strip():
                        continue
                    if label.endswith("Winlogon") and name not in {"Shell", "Userinit"}:
                        continue
                    items.append(
                        _item("registry_run", name, value, f"{label}\\{subkey}")
                    )
        except (OSError, PermissionError):
            continue

    startup_dirs = [
        Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
        Path(os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup")),
    ]
    for directory in startup_dirs:
        try:
            if not directory.is_dir():
                continue
            for entry in directory.iterdir():
                if entry.is_file():
                    items.append(
                        _item("startup_folder", entry.name, str(entry), str(directory),
                              target=str(entry))
                    )
        except (OSError, PermissionError):
            continue

    items.extend(_collect_windows_services())
    items.extend(_collect_scheduled_tasks())
    return items


def _collect_windows_services() -> list[dict]:
    items: list[dict] = []
    try:
        service_iter = psutil.win_service_iter()
    except (AttributeError, psutil.Error, OSError):
        return items

    for service in service_iter:
        try:
            info = service.as_dict()
        except (psutil.Error, OSError):
            continue
        start_type = (info.get("start_type") or "").lower()
        if start_type in {"disabled", "manual"}:
            continue
        binpath = info.get("binpath") or ""
        items.append(
            _item(
                "windows_service",
                info.get("name") or "",
                binpath,
                f"service start_type={start_type}",
                enabled=True,
            )
        )
    return items


def _collect_scheduled_tasks() -> list[dict]:
    try:
        completed = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True,
            text=True,
            timeout=45,
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0 or not completed.stdout.strip():
        return []

    items: list[dict] = []
    reader = csv.DictReader(completed.stdout.splitlines())
    for row in reader:
        name = (row.get("TaskName") or "").strip()
        action = (row.get("Task To Run") or "").strip()
        status = (row.get("Scheduled Task State") or row.get("Status") or "").strip().lower()
        if not name or not action or action.lower() == "com handler":
            continue
        items.append(
            _item(
                "scheduled_task",
                name,
                action,
                f"schtasks state={status or 'unknown'}",
                enabled=status != "disabled",
            )
        )
    return items


_SYSTEMD_DIRS = (
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/etc/systemd/user",
)

_EXEC_START = re.compile(r"^\s*ExecStart\s*=\s*(.+)$", re.M)
_CRON_LINE = re.compile(r"^\s*(?:@\w+|[-\d*/,]+\s+[-\d*/,]+\s+[-\d*/,]+\s+[-\d*/,]+\s+[-\d*/,]+)\s+(.*)$")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return ""


def _collect_linux() -> list[dict]:
    items: list[dict] = []

    unit_dirs = [Path(d) for d in _SYSTEMD_DIRS]
    home = Path.home()
    unit_dirs.append(home / ".config/systemd/user")

    for directory in unit_dirs:
        try:
            if not directory.is_dir():
                continue
            for unit in sorted(directory.glob("*.service")):
                content = _read_text(unit)
                if not content:
                    continue
                for match in _EXEC_START.finditer(content):
                    command = match.group(1).strip()
                    items.append(_item("systemd_service", unit.name, command, str(unit)))
                    break
        except (OSError, PermissionError):
            continue

    cron_files = [Path("/etc/crontab")]
    for directory in ("/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"):
        path = Path(directory)
        try:
            if path.is_dir():
                cron_files.extend(sorted(p for p in path.iterdir() if p.is_file()))
        except (OSError, PermissionError):
            continue

    for cron_file in cron_files:
        content = _read_text(cron_file)
        # System-wide crontabs carry a user field between the schedule and the
        # command; per-user crontabs do not.
        has_user_field = str(cron_file) == "/etc/crontab" or "/etc/cron.d" in str(cron_file)
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = _CRON_LINE.match(line)
            if not match:
                continue
            command = match.group(1).strip()
            if has_user_field:
                command = command.split(maxsplit=1)[1] if " " in command else command
            if not command:
                continue
            items.append(_item("cron_job", cron_file.name, command, str(cron_file)))

    for script in ("/etc/rc.local", str(home / ".bashrc"), str(home / ".profile"),
                   str(home / ".bash_profile")):
        path = Path(script)
        content = _read_text(path)
        if not content:
            continue
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if any(token in line for token in ("curl ", "wget ", "stratum+", "nohup ", "/tmp/",
                                               "/dev/shm/", "base64 -d", "xmrig")):
                items.append(_item("startup_script", path.name, line, script))

    init_dir = Path("/etc/init.d")
    try:
        if init_dir.is_dir():
            for entry in sorted(init_dir.iterdir()):
                if entry.is_file():
                    items.append(
                        _item("init_script", entry.name, str(entry), str(init_dir),
                              target=str(entry))
                    )
    except (OSError, PermissionError):
        pass

    return items


def _collect_macos() -> list[dict]:
    items: list[dict] = []
    home = Path.home()
    plist_dirs = (
        home / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        Path("/System/Library/LaunchAgents"),
    )
    program_args = re.compile(r"<key>Program(?:Arguments)?</key>\s*(?:<array>)?\s*<string>([^<]+)</string>")

    for directory in plist_dirs:
        try:
            if not directory.is_dir():
                continue
            for plist in sorted(directory.glob("*.plist")):
                content = _read_text(plist)
                match = program_args.search(content)
                command = match.group(1).strip() if match else str(plist)
                items.append(_item("launch_agent", plist.stem, command, str(plist)))
        except (OSError, PermissionError):
            continue
    return items


def collect_persistence() -> list[dict]:
    """Enumerate autostart entries for the current platform."""
    try:
        if sys.platform.startswith("win"):
            items = _collect_windows()
        elif sys.platform == "darwin":
            items = _collect_macos()
        else:
            items = _collect_linux()
    except Exception:
        # Persistence is supporting evidence; never let it break a collection.
        return []

    deduped: dict[tuple[str, str, str], dict] = {}
    for item in items:
        key = (item["mechanism"], item["name"], item["command"])
        deduped.setdefault(key, item)
    return list(deduped.values())[:_MAX_ITEMS]


