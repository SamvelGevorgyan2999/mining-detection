"""Indicators of compromise for cryptomining and browser cryptojacking.

Everything here is data plus small matching helpers. The rule engine in
``rules.py`` decides what a match is worth; this module only answers
"does this look like known mining infrastructure or tooling?".

Custom indicators can be merged at runtime from a JSON feed so the
detector can be updated without a code change. See ``load_feed``.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# Filenames shipped by well-known CPU/GPU miners, plus the process names used
# by mining-oriented Linux malware families (kdevtmpfsi, kinsing, sysrv).
MINER_BINARIES: frozenset[str] = frozenset(
    {
        "xmrig",
        "xmrigcc",
        "xmrigdaemon",
        "xmrigminer",
        "xmr-stak",
        "xmr-stak-cpu",
        "xmr-stak-rx",
        "xmrig-notls",
        "cpuminer",
        "cpuminer-multi",
        "cpuminer-opt",
        "minerd",
        "minergate",
        "minergate-cli",
        "ccminer",
        "cgminer",
        "bfgminer",
        "sgminer",
        "ethminer",
        "phoenixminer",
        "lolminer",
        "nbminer",
        "gminer",
        "t-rex",
        "trex",
        "teamredminer",
        "srbminer",
        "srbminer-multi",
        "nanominer",
        "bminer",
        "claymore",
        "ethdcrminer64",
        "z-enemy",
        "wildrig",
        "rigel",
        "onezerominer",
        "verusminer",
        "randomx",
        "nheqminer",
        "excavator",
        "nicehashminer",
        "nicehash",
        "kdevtmpfsi",
        "kinsing",
        "sysrv",
        "sysrv-hello",
        "dbused",
        "dbusex",
        "kswapd00",
        "xmrigMiner",
        "moneroocean",
        "cryptonight",
        "sustes",
        "hezb",
        "rainbowminer",
    }
)

# Matched as domain suffixes, so "eu.pool.supportxmr.com" hits "supportxmr.com".
MINING_POOL_DOMAINS: tuple[str, ...] = (
    "minexmr.com",
    "supportxmr.com",
    "moneroocean.stream",
    "monerohash.com",
    "xmrpool.eu",
    "xmrpool.net",
    "nanopool.org",
    "herominers.com",
    "hashvault.pro",
    "c3pool.com",
    "c3pool.org",
    "2miners.com",
    "f2pool.com",
    "antpool.com",
    "poolin.com",
    "viabtc.com",
    "btc.com",
    "slushpool.com",
    "braiins.com",
    "ethermine.org",
    "flexpool.io",
    "hiveon.net",
    "hiveos.farm",
    "nicehash.com",
    "unmineable.com",
    "zergpool.com",
    "zpool.ca",
    "prohashing.com",
    "miningpoolhub.com",
    "dxpool.com",
    "luxor.tech",
    "k1pool.com",
    "woolypooly.com",
    "skypool.org",
    "solopool.org",
    "cruxpool.com",
    "emcd.io",
    "binance.pool.com",
    "minerstat.com",
    "minerpool.net",
    "pool.gntl.co.uk",
    "miningocean.org",
    "rplant.xyz",
    "nlpool.nl",
    "mining-dutch.nl",
    "coinfoundry.org",
    "moneropool.com",
    "xmrminingpool.com",
    "ss.antpool.com",
)

# In-browser mining scripts. Coinhive is dead but its clones are still active,
# and the original domains are still a strong signal in historical telemetry.
CRYPTOJACKING_DOMAINS: tuple[str, ...] = (
    "coinhive.com",
    "coin-hive.com",
    "authedmine.com",
    "coinhive-manager.com",
    "crypto-loot.com",
    "cryptoloot.pro",
    "cryptaloot.pro",
    "coinimp.com",
    "coinimp.net",
    "www-coinimp.com",
    "freecontent.stream",
    "freecontent.date",
    "webminepool.com",
    "webminerpool.com",
    "webmine.cz",
    "webmine.pro",
    "jsecoin.com",
    "minero.cc",
    "minero-proxy.com",
    "mineralt.io",
    "monerise.com",
    "cryptonoter.com",
    "coinpot.co",
    "nerohut.com",
    "deepminer.net",
    "ppoi.org",
    "cpufan.club",
    "afminer.com",
    "coinblind.com",
    "coinerra.com",
    "kisshentai.net",
    "ad-miner.com",
    "papoto.com",
    "hashsize.com",
)

# Stratum and miner-RPC ports. These are non-standard for normal traffic, which
# is what makes them useful, but they are also used by unrelated software, so
# the engine treats a port hit as supporting evidence rather than proof.
STRATUM_PORTS: frozenset[int] = frozenset(
    {
        3032,
        3033,
        3333,
        3334,
        3335,
        3336,
        3357,
        3380,
        4444,
        4445,
        5555,
        5556,
        5730,
        6666,
        7777,
        7778,
        8008,
        8888,
        9999,
        10001,
        10343,
        12345,
        13333,
        14433,
        14444,
        17777,
        18081,
        18082,
        19999,
        20580,
        23333,
        25000,
        30303,
        33333,
        40000,
        45560,
        45690,
        45700,
    }
)

# Command-line shapes that are close to unique to mining software.
#
# Every pattern here has to survive contact with ordinary software: generic
# flags such as --threads, --url, --worker, --daemon and --keepalive are used
# by compilers, media tools and half of all Electron apps, so they are
# deliberately absent. A flag only earns a place if mining software is its
# dominant user, or if a value that is specific to mining accompanies it.
MINING_CLI_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stratum URL", re.compile(r"stratum\+(tcp|ssl|tcps|udp)://", re.I)),
    ("donate-level flag", re.compile(r"--donate-level", re.I)),
    ("nicehash flag", re.compile(r"--nicehash\b", re.I)),
    (
        "mining algorithm flag",
        re.compile(
            r"--(algo|coin|variant)[=\s]+(randomx|rx/0|rx/wow|rx/arq|cn/|cn-lite|cryptonight|"
            r"kawpow|ethash|etchash|autolykos|verushash|ghostrider|equihash|zelhash|octopus|"
            r"firopow|progpow|blake3|sha256d|scrypt)",
            re.I,
        ),
    ),
    ("CPU pinning flags", re.compile(r"--(cpu-affinity|cpu-priority|cpu-max-threads-hint|max-cpu-usage)\b", re.I)),
    ("hugepages flag", re.compile(r"--(huge-pages|randomx-1gb-pages|randomx-mode|hugepage-size)", re.I)),
    ("pool/worker flags", re.compile(r"(^|\s)-(o|u|p)\s+\S+.*(^|\s)-(o|u|p)\s+\S+", re.I)),
    ("miner-specific flags", re.compile(r"--(rig-id|user-agent-suppress|pool-user|pool-pass|no-tls|tls-fingerprint|coin-fork|hash-report)\b", re.I)),
    # A pool flag only counts when its value looks like a mining endpoint.
    ("pool endpoint flag", re.compile(r"--(pool|url)[=\s]+(stratum|[\w.-]+:\d{3,5})", re.I)),
    ("config fetched over network", re.compile(r"(curl|wget)\s+[^|]*\|\s*(ba)?sh", re.I)),
    ("encoded PowerShell payload", re.compile(r"powershell(\.exe)?\s+.*-(enc|encodedcommand)\b", re.I)),
    ("hidden window launch", re.compile(r"-(w|windowstyle)\s+hidden", re.I)),
)

# Wallet addresses passed on the command line are among the strongest signals.
WALLET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Monero wallet address", re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")),
    ("Monero integrated address", re.compile(r"\b8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")),
    ("Ethereum wallet address", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("Bitcoin bech32 address", re.compile(r"\bbc1[a-z0-9]{25,62}\b")),
    ("Bitcoin legacy address", re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")),
)

# Processes that are legitimately allowed to sit at 100% CPU for a long time.
# Used to subtract risk, never to skip evaluation outright.
LEGITIMATE_HEAVY_WORKLOADS: frozenset[str] = frozenset(
    {
        "ffmpeg",
        "handbrakecli",
        "handbrake",
        "blender",
        "cycles",
        "cl",
        "cc1",
        "cc1plus",
        "clang",
        "clang++",
        "gcc",
        "g++",
        "ld",
        "link",
        "msbuild",
        "devenv",
        "rustc",
        "cargo",
        "go",
        "javac",
        "java",
        "gradle",
        "node",
        "ninja",
        "make",
        "cmake",
        "docker",
        "dockerd",
        "containerd",
        "qemu-system-x86_64",
        "vmware-vmx",
        "vmwp",
        "virtualboxvm",
        "msmpeng",
        "mssense",
        "antimalwareserviceexecutable",
        "tiworker",
        "trustedinstaller",
        "searchindexer",
        "searchprotocolhost",
        "compattelrunner",
        "windowsupdate",
        "wuauclt",
        "defrag",
        "dwm",
        "davinci resolve",
        "resolve",
        "premiere pro",
        "adobe premiere pro",
        "aftereffects",
        "afterfx",
        "photoshop",
        "lightroom",
        "topazvideoai",
        "obs64",
        "obs",
        "unrealeditor",
        "unity",
        "unityshadercompiler",
        "7z",
        "7zfm",
        "winrar",
        "zstd",
        "xz",
        "rsync",
        "borg",
        "restic",
        "veeam",
        "sqlservr",
        "postgres",
        "mysqld",
        "mongod",
        "redis-server",
        "python",  # scored via path/command line instead of name
        "python3",
        "pythonw",
        "prime95",
        "cinebench",
        "occt",
        "furmark",
    }
)

# Processes with no backing executable by design. Scoring them for "unknown
# executable" or a system-like name would flag the kernel on every host.
SYSTEM_PSEUDO_PROCESSES: frozenset[str] = frozenset(
    {
        "system",
        "registry",
        "memory compression",
        "secure system",
        "vmmem",
        "vmmemwsl",
        "kthreadd",
        "kdevtmpfs",
        "khugepaged",
        "khungtaskd",
        "kauditd",
        "kblockd",
        "kintegrityd",
        "ksmd",
        "kthrotld",
        "oom_reaper",
        "writeback",
        "netns",
        "kdmflush",
        "charger_manager",
        "acpi_thermal_pm",
        "devfreq_wq",
        "edac-poller",
    }
)

# Idle accounting entries. Windows reports "System Idle Process" at 100% CPU
# whenever the machine is doing nothing, which is the opposite of a signal.
IDLE_PSEUDO_PROCESSES: frozenset[str] = frozenset(
    {"system idle process", "idle", "swapper", "swapper/0"}
)

# Linux kernel threads carry a CPU or device index in the name.
_KERNEL_THREAD = re.compile(
    r"^(kworker/[\w.:+-]+|ksoftirqd/\d+|migration/\d+|cpuhp/\d+|watchdog/\d+|idle_inject/\d+|"
    r"irq/\d+[\w-]*|rcu_[a-z_]+|rcuo[a-z]*/\d+|kswapd\d+|kcompactd\d+|jbd2/[\w.-]+|"
    r"ext4-[\w-]+|xfs[\w-]*/[\w.-]+|btrfs-[\w-]+|scsi_(eh|tmf)_\d+|nvme-[\w-]+|"
    r"md\d*_raid\d*|dmcrypt_write/\d+|loop\d+|zswap[\w-]*|ipv6_addrconf)$"
)

BROWSER_PROCESSES: frozenset[str] = frozenset(
    {
        "chrome",
        "chromium",
        "chromium-browser",
        "msedge",
        "msedgewebview2",
        "firefox",
        "firefox-bin",
        "brave",
        "brave-browser",
        "opera",
        "opera_gx",
        "vivaldi",
        "vivaldi-bin",
        "safari",
        "yandex",
        "browser",
        "waterfox",
        "librewolf",
        "tor",
        "torbrowser",
        "electron",
    }
)

# Renderer/content child processes are where page JavaScript actually runs.
BROWSER_RENDERER_MARKERS: tuple[str, ...] = (
    "--type=renderer",
    "--type=utility",
    "-childid",
    "-contentproc",
    "tab",
    "web content",
    "webextensions",
    "gpu-process",
)

_WINDOWS_TRUSTED_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\",
    # 8.3 short-path aliases. Some processes report these instead of the long
    # form, and they are unambiguous.
    "c:\\progra~1\\",
    "c:\\progra~2\\",
    "c:\\windows\\",
)

# Hostname suffixes belonging to cloud and CDN providers that legitimately use
# machine-generated subdomains. Without this, the DGA heuristic fires on
# ordinary AWS, Azure and Akamai traffic.
BENIGN_GENERATED_DOMAINS: tuple[str, ...] = (
    "amazonaws.com",
    "awsglobalaccelerator.com",
    "cloudfront.net",
    "elb.amazonaws.com",
    "azure.com",
    "azurewebsites.net",
    "azureedge.net",
    "windows.net",
    "trafficmanager.net",
    "cloudapp.azure.com",
    "akamai.net",
    "akamaiedge.net",
    "akamaitechnologies.com",
    "edgekey.net",
    "edgesuite.net",
    "cloudflare.com",
    "cloudflare.net",
    "cdn.cloudflare.net",
    "fastly.net",
    "fastlylb.net",
    "googleusercontent.com",
    "1e100.net",
    "gvt1.com",
    "gstatic.com",
    "msedge.net",
    "office.com",
    "office365.com",
    "live.com",
    "skype.net",
    "teams.microsoft.com",
    "digitaloceanspaces.com",
    "oraclecloud.com",
    "herokuapp.com",
    "githubusercontent.com",
    "githubassets.com",
    "sentry.io",
    "segment.io",
    "datadoghq.com",
    "in.applicationinsights.azure.com",
)

_POSIX_TRUSTED_PREFIXES: tuple[str, ...] = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/opt/",
    "/snap/",
    "/system/",
    "/library/",
    "/applications/",
)

# Directories that are world-writable or user-scoped: normal for installers and
# updaters, unusual for something pinning every core for half an hour.
_SUSPICIOUS_PATH_MARKERS: tuple[str, ...] = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\windows\\temp\\",
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
    "\\programdata\\temp\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/user/",
    "/run/shm/",
    "/var/www/",
    "/home/.cache/",
    "/.cache/",
    "/.config/.",
    "/var/lib/docker/tmp/",
)

_HEX_NAME = re.compile(r"^[a-f0-9]{8,}$", re.I)
_RANDOM_NAME = re.compile(r"^[a-z]{1,3}[0-9]{4,}$", re.I)
_DOMAIN_LABEL = re.compile(r"^[a-z0-9-]+$", re.I)


@dataclass
class Feed:
    """Extra indicators merged from a JSON reputation feed."""

    pool_domains: set[str] = field(default_factory=set)
    cryptojacking_domains: set[str] = field(default_factory=set)
    miner_binaries: set[str] = field(default_factory=set)
    bad_ips: set[str] = field(default_factory=set)
    bad_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    allowlist_processes: set[str] = field(default_factory=set)
    allowlist_domains: set[str] = field(default_factory=set)

    @property
    def indicator_count(self) -> int:
        return (
            len(self.pool_domains)
            + len(self.cryptojacking_domains)
            + len(self.miner_binaries)
            + len(self.bad_ips)
            + len(self.bad_networks)
        )


_feed = Feed()


def load_feed(path: str | Path | None) -> Feed:
    """Merge a JSON indicator feed into the active indicator set.

    Unknown keys are ignored so a feed file can carry extra metadata.
    """
    global _feed
    if not path:
        _feed = Feed()
        return _feed

    source = Path(path)
    if not source.is_file():
        _feed = Feed()
        return _feed

    raw = json.loads(source.read_text(encoding="utf-8"))
    feed = Feed(
        pool_domains={d.lower().lstrip(".") for d in raw.get("pool_domains", [])},
        cryptojacking_domains={d.lower().lstrip(".") for d in raw.get("cryptojacking_domains", [])},
        miner_binaries={b.lower() for b in raw.get("miner_binaries", [])},
        allowlist_processes={p.lower() for p in raw.get("allowlist_processes", [])},
        allowlist_domains={d.lower().lstrip(".") for d in raw.get("allowlist_domains", [])},
    )
    for entry in raw.get("bad_ips", []):
        text = str(entry).strip()
        if "/" in text:
            try:
                feed.bad_networks.append(ipaddress.ip_network(text, strict=False))
            except ValueError:
                continue
        else:
            feed.bad_ips.add(text)
    _feed = feed
    return _feed


def active_feed() -> Feed:
    return _feed


def indicator_summary() -> dict[str, int]:
    return {
        "miner_binaries": len(MINER_BINARIES) + len(_feed.miner_binaries),
        "mining_pool_domains": len(MINING_POOL_DOMAINS) + len(_feed.pool_domains),
        "cryptojacking_domains": len(CRYPTOJACKING_DOMAINS) + len(_feed.cryptojacking_domains),
        "stratum_ports": len(STRATUM_PORTS),
        "command_line_patterns": len(MINING_CLI_PATTERNS) + len(WALLET_PATTERNS),
        "feed_indicators": _feed.indicator_count,
    }


def binary_stem(value: str | None) -> str:
    """Lowercase executable name without directory or extension."""
    if not value:
        return ""
    cleaned = value.strip().strip('"').replace("\\", "/")
    stem = cleaned.rsplit("/", 1)[-1]
    for suffix in (".exe", ".com", ".scr", ".bin", ".elf", ".out"):
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem.lower().strip()


def matches_miner_binary(name: str | None, exe_path: str | None = None) -> str:
    """Return the matched miner signature, or an empty string."""
    known = MINER_BINARIES | _feed.miner_binaries
    for candidate in (binary_stem(name), binary_stem(exe_path)):
        if candidate and candidate in known:
            return candidate
    haystack = f"{name or ''} {exe_path or ''}".lower()
    for signature in known:
        if len(signature) >= 6 and signature in haystack:
            return signature
    return ""
def _domain_suffix_match(domain: str, suffixes) -> str:
    host = (domain or "").strip().lower().rstrip(".")
    if not host:
        return ""
    for suffix in suffixes:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return ""


def is_allowlisted_domain(domain: str | None) -> bool:
    return bool(_domain_suffix_match(domain or "", _feed.allowlist_domains))


def match_mining_domain(domain: str | None) -> str:
    """Match a hostname against mining pool infrastructure."""
    if is_allowlisted_domain(domain):
        return ""
    return _domain_suffix_match(domain or "", tuple(MINING_POOL_DOMAINS) + tuple(_feed.pool_domains))


def match_cryptojacking_domain(domain: str | None) -> str:
    if is_allowlisted_domain(domain):
        return ""
    return _domain_suffix_match(
        domain or "", tuple(CRYPTOJACKING_DOMAINS) + tuple(_feed.cryptojacking_domains)
    )


def match_mining_keyword(domain: str | None) -> str:
    """Weak lexical signal: pool-ish words in an otherwise unknown domain."""
    host = (domain or "").strip().lower()
    if not host or is_allowlisted_domain(host):
        return ""
    for keyword in ("stratum", "xmr", "monero", "miningpool", "mining", "miner", "hashrate", "nicehash", "pool."):
        if keyword in host:
            return keyword
    return ""


def is_stratum_port(port: int | None) -> bool:
    return bool(port) and int(port) in STRATUM_PORTS


def match_bad_ip(ip: str | None) -> str:
    if not ip:
        return ""
    if ip in _feed.bad_ips:
        return ip
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for network in _feed.bad_networks:
        if address.version == network.version and address in network:
            return str(network)
    return ""


def is_routable(ip: str | None) -> bool:
    """True for addresses that leave the machine (excludes LAN and loopback)."""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def match_command_line(command_line: str | None) -> list[str]:
    """Return labels for every mining-specific command-line pattern found."""
    text = (command_line or "").strip()
    if not text:
        return []
    hits: list[str] = []
    for label, pattern in MINING_CLI_PATTERNS:
        if pattern.search(text):
            hits.append(label)
    for label, pattern in WALLET_PATTERNS:
        if pattern.search(text):
            hits.append(label)
            break  # One wallet finding is enough; avoid double counting.
    return hits


def is_legitimate_heavy_workload(name: str | None, exe_path: str | None = None) -> bool:
    stem = binary_stem(name)
    if not stem:
        return False
    if stem in _feed.allowlist_processes:
        return True
    if stem not in LEGITIMATE_HEAVY_WORKLOADS:
        return False
    # An allowlisted name only counts when it runs from a trusted location,
    # otherwise "svchost.exe" in %TEMP% would launder itself.
    return path_trust(exe_path) == "trusted" if exe_path else False


def is_idle_pseudo_process(name: str | None) -> bool:
    return binary_stem(name) in IDLE_PSEUDO_PROCESSES


def is_system_pseudo_process(name: str | None) -> bool:
    """True for the kernel and other processes with no real executable.

    A miner signature always wins, so malware that names itself after a
    kernel thread (``kdevtmpfsi`` imitating ``kdevtmpfs``) is not excused.
    """
    if matches_miner_binary(name):
        return False
    raw = (name or "").strip().lower()
    if binary_stem(name) in SYSTEM_PSEUDO_PROCESSES or raw in SYSTEM_PSEUDO_PROCESSES:
        return True
    return bool(_KERNEL_THREAD.match(raw))


def is_browser(name: str | None) -> bool:
    return binary_stem(name) in BROWSER_PROCESSES


def is_browser_renderer(name: str | None, command_line: str | None) -> bool:
    if not is_browser(name):
        return False
    text = (command_line or "").lower()
    return any(marker in text for marker in BROWSER_RENDERER_MARKERS)


def path_trust(exe_path: str | None) -> str:
    """Classify an executable path as ``trusted``, ``unknown`` or ``suspicious``."""
    if not exe_path or not exe_path.strip():
        return "unknown"

    raw = exe_path.strip().strip('"')
    lowered = raw.lower().replace("\\", "/")
    windows_style = raw.lower().replace("/", "\\")

    for marker in _SUSPICIOUS_PATH_MARKERS:
        normalized = marker.replace("\\", "/")
        if normalized in lowered:
            return "suspicious"

    name = binary_stem(raw)
    if name.startswith(".") or _HEX_NAME.match(name) or _RANDOM_NAME.match(name):
        return "suspicious"

    if windows_style.startswith(_WINDOWS_TRUSTED_PREFIXES):
        return "trusted"
    if lowered.startswith(_POSIX_TRUSTED_PREFIXES):
        return "trusted"
    return "unknown"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_like_dga(domain: str | None) -> bool:
    """Heuristic for algorithmically generated hostnames.

    Mining malware and cryptojacking proxies rotate through machine-generated
    subdomains, which carry higher character entropy and far fewer vowels than
    human-chosen names.

    Cloud and CDN providers also generate subdomains, so their parent domains
    are excluded outright. The remaining test requires *both* high entropy and
    a near-total absence of vowels: a hex-looking name such as
    ``ae2c518386054b8a3`` is high entropy but vowel-rich, and flagging it would
    mean alerting on ordinary AWS traffic.
    """
    host = (domain or "").strip().lower().rstrip(".")
    if not host or "." not in host or is_allowlisted_domain(host):
        return False
    if _domain_suffix_match(host, BENIGN_GENERATED_DOMAINS):
        return False

    label = host.split(".")[0]
    if len(label) < 12 or not _DOMAIN_LABEL.match(label):
        return False

    letters = [c for c in label if c.isalpha()]
    if len(letters) < 6:
        return False
    vowel_ratio = sum(1 for c in letters if c in "aeiou") / len(letters)

    return shannon_entropy(label) > 3.5 and vowel_ratio < 0.25


