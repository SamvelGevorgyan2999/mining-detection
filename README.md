# MiningGuard

Cryptomining and browser-cryptojacking detection for monitored hosts.

A collector samples processes, outbound connections, DNS and autostart entries.
A central rule engine turns that telemetry into an attributable risk score, and
a dashboard shows the fleet with an alert queue for triage.

The design point worth arguing about: **high CPU never convicts on its own.**
Resource pressure is the noisiest signal available, so a finding backed only by
CPU or GPU evidence is capped inside the NORMAL band. A mining verdict requires
corroboration from a different class of evidence — network, identity,
persistence, command line or DNS.

## Quick start

No database server, no Docker, no configuration:

```bash
python3 -m pip install -r requirements.txt

python3 -m miningguard scan            # scan this machine, print a report
python3 -m miningguard seed-demo       # load a synthetic fleet into SQLite
python3 -m miningguard serve           # dashboard at http://127.0.0.1:8000
```

To report this machine into the dashboard continuously, leave `serve` running
and start a collector in a second terminal:

```bash
python3 -m miningguard collect
```

Other commands:

```bash
python3 -m miningguard rules           # rule catalogue, bands, indicator counts
python3 -m miningguard scan --json     # raw snapshot, for piping elsewhere
python3 -m pytest                      # test suite
```

## Risk scoring

Each rule contributes points. Every point is attributable to a named signal
with its own evidence string, so a score can always be explained.

| Points | Rule | Evidence class |
| --- | --- | --- |
| +30 | `known_miner_binary` | identity |
| +25 | `mining_infrastructure` | network |
| +20 | `sustained_cpu` | resource |
| +20 | `unknown_executable` | identity |
| +20 | `browser_cryptojacking` | browser |
| +15 | `sustained_gpu` | resource |
| +15 | `stratum_port` | network |
| +15 | `suspicious_persistence` | persistence |
| +15 | `masquerading_name` | identity |
| +10 | `elevated_cpu` | resource |
| +10 | `long_lived_connection` | network |
| +10 | `repeated_connections` | network |
| +10 | `unusual_command_line` | command line |
| +10 | `suspicious_dns` | DNS |
| −10 | `trusted_system_path` | mitigation |
| −25 | `allowlisted_workload` | mitigation |

Bands: `0–24 NORMAL`, `25–49 LOW`, `50–74 MEDIUM`, `75–89 HIGH`, `90–100 CRITICAL`.
Findings at 25 or above become a detection with an alert.

### False-positive reduction

Four mechanisms, in the order they apply:

1. **Corroboration requirement.** Resource-only findings are capped at 24 and
   reported as `suppressed` on ingest with an explanation, not as an alert.
   A compiler at 100% CPU for an hour stays NORMAL.
2. **Mitigating signals.** Known CPU-heavy applications (`ffmpeg`, `cc1plus`,
   `MsMpEng`, video editors, database engines) subtract points — but only when
   they run from a trusted path, so `svchost.exe` in `%TEMP%` cannot launder
   itself through the allowlist.
3. **Fingerprint deduplication.** A detection is keyed by host, subject and the
   set of rules that fired. Repeat observations update the existing finding and
   bump `observation_count` instead of generating a new alert every 15 seconds.
4. **Lifecycle.** Findings whose evidence stops being observed auto-resolve
   after 15 minutes. Marking an alert as a false positive suppresses its
   fingerprint so the same evidence does not immediately reopen it.

Three specific traps are worth calling out, because a first pass at this
project walks straight into all of them — running the scan against a clean
Linux host produced one MEDIUM and one LOW finding, both wrong:

- **The kernel has no executable.** Linux kernel threads such as
  `kworker/3:1H` and system daemons with no path or command line can look like
  suspicious binaries to the identity rules. They are excluded from scoring —
  but a miner signature still wins, so `kdevtmpfsi` masquerading as the real
  `kdevtmpfs` is not excused.
- **Generic flags are not mining flags.** `--threads`, `--url`, `--worker`,
  `--daemon` and `--keepalive` appear in compilers, media tools and most
  Electron apps. Only flags whose dominant user is mining software count, and
  `--pool`/`--url` require a value that looks like a mining endpoint.
- **Clouds generate hostnames too.** A DGA heuristic tuned on entropy alone
  flags `ae2c518386054b8a3.awsglobalaccelerator.com`. Provider domains are
  excluded outright, and the test now needs high entropy *and* a near-total
  absence of vowels, since hex-looking names are entropy-rich but vowel-rich.

Autostart matching has the same flavour of problem: linking a systemd unit or
cron entry to a process by substring can falsely attribute a service to a
similar name. A link requires the full executable path or an exact match on
its own filename.

## What is collected

**Processes** — name, command line, executable path, parent process, CPU, GPU,
memory, thread count, process lifetime. CPU is tracked across polls, because
"sustained" is the whole signal: the collector reports instantaneous CPU, an
exponentially weighted average, and how long the process has stayed
continuously above the elevated threshold.

`cpu_usage` is core-saturation percent capped at 100, so one fully pinned
thread reads as 100%. `cpu_share` divides that by core count to show how much
of the whole machine a process is eating. Both are stored; the rules use the
first, the dashboard shows both.

Sampling is split in two, because opening a process handle dominates the cost
of a poll. A cheap pass reads CPU for all processes, reusing cached handles and
caching attributes that cannot change for the life of a pid (name, path,
command line, owner, parent). Memory, thread counts and a pid-reuse identity
check are then applied only to the ~40 processes actually being reported.
Measured on a 380-process Windows host, that took a steady-state poll from
6.5s to 2.1s; the naive version was slower than the default 15-second
collection interval.

**Network** — destination IP, reverse-resolved domain, port, protocol, socket
state, plus two things the OS does not expose portably: how long an endpoint
has been in use, and how many times it has been reconnected. Those are measured
across polls and are what separate a mining session from an ordinary API call.

**DNS** — on Linux, resolver visibility usually comes from the system resolver
log or packet capture because the cache is not exposed in a portable way. The
engine scores fewer DNS signals when the host environment does not provide a
reliable query history.

Reverse lookups run on daemon threads rather than inline. `gethostbyaddr` can
stall for seconds per address and ignores socket timeouts, so resolving 70-odd
endpoints during a poll takes longer than the interval; callers read whatever
is cached and a name that is not ready yet appears on the next poll.

**Persistence** — Linux systemd units, cron (`/etc/crontab`, `/etc/cron.d`,
user crontabs), `rc.local`, init scripts and shell profiles. All read-only, and
each source degrades quietly when it is not readable at the current privilege
level.

**GPU** — optional, via `nvidia-smi pmon`, falling back to a GPU-memory-share
estimate on drivers without per-process SM accounting. GPU mining leaves the
CPU nearly idle, so CPU-only telemetry misses it entirely.

## Detection signals in detail

**Identity.** Executable paths are classified `trusted` (under `/usr/bin`,
`/usr/local/bin`, `/opt`, `/snap`, …), `suspicious` (temp directories,
`/dev/shm`, `Downloads`, dot-prefixed or hex-random filenames) or `unknown`.
A `suspicious` path scores the full 20 points; `unknown` scores half, because
"not on my list" is weaker evidence than "hiding in `/tmp`". About 80 miner
binary names are matched, including malware families that rename themselves
(`kdevtmpfsi`, `kinsing`, `sysrv`).

**Network.** Around 50 mining pool domains and 35 in-browser mining services are
matched as domain suffixes, so `eu.pool.supportxmr.com` hits `supportxmr.com`
while `notsupportxmr.com.example.net` does not. Stratum ports are supporting
evidence only, since other software uses them too. Private, loopback and
link-local destinations are ignored entirely.

**Command line.** Stratum URLs, `--donate-level`, RandomX/KawPow/Ethash algorithm
flags, CPU-pinning and hugepages flags, `curl … | sh` pipelines, encoded
PowerShell, and Monero/Ethereum/Bitcoin wallet address patterns.

**DNS.** Mining domains in the resolver cache, plus a DGA heuristic: hostname
labels with Shannon entropy above 3.3 combined with an unusually low vowel ratio
or high digit ratio. DNS evidence only *reinforces* a process that is already
suspicious — it never stands up a finding on its own, otherwise one bad entry in
a shared cache would implicate every process on the box.

**Browser cryptojacking.** Renderer and content child processes are identified
from their command line (`--type=renderer`, `-contentproc`). Chromium funnels
sockets through its network service, so a mining tab usually owns no sockets;
connections are pooled across the browser process tree to keep domain evidence
attached to the tab. A finding needs a sustained-busy renderer *and* a
cryptojacking or algorithmically-generated domain in that tree. Note the honest
limitation: an external agent cannot inspect a page's JavaScript or WebAssembly,
so sustained renderer CPU is used as the proxy for that step.

**Persistence.** Autostart entries are linked to running processes by executable
path or name. Entries that reference a miner binary, launch from a suspicious
path, or carry mining arguments are also reported on their own as
`persistence_mining`, so a miner that reinstalls itself at boot is caught while
the process is idle or already dead.

## Data model

```
hosts ──┬── processes ──┬── network_events
        │               └── detections ── alerts
        ├── network_events
        ├── persistence_items
        └── detections
```

`hosts` carries a denormalised `risk_score`/`severity` rollup of its worst open
detection, refreshed on every ingest, so the host list is one cheap query.
`detections.signals` is a JSON array of the scored signals, which keeps the
evidence with the finding and portable across PostgreSQL and SQLite.
`persistence_items` is not in the original sketch, but the risk model scores
persistence and that evidence needs somewhere to live; it is replaced wholesale
per host on each report because it is current state, not an event stream.

Raw `processes` and `network_events` rows are pruned after `MG_RETENTION_DAYS`
(default 14). Detections and alerts are kept, as are process rows referenced by
a detection.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/ingest` | agent submits a host snapshot; returns the detections it produced |
| `GET` | `/api/v1/stats` | dashboard rollup |
| `GET` | `/api/v1/hosts` | host list with risk, filterable by `severity` |
| `GET` | `/api/v1/hosts/{id}` | detections, latest processes, network, persistence |
| `GET` | `/api/v1/detections` | filter by `severity`, `status`, `host_id`, `min_score` |
| `GET` | `/api/v1/alerts` | alert queue, open by default |
| `PATCH` | `/api/v1/alerts/{id}` | assign, acknowledge, close, mark false positive |
| `GET` | `/api/v1/intel` | loaded rules, bands, thresholds, indicator counts |
| `GET` | `/api/v1/health` | liveness with a database round-trip |

Interactive docs at `/docs`. Setting `MG_API_TOKEN` requires agents to send
`Authorization: Bearer <token>` on `/ingest`; leaving it empty disables the
check so a local demo needs no setup.

## PostgreSQL and Docker

SQLite is the default so the project runs with one command. For PostgreSQL on Linux:

```bash
docker compose up -d db api
```

Or point an existing server at it:

```bash
export MG_DATABASE_URL="postgresql+psycopg://miningguard:miningguard@localhost:5432/miningguard"
python3 -m miningguard serve
```

The `collector` compose service is Linux-only and gated behind the
`linux-agent` profile, because an agent in a container sees the container's
processes unless it shares the host PID and network namespaces. On Linux, run
`python3 -m miningguard collect` directly when you want the agent on the host.

## Configuration

Copy `.env.example` to `.env`. Every value has a working default. Thresholds
(`MG_SUSTAINED_CPU_PERCENT`, `MG_SUSTAINED_CPU_SECONDS`, …) live in one place
and are shared by the collector and the engine so the two cannot disagree.

Set `MG_FEED_PATH` to a JSON file shaped like `feeds/indicators.example.json` to
add pool domains, cryptojacking domains, miner names, bad IPs or CIDR ranges —
and to allowlist processes and domains — without touching code. Allowlist
entries override built-in indicators, which is how you silence a false positive
in a specific environment.

## Project layout

- `miningguard/intel.py` — indicators and matching helpers
- `miningguard/rules.py` — risk scoring and the corroboration guard
- `miningguard/service.py` — ingest pipeline and detection lifecycle
- `miningguard/api.py` — FastAPI routes
- `miningguard/models.py` — SQLAlchemy schema
- `miningguard/collector/` — process, network, DNS, persistence and GPU sampling
- `miningguard/web/` — dashboard
- `miningguard/demo.py` — synthetic fleet used by the demo and the tests

## Demo fleet

`seed-demo` loads six hosts chosen to exercise the interesting paths:

| Host | Scenario | Expected |
| --- | --- | --- |
| `PC-001` | ordinary workstation | NORMAL |
| `PC-002` | XMRig in `%TEMP%`, stratum pool, scheduled task | CRITICAL |
| `SERVER-01` | `kdevtmpfsi` in `/tmp`, systemd unit, cron downloader | CRITICAL |
| `PC-014` | browser tab talking to `coinimp` | MEDIUM |
| `BUILD-02` | compiler and ffmpeg at 100% CPU for an hour | NORMAL, suppressed |
| `PC-031` | GPU miner with an idle CPU | CRITICAL |

`BUILD-02` is the one to look at: two processes pinned at 100% CPU, and no
alert.

## Limitations

- No code signature verification. Path trust is a proxy for it; package-manager
  or ELF-signature verification would be a clear improvement.
- Page-level JavaScript and WebAssembly are not inspected, so browser
  cryptojacking relies on renderer CPU plus domain reputation.
- DNS visibility depends on resolver logs or packet capture when the system does
  not expose reliable cache data.
- Without elevation, `psutil` cannot read every process's executable path or
  the system-wide socket table; the collector falls back to per-process
  enumeration and the engine scores what it has.
- The ingest token is a shared secret, not authentication. Real
  authentication, RBAC and per-agent identity are Phase 4.

## Roadmap

Built: process, network, DNS, persistence and GPU collection; risk scoring with
corroboration; reputation feeds; REST API; dashboard; alert triage; PostgreSQL
and SQLite; Docker; tests.

Next:

- **Phase 3** — behavioural baselining per host, anomaly detection on the
  collected features, hashrate estimation from connection timing.
- **Phase 4** — authentication and RBAC, agent enrolment with per-agent keys,
  centralised logging, SIEM export (CEF/ECS), response actions.
- A C++ collector sharing this API contract, for lower overhead on monitored
  hosts.


