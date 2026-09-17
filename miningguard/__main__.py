"""MiningGuard command line interface."""

from __future__ import annotations

import argparse
import importlib
import json
import sys

from . import intel
from .config import settings


def _cmd_serve(args: argparse.Namespace) -> int:
    uvicorn = importlib.import_module("uvicorn")

    uvicorn.run(
        "miningguard.api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )
    return 0


def _cmd_collect(args: argparse.Namespace) -> int:
    from .collector.agent import run_forever

    try:
        run_forever(settings, max_iterations=args.iterations)
    except KeyboardInterrupt:
        print("\nCollector stopped.")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Evaluate the local machine and print a report. No server required."""
    from .collector.agent import Collector
    from .rules import ALERT_THRESHOLD, evaluate_host
    from .service import build_observation
    from .schemas import SnapshotIn

    intel.load_feed(settings.feed_path)
    collector = Collector(settings)
    print(f"Sampling {collector.facts.hostname} for {args.settle:.0f}s ...", file=sys.stderr)
    payload = SnapshotIn.model_validate(collector.snapshot_once(args.settle))

    if args.json:
        print(json.dumps(payload.model_dump(mode="json"), indent=2, default=str))
        return 0

    observation = build_observation(payload)
    assessments = evaluate_host(observation, settings)

    print()
    print(f"MiningGuard scan — {payload.host.hostname} ({payload.host.os})")
    print("=" * 72)
    print(f"Processes sampled : {len(payload.processes)}")
    print(f"Remote endpoints  : {len(payload.connections)}")
    print(f"Autostart entries : {len(payload.persistence)}")
    print(f"DNS names seen    : {len(payload.dns_queries)}")
    print()

    findings = [a for a in assessments if a.risk_score >= ALERT_THRESHOLD]
    if not findings:
        print("No mining indicators found.")
    for assessment in findings:
        subject = assessment.process.name if assessment.process else "host"
        print(f"[{assessment.severity}] {assessment.risk_score:>3}  {subject}")
        print(f"       {assessment.reason}")
        for signal in assessment.signals:
            sign = "+" if signal.points >= 0 else ""
            print(f"       {sign}{signal.points:>3}  {signal.title}: {signal.detail}")
        print()

    held = [a for a in assessments if a.capped]
    if held:
        print("Held below alerting threshold (resource usage without corroboration):")
        for assessment in held:
            subject = assessment.process.name if assessment.process else "host"
            detail = ", ".join(s.title for s in assessment.signals if s.points > 0)
            print(f"  - {subject}: {detail}")
        print()

    top = sorted(
        payload.processes, key=lambda p: -max(p.cpu_usage, p.cpu_average)
    )[: args.top]
    print(f"Top {len(top)} processes by CPU")
    print(f"{'PROCESS':<28}{'CPU':>7}{'AVG':>7}{'SUSTAINED':>11}  PATH")
    for proc in top:
        sustained = f"{proc.cpu_sustained_seconds / 60:.1f} min" if proc.cpu_sustained_seconds else "-"
        print(
            f"{proc.name[:27]:<28}{proc.cpu_usage:>6.0f}%{proc.cpu_average:>6.0f}%"
            f"{sustained:>11}  {proc.path[:60]}"
        )
    return 0


def _cmd_seed_demo(args: argparse.Namespace) -> int:
    from .db import init_db, session_scope
    from .demo import fleet
    from .service import ingest_snapshot

    init_db()
    with session_scope() as session:
        for snapshot in fleet():
            result = ingest_snapshot(session, snapshot, settings)
            print(
                f"{result['hostname']:<12} risk {result['host_risk_score']:>3} "
                f"{result['host_severity']:<9} {len(result['detections'])} detection(s)"
            )
            for note in result["suppressed"]:
                print(f"             suppressed: {note}")
    print(f"\nDemo fleet loaded into {settings.database_url}")
    print(f"Start the dashboard with: python -m miningguard serve")
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    from .rules import ALERT_THRESHOLD, RULE_POINTS, SEVERITY_BANDS, UNCORROBORATED_CEILING

    intel.load_feed(settings.feed_path)
    print("Risk scoring rules")
    print("-" * 52)
    for rule_id, points in sorted(RULE_POINTS.items(), key=lambda kv: -kv[1]):
        sign = "+" if points >= 0 else ""
        print(f"{sign}{points:>4}  {rule_id}")
    print()
    print("Severity bands")
    print("-" * 52)
    bands = list(reversed(SEVERITY_BANDS))
    for index, (floor, label) in enumerate(bands):
        ceiling = bands[index + 1][0] - 1 if index + 1 < len(bands) else 100
        print(f"{floor:>3}-{ceiling:<3}  {label}")
    print()
    print(f"Alert threshold            : {ALERT_THRESHOLD}")
    print(f"Uncorroborated score cap   : {UNCORROBORATED_CEILING}")
    print()
    print("Loaded indicators")
    print("-" * 52)
    for key, count in intel.indicator_summary().items():
        print(f"{count:>6}  {key}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miningguard",
        description="Cryptomining and cryptojacking detection.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the API and dashboard")
    serve.add_argument("--host", default=settings.api_host)
    serve.add_argument("--port", type=int, default=settings.api_port)
    serve.add_argument("--reload", action="store_true")
    serve.add_argument("--log-level", default="info")
    serve.set_defaults(func=_cmd_serve)

    collect = sub.add_parser("collect", help="run the collector agent against the API")
    collect.add_argument(
        "--iterations", type=int, default=None, help="stop after N reports (default: run forever)"
    )
    collect.set_defaults(func=_cmd_collect)

    scan = sub.add_parser("scan", help="scan this machine once and print a report")
    scan.add_argument("--settle", type=float, default=3.0, help="CPU sampling window in seconds")
    scan.add_argument("--top", type=int, default=12, help="processes to list")
    scan.add_argument("--json", action="store_true", help="emit the raw snapshot instead")
    scan.set_defaults(func=_cmd_scan)

    seed = sub.add_parser("seed-demo", help="load a synthetic fleet into the database")
    seed.set_defaults(func=_cmd_seed_demo)

    rules_cmd = sub.add_parser("rules", help="print the rule catalogue and indicator counts")
    rules_cmd.set_defaults(func=_cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())


