"""Command-line entry point.

Example
-------
    python -m siem_hunter.cli \
        --log sample_data/auth.log \
        --rules rules \
        --format syslog \
        --out logs/detections.json
"""

from __future__ import annotations

import argparse
import sys

from .logging_config import RUN_ID, configure_logging, get_logger
from .pipeline import Pipeline, write_report

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siem-hunter",
        description="Detection-rule engine + anomaly hunter with structured logging.",
    )
    p.add_argument("--log", required=True, help="log file to analyse")
    p.add_argument("--rules", default="rules", help="directory of YAML rules")
    p.add_argument("--format", default="syslog", choices=["syslog", "json"],
                   help="input log format")
    p.add_argument("--out", default="logs/detections.json",
                   help="where to write the JSON detection report")
    p.add_argument("--anomaly-field", default="src_ip",
                   help="entity field the anomaly detector baselines on")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--log-dir", default="logs", help="directory for JSON logs")
    p.add_argument("--quiet", action="store_true",
                   help="suppress console logs (JSON file still written)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(log_dir=args.log_dir, level=args.log_level,
                      console=not args.quiet)
    log = get_logger("siem_hunter.cli")
    log.info("startup", run_id=RUN_ID, args=vars(args))

    pipeline = Pipeline(rules_dir=args.rules, anomaly_field=args.anomaly_field)
    detections = pipeline.run(args.log, fmt=args.format)
    write_report(detections, args.out)

    detections.sort(key=lambda d: (SEV_ORDER.get(d.severity, 9),
                                   d.timestamp or 0))
    _print_summary(detections)
    return 0


def _print_summary(detections) -> None:
    print("\n" + "=" * 68)
    print(f"  DETECTION SUMMARY — {len(detections)} finding(s)")
    print("=" * 68)
    if not detections:
        print("  No detections.")
        return
    for d in detections:
        mitre = ", ".join(f"{m['id']} ({m['tactic']})"
                          for m in d.mitre_techniques) or "-"
        print(f"\n  [{d.severity.upper():8}] {d.title}")
        print(f"    rule={d.rule_id}  detector={d.detector}  entity={d.entity}")
        print(f"    events={len(d.event_ids)}  mitre={mitre}")
    print("\n" + "=" * 68)


if __name__ == "__main__":
    sys.exit(main())
