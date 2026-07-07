"""Live monitor entrypoint — follow a stream and fan detections out to sinks.

    python -m siem_hunter.monitor --follow logs/live.log --elastic

Sinks (composable):
  * console     — human-readable alert line (always on)
  * jsonl       — append each detection to logs/detections_stream.jsonl
  * live-store  — rolling JSON the dashboard's /api/live endpoint serves
  * elastic     — ship events + detections to Elasticsearch (--elastic)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path

from .elastic import ElasticClient
from .logging_config import RUN_ID, configure_logging, get_logger
from .models import Detection
from .streaming import StreamingPipeline

SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟩"}


def console_sink(det: Detection) -> None:
    icon = SEV_ICON.get(det.severity, "⬜")
    mitre = ",".join(m["id"] for m in det.mitre_techniques) or "-"
    ts = det.timestamp.strftime("%H:%M:%S") if det.timestamp else "--:--:--"
    print(f"{icon} [{ts}] {det.severity.upper():8} {det.title}  "
          f"(entity={det.entity} detector={det.detector} attack={mitre})",
          flush=True)


class JsonlSink:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def __call__(self, det: Detection) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(det.to_dict()) + "\n")


class LiveStoreSink:
    """Keep the most recent N detections in a JSON file for the dashboard."""

    def __init__(self, path: Path, keep: int = 200):
        self.path = path
        self.recent: deque[dict] = deque(maxlen=keep)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def __call__(self, det: Detection) -> None:
        self.recent.appendleft(det.to_dict())
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(list(self.recent)), encoding="utf-8")
        tmp.replace(self.path)          # atomic swap so readers never see partial


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="siem-monitor",
                                description="Live streaming threat monitor.")
    p.add_argument("--follow", required=True, help="log file to tail")
    p.add_argument("--rules", default="rules")
    p.add_argument("--format", default="syslog", choices=["syslog", "json"])
    p.add_argument("--from-start", action="store_true",
                   help="process the whole file first, then follow")
    p.add_argument("--elastic", action="store_true",
                   help="also ship events + detections to Elasticsearch")
    p.add_argument("--elastic-url", default="http://localhost:9200")
    p.add_argument("--log-dir", default="logs")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(log_dir=args.log_dir, level="INFO", console=False)
    log = get_logger("siem_hunter.monitor")
    log.info("monitor_startup", run_id=RUN_ID, follow=args.follow)

    log_dir = Path(args.log_dir)
    sinks = [
        console_sink,
        JsonlSink(log_dir / "detections_stream.jsonl"),
        LiveStoreSink(log_dir / "live_detections.json"),
    ]

    es = None
    if args.elastic:
        es = ElasticClient(args.elastic_url)
        if es.connect():
            sinks.append(es.index_detection)

    pipeline = StreamingPipeline(rules_dir=args.rules, sinks=sinks, fmt=args.format)
    # Mirror raw events into ES too (so Kibana can chart the full stream).
    if es and es.enabled:
        _wrap_events_to_elastic(pipeline, es)

    print(f"● live monitor watching {args.follow} "
          f"(elastic={'on' if es and es.enabled else 'off'}) — Ctrl-C to stop\n",
          flush=True)
    try:
        pipeline.follow(args.follow, from_start=args.from_start)
    except KeyboardInterrupt:
        print("\n● monitor stopped", flush=True)
    return 0


def _wrap_events_to_elastic(pipeline: StreamingPipeline, es: ElasticClient) -> None:
    """Tee every parsed event into Elasticsearch, keeping detection flow intact."""
    original = pipeline.process_line

    def wrapped(line: str, source: str):
        event = pipeline._parse(line, source)
        if event is not None:
            es.index_event(event)
        return original(line, source)

    pipeline.process_line = wrapped


if __name__ == "__main__":
    sys.exit(main())
