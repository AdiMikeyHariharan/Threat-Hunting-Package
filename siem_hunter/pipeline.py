"""Pipeline orchestration: ingest -> normalise -> detect -> hunt -> report.

Ties the stages together and produces a detection report. Emits structured
timing/summary logs at every boundary so a run is fully auditable end to end.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .anomaly import AnomalyDetector
from .logging_config import get_logger
from .models import Detection
from .parser import parse_lines
from .rule_engine import RuleEngine, load_rules

log = get_logger(__name__)


class Pipeline:
    def __init__(self, rules_dir: str | Path, anomaly_field: str = "src_ip"):
        self.engine = RuleEngine(load_rules(rules_dir))
        self.anomaly = AnomalyDetector(entity_field=anomaly_field)

    def run(self, log_file: str | Path, fmt: str = "syslog") -> list[Detection]:
        started = time.perf_counter()
        log_file = Path(log_file)
        log.info("pipeline_start", log_file=str(log_file), format=fmt)

        # 1. Ingest + normalise.
        with log_file.open(encoding="utf-8", errors="replace") as fh:
            events = list(parse_lines(fh, source=log_file.name, fmt=fmt))

        # 2. Order by time so threshold windows are correct.
        events.sort(key=lambda e: e.timestamp)

        # 3. Signature + frequency detection, and feed the hunter.
        detections: list[Detection] = []
        for event in events:
            detections.extend(self.engine.evaluate(event))
            self.anomaly.observe(event)

        # 4. Anomaly hunt over the full window.
        detections.extend(self.anomaly.finalize())

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        by_detector: dict[str, int] = {}
        for d in detections:
            by_detector[d.detector] = by_detector.get(d.detector, 0) + 1

        log.info("pipeline_complete", events=len(events),
                 detections=len(detections), by_detector=by_detector,
                 elapsed_ms=elapsed_ms)
        return detections


def write_report(detections: list[Detection], out_path: str | Path) -> None:
    """Persist detections as a JSON array (one object per finding)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload: list[dict[str, Any]] = [d.to_dict() for d in detections]
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.info("report_written", path=str(out_path), findings=len(detections))
