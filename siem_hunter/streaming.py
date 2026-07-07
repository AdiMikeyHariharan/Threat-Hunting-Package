"""Live streaming pipeline — turns the batch engine into a real-time monitor.

Instead of reading a whole file and finishing, this *follows* a growing log
(``tail -f`` semantics), normalises each new line, and runs detection as events
arrive. Detections are pushed to a list of *sinks* (console, JSONL, a live
store the dashboard polls, and/or Elasticsearch).

Signature and frequency/threshold rules are evaluated per-event, so they alert
in real time. The statistical anomaly hunter is inherently batch (it needs a
population to compare against), so it is run periodically over a rolling window
of recent events.
"""

from __future__ import annotations

import time
from collections import deque
from pathlib import Path
from typing import Callable

from .anomaly import AnomalyDetector
from .logging_config import get_logger
from .models import Detection, Event
from .parser import parse_syslog_line, parse_json_line
from .rule_engine import RuleEngine, load_rules

log = get_logger(__name__)

Sink = Callable[[Detection], None]


class StreamingPipeline:
    def __init__(
        self,
        rules_dir: str | Path,
        sinks: list[Sink],
        anomaly_field: str = "src_ip",
        anomaly_window_seconds: int = 900,
        anomaly_interval_seconds: int = 30,
        fmt: str = "syslog",
    ):
        self.engine = RuleEngine(load_rules(rules_dir))
        self.sinks = sinks
        self.fmt = fmt
        self.anomaly_field = anomaly_field
        self.anomaly_window = anomaly_window_seconds
        self.anomaly_interval = anomaly_interval_seconds
        # Rolling buffer of recent events for periodic anomaly scans.
        self._buffer: deque[Event] = deque()
        self._last_anomaly_scan = 0.0
        # (rule_id, entity) -> last alert time, to avoid re-alerting each pass.
        self._anomaly_seen: dict[tuple[str, str], float] = {}

    # -- event handling ----------------------------------------------------- #
    def _parse(self, line: str, source: str) -> Event | None:
        line = line.rstrip("\n")
        if not line.strip():
            return None
        if self.fmt == "json":
            return parse_json_line(line, source)
        return parse_syslog_line(line, source, time.gmtime().tm_year)

    def process_line(self, line: str, source: str) -> list[Detection]:
        event = self._parse(line, source)
        if event is None:
            return None if not line.strip() else []

        detections = self.engine.evaluate(event)     # signature + threshold, live
        self._buffer.append(event)
        self._evict_buffer(event.timestamp.timestamp())

        now = time.monotonic()
        if now - self._last_anomaly_scan >= self.anomaly_interval:
            detections.extend(self._run_anomaly_scan())
            self._last_anomaly_scan = now

        for det in detections:
            self._emit(det)
        return detections

    def _evict_buffer(self, latest_ts: float) -> None:
        cutoff = latest_ts - self.anomaly_window
        while self._buffer and self._buffer[0].timestamp.timestamp() < cutoff:
            self._buffer.popleft()

    def _run_anomaly_scan(self) -> list[Detection]:
        detector = AnomalyDetector(entity_field=self.anomaly_field)
        for ev in self._buffer:
            detector.observe(ev)
        fresh: list[Detection] = []
        now = time.monotonic()
        for det in detector.finalize():
            key = (det.rule_id, det.entity or "")
            last = self._anomaly_seen.get(key)      # None = never alerted
            if last is None or (now - last) >= self.anomaly_window:
                self._anomaly_seen[key] = now
                fresh.append(det)
        return fresh

    def _emit(self, det: Detection) -> None:
        for sink in self.sinks:
            try:
                sink(det)
            except Exception as exc:                # a bad sink must not kill the stream
                log.error("sink_error", error=str(exc))

    # -- follow loop -------------------------------------------------------- #
    def follow(self, path: str | Path, from_start: bool = False,
               poll: float = 0.4) -> None:
        """Tail a growing file forever, detecting on each new line."""
        path = Path(path)
        source = path.name
        log.info("stream_follow_start", path=str(path), from_start=from_start)

        # Wait for the file to exist (the generator may start after us).
        while not path.exists():
            time.sleep(poll)

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            if not from_start:
                fh.seek(0, 2)                        # jump to EOF: only new lines
            while True:
                line = fh.readline()
                if line:
                    self.process_line(line, source)
                else:
                    time.sleep(poll)
