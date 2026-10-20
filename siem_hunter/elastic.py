"""Minimal Elasticsearch shipper (no third-party client dependency).

Ships events and detections to Elasticsearch via the ``_bulk`` HTTP API using
only the standard library. If ES is unreachable the client disables itself and
the pipeline keeps running — telemetry to ES is best-effort, never a hard
dependency.

Indices:
  * ``siem-events``     — every normalised event
  * ``siem-detections`` — every finding (severity, detector, entity, ATT&CK)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .logging_config import get_logger
from .models import Detection, Event

log = get_logger(__name__)

EVENTS_INDEX = "siem-events"
DETECTIONS_INDEX = "siem-detections"

# Minimal mappings so Kibana treats fields correctly (keywords + date).
_DETECTION_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "rule_id": {"type": "keyword"},
            "title": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "detector": {"type": "keyword"},
            "entity": {"type": "keyword"},
            "event_count": {"type": "integer"},
            "mitre_ids": {"type": "keyword"},
            "mitre_tactics": {"type": "keyword"},
        }
    }
}
_EVENT_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "source": {"type": "keyword"},
            "program": {"type": "keyword"},
            "user": {"type": "keyword"},
            "src_ip": {"type": "ip"},
            "dst_port": {"type": "integer"},
        }
    }
}


class ElasticClient:
    def __init__(self, url: str = "http://localhost:9200", timeout: float = 5.0):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.enabled = False

    def connect(self) -> bool:
        """Ping ES and create indices. Returns False (and disables) on failure."""
        try:
            self._request("GET", "/")
            self._ensure_index(DETECTIONS_INDEX, _DETECTION_MAPPING)
            self._ensure_index(EVENTS_INDEX, _EVENT_MAPPING)
        except (urllib.error.URLError, OSError) as exc:
            log.warning("elastic_unreachable", url=self.url, error=str(exc))
            self.enabled = False
            return False
        self.enabled = True
        log.info("elastic_connected", url=self.url)
        return True

    # -- indexing ----------------------------------------------------------- #
    def index_detection(self, det: Detection) -> None:
        if not self.enabled:
            return
        doc = {
            "@timestamp": (det.timestamp or datetime.now(timezone.utc)).isoformat(),
            "rule_id": det.rule_id,
            "title": det.title,
            "severity": det.severity,
            "detector": det.detector,
            "entity": det.entity,
            "event_count": len(det.event_ids),
            "mitre_ids": [m["id"] for m in det.mitre_techniques],
            "mitre_tactics": [m["tactic"] for m in det.mitre_techniques],
            "context": det.context,
        }
        self._index(DETECTIONS_INDEX, doc)

    def index_event(self, event: Event) -> None:
        if not self.enabled:
            return
        doc = {"@timestamp": event.timestamp.isoformat(),
               "source": event.source, **event.fields}
        self._index(EVENTS_INDEX, doc)

    # -- low level ---------------------------------------------------------- #
    def _index(self, index: str, doc: dict) -> None:
        try:
            self._request("POST", f"/{index}/_doc", body=doc)
        except (urllib.error.URLError, OSError) as exc:
            log.error("elastic_index_failed", index=index, error=str(exc))

    def _ensure_index(self, index: str, mapping: dict) -> None:
        try:
            self._request("PUT", f"/{index}", body=mapping)
            log.info("elastic_index_created", index=index)
        except urllib.error.HTTPError as exc:
            if exc.code != 400:                      # 400 = already exists
                log.error("elastic_index_error", index=index, code=exc.code)
                raise

    def _request(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.url + path, data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.load(resp) if resp.length else {}
