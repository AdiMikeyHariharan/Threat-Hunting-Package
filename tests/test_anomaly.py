from datetime import datetime, timezone

from siem_hunter.anomaly import AnomalyDetector
from siem_hunter.models import Event


def _ev(ip):
    return Event(timestamp=datetime(2026, 3, 10, tzinfo=timezone.utc),
                 source="auth.log", raw=f"{ip}-x", fields={"src_ip": ip})


def test_volume_outlier_is_flagged():
    det = AnomalyDetector(entity_field="src_ip", threshold=3.5)
    # Baseline hosts: 1 event each. One noisy host: 30 events.
    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]:
        det.observe(_ev(ip))
    for _ in range(30):
        det.observe(_ev("45.83.19.7"))

    detections = det.finalize()
    assert len(detections) == 1
    d = detections[0]
    assert d.entity == "45.83.19.7"
    assert d.detector == "anomaly"
    assert d.context["modified_z_score"] >= 3.5


def test_no_anomaly_when_uniform():
    det = AnomalyDetector(entity_field="src_ip")
    for ip in ["a", "b", "c", "d", "e"]:
        det.observe(_ev(ip))
    assert det.finalize() == []


def test_skips_when_too_few_entities():
    det = AnomalyDetector(entity_field="src_ip", min_entities=4)
    det.observe(_ev("only-one"))
    assert det.finalize() == []
