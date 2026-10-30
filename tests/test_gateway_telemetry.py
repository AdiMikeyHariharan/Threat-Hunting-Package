"""Quality and safety checks for gateway audit telemetry."""

import json

from fastapi.testclient import TestClient

from gateway import telemetry
from gateway.main import app


def test_request_id_and_operational_fields_are_recorded():
    request_id = "security-review-123"
    client = TestClient(app)

    response = client.post(
        "/auth/token",
        headers={"X-Request-ID": request_id},
        json={"username": "alice", "password": "not-the-password"},
    )

    assert response.status_code == 401
    assert response.headers["X-Request-ID"] == request_id
    event = next(
        event for event in telemetry.read_recent_telemetry(200)
        if event.get("request_id") == request_id
    )
    assert event["schema_version"] == 1
    assert event["event_id"]
    assert event["status_class"] == "4xx"
    assert event["outcome"] == "denied"
    assert event["severity"] == "warning"
    assert event["latency_ms"] >= 0


def test_audit_writer_creates_parent_and_redacts_sensitive_reason_values(tmp_path, monkeypatch):
    audit_path = tmp_path / "nested" / "gateway_audit.jsonl"
    monkeypatch.setattr(telemetry, "GATEWAY_AUDIT_LOG", audit_path)

    tokens = telemetry.begin_request("safe-request-456")
    try:
        event = telemetry.log_gateway_event(
            method="GET",
            path="/proxy/inventory/items?token=do-not-log#fragment",
            target_service="inventory",
            status_code=502,
            decision="DENY",
            client_ip="198.51.100.10",
            reason="Authorization: Bearer super-secret password=hunter2",
        )
    finally:
        telemetry.end_request(tokens)

    assert audit_path.exists()
    assert event["request_id"] == "safe-request-456"
    assert event["path"] == "/proxy/inventory/items"
    assert "super-secret" not in event["reason"]
    assert "hunter2" not in event["reason"]
    assert "<redacted>" in event["reason"]
    assert json.loads(audit_path.read_text())["event_id"] == event["event_id"]


def test_recent_reader_skips_one_malformed_line(tmp_path, monkeypatch):
    audit_path = tmp_path / "gateway_audit.jsonl"
    audit_path.write_text('{"event_id":"first"}\nnot-json\n{"event_id":"last"}\n')
    monkeypatch.setattr(telemetry, "GATEWAY_AUDIT_LOG", audit_path)

    assert [event["event_id"] for event in telemetry.read_recent_telemetry(10)] == ["last", "first"]
