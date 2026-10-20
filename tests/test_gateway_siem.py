"""Phase 5 tests: SIEM Threat Hunting integration with Micro-SASE Gateway telemetry."""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from siem_hunter.anomaly import AnomalyDetector
from siem_hunter.models import Event
from siem_hunter.parser import parse_json_line, parse_lines
from siem_hunter.pipeline import Pipeline, write_report
from siem_hunter.rule_engine import RuleEngine, load_rules


RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def _make_gateway_event(
    delta_s: int = 0,
    event_type: str = "sase_gateway_access",
    decision: str = "ALLOW",
    status_code: int = 200,
    method: str = "GET",
    path: str = "/proxy/inventory/items",
    target_service: str = "inventory",
    subject: str = "alice",
    client_ip: str = "192.168.1.50",
    reason: str = "Allowed by PEP",
) -> str:
    base_ts = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)
    ts = base_ts + timedelta(seconds=delta_s)
    data = {
        "timestamp": ts.isoformat(),
        "event_type": event_type,
        "decision": decision,
        "status_code": status_code,
        "method": method,
        "path": path,
        "target_service": target_service,
        "subject": subject,
        "auth_type": "jwt",
        "role": "developer",
        "client_ip": client_ip,
        "latency_ms": 1.25,
        "reason": reason,
    }
    return json.dumps(data)


# --- 1. Parser Normalization Tests -------------------------------------------

def test_gateway_json_parser_normalizes_fields():
    line = _make_gateway_event(
        subject="alice_dev",
        client_ip="10.200.1.5",
        status_code=200,
        decision="ALLOW",
    )
    ev = parse_json_line(line, source="gateway_audit.jsonl")
    assert ev is not None
    # Verifies both original gateway keys and normalized SIEM keys exist
    assert ev.get("subject") == "alice_dev"
    assert ev.get("user") == "alice_dev"
    assert ev.get("client_ip") == "10.200.1.5"
    assert ev.get("src_ip") == "10.200.1.5"
    assert ev.get("decision") == "ALLOW"
    assert ev.get("status_code") == 200
    assert ev.get("hour") == 12


# --- 2. Backend Bypass Detection Test (Signature) ----------------------------

def test_sase_direct_bypass_rule():
    rules = load_rules(RULES_DIR)
    engine = RuleEngine(rules)

    bypass_line = _make_gateway_event(
        decision="DENY",
        status_code=403,
        path="/mock-service/billing",
        reason="Direct access to backend services is not allowed. Go through /proxy/.",
    )
    ev = parse_json_line(bypass_line, "gateway_audit.jsonl")
    detections = engine.evaluate(ev)

    matching = [d for d in detections if d.rule_id == "SASE-BYPASS-0001"]
    assert len(matching) == 1
    assert matching[0].severity == "critical"
    assert "T1190" in [m["id"] for m in matching[0].mitre_techniques]


# --- 3. Password Spraying Detection Test (Threshold + Distinct User) ---------

def test_sase_password_spraying_detection():
    rules = load_rules(RULES_DIR)
    engine = RuleEngine(rules)

    # Attacker from 198.51.100.99 tries 3 distinct accounts: bob, alice, charlie
    lines = [
        _make_gateway_event(delta_s=10, path="/auth/token", status_code=401, decision="DENY", subject="bob", client_ip="198.51.100.99"),
        _make_gateway_event(delta_s=20, path="/auth/token", status_code=401, decision="DENY", subject="alice", client_ip="198.51.100.99"),
        _make_gateway_event(delta_s=30, path="/auth/token", status_code=401, decision="DENY", subject="charlie", client_ip="198.51.100.99"),
    ]

    detections = []
    for line in lines:
        ev = parse_json_line(line, "gateway_audit.jsonl")
        detections.extend(engine.evaluate(ev))

    spray_dets = [d for d in detections if d.rule_id == "SASE-SPRAY-0001"]
    assert len(spray_dets) == 1
    det = spray_dets[0]
    assert det.entity == "198.51.100.99"
    assert det.severity == "high"
    assert det.context["distinct_count"] == 3
    assert set(det.context["distinct_values"]) == {"alice", "bob", "charlie"}
    assert "T1110.003" in [m["id"] for m in det.mitre_techniques]


# --- 4. Single Account Brute Force Detection Test (Threshold) ----------------

def test_sase_single_account_brute_force():
    rules = load_rules(RULES_DIR)
    engine = RuleEngine(rules)

    # Attacker attempts 4 passwords against user 'bob'
    lines = [
        _make_gateway_event(delta_s=i * 5, path="/auth/token", status_code=401, decision="DENY", subject="bob", client_ip="203.0.113.4")
        for i in range(4)
    ]

    detections = []
    for line in lines:
        ev = parse_json_line(line, "gateway_audit.jsonl")
        detections.extend(engine.evaluate(ev))

    brute_dets = [d for d in detections if d.rule_id == "SASE-BRUTE-0001"]
    assert len(brute_dets) == 1
    assert brute_dets[0].entity == "bob"
    assert brute_dets[0].severity == "medium"
    assert "T1110.001" in [m["id"] for m in brute_dets[0].mitre_techniques]


# --- 5. PBAC Privilege Probing Reconnaissance Test (Threshold + Distinct Path)

def test_sase_pbac_reconnaissance_probing():
    rules = load_rules(RULES_DIR)
    engine = RuleEngine(rules)

    # Rogue user 'mallory' attempts 3 distinct forbidden administrative endpoints
    forbidden_paths = [
        "/proxy/admin-panel/config",
        "/proxy/admin-panel/firewall",
        "/proxy/billing/secret-dump",
    ]
    lines = [
        _make_gateway_event(delta_s=i * 10, path=p, status_code=403, decision="DENY", subject="mallory", client_ip="10.0.5.99")
        for i, p in enumerate(forbidden_paths)
    ]

    detections = []
    for line in lines:
        ev = parse_json_line(line, "gateway_audit.jsonl")
        detections.extend(engine.evaluate(ev))

    probing_dets = [d for d in detections if d.rule_id == "SASE-PBAC-ABUSE-0001"]
    assert len(probing_dets) == 1
    assert probing_dets[0].entity == "mallory"
    assert probing_dets[0].severity == "high"
    assert probing_dets[0].context["distinct_count"] == 3


# --- 6. QBAC Burst Exhaustion Test (Threshold) -------------------------------

def test_sase_burst_exhaustion_detection():
    rules = load_rules(RULES_DIR)
    engine = RuleEngine(rules)

    # Scraper 'eve' exceeds burst tokens triggering 4 consecutive 429s
    lines = [
        _make_gateway_event(delta_s=i * 2, path="/proxy/inventory/items", status_code=429, decision="DENY", subject="eve", client_ip="198.51.100.77")
        for i in range(4)
    ]

    detections = []
    for line in lines:
        ev = parse_json_line(line, "gateway_audit.jsonl")
        detections.extend(engine.evaluate(ev))

    burst_dets = [d for d in detections if d.rule_id == "SASE-BURST-EXHAUSTION-0001"]
    assert len(burst_dets) == 1
    assert burst_dets[0].entity == "eve"
    assert burst_dets[0].severity == "medium"
    assert "T1499" in [m["id"] for m in burst_dets[0].mitre_techniques]


# --- 7. Statistical Anomaly Hunting on Gateway Traffic -----------------------

def test_sase_statistical_volume_anomaly():
    # Setup dataset with 5 distinct clients:
    # 4 benign clients with normal event counts (2 events each)
    # 1 outlier client sending 40 requests
    detector = AnomalyDetector(entity_field="src_ip", threshold=3.5, min_entities=4)

    # Baseline traffic
    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]:
        for _ in range(2):
            ev = parse_json_line(_make_gateway_event(client_ip=ip), "gateway_audit.jsonl")
            detector.observe(ev)

    # Anomaly spike
    for _ in range(40):
        ev = parse_json_line(_make_gateway_event(client_ip="192.168.100.99"), "gateway_audit.jsonl")
        detector.observe(ev)

    anomalies = detector.finalize()
    assert len(anomalies) == 1
    assert anomalies[0].entity == "192.168.100.99"
    assert anomalies[0].detector == "anomaly"
    assert anomalies[0].context["event_count"] == 40
    assert anomalies[0].context["modified_z_score"] >= 3.5


# --- 8. End-to-End Pipeline Ingestion & Report Output ------------------------

def test_sase_full_pipeline_run_and_reporting():
    with TemporaryDirectory() as tmpdir:
        tmp_log = Path(tmpdir) / "gateway_audit.jsonl"
        tmp_report = Path(tmpdir) / "detections.json"

        # Write a realistic mixed log file:
        # - Benign requests
        # - 1 backend direct bypass attempt (Critical)
        # - 3 password spray attempts (High)
        content = [
            _make_gateway_event(delta_s=1, subject="alice", status_code=200, decision="ALLOW"),
            _make_gateway_event(delta_s=2, subject="bob", status_code=200, decision="ALLOW"),
            _make_gateway_event(delta_s=3, subject="mallory", status_code=403, decision="DENY", path="/mock-service/billing", reason="Direct access to backend services is not allowed"),
            _make_gateway_event(delta_s=4, client_ip="45.33.32.156", path="/auth/token", status_code=401, subject="user1"),
            _make_gateway_event(delta_s=5, client_ip="45.33.32.156", path="/auth/token", status_code=401, subject="user2"),
            _make_gateway_event(delta_s=6, client_ip="45.33.32.156", path="/auth/token", status_code=401, subject="user3"),
        ]
        tmp_log.write_text("\n".join(content) + "\n", encoding="utf-8")

        pipeline = Pipeline(rules_dir=RULES_DIR, anomaly_field="src_ip")
        results = pipeline.analyze(tmp_log, fmt="json")

        assert results["summary"]["events"] == 6
        assert results["summary"]["detections"] >= 2

        rule_ids = [d["rule_id"] for d in results["detections"]]
        assert "SASE-BYPASS-0001" in rule_ids
        assert "SASE-SPRAY-0001" in rule_ids

        # Write report and verify valid JSON structure
        write_report(pipeline.run(tmp_log, fmt="json"), tmp_report)
        assert tmp_report.exists()
        saved = json.loads(tmp_report.read_text(encoding="utf-8"))
        assert isinstance(saved, list)
        assert len(saved) >= 2


def test_private_ten_network_is_not_classified_as_external():
    rules = load_rules(RULES_DIR)
    engine = RuleEngine(rules)
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="endpoint.csv",
        raw="",
        fields={"image": "svchost.exe", "destinationip": "10.10.10.5"},
    )

    detections = engine.evaluate(event)
    assert "ENDPT-LMOV-0001" not in {d.rule_id for d in detections}
