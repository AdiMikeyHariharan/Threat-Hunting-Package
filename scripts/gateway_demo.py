"""Interactive demonstration script for Micro-SASE Gateway Phase 1.

Run this script to see the Zero-Trust Policy Enforcement Point (PEP) in action:
    source .venv/bin/activate
    python scripts/gateway_demo.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from gateway import mock_backends, proxy  # noqa: E402
from gateway.main import app  # noqa: E402
from gateway.users import DEMO_USERS  # noqa: E402

# The mock backends normally run as their own process; run them in-process here.
proxy.UPSTREAM_TRANSPORT = httpx.ASGITransport(app=mock_backends.app)
client = TestClient(app)
backend = TestClient(mock_backends.app)


def login(username: str) -> str:
    pw = DEMO_USERS[username][0]
    return client.post("/auth/token", json={"username": username, "password": pw}).json()["access_token"]


def step(n: int, title: str) -> None:
    print(f"\n[STEP {n}] {title}")


print("\n" + "=" * 70)
print(" 🚀 MICRO-SASE ENTERPRISE API GATEWAY — PHASE 1 DEMONSTRATION")
print("=" * 70)

step(1, "Unauthenticated request to /proxy/inventory/items")
r = client.get("/proxy/inventory/items")
print(f"Status: {r.status_code} (expected 401) -> {r.json()['detail']}")

step(2, "Login with WRONG password")
r = client.post("/auth/token", json={"username": "alice", "password": "guess"})
print(f"Status: {r.status_code} (expected 401) -> {r.json()['detail']}")

step(3, "Alice tries to make herself admin by sending role=admin")
r = client.post("/auth/token", json={"username": "alice", "password": DEMO_USERS["alice"][0], "role": "admin"})
print(f"Status: {r.status_code} -> role actually granted: '{r.json()['role']}' (server decides, not client)")
alice = r.json()["access_token"]

step(4, "Alice (developer) -> /proxy/inventory/items")
r = client.get("/proxy/inventory/items", headers={"Authorization": f"Bearer {alice}"})
print(f"Status: {r.status_code} -> {json.dumps(r.json()['verified_headers_from_gateway'])}")

step(5, "Alice (developer) -> /proxy/admin-panel/config")
r = client.get("/proxy/admin-panel/config", headers={"Authorization": f"Bearer {alice}"})
print(f"Status: {r.status_code} (expected 403) -> {r.json()['detail']}")

step(6, "Alice tries to issue herself an API key")
r = client.post("/auth/register-api-key", json={"service_id": "x", "role": "admin"},
                headers={"Authorization": f"Bearer {alice}"})
print(f"Status: {r.status_code} (expected 403) -> {r.json()['detail']}")

step(7, "Attacker skips the gateway and calls the backend directly")
r = backend.get("/mock-service/admin-panel/config")
print(f"Status: {r.status_code} (expected 403) -> {r.json()['detail']}")

step(8, "Charlie (admin) issues a machine API key for the billing daemon")
charlie = login("charlie")
r = client.post("/auth/register-api-key", json={"service_id": "svc-billing-job", "role": "billing-service"},
                headers={"Authorization": f"Bearer {charlie}"})
api_key = r.json()["api_key"]
print(f"Key (shown once): {api_key[:14]}...   Stored hash: {r.json()['key_sha256'][:16]}...")

step(9, "Billing daemon -> /proxy/billing/invoices with X-API-Key")
r = client.get("/proxy/billing/invoices", headers={"X-API-Key": api_key})
print(f"Status: {r.status_code} -> {json.dumps(r.json()['verified_headers_from_gateway'])}")

print("\n" + "-" * 70)
print(" PHASE 2 — PBAC (method/path/scope) + QBAC (rate limits & quotas)")
print("-" * 70)

step(11, "Alice (scopes read,write) POSTs to inventory  -> allowed by 'write'")
r = client.post("/proxy/inventory/items", headers={"Authorization": f"Bearer {alice}"})
print(f"Status: {r.status_code}  RateLimit remaining: {r.headers.get('X-RateLimit-Remaining')}")

step(12, "Alice DELETEs an inventory item  -> needs 'admin' scope")
r = client.delete("/proxy/inventory/items/42", headers={"Authorization": f"Bearer {alice}"})
print(f"Status: {r.status_code} -> {r.json()['detail']}")

step(13, "Read-only billing daemon tries to POST an invoice")
r = client.post("/proxy/billing/invoices", headers={"X-API-Key": api_key})
print(f"Status: {r.status_code} -> {r.json()['detail']}")

step(14, "Bob (finance) requests an unlisted path  -> default-deny")
bob = login("bob")
r = client.get("/proxy/billing/secret-dump", headers={"Authorization": f"Bearer {bob}"})
print(f"Status: {r.status_code} -> {r.json()['detail']}")

step(15, "Alice fires 30 requests instantly (developer burst = 20)")
codes = [client.get("/proxy/inventory/items", headers={"Authorization": f"Bearer {alice}"}).status_code
         for _ in range(30)]
print(f"200s: {codes.count(200)}   429s: {codes.count(429)}")

step(16, "Attacker guesses Bob's password 7 times")
for i in range(7):
    r = client.post("/auth/token", json={"username": "bob", "password": f"guess{i}"})
    print(f"  attempt {i + 1}: {r.status_code}" + (f"  Retry-After={r.headers['Retry-After']}s" if r.status_code == 429 else ""))

step(17, "Charlie (admin) reads the audit log")
logs = client.get("/telemetry/audit?limit=10", headers={"Authorization": f"Bearer {charlie}"}).json()["logs"]
for e in logs:
    print(f" • {e['decision']:5} {e['status_code']} {e['method']:6} {e['path']:32} {e['subject']:16} {e['reason'][:55]}")

print("\n" + "-" * 70)
print(" PHASE 3 — AT-REST ENCRYPTED CREDENTIAL VAULT (AES-256-GCM)")
print("-" * 70)

DOWNSTREAM_SECRET = "vault_mock_enterprise_cloud_billing_key_98765"

step(18, "Charlie (admin) stores an encrypted downstream credential for 'billing'")
r = client.put(
    "/vault/credentials/billing",
    json={"header": "Authorization", "prefix": "Bearer ", "secret": DOWNSTREAM_SECRET},
    headers={"Authorization": f"Bearer {charlie}"},
)
print(f"Status: {r.status_code} -> Stored Version: {r.json()['version']}, Key ID: {r.json()['key_id']}")

step(19, "Alice (developer) tries to inspect or modify vault credentials")
r = client.get("/vault/credentials", headers={"Authorization": f"Bearer {alice}"})
print(f"Status: {r.status_code} (expected 403) -> {r.json()['detail']}")

step(20, "Bob (finance) accesses /proxy/billing/invoices with his standard JWT")
r = client.get("/proxy/billing/invoices", headers={"Authorization": f"Bearer {bob}"})
print(f"Status: {r.status_code}")
cred_info = r.json().get("upstream_credential", {})
print(f"Backend received credential: {cred_info.get('received')} (SHA-256 prefix: {cred_info.get('sha256_prefix')})")
print(f"Was secret leaked to Bob? -> {'NO (Secure)' if DOWNSTREAM_SECRET not in r.text else 'YES (Leaked!)'}")

step(21, "Inspecting encrypted vault storage on disk (gateway/data/vault.json)")
from gateway.vault import vault
raw_vault_disk = vault.store.read_text()
print(f"Plaintext secret present on disk? -> {'NO (Encrypted AES-256-GCM)' if DOWNSTREAM_SECRET not in raw_vault_disk else 'YES (Unsafe)'}")
billing_record = vault._records.get("billing", {})
print(f"Ciphertext preview: {billing_record.get('ciphertext')[:24]}... (Nonce: {billing_record.get('nonce')})")

step(22, "Charlie (admin) rotates the vault encryption key")
r = client.post("/vault/rotate", headers={"Authorization": f"Bearer {charlie}"})
print(f"Status: {r.status_code} -> {r.json()}")

step(23, "Final Telemetry Audit Log Verification")
logs = client.get("/telemetry/audit?limit=6", headers={"Authorization": f"Bearer {charlie}"}).json()["logs"]
for e in logs:
    print(f" • {e['decision']:5} {e['status_code']} {e['method']:6} {e['path']:32} {e['subject']:16} {e['reason'][:55]}")

print("\n" + "-" * 70)
print(" PHASE 4 — SD-WAN MULTI-PATH ROUTING, CIRCUIT BREAKER & FAILOVER")
print("-" * 70)

from gateway import proxy, sdwan
from gateway.quota import reset as reset_quotas
from gateway.sdwan import sdwan_router

# Reset quota buckets after Phase 2 burst saturation testing
reset_quotas()

step(24, "Default healthy routing to primary path")
r = client.get("/proxy/inventory/items", headers={"Authorization": f"Bearer {alice}"})
print(f"Status: {r.status_code}")
print(f"  X-SDWAN-Route:    {r.headers.get('X-SDWAN-Route')}")
print(f"  X-SDWAN-Region:   {r.headers.get('X-SDWAN-Region')}")
print(f"  X-SDWAN-Failover: {r.headers.get('X-SDWAN-Failover')}")
print(f"  Downstream:       {r.json().get('downstream_service')}")

step(25, "Simulate primary failure -> Instant dynamic failover to secondary backup")
original_dispatch = proxy._dispatch_http

async def mock_fail_primary(target_url, method, headers, params, body):
    # If target is primary billing, simulate downstream 500 failure
    if "mock-service/billing" in target_url and "billing-backup" not in target_url:
        import httpx
        return httpx.Response(status_code=500, content=b'{"error": "primary data center outage"}')
    return await original_dispatch(target_url, method, headers, params, body)

proxy._dispatch_http = mock_fail_primary
try:
    r = client.get("/proxy/billing/invoices", headers={"Authorization": f"Bearer {bob}"})
    print(f"Status: {r.status_code}")
    print(f"  X-SDWAN-Route:    {r.headers.get('X-SDWAN-Route')} (auto-failed over!)")
    print(f"  X-SDWAN-Region:   {r.headers.get('X-SDWAN-Region')}")
    print(f"  X-SDWAN-Failover: {r.headers.get('X-SDWAN-Failover')}")
    print(f"  Downstream:       {r.json().get('downstream_service')}")
finally:
    proxy._dispatch_http = original_dispatch

step(26, "Simulate repeated link failures -> Circuit breaker trips to OPEN")
candidates = sdwan_router.get_candidate_paths("billing")
primary_link = next(ep for ep in candidates if ep.name == "primary")
print(f"Initial Primary Circuit State: {primary_link.circuit_state}")
for i in range(3):
    sdwan_router.record_failure(primary_link, f"synthetic timeout {i+1}")
    print(f"  Failure {i+1}/3 recorded -> State: {primary_link.circuit_state}, Failure Count: {primary_link.failure_count}")

# Verify that candidates now prioritize healthy secondary link first
active_candidates = sdwan_router.get_candidate_paths("billing")
print(f"Top available route after trip: {active_candidates[0].name} (state={active_candidates[0].circuit_state})")

step(27, "Charlie (admin) inspects SD-WAN link health and telemetry metrics")
r = client.get("/sdwan/status", headers={"Authorization": f"Bearer {charlie}"})
print(f"Status: {r.status_code}")
for svc, links in r.json().get("routes", {}).items():
    print(f" • Service '{svc}':")
    for link in links:
        print(f"    [{link['name'].upper()}] region={link['region']:10} state={link['circuit_state']:10} reqs={link['total_requests']} fails={link['total_failures']} latency_ema={link['latency_ema_ms']}ms")

step(28, "Charlie (admin) resets all circuit breakers back to CLOSED")
r = client.post("/sdwan/reset", headers={"Authorization": f"Bearer {charlie}"})
print(f"Status: {r.status_code} -> {r.json()['message']}")
candidates_after = sdwan_router.get_candidate_paths("billing")
pri_after = next(ep for ep in candidates_after if ep.name == "primary")
print(f"Primary Circuit State after reset: {pri_after.circuit_state}")

print("\n" + "-" * 70)
print(" PHASE 5 — SIEM THREAT HUNTING INTEGRATION (logs/gateway_audit.jsonl)")
print("-" * 70)

from gateway.config import GATEWAY_AUDIT_LOG
from siem_hunter.pipeline import Pipeline, write_report

step(29, f"Ingest gateway telemetry from {GATEWAY_AUDIT_LOG}")
pipeline = Pipeline(rules_dir=ROOT / "rules", anomaly_field="src_ip")
results = pipeline.analyze(GATEWAY_AUDIT_LOG, fmt="json")
summary = results["summary"]
print(f"Total Gateway Events Analyzed: {summary['events']}")
print(f"Detections Triggered:         {summary['detections']}")
print(f"Breakdown by Severity:        {summary.get('by_severity', {})}")
print(f"Breakdown by Detector:        {summary.get('by_detector', {})}")

step(30, "Review detections produced by SIEM rule engine & anomaly detector")
detections = results["detections"]
for d in detections:
    print(f" • [{d['severity'].upper():8}] {d['rule_id']:25} Entity: {str(d.get('entity')):16} Title: {d['title'][:45]}")

step(31, "Inspect MITRE ATT&CK kill chain enrichment on gateway findings")
for d in detections:
    mitre_list = d.get("mitre", [])
    if mitre_list:
        m = mitre_list[0]
        print(f" • Rule {d['rule_id']:25} -> Technique {m['id']} ({m['name']}) [Tactic: {m['tactic']}]")

step(32, "Write detection findings report to logs/detections.json")
out_report = ROOT / "logs" / "detections.json"
write_report(pipeline.run(GATEWAY_AUDIT_LOG, fmt="json"), out_report)
print(f"Report written successfully to: {out_report} ({out_report.stat().st_size} bytes)")

print("\n" + "=" * 70)
print(" ✅ ALL 5 PHASES DEMO COMPLETE: ZERO-TRUST MICRO-SASE + SIEM HUNTING")
print("=" * 70 + "\n")

