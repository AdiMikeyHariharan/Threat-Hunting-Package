"""Phase 4 tests: SD-WAN virtual multi-path routing, circuit breakers, and automatic failover."""

import time
import httpx
from fastapi.testclient import TestClient

from gateway import proxy, sdwan
from gateway.main import app
from gateway.sdwan import sdwan_router
from gateway.users import DEMO_USERS

client = TestClient(app)


def _login(username: str = "alice") -> dict:
    pw = DEMO_USERS[username][0]
    r = client.post("/auth/token", json={"username": username, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# --- Primary Route & Header Tests --------------------------------------------

def test_default_request_uses_primary_route():
    """Verify healthy requests route to primary endpoint without failover."""
    r = client.get("/proxy/inventory/items", headers=_login("alice"))
    assert r.status_code == 200
    assert r.headers["X-SDWAN-Route"] == "primary"
    assert r.headers["X-SDWAN-Region"] == "us-east"
    assert r.headers["X-SDWAN-Failover"] == "false"
    assert r.json()["downstream_service"] == "Inventory Service"


def test_billing_request_uses_primary_route():
    r = client.get("/proxy/billing/invoices", headers=_login("bob"))
    assert r.status_code == 200
    assert r.headers["X-SDWAN-Route"] == "primary"
    assert r.headers["X-SDWAN-Region"] == "us-east"
    assert r.headers["X-SDWAN-Failover"] == "false"


# --- Dynamic Failover Tests --------------------------------------------------

def test_automatic_failover_when_primary_errors():
    """When primary link returns HTTP 500+, automatically fail over to secondary link."""
    original_dispatch = proxy._dispatch_http

    async def mock_dispatch(target_url, method, headers, params, body):
        # Force primary route to fail with 500 Internal Server Error
        if "mock-service/billing" in target_url and "billing-backup" not in target_url:
            import httpx
            return httpx.Response(status_code=500, content=b'{"error": "primary down"}')
        return await original_dispatch(target_url, method, headers, params, body)

    proxy._dispatch_http = mock_dispatch
    try:
        r = client.get("/proxy/billing/invoices", headers=_login("bob"))
        assert r.status_code == 200
        # Verified that response came from secondary failover route!
        assert r.headers["X-SDWAN-Route"] == "secondary"
        assert r.headers["X-SDWAN-Region"] == "us-west"
        assert r.headers["X-SDWAN-Failover"] == "true"
        assert r.json()["payload"]["backup_route_active"] is True
    finally:
        proxy._dispatch_http = original_dispatch


def test_automatic_failover_on_connection_exception():
    """When primary link raises connection error, automatically fail over to secondary."""
    original_dispatch = proxy._dispatch_http

    async def mock_dispatch(target_url, method, headers, params, body):
        if "mock-service/inventory" in target_url and "inventory-backup" not in target_url:
            import httpx
            raise httpx.ConnectError("Connection refused on primary link")
        return await original_dispatch(target_url, method, headers, params, body)

    proxy._dispatch_http = mock_dispatch
    try:
        r = client.get("/proxy/inventory/items", headers=_login("alice"))
        assert r.status_code == 200
        assert r.headers["X-SDWAN-Route"] == "secondary"
        assert r.headers["X-SDWAN-Region"] == "eu-central"
        assert r.headers["X-SDWAN-Failover"] == "true"
        assert r.json()["downstream_service"] == "Inventory Service (Secondary Backup Route)"
    finally:
        proxy._dispatch_http = original_dispatch


def test_state_changing_request_is_not_replayed_on_failure():
    attempts = []
    original_dispatch = proxy._dispatch_http

    async def failing_dispatch(target_url, method, headers, params, body):
        attempts.append(target_url)
        return httpx.Response(status_code=500, content=b'{"error":"committed then failed"}')

    proxy._dispatch_http = failing_dispatch
    try:
        r = client.post("/proxy/billing/invoices", headers=_login("bob"))
        assert r.status_code == 500
        assert len(attempts) == 1
    finally:
        proxy._dispatch_http = original_dispatch


def test_proxy_preserves_repeated_query_parameters():
    seen = {}
    original_dispatch = proxy._dispatch_http

    async def capture_dispatch(target_url, method, headers, params, body):
        seen["params"] = params
        return httpx.Response(status_code=200, content=b"{}")

    proxy._dispatch_http = capture_dispatch
    try:
        r = client.get(
            "/proxy/inventory/items?tag=a&tag=b", headers=_login("alice")
        )
        assert r.status_code == 200
        assert seen["params"] == [("tag", "a"), ("tag", "b")]
    finally:
        proxy._dispatch_http = original_dispatch


# --- Circuit Breaker Tests ---------------------------------------------------

def test_circuit_trips_to_open_after_threshold_failures():
    """After 3 consecutive failures, primary circuit trips to OPEN and is bypassed."""
    candidates = sdwan_router.get_candidate_paths("billing")
    primary = next(ep for ep in candidates if ep.name == "primary")

    # Simulate 3 failures
    sdwan_router.record_failure(primary, "failure 1")
    assert primary.circuit_state == "CLOSED"
    assert primary.failure_count == 1

    sdwan_router.record_failure(primary, "failure 2")
    assert primary.circuit_state == "CLOSED"
    assert primary.failure_count == 2

    sdwan_router.record_failure(primary, "failure 3")
    assert primary.circuit_state == "OPEN"
    assert primary.is_available(recovery_timeout=30.0) is False

    # Now when a request arrives, it shouldn't even attempt primary -> goes straight to secondary!
    r = client.get("/proxy/billing/invoices", headers=_login("bob"))
    assert r.status_code == 200
    assert r.headers["X-SDWAN-Route"] == "secondary"
    assert r.headers["X-SDWAN-Failover"] == "false"  # Direct selection, not mid-flight failover


def test_circuit_half_open_recovery_and_healing(monkeypatch):
    """After recovery_timeout, OPEN circuit transitions to HALF_OPEN and heals on success."""
    candidates = sdwan_router.get_candidate_paths("billing")
    primary = next(ep for ep in candidates if ep.name == "primary")

    # Trip circuit to OPEN
    for _ in range(3):
        sdwan_router.record_failure(primary, "err")
    assert primary.circuit_state == "OPEN"

    # Fast forward clock past recovery_timeout
    frozen_time = [time.monotonic()]
    monkeypatch.setattr(sdwan, "_now", lambda: frozen_time[0])

    assert primary.is_available(recovery_timeout=30.0) is False

    frozen_time[0] += 31.0  # past 30s recovery timeout
    assert primary.is_available(recovery_timeout=30.0) is True
    assert primary.circuit_state == "HALF_OPEN"

    # Record 2 consecutive successes to heal back to CLOSED
    sdwan_router.record_success(primary, 5.0)
    assert primary.circuit_state == "HALF_OPEN"
    sdwan_router.record_success(primary, 4.0)
    assert primary.circuit_state == "CLOSED"
    assert primary.failure_count == 0


def test_half_open_single_failure_trips_back_to_open(monkeypatch):
    """A failure during HALF_OPEN probe immediately trips circuit back to OPEN."""
    candidates = sdwan_router.get_candidate_paths("billing")
    primary = next(ep for ep in candidates if ep.name == "primary")

    for _ in range(3):
        sdwan_router.record_failure(primary, "err")
    assert primary.circuit_state == "OPEN"

    frozen_time = [time.monotonic() + 35.0]
    monkeypatch.setattr(sdwan, "_now", lambda: frozen_time[0])
    assert primary.is_available(recovery_timeout=30.0) is True
    assert primary.circuit_state == "HALF_OPEN"

    # One probe failure trips right back to OPEN
    sdwan_router.record_failure(primary, "probe failed")
    assert primary.circuit_state == "OPEN"


def test_half_open_allows_only_one_reserved_probe(monkeypatch):
    primary = next(
        ep for ep in sdwan_router.get_candidate_paths("billing") if ep.name == "primary"
    )
    primary.circuit_state = "OPEN"
    primary.last_failure_time = 1000.0
    monkeypatch.setattr(sdwan, "_now", lambda: 1031.0)

    candidates = sdwan_router.get_available_candidate_paths("billing")
    assert primary in candidates
    assert sdwan_router.reserve(primary) is True
    assert sdwan_router.reserve(primary) is False


def test_all_upstream_routes_failed_returns_502():
    """If all configured virtual links fail, returns 502 Bad Gateway."""
    original_dispatch = proxy._dispatch_http

    async def mock_dispatch(target_url, method, headers, params, body):
        import httpx
        raise httpx.ConnectError("Total network partition")

    proxy._dispatch_http = mock_dispatch
    try:
        r = client.get("/proxy/billing/invoices", headers=_login("bob"))
        assert r.status_code == 502
        assert "All upstream paths failed" in r.json()["detail"]
    finally:
        proxy._dispatch_http = original_dispatch


def test_all_circuits_open_returns_503():
    """If all circuits are tripped OPEN, immediately returns 503 Service Unavailable."""
    for ep in sdwan_router.get_candidate_paths("billing"):
        ep.circuit_state = "OPEN"
        ep.last_failure_time = time.monotonic()

    r = client.get("/proxy/billing/invoices", headers=_login("bob"))
    assert r.status_code == 503
    assert "circuit OPEN" in r.json()["detail"]


# --- Admin Status & Reset Endpoints ------------------------------------------

def test_sdwan_status_requires_admin():
    assert client.get("/sdwan/status").status_code == 401
    assert client.get("/sdwan/status", headers=_login("alice")).status_code == 403
    r = client.get("/sdwan/status", headers=_login("charlie"))
    assert r.status_code == 200
    routes = r.json()["routes"]
    assert "billing" in routes
    assert len(routes["billing"]) == 2
    assert routes["billing"][0]["name"] == "primary"
    assert routes["billing"][1]["name"] == "secondary"


def test_sdwan_reset_heals_all_circuits():
    # Trip a circuit
    primary = next(ep for ep in sdwan_router.get_candidate_paths("billing") if ep.name == "primary")
    for _ in range(3):
        sdwan_router.record_failure(primary, "err")
    assert primary.circuit_state == "OPEN"

    # Non-admin cannot reset
    assert client.post("/sdwan/reset", headers=_login("bob")).status_code == 403

    # Admin resets
    r = client.post("/sdwan/reset", headers=_login("charlie"))
    assert r.status_code == 200
    assert primary.circuit_state == "CLOSED"
    assert primary.failure_count == 0


def test_latency_ema_tracking():
    candidates = sdwan_router.get_candidate_paths("inventory")
    ep = candidates[0]
    sdwan_router.record_success(ep, latency_ms=10.0)
    assert ep.latency_ema_ms == 10.0
    sdwan_router.record_success(ep, latency_ms=20.0)
    # EMA: 0.7 * 10 + 0.3 * 20 = 13.0
    assert round(ep.latency_ema_ms, 1) == 13.0
