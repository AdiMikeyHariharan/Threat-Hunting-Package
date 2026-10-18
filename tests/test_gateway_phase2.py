"""Phase 2 tests: PBAC (method/path/scope) and QBAC (burst, quota, login limiting)."""

from fastapi.testclient import TestClient

from gateway import quota
from gateway.main import app
from gateway.users import DEMO_USERS

client = TestClient(app)


def _login(username: str) -> dict:
    pw = DEMO_USERS[username][0]
    r = client.post("/auth/token", json={"username": username, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _machine_key(role: str, scopes: list[str]) -> dict:
    r = client.post(
        "/auth/register-api-key",
        json={"service_id": f"svc-{role}", "role": role, "scopes": scopes},
        headers=_login("charlie"),
    )
    assert r.status_code == 200, r.text
    return {"X-API-Key": r.json()["api_key"]}


# --- PBAC --------------------------------------------------------------------

def test_read_scope_allows_get():
    assert client.get("/proxy/inventory/items", headers=_login("alice")).status_code == 200


def test_write_scope_allows_post():
    # alice: developer with ["read", "write"]
    assert client.post("/proxy/inventory/items", headers=_login("alice")).status_code == 200


def test_delete_requires_admin_scope():
    r = client.delete("/proxy/inventory/items/42", headers=_login("alice"))
    assert r.status_code == 403
    assert "requires scope 'admin'" in r.json()["detail"]


def test_admin_scope_allows_delete():
    assert client.delete("/proxy/inventory/items/42", headers=_login("charlie")).status_code == 200


def test_finance_can_read_and_create_invoices():
    bob = _login("bob")  # finance: ["read", "invoice"]
    assert client.get("/proxy/billing/invoices", headers=bob).status_code == 200
    assert client.post("/proxy/billing/invoices", headers=bob).status_code == 200


def test_finance_cannot_delete_invoices():
    assert client.delete("/proxy/billing/invoices/INV-1", headers=_login("bob")).status_code == 403


def test_read_only_machine_key_cannot_write():
    key = _machine_key("billing-service", ["read"])
    assert client.get("/proxy/billing/invoices", headers=key).status_code == 200
    assert client.post("/proxy/billing/invoices", headers=key).status_code == 403


def test_unknown_path_default_denied():
    r = client.get("/proxy/billing/secret-dump", headers=_login("bob"))
    assert r.status_code == 403
    assert "default-deny" in r.json()["detail"]


def test_rbac_still_checked_before_pbac():
    # bob is finance: not allowed on inventory at all -> RBAC message, not PBAC
    r = client.get("/proxy/inventory/items", headers=_login("bob"))
    assert r.status_code == 403
    assert "Access Denied by PEP" in r.json()["detail"]


# --- QBAC: burst -------------------------------------------------------------

def test_rate_limit_headers_present():
    r = client.get("/proxy/inventory/items", headers=_login("alice"))
    assert r.headers["X-RateLimit-Limit"] == "1000"
    assert int(r.headers["X-RateLimit-Remaining"]) == 999


def test_burst_limit_returns_429(monkeypatch):
    frozen = [1000.0]
    monkeypatch.setattr(quota, "_now", lambda: frozen[0])
    alice = _login("alice")
    burst = quota.ROLE_QUOTAS["developer"].burst

    codes = [client.get("/proxy/inventory/items", headers=alice).status_code for _ in range(burst + 1)]
    assert codes[:burst] == [200] * burst
    assert codes[burst] == 429

    r = client.get("/proxy/inventory/items", headers=alice)
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


def test_burst_refills_over_time(monkeypatch):
    frozen = [1000.0]
    monkeypatch.setattr(quota, "_now", lambda: frozen[0])
    alice = _login("alice")
    policy = quota.ROLE_QUOTAS["developer"]
    for _ in range(policy.burst):
        client.get("/proxy/inventory/items", headers=alice)
    assert client.get("/proxy/inventory/items", headers=alice).status_code == 429

    frozen[0] += 1.0 / policy.refill_per_sec  # one token's worth of time
    assert client.get("/proxy/inventory/items", headers=alice).status_code == 200


def test_limits_are_per_identity(monkeypatch):
    frozen = [1000.0]
    monkeypatch.setattr(quota, "_now", lambda: frozen[0])
    alice, charlie = _login("alice"), _login("charlie")
    for _ in range(quota.ROLE_QUOTAS["developer"].burst + 1):
        client.get("/proxy/inventory/items", headers=alice)
    assert client.get("/proxy/inventory/items", headers=alice).status_code == 429
    assert client.get("/proxy/inventory/items", headers=charlie).status_code == 200


def test_denied_requests_do_not_consume_quota(monkeypatch):
    frozen = [1000.0]
    monkeypatch.setattr(quota, "_now", lambda: frozen[0])
    alice = _login("alice")
    for _ in range(50):  # PBAC-denied DELETEs
        client.delete("/proxy/inventory/items/1", headers=alice)
    assert client.get("/proxy/inventory/items", headers=alice).status_code == 200


# --- QBAC: window quota ------------------------------------------------------

def test_window_quota_exhaustion(monkeypatch):
    frozen = [1000.0]
    monkeypatch.setattr(quota, "_now", lambda: frozen[0])
    monkeypatch.setitem(
        quota.ROLE_QUOTAS, "developer",
        quota.QuotaPolicy(burst=100, refill_per_sec=100, window_limit=3, window_seconds=60),
    )
    alice = _login("alice")
    codes = [client.get("/proxy/inventory/items", headers=alice).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]

    frozen[0] += 61  # new window
    assert client.get("/proxy/inventory/items", headers=alice).status_code == 200


# --- Login limiter -----------------------------------------------------------

def _bad_login(user: str = "alice"):
    return client.post("/auth/token", json={"username": user, "password": "wrong"})


def test_login_locked_after_failed_attempts():
    for _ in range(quota.LOGIN_MAX_ATTEMPTS):
        assert _bad_login().status_code == 401
    r = _bad_login()
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_lockout_blocks_correct_password_too():
    for _ in range(quota.LOGIN_MAX_ATTEMPTS):
        _bad_login()
    r = client.post("/auth/token", json={"username": "alice", "password": DEMO_USERS["alice"][0]})
    assert r.status_code == 429


def test_successful_logins_not_counted():
    for _ in range(quota.LOGIN_MAX_ATTEMPTS * 2):
        _login("alice")


def test_login_lockout_expires(monkeypatch):
    frozen = [1000.0]
    monkeypatch.setattr(quota, "_now", lambda: frozen[0])
    for _ in range(quota.LOGIN_MAX_ATTEMPTS):
        _bad_login()
    assert _bad_login().status_code == 429
    frozen[0] += quota.LOGIN_WINDOW_SECONDS + 1
    assert _bad_login().status_code == 401


# --- Audit coverage of new denials ------------------------------------------

def test_new_denials_are_audited(monkeypatch):
    alice = _login("alice")
    client.delete("/proxy/inventory/items/1", headers=alice)               # PBAC
    client.post("/auth/register-api-key", json={"service_id": "x"}, headers=alice)  # admin-only
    client.get("/mock-service/inventory/items")                            # bypass

    logs = client.get("/telemetry/audit?limit=50", headers=_login("charlie")).json()["logs"]
    reasons = " | ".join(l["reason"] for l in logs)
    assert "requires scope 'admin'" in reasons
    assert "Admin role required" in reasons
    assert "PEP bypass attempt" in reasons
