"""Hardening tests: token lifecycle and revocation, user management, YAML policy,
lockout that can't be used to lock out a real user, trusted proxies, the Redis
state store, CORS and header stripping."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import fakeredis
import httpx
import ipaddress
import jwt
import pytest
from fastapi.testclient import TestClient

from gateway import auth, policy, proxy, quota, state, users
from gateway.config import JWT_SECRET_KEY
from gateway.main import app
from gateway.users import DEMO_USERS

client = TestClient(app)
ROOT = Path(__file__).resolve().parents[1]


def _login_body(username: str, c: TestClient = client) -> dict:
    r = c.post("/auth/token", json={"username": username, "password": DEMO_USERS[username][0]})
    assert r.status_code == 200, r.text
    return r.json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _admin() -> dict:
    return _bearer(_login_body("charlie")["access_token"])


@pytest.fixture
def temp_user():
    """Create a throwaway user and clean it up afterwards."""
    created = []

    def make(name="dave", role="developer", scopes=("read", "write"), password="correct-horse-battery"):
        r = client.post("/users", json={"username": name, "password": password,
                                         "role": role, "scopes": list(scopes)}, headers=_admin())
        assert r.status_code == 201, r.text
        created.append(name)
        return name, password

    yield make
    for name in created:
        if users.get_user(name):
            users.delete_user(name)


# --- Tokens ------------------------------------------------------------------

def test_access_token_has_hardened_claims():
    body = _login_body("alice")
    claims = jwt.decode(body["access_token"], JWT_SECRET_KEY, algorithms=["HS256"], audience="micro-sase")
    assert claims["iss"] == "micro-sase-gateway"
    assert claims["typ"] == "access"
    assert claims["jti"]
    assert claims["exp"] - claims["iat"] <= 15 * 60 + 1
    assert body["refresh_token"]


def test_token_response_is_not_cacheable():
    r = client.post("/auth/token", json={"username": "alice", "password": DEMO_USERS["alice"][0]})
    assert r.headers["Cache-Control"] == "no-store"


def test_token_without_issuer_or_audience_is_rejected():
    legacy = jwt.encode(
        {"sub": "charlie", "role": "admin", "scopes": ["admin"], "iat": int(time.time()),
         "exp": int(time.time()) + 600},
        JWT_SECRET_KEY, algorithm="HS256",
    )
    assert client.get("/telemetry/audit", headers=_bearer(legacy)).status_code == 401


def test_refresh_token_cannot_be_used_as_access_token():
    refresh = _login_body("charlie")["refresh_token"]
    assert client.get("/telemetry/audit", headers=_bearer(refresh)).status_code == 401


def test_access_token_cannot_be_used_to_refresh():
    access = _login_body("alice")["access_token"]
    assert client.post("/auth/refresh", json={"refresh_token": access}).status_code == 401


def test_refresh_rotates_and_reuse_revokes_all_sessions():
    first = _login_body("alice")
    r = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert r.status_code == 200
    second = r.json()
    assert second["refresh_token"] != first["refresh_token"]
    assert client.get("/proxy/inventory/items", headers=_bearer(second["access_token"])).status_code == 200

    # Replaying the rotated token is treated as theft: every session dies.
    assert client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401
    assert client.get("/proxy/inventory/items", headers=_bearer(second["access_token"])).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": second["refresh_token"]}).status_code == 401
    # A fresh login still works.
    assert _login_body("alice")["access_token"]


def test_logout_revokes_access_and_refresh_tokens():
    body = _login_body("alice")
    headers = _bearer(body["access_token"])
    r = client.post("/auth/logout", json={"refresh_token": body["refresh_token"]}, headers=headers)
    assert r.status_code == 200
    assert client.get("/proxy/inventory/items", headers=headers).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": body["refresh_token"]}).status_code == 401


def test_admin_can_revoke_all_sessions_of_a_user():
    alice = _bearer(_login_body("alice")["access_token"])
    assert client.post("/auth/revoke/alice", headers=alice).status_code == 403
    assert client.post("/auth/revoke/alice", headers=_admin()).status_code == 200
    assert client.get("/proxy/inventory/items", headers=alice).status_code == 401
    fresh = _bearer(_login_body("alice")["access_token"])
    assert client.get("/proxy/inventory/items", headers=fresh).status_code == 200


def test_revoked_token_is_rejected_by_siem_api():
    from web.backend import app as backend_module

    siem = TestClient(backend_module.app)
    body = _login_body("alice")
    headers = _bearer(body["access_token"])
    assert siem.get("/api/samples", headers=headers).status_code == 200
    client.post("/auth/logout", headers=headers)
    assert siem.get("/api/samples", headers=headers).status_code == 401


def test_short_jwt_secret_refuses_to_start():
    env = {**os.environ, "SASE_JWT_SECRET": "too-short"}
    r = subprocess.run([sys.executable, "-c", "import gateway.config"], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "at least 32 bytes" in r.stderr


# --- User management ---------------------------------------------------------

def test_admin_creates_user_who_can_log_in(temp_user):
    name, pw = temp_user()
    r = client.post("/auth/token", json={"username": name, "password": pw})
    assert r.status_code == 200
    assert r.json()["role"] == "developer"
    listing = client.get("/users", headers=_admin()).json()["users"]
    assert any(u["username"] == name for u in listing)
    assert all("hash" not in u and "salt" not in u for u in listing)
    assert pw not in Path(os.environ["SASE_USER_STORE"]).read_text()


def test_non_admin_cannot_manage_users():
    alice = _bearer(_login_body("alice")["access_token"])
    assert client.get("/users", headers=alice).status_code == 403
    r = client.post("/users", json={"username": "evil", "password": "x" * 20, "role": "admin",
                                     "scopes": ["admin"]}, headers=alice)
    assert r.status_code == 403


@pytest.mark.parametrize("body", [
    {"username": "erin", "password": "short", "role": "developer", "scopes": ["read"]},
    {"username": "erin", "password": "erin-is-my-password", "role": "developer", "scopes": ["read"]},
    {"username": "erin", "password": "long-enough-password", "role": "superuser", "scopes": ["read"]},
    {"username": "erin", "password": "long-enough-password", "role": "developer", "scopes": ["admin"]},
    {"username": "Bad Name!", "password": "long-enough-password", "role": "developer", "scopes": ["read"]},
    {"username": "alice", "password": "long-enough-password", "role": "developer", "scopes": ["read"]},
])
def test_invalid_user_requests_rejected(body):
    assert client.post("/users", json=body, headers=_admin()).status_code == 400


def test_disable_user_revokes_tokens_and_blocks_login(temp_user):
    name, pw = temp_user()
    token = _bearer(client.post("/auth/token", json={"username": name, "password": pw}).json()["access_token"])
    r = client.patch(f"/users/{name}", json={"disabled": True}, headers=_admin())
    assert r.status_code == 200
    assert client.get("/proxy/inventory/items", headers=token).status_code == 401
    assert client.post("/auth/token", json={"username": name, "password": pw}).status_code == 401


def test_role_change_takes_effect_after_reauth(temp_user):
    name, pw = temp_user()
    r = client.patch(f"/users/{name}", json={"role": "finance", "scopes": ["read", "invoice"]}, headers=_admin())
    assert r.status_code == 200
    body = client.post("/auth/token", json={"username": name, "password": pw}).json()
    assert body["role"] == "finance"


def test_cannot_remove_last_admin():
    assert client.delete("/users/charlie", headers=_admin()).status_code == 400
    r = client.patch("/users/charlie", json={"role": "developer", "scopes": ["read"]}, headers=_admin())
    assert r.status_code == 400


def test_admin_password_reset_and_delete(temp_user):
    name, _ = temp_user()
    new_pw = "brand-new-secret-123"
    assert client.put(f"/users/{name}/password", json={"password": new_pw}, headers=_admin()).status_code == 200
    assert client.post("/auth/token", json={"username": name, "password": new_pw}).status_code == 200
    assert client.delete(f"/users/{name}", headers=_admin()).status_code == 200
    assert client.post("/auth/token", json={"username": name, "password": new_pw}).status_code == 401


def test_self_service_password_change_revokes_sessions(temp_user):
    name, pw = temp_user()
    token = _bearer(client.post("/auth/token", json={"username": name, "password": pw}).json()["access_token"])
    bad = client.post("/auth/change-password", json={"current_password": "wrong-password",
                                                     "new_password": "another-good-secret"}, headers=token)
    assert bad.status_code == 403
    ok = client.post("/auth/change-password", json={"current_password": pw,
                                                    "new_password": "another-good-secret"}, headers=token)
    assert ok.status_code == 200
    assert client.get("/proxy/inventory/items", headers=token).status_code == 401
    assert client.post("/auth/token", json={"username": name, "password": "another-good-secret"}).status_code == 200


def test_old_pbkdf2_hashes_are_upgraded_on_login(temp_user, monkeypatch):
    name, pw = temp_user()
    user = users.get_user(name)
    user.iterations = 10
    user.password_hash = users._hash_password(pw, user.password_salt, 10)
    assert client.post("/auth/token", json={"username": name, "password": pw}).status_code == 200
    assert user.iterations == users._PBKDF2_ITERATIONS
    assert user.password_hash == users._hash_password(pw, user.password_salt)


def test_oversized_password_rejected_before_hashing():
    r = client.post("/auth/token", json={"username": "alice", "password": "x" * 10_000})
    assert r.status_code == 422


# --- API key revocation ------------------------------------------------------

def test_admin_can_list_and_revoke_api_keys():
    issued = client.post("/auth/register-api-key", json={"service_id": "svc-rotate", "role": "billing-service",
                                                         "scopes": ["read"]}, headers=_admin()).json()
    key = {"X-API-Key": issued["api_key"]}
    assert client.get("/proxy/billing/invoices", headers=key).status_code == 200

    listing = client.get("/auth/api-keys", headers=_admin()).json()["api_keys"]
    assert any(k["key_sha256"] == issued["key_sha256"] for k in listing)
    assert issued["api_key"] not in json.dumps(listing)

    assert client.delete(f"/auth/api-keys/{issued['key_sha256']}", headers=_admin()).status_code == 200
    assert client.get("/proxy/billing/invoices", headers=key).status_code == 401


def test_service_listing_hides_upstream_urls_from_non_admins():
    alice = client.get("/auth/services", headers=_bearer(_login_body("alice")["access_token"])).json()
    assert "url" not in json.dumps(alice)
    assert alice["services"]["inventory"]["allowed"] is True
    admin = client.get("/auth/services", headers=_admin()).json()
    assert "endpoints" in admin["services"]["billing"]


# --- YAML policy -------------------------------------------------------------

def test_policy_is_loaded_from_yaml():
    snap = client.get("/policy", headers=_admin()).json()
    assert snap["quotas"]["roles"]["developer"]["burst"] == 20
    assert any(r["path"] == "invoices/*" for r in snap["services"]["billing"])
    assert client.get("/policy", headers=_bearer(_login_body("alice")["access_token"])).status_code == 403


def test_policy_reload_applies_changes(tmp_path, monkeypatch):
    original = (ROOT / "gateway" / "policy.yml").read_text()
    edited = tmp_path / "policy.yml"
    edited.write_text(original.replace(
        '{methods: [GET, HEAD], path: "*", scope: read, description: Read inventory}',
        '{methods: [GET, HEAD], path: "*", scope: admin, description: Read inventory}',
    ))
    monkeypatch.setattr(policy, "POLICY_FILE", edited)
    alice = _bearer(_login_body("alice")["access_token"])
    assert client.get("/proxy/inventory/items", headers=alice).status_code == 200
    try:
        assert client.post("/policy/reload", headers=_admin()).status_code == 200
        assert client.get("/proxy/inventory/items", headers=alice).status_code == 403
    finally:
        policy.load_policy(ROOT / "gateway" / "policy.yml")


@pytest.mark.parametrize("content", [
    "services: [not, a, mapping]",
    "services:\n  unknown-svc: []\nquotas: {default: {burst: 1, refill_per_sec: 1, window_limit: 1, window_seconds: 1}}",
    "services:\n  billing:\n    - {methods: [FETCH], path: x, scope: read}\nquotas: {default: {burst: 1, refill_per_sec: 1, window_limit: 1, window_seconds: 1}}",
    "services: {}\nquotas: {default: {burst: 0, refill_per_sec: 1, window_limit: 1, window_seconds: 1}}",
    "services: {: bad yaml",
])
def test_invalid_policy_reload_keeps_running_policy(tmp_path, monkeypatch, content):
    bad = tmp_path / "policy.yml"
    bad.write_text(content)
    monkeypatch.setattr(policy, "POLICY_FILE", bad)
    before = policy.policy_snapshot()
    assert client.post("/policy/reload", headers=_admin()).status_code == 400
    assert policy.policy_snapshot() == before


# --- Login lockout cannot lock out the real user ------------------------------

def test_attacker_cannot_lock_out_user_on_known_device():
    victim = TestClient(app, client=("198.51.100.10", 5000))
    attacker = TestClient(app, client=("203.0.113.66", 5000))
    stranger = TestClient(app, client=("192.0.2.77", 5000))
    _login_body("alice", victim)  # victim's device becomes known

    for _ in range(quota.LOGIN_MAX_ATTEMPTS):
        attacker.post("/auth/token", json={"username": "alice", "password": "guess"})
    # The attacker's own IP is locked out ...
    assert attacker.post("/auth/token", json={"username": "alice", "password": "guess"}).status_code == 429
    # ... unknown devices get the account lock ...
    r = stranger.post("/auth/token", json={"username": "alice", "password": DEMO_USERS["alice"][0]})
    assert r.status_code == 429
    # ... but alice on her usual device still gets in.
    assert victim.post("/auth/token", json={"username": "alice",
                                            "password": DEMO_USERS["alice"][0]}).status_code == 200


# --- Trusted proxies ---------------------------------------------------------

def _seen_client_ip(c: TestClient, xff: str | None) -> str:
    headers = _bearer(_login_body("bob", c)["access_token"])
    if xff:
        headers["X-Forwarded-For"] = xff
    return c.get("/proxy/billing/invoices", headers=headers).json()["verified_headers_from_gateway"]["x-sase-client-ip"]


def test_x_forwarded_for_ignored_from_untrusted_peer(monkeypatch):
    monkeypatch.setattr(auth, "TRUSTED_PROXIES", [ipaddress.ip_network("10.0.0.0/8")])
    direct = TestClient(app, client=("198.51.100.20", 5000))
    assert _seen_client_ip(direct, "1.2.3.4") == "198.51.100.20"


def test_x_forwarded_for_used_from_trusted_proxy(monkeypatch):
    monkeypatch.setattr(auth, "TRUSTED_PROXIES", [ipaddress.ip_network("10.0.0.0/8")])
    via_lb = TestClient(app, client=("10.0.0.5", 5000))
    # The client spoofed "1.2.3.4"; the LB appended the real address. Read right-to-left.
    assert _seen_client_ip(via_lb, "1.2.3.4, 198.51.100.30, 10.0.0.9") == "198.51.100.30"


# --- Headers & CORS ----------------------------------------------------------

def test_proxy_strips_cookies_and_proxy_credentials(monkeypatch):
    seen = {}

    async def capture(target_url, method, headers, params, body):
        seen.update({k.lower(): v for k, v in headers.items()})
        return httpx.Response(200, content=b"{}")

    monkeypatch.setattr(proxy, "_dispatch_http", capture)
    headers = {**_bearer(_login_body("alice")["access_token"]), "Cookie": "session=abc",
               "Proxy-Authorization": "Basic Zm9vOmJhcg==", "X-Trace": "keep-me"}
    assert client.get("/proxy/inventory/items", headers=headers).status_code == 200
    assert "cookie" not in seen and "proxy-authorization" not in seen and "authorization" not in seen
    assert seen["x-trace"] == "keep-me"


def test_cors_allows_only_configured_origins():
    ok = client.options("/auth/token", headers={"Origin": "http://localhost:5173",
                                                "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    evil = client.options("/auth/token", headers={"Origin": "https://evil.example",
                                                  "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in evil.headers


def test_backend_rejects_wrong_internal_token():
    from gateway import mock_backends

    backend = TestClient(mock_backends.app)
    r = backend.get("/mock-service/billing/invoices", headers={"X-SASE-Internal": "guess"})
    assert r.status_code == 403


# --- Redis state store -------------------------------------------------------

@pytest.fixture
def redis_store(monkeypatch):
    store = state.RedisStore(fakeredis.FakeRedis())
    monkeypatch.setattr(state, "store", store)
    yield store
    store.reset()


def test_redis_token_bucket_and_window(redis_store):
    assert redis_store.take_token("b", burst=2, refill=1.0, now=100.0) == 0
    assert redis_store.take_token("b", burst=2, refill=1.0, now=100.0) == 0
    assert redis_store.take_token("b", burst=2, refill=1.0, now=100.0) == pytest.approx(1.0)
    assert redis_store.take_token("b", burst=2, refill=1.0, now=101.0) == 0

    assert redis_store.incr_window("w", 60, 100.0) == (1, 100.0)
    assert redis_store.incr_window("w", 60, 110.0) == (2, 100.0)
    assert redis_store.peek_window("w", 60, 120.0) == (2, 100.0)
    assert redis_store.incr_window("w", 60, 161.0) == (1, 161.0)


def test_gateway_limits_and_revocation_work_on_redis(redis_store, monkeypatch):
    frozen = [1000.0]
    monkeypatch.setattr(quota, "_now", lambda: frozen[0])
    body = _login_body("alice")
    alice = _bearer(body["access_token"])
    burst = quota.ROLE_QUOTAS["developer"].burst
    codes = [client.get("/proxy/inventory/items", headers=alice).status_code for _ in range(burst + 1)]
    assert codes[-1] == 429 and codes[:-1] == [200] * burst

    for _ in range(quota.LOGIN_MAX_ATTEMPTS):
        client.post("/auth/token", json={"username": "bob", "password": "nope"})
    assert client.post("/auth/token", json={"username": "bob", "password": "nope"}).status_code == 429

    client.post("/auth/logout", headers=alice)
    assert redis_store.get(f"revoked-jti:{auth.decode_jwt_token(body['access_token'])['jti']}") == "1"
    assert client.get("/proxy/inventory/items", headers=alice).status_code == 401
