"""Automated verification suite for Micro-SASE Gateway Phase 1 (hardened).

Audit log / key store isolation is set up in conftest.py.
"""

import os
from pathlib import Path

import jwt
from fastapi.testclient import TestClient

from gateway.main import app  # noqa: E402
from gateway.users import DEMO_USERS  # noqa: E402

client = TestClient(app)


def _login(username: str) -> str:
    password = DEMO_USERS[username][0]
    resp = client.post("/auth/token", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- Zero trust basics -------------------------------------------------------

def test_unauthenticated_blocked():
    resp = client.get("/proxy/inventory/items")
    assert resp.status_code == 401


def test_invalid_api_key_blocked():
    resp = client.get("/proxy/inventory/items", headers={"X-API-Key": "sase_fake"})
    assert resp.status_code == 401


# --- Login hardening ---------------------------------------------------------

def test_login_wrong_password_rejected():
    resp = client.post("/auth/token", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user_rejected():
    resp = client.post("/auth/token", json={"username": "mallory", "password": "x"})
    assert resp.status_code == 401


def test_client_cannot_choose_own_role():
    """Extra 'role' in the body is ignored - role comes from the user directory."""
    resp = client.post(
        "/auth/token",
        json={"username": "alice", "password": DEMO_USERS["alice"][0], "role": "admin"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "developer"


def test_forged_jwt_rejected():
    forged = jwt.encode({"sub": "alice", "role": "admin"}, "attacker-secret", algorithm="HS256")
    resp = client.get("/proxy/admin-panel/config", headers=_auth(forged))
    assert resp.status_code == 401


# --- RBAC --------------------------------------------------------------------

def test_developer_allowed_inventory():
    resp = client.get("/proxy/inventory/items", headers=_auth(_login("alice")))
    assert resp.status_code == 200
    assert resp.json()["verified_headers_from_gateway"]["x-sase-subject"] == "alice"


def test_developer_blocked_from_admin_panel():
    resp = client.get("/proxy/admin-panel/config", headers=_auth(_login("alice")))
    assert resp.status_code == 403


def test_admin_allowed_admin_panel():
    resp = client.get("/proxy/admin-panel/config", headers=_auth(_login("charlie")))
    assert resp.status_code == 200


# --- Admin-only endpoints ----------------------------------------------------

def test_non_admin_cannot_issue_api_key():
    resp = client.post(
        "/auth/register-api-key",
        json={"service_id": "evil", "role": "admin"},
        headers=_auth(_login("alice")),
    )
    assert resp.status_code == 403


def test_unauthenticated_cannot_issue_api_key():
    resp = client.post("/auth/register-api-key", json={"service_id": "evil", "role": "admin"})
    assert resp.status_code == 401


def test_admin_issues_api_key_and_machine_uses_it():
    resp = client.post(
        "/auth/register-api-key",
        json={"service_id": "svc-billing-job", "role": "billing-service"},
        headers=_auth(_login("charlie")),
    )
    assert resp.status_code == 200
    api_key = resp.json()["api_key"]

    proxy = client.get("/proxy/billing/invoices", headers={"X-API-Key": api_key})
    assert proxy.status_code == 200
    hdrs = proxy.json()["verified_headers_from_gateway"]
    assert hdrs["x-sase-subject"] == "svc-billing-job"
    assert hdrs["x-sase-auth-type"] == "api_key"

    # Only the hash is persisted, never the plaintext key.
    store = Path(os.environ["SASE_API_KEY_STORE"]).read_text()
    assert api_key not in store
    assert resp.json()["key_sha256"] in store


def test_audit_log_admin_only():
    assert client.get("/telemetry/audit").status_code == 401
    assert client.get("/telemetry/audit", headers=_auth(_login("alice"))).status_code == 403
    resp = client.get("/telemetry/audit", headers=_auth(_login("charlie")))
    assert resp.status_code == 200
    assert resp.json()["count"] > 0


# --- Bypass / spoofing -------------------------------------------------------

def test_backend_not_reachable_directly():
    resp = client.get("/mock-service/admin-panel/config")
    assert resp.status_code == 403


def test_spoofed_sase_headers_are_overwritten():
    resp = client.get(
        "/proxy/inventory/items",
        headers={**_auth(_login("alice")), "X-SASE-Role": "admin", "X-SASE-Subject": "charlie"},
    )
    hdrs = resp.json()["verified_headers_from_gateway"]
    assert hdrs["x-sase-subject"] == "alice"
    assert hdrs["x-sase-role"] == "developer"


def test_failed_login_is_audited():
    client.post("/auth/token", json={"username": "alice", "password": "nope"})
    logs = client.get("/telemetry/audit?limit=200", headers=_auth(_login("charlie"))).json()["logs"]
    assert any(l["path"] == "/auth/token" and l["decision"] == "DENY" for l in logs)
