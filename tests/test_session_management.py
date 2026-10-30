"""Session lifetime and deprovisioning.

Deprovisioning (disable, delete, role change) must cut access on the next
request even if the revocation list in Redis/memory is lost, and refreshing
must never extend a session past its absolute lifetime.
"""

import time

import jwt
import pytest
from fastapi.testclient import TestClient

from gateway import auth, state, users
from gateway.config import JWT_SECRET_KEY, SESSION_MAX_MINUTES
from gateway.main import app
from gateway.users import DEMO_USERS

client = TestClient(app)
PASSWORD = "Correct-Horse-Battery-9"


def _login(username: str, password: str) -> dict:
    r = client.post("/auth/token", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _admin() -> dict:
    return _bearer(_login("charlie", DEMO_USERS["charlie"][0])["access_token"])


def _claims(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"], audience="micro-sase")


@pytest.fixture
def erin():
    r = client.post("/users", headers=_admin(), json={"username": "erin", "password": PASSWORD,
                                                       "role": "developer", "scopes": ["read", "write"]})
    assert r.status_code == 201, r.text
    yield _login("erin", PASSWORD)
    if users.get_user("erin"):
        users.delete_user("erin")


# --- Deprovisioning -----------------------------------------------------------

@pytest.mark.parametrize("deprovision", [
    lambda: client.patch("/users/erin", headers=_admin(), json={"disabled": True}),
    lambda: client.delete("/users/erin", headers=_admin()),
    lambda: client.patch("/users/erin", headers=_admin(), json={"role": "finance", "scopes": ["read"]}),
], ids=["disabled", "deleted", "role-changed"])
def test_deprovisioning_holds_even_if_revocation_list_is_lost(erin, deprovision):
    headers = _bearer(erin["access_token"])
    assert client.get("/proxy/inventory/items", headers=headers).status_code == 200
    assert deprovision().status_code == 200
    state.store.reset()  # Redis flushed / restarted, or a replica without shared state
    assert client.get("/proxy/inventory/items", headers=headers).status_code == 401
    assert client.get("/auth/me", headers=headers).status_code == 401


def test_deprovisioned_user_is_locked_out_of_the_siem_api_too(erin):
    from web.backend import app as backend_module

    siem = TestClient(backend_module.app)
    headers = _bearer(erin["access_token"])
    assert siem.get("/api/samples", headers=headers).status_code == 200
    client.patch("/users/erin", headers=_admin(), json={"disabled": True})
    state.store.reset()
    assert siem.get("/api/samples", headers=headers).status_code == 401


def test_disabled_user_cannot_refresh_or_sign_in(erin):
    client.patch("/users/erin", headers=_admin(), json={"disabled": True})
    state.store.reset()
    assert client.post("/auth/refresh", json={"refresh_token": erin["refresh_token"]}).status_code == 401
    assert client.post("/auth/token", json={"username": "erin", "password": PASSWORD}).status_code == 401


def test_role_change_takes_effect_through_refresh(erin):
    client.patch("/users/erin", headers=_admin(), json={"role": "finance", "scopes": ["read", "invoice"]})
    state.store.reset()
    fresh = client.post("/auth/refresh", json={"refresh_token": erin["refresh_token"]}).json()
    assert fresh["role"] == "finance"
    headers = _bearer(fresh["access_token"])
    assert client.get("/proxy/billing/invoices", headers=headers).status_code == 200
    assert client.get("/proxy/inventory/items", headers=headers).status_code == 403


# --- Session lifetime -----------------------------------------------------------

def test_refresh_keeps_the_same_session():
    first = _login("alice", DEMO_USERS["alice"][0])
    second = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]}).json()
    a, b = _claims(first["access_token"]), _claims(second["access_token"])
    assert a["sid"] == b["sid"]
    assert a["auth_time"] == b["auth_time"]
    assert second["session_expires_at"] == pytest.approx(a["auth_time"] + SESSION_MAX_MINUTES * 60)


def test_tokens_never_outlive_the_session(monkeypatch):
    session = _login("alice", DEMO_USERS["alice"][0])
    start = _claims(session["access_token"])["auth_time"]
    real_time = time.time
    # One minute before the session's absolute end: new tokens are capped at that end.
    monkeypatch.setattr(auth.time, "time", lambda: start + SESSION_MAX_MINUTES * 60 - 60)
    fresh = client.post("/auth/refresh", json={"refresh_token": session["refresh_token"]})
    assert fresh.status_code == 200
    assert fresh.json()["expires_in"] <= 60
    refreshed = jwt.decode(fresh.json()["refresh_token"], JWT_SECRET_KEY, algorithms=["HS256"],
                           audience="micro-sase", options={"verify_iat": False})  # issued on the faked clock
    assert refreshed["exp"] <= start + SESSION_MAX_MINUTES * 60
    monkeypatch.setattr(auth.time, "time", real_time)


def test_refresh_is_refused_after_the_session_ends(monkeypatch):
    session = _login("alice", DEMO_USERS["alice"][0])
    start = _claims(session["access_token"])["auth_time"]
    monkeypatch.setattr(auth.time, "time", lambda: start + SESSION_MAX_MINUTES * 60 + 1)
    r = client.post("/auth/refresh", json={"refresh_token": session["refresh_token"]})
    assert r.status_code == 401
    assert "Session has ended" in r.json()["detail"]


def test_me_reports_identity_and_session_end():
    session = _login("bob", DEMO_USERS["bob"][0])
    me = client.get("/auth/me", headers=_bearer(session["access_token"])).json()
    assert me["subject"] == "bob" and me["role"] == "finance"
    assert me["session_expires_at"] == pytest.approx(session["session_expires_at"])
    assert client.get("/auth/me").status_code == 401
