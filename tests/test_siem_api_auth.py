"""SIEM API access control uses identities issued by the Micro-SASE gateway."""

from fastapi.testclient import TestClient

from gateway.users import DEMO_USERS
from web.backend import app as backend_module

app = backend_module.app

client = TestClient(app)


def _token(username: str) -> str:
    password = DEMO_USERS[username][0]
    response = client.post(
        "/api/gateway/auth/token", json={"username": username, "password": password}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def _auth(username: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(username)}"}


def test_siem_endpoints_require_gateway_token():
    assert client.get("/api/samples").status_code == 401
    assert client.get("/api/analyze", params={"source": "auth.log"}).status_code == 401


def test_gateway_roles_can_read_siem_catalogue_and_samples():
    for username in ("alice", "bob", "charlie"):
        headers = _auth(username)
        assert client.get("/api/samples", headers=headers).status_code == 200
        assert client.get("/api/rules", headers=headers).status_code == 200


def test_analyst_can_analyze_and_upload_but_viewer_cannot_upload():
    analyst = _auth("alice")
    assert client.get("/api/analyze", params={"source": "auth.log"}, headers=analyst).status_code == 200
    assert client.post(
        "/api/analyze", files={"file": ("small.log", "test log\n")}, headers=analyst
    ).status_code == 200

    viewer = _auth("bob")
    assert client.get("/api/analyze", params={"source": "auth.log"}, headers=viewer).status_code == 200
    assert client.post(
        "/api/analyze", files={"file": ("small.log", "test log\n")}, headers=viewer
    ).status_code == 403


def test_live_gateway_analysis_is_admin_only():
    assert client.get("/api/analyze-live-gateway", headers=_auth("alice")).status_code == 403
    assert client.get("/api/analyze-live-gateway", headers=_auth("charlie")).status_code == 200


def test_upload_size_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(backend_module, "MAX_UPLOAD_BYTES", 4)
    response = client.post(
        "/api/analyze",
        files={"file": ("too-large.log", b"12345")},
        headers=_auth("alice"),
    )
    assert response.status_code == 413
