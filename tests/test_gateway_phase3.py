"""Phase 3 tests: encrypted credential vault (AES-256-GCM) and proxy injection."""

import base64
import hashlib
import json
import os

import pytest
from fastapi.testclient import TestClient

from gateway.main import app
from gateway.users import DEMO_USERS
from gateway.vault import CredentialVault, VaultError, vault

client = TestClient(app)
SECRET = "vault_mock_downstream_secret_value_98765"


@pytest.fixture(autouse=True)
def _empty_vault():
    vault._records.clear()
    vault._save()
    yield
    vault._records.clear()
    vault._save()


def _login(username: str) -> dict:
    r = client.post("/auth/token", json={"username": username, "password": DEMO_USERS[username][0]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _store(service="billing", header="Authorization", prefix="Bearer ", secret=SECRET):
    return client.put(
        f"/vault/credentials/{service}",
        json={"header": header, "prefix": prefix, "secret": secret},
        headers=_login("charlie"),
    )


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


# --- Admin API ---------------------------------------------------------------

def test_store_requires_admin():
    body = {"secret": "x"}
    assert client.put("/vault/credentials/billing", json=body).status_code == 401
    assert client.put("/vault/credentials/billing", json=body, headers=_login("alice")).status_code == 403
    assert client.get("/vault/credentials", headers=_login("bob")).status_code == 403


def test_store_unregistered_service_404():
    assert _store(service="nope").status_code == 404


@pytest.mark.parametrize("header", ["X-SASE-Internal", "x-sase-role", "Host", "Content-Length", "bad header!"])
def test_reserved_or_invalid_headers_rejected(header):
    r = _store(header=header)
    assert r.status_code == 400


def test_list_returns_metadata_only():
    _store()
    data = client.get("/vault/credentials", headers=_login("charlie")).json()
    blob = json.dumps(data)
    assert SECRET not in blob
    assert "ciphertext" not in blob and "nonce" not in blob
    assert data["credentials"][0]["service"] == "billing"
    assert data["credentials"][0]["version"] == 1


def test_version_increments_on_update():
    _store()
    assert _store(secret="rotated-secret").json()["version"] == 2


def test_delete():
    _store()
    h = _login("charlie")
    assert client.delete("/vault/credentials/billing", headers=h).status_code == 200
    assert client.delete("/vault/credentials/billing", headers=h).status_code == 404


# --- At-rest encryption ------------------------------------------------------

def test_store_file_contains_no_plaintext():
    _store()
    raw = vault.store.read_text()
    assert SECRET not in raw
    assert base64.b64encode(SECRET.encode()).decode() not in raw


def test_same_secret_encrypts_differently_each_time():
    _store()
    c1 = vault._records["billing"]["ciphertext"]
    _store()
    assert vault._records["billing"]["ciphertext"] != c1  # fresh nonce per write


# --- Proxy injection ---------------------------------------------------------

def test_backend_receives_credential_caller_never_sees_it():
    _store()
    r = client.get("/proxy/billing/invoices", headers=_login("bob"))
    assert r.status_code == 200
    cred = r.json()["upstream_credential"]
    assert cred["received"] is True
    assert cred["sha256_prefix"] == _fp("Bearer " + SECRET)   # exact value reached backend
    assert SECRET not in r.text                                # ...but not the caller


def test_callers_gateway_jwt_is_not_forwarded_when_no_vault_entry():
    r = client.get("/proxy/billing/invoices", headers=_login("bob"))
    assert r.json()["upstream_credential"]["received"] is False


def test_client_cannot_override_injected_header():
    _store(header="X-Upstream-Key", prefix="")
    key = client.post(
        "/auth/register-api-key",
        json={"service_id": "svc-b", "role": "billing-service", "scopes": ["read"]},
        headers=_login("charlie"),
    ).json()["api_key"]
    # Mock billing fingerprints Authorization; check the custom header via the rule instead:
    from gateway import proxy
    seen = {}

    original = proxy.httpx.AsyncClient.request

    async def spy(self, method, url, headers=None, **kw):
        seen.update({k.lower(): v for k, v in (headers or {}).items()})
        return await original(self, method, url, headers=headers, **kw)

    proxy.httpx.AsyncClient.request = spy
    try:
        client.get("/proxy/billing/invoices",
                   headers={"X-API-Key": key, "X-Upstream-Key": "attacker-value"})
    finally:
        proxy.httpx.AsyncClient.request = original
    assert seen["x-upstream-key"] == SECRET


def test_secret_never_written_to_audit_log():
    _store()
    client.get("/proxy/billing/invoices", headers=_login("bob"))
    audit = open(os.environ["SASE_AUDIT_LOG"]).read()
    assert SECRET not in audit
    assert "vault credential 'Authorization' injected" in audit


# --- Integrity / tamper resistance ------------------------------------------

def test_ciphertext_moved_to_other_service_fails_closed():
    """AAD binds ciphertext to its service: copying billing's secret onto inventory must fail."""
    _store()
    vault._records["inventory"] = dict(vault._records["billing"])
    r = client.get("/proxy/inventory/items", headers=_login("alice"))
    assert r.status_code == 503
    assert SECRET not in r.text


def test_tampered_ciphertext_fails():
    _store()
    rec = vault._records["billing"]
    ct = bytearray(base64.b64decode(rec["ciphertext"]))
    ct[0] ^= 0x01
    rec["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(VaultError, match="Integrity"):
        vault.header_for("billing")


def test_wrong_master_key_cannot_decrypt(tmp_path, monkeypatch):
    store = tmp_path / "v.json"
    monkeypatch.setenv("SASE_VAULT_KEY", base64.b64encode(b"A" * 32).decode())
    CredentialVault(store).put("billing", "Authorization", SECRET)

    monkeypatch.setenv("SASE_VAULT_KEY", base64.b64encode(b"B" * 32).decode())
    with pytest.raises(VaultError, match="unknown key"):
        CredentialVault(store).header_for("billing")


def test_invalid_master_key_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("SASE_VAULT_KEY", base64.b64encode(b"short").decode())
    with pytest.raises(VaultError, match="32 bytes"):
        CredentialVault(tmp_path / "v.json")


# --- Key rotation ------------------------------------------------------------

def test_key_rotation(tmp_path, monkeypatch):
    store = tmp_path / "v.json"
    k1 = base64.b64encode(b"1" * 32).decode()
    k2 = base64.b64encode(b"2" * 32).decode()

    monkeypatch.setenv("SASE_VAULT_KEY", k1)
    v1 = CredentialVault(store)
    v1.put("billing", "Authorization", SECRET, prefix="Bearer ")
    old_id = v1.current_key_id

    # New primary key, old key still accepted for decrypt
    monkeypatch.setenv("SASE_VAULT_KEY", k2)
    monkeypatch.setenv("SASE_VAULT_OLD_KEYS", k1)
    v2 = CredentialVault(store)
    assert v2.header_for("billing") == ("Authorization", "Bearer " + SECRET)
    assert v2.rotate() == {"rotated": 1, "total": 1, "current_key_id": v2.current_key_id}
    assert v2.current_key_id != old_id

    # Old key can now be retired completely
    monkeypatch.delenv("SASE_VAULT_OLD_KEYS")
    v3 = CredentialVault(store)
    assert v3.header_for("billing") == ("Authorization", "Bearer " + SECRET)


def test_rotate_endpoint_admin_only():
    assert client.post("/vault/rotate", headers=_login("alice")).status_code == 403
    r = client.post("/vault/rotate", headers=_login("charlie"))
    assert r.status_code == 200
    assert r.json()["rotated"] == 0
