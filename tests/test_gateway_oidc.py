"""OIDC gateway flow tests using a local provider transport."""

import base64
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
import fakeredis
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from gateway import auth, oidc, state, users
from gateway.config import GATEWAY_AUDIT_LOG
from web.backend.app import app


ISSUER = "https://idp.example"
CALLBACK = "https://dashboard.example/api/gateway/auth/sso/callback"
FRONTEND = "https://dashboard.example/app"


@pytest.fixture
def oidc_env(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_numbers()
    def b64(value):
        return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    config = oidc.Settings(
        issuer=ISSUER, client_id="dashboard", client_secret="top-secret",
        redirect_uri=CALLBACK, frontend_url=FRONTEND,
        subject_map={"sub-alice": "alice"}, allow_local_http=False,
    )
    monkeypatch.setattr(oidc, "settings", config)
    state.store.reset()
    requests = []
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test",
                       "n": b64(public.n), "e": b64(public.e), "key_ops": ["verify"]}]}

    def sign(claims, alg="RS256"):
        return jwt.encode(claims, key, algorithm=alg, headers={"kid": "test"})

    def make_handler(token_claims=None, discovery_issuer=ISSUER, token_status=200, raw_token=None):
        def handler(request):
            requests.append(request)
            if request.url.path == "/.well-known/openid-configuration":
                return httpx.Response(200, json={"issuer": discovery_issuer,
                    "authorization_endpoint": ISSUER + "/authorize",
                    "token_endpoint": ISSUER + "/token", "jwks_uri": ISSUER + "/jwks",
                    "id_token_signing_alg_values_supported": ["RS256"]})
            if request.url.path == "/token":
                if token_status != 200:
                    return httpx.Response(token_status, json={"error": "denied"})
                if raw_token is not None:
                    return httpx.Response(200, json={"id_token": raw_token, "access_token": "access"})
                body = dict(token_claims or {})
                body.setdefault("iss", ISSUER); body.setdefault("sub", "sub-alice")
                body.setdefault("aud", "dashboard"); body.setdefault("iat", int(time.time()))
                body.setdefault("exp", int(time.time()) + 300)
                body.setdefault("nonce", "wrong")
                return httpx.Response(200, json={"id_token": sign(body), "access_token": "access"})
            if request.url.path == "/jwks":
                return httpx.Response(200, json=jwks)
            return httpx.Response(404)
        return handler

    def install(handler):
        monkeypatch.setattr(oidc, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    return config, requests, sign, make_handler, install


def _client():
    return TestClient(app, base_url="https://dashboard.example")


def _login(c, handler, install):
    install(handler)
    response = c.get("/api/gateway/auth/sso/login", follow_redirects=False)
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    return response, query


def test_oidc_config_is_fail_closed_and_login_uses_pkce(oidc_env, monkeypatch):
    config, requests, _sign, make_handler, install = oidc_env
    c = _client()
    monkeypatch.setattr(oidc, "settings", None)
    assert c.get("/api/gateway/auth/sso/config").json() == {"configured": False}
    assert c.get("/api/gateway/auth/sso/login").status_code == 503
    monkeypatch.setattr(oidc, "settings", config)
    response, query = _login(c, make_handler(), install)
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == [CALLBACK]
    assert response.cookies.get(config.cookie_name("state"))
    assert "client_secret" not in response.headers["location"]
    state_req = next(r for r in requests if r.url.path.endswith("configuration"))
    assert state_req.url.path.endswith("openid-configuration")


def test_oidc_success_exchanges_handoff_once_and_existing_session_works(oidc_env):
    config, requests, _sign, make_handler, install = oidc_env
    c = _client()
    response, query = _login(c, make_handler(), install)
    challenge = query["code_challenge"][0]
    expected_basic = base64.b64encode(b"dashboard:top-secret").decode()
    base_handler = make_handler({"nonce": query["nonce"][0]})
    def handler(request):
        if request.url.path == "/token":
            form = parse_qs(request.content.decode())
            verifier = form["code_verifier"][0]
            assert base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode() == challenge
            assert request.headers.get("authorization") == "Basic " + expected_basic
        return base_handler(request)
    install(handler)
    callback = c.get("/api/gateway/auth/sso/callback", params={"code": "one", "state": query["state"][0]}, follow_redirects=False)
    assert callback.status_code == 303 and callback.headers["location"].endswith("#sso=complete")
    assert "id_token" not in callback.headers["location"]
    session = c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://dashboard.example"})
    assert session.status_code == 200
    body = session.json()
    assert body["subject"] == "alice" and body["access_token"]
    assert body["role"] == "developer"
    assert session.headers["cache-control"] == "no-store"
    cookie = response.headers.get_list("set-cookie")[0]
    assert "__Host-" in cookie and "Secure" in cookie and "HttpOnly" in cookie
    assert "SameSite=lax" in cookie and "Path=/" in cookie and "Domain=" not in cookie
    audit = GATEWAY_AUDIT_LOG.read_text()
    for secret in (config.client_secret, body["access_token"], body["refresh_token"]):
        assert secret not in audit
    assert c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://dashboard.example"}).status_code == 401
    assert c.get("/api/samples", headers={"Authorization": "Bearer " + body["access_token"]}).status_code == 200
    refreshed = c.post("/api/gateway/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert refreshed.status_code == 200
    assert c.post("/api/gateway/auth/logout", headers={"Authorization": "Bearer " + refreshed.json()["access_token"]},
                  json={"refresh_token": refreshed.json()["refresh_token"]}).status_code == 200
    assert requests


@pytest.mark.parametrize("auth_method", ["client_secret_basic", "client_secret_post"])
def test_oidc_token_auth_method_and_pkce_are_exact(oidc_env, monkeypatch, auth_method):
    config, _requests, _sign, make_handler, install = oidc_env
    monkeypatch.setattr(oidc, "settings", oidc.Settings(**{**config.__dict__, "auth_method": auth_method}))
    c = _client()
    response, query = _login(c, make_handler(), install)
    base_handler = make_handler({"nonce": query["nonce"][0]})
    def handler(request):
        if request.url.path == "/token":
            form = parse_qs(request.content.decode())
            assert base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()).rstrip(b"=").decode() == query["code_challenge"][0]
            if auth_method == "client_secret_post":
                assert form["client_id"] == ["dashboard"] and form["client_secret"] == ["top-secret"]
                assert "authorization" not in request.headers
            else:
                assert request.headers["authorization"] == "Basic " + base64.b64encode(b"dashboard:top-secret").decode()
        return base_handler(request)
    install(handler)
    result = c.get("/api/gateway/auth/sso/callback", params={"code": "code", "state": query["state"][0]}, follow_redirects=False)
    assert result.headers["location"].endswith("#sso=complete")


@pytest.mark.parametrize("tamper", ["wrong_state", "wrong_browser", "replay"])
def test_oidc_callback_requires_bound_one_use_state(oidc_env, tamper):
    config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    state_value = query["state"][0]
    if tamper == "wrong_state":
        state_value = "x" * 32
    elif tamper == "wrong_browser":
        c.cookies.set(config.cookie_name("state"), "other")
    result = c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": state_value}, follow_redirects=False)
    assert result.status_code == 303 and result.headers["location"].endswith("#sso=failed")
    if tamper == "replay":
        # A valid state was consumed even though the provider code was rejected.
        assert c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False).headers["location"].endswith("#sso=failed")


@pytest.mark.parametrize("claim", [
    {"iss": "https://evil.example"}, {"aud": "other"},
    {"exp": int(time.time()) - oidc.CLOCK_SKEW_SECONDS - 60},  # expired beyond the allowed skew
    {"nonce": "bad"}, {"sub": ""},
])
def test_oidc_rejects_invalid_identity_claims(oidc_env, claim):
    _config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    binding = c.cookies.get(oidc._settings().cookie_name("state"))
    tx = json.loads(state.store.get(oidc._key("state", query["state"][0] + ":" + binding)))
    claims = {"nonce": tx["nonce"], **claim}
    install(make_handler(claims))
    result = c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False)
    assert result.headers["location"].endswith("#sso=failed")


def test_oidc_session_requires_exact_origin_and_disabled_or_unlinked_accounts(oidc_env):
    config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    binding = c.cookies.get(config.cookie_name("state"))
    tx = json.loads(state.store.get(oidc._key("state", query["state"][0] + ":" + binding)))
    install(make_handler({"nonce": tx["nonce"]}))
    assert c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False).status_code == 303
    assert c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://dashboard.example"}).status_code == 200
    assert users.get_user("alice") is not None


def test_unlinked_external_subject_is_denied_even_with_provider_role(oidc_env):
    config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler({"sub": "external-admin", "role": "admin", "nonce": "bad"}), install)
    install(make_handler({"sub": "external-admin", "role": "admin", "nonce": query["nonce"][0]}))
    result = c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False)
    assert result.headers["location"].endswith("#sso=denied")


def test_disabled_account_is_rechecked_before_handoff_exchange(oidc_env, monkeypatch):
    config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    install(make_handler({"nonce": query["nonce"][0]}))
    assert c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False).headers["location"].endswith("#sso=complete")
    user = users.get_user("alice")
    monkeypatch.setattr(user, "disabled", True)
    assert c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://dashboard.example"}).status_code == 403


def test_state_cookie_replay_is_consumed_server_side(oidc_env):
    config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    original = c.cookies.get(config.cookie_name("state"))
    install(make_handler())
    c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False)
    c.cookies.set(config.cookie_name("state"), original)
    replay = c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False)
    assert replay.headers["location"].endswith("#sso=failed")


def test_provider_error_and_discovery_mismatch_fail_without_leaking_values(oidc_env):
    config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    install(make_handler({"nonce": query["nonce"][0]}, token_status=500))
    denied = c.get("/api/gateway/auth/sso/callback", params={"code": "super-secret-code", "state": query["state"][0], "error": "provider_secret"}, follow_redirects=False)
    assert denied.headers["location"].endswith("#sso=failed")
    assert "super-secret-code" not in denied.headers["location"] and "provider_secret" not in denied.headers["location"]
    c = _client()
    install(make_handler(discovery_issuer="https://wrong.example"))
    assert c.get("/api/gateway/auth/sso/login").status_code == 502


def test_handoff_cookie_requires_origin_and_is_one_use(oidc_env):
    config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    install(make_handler({"nonce": query["nonce"][0]}))
    assert c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False).status_code == 303
    ticket = c.cookies.get(config.cookie_name("handoff"))
    assert c.post("/api/gateway/auth/sso/session").status_code == 403
    assert c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://dashboard.example"}).status_code == 200
    c.cookies.set(config.cookie_name("handoff"), ticket)
    assert c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://dashboard.example"}).status_code == 401


@pytest.mark.parametrize("kwargs", [
    {"issuer": "http://idp.example"},
    {"redirect_uri": "https://other.example/api/gateway/auth/sso/callback"},
    {"frontend_url": "https://other.example/app"},
])
def test_settings_reject_insecure_or_cross_origin_urls(oidc_env, kwargs):
    config = oidc_env[0]
    with pytest.raises(ValueError):
        oidc.Settings(**{**config.__dict__, **kwargs})


def test_settings_repr_does_not_contain_secret(oidc_env):
    config = oidc_env[0]
    assert "top-secret" not in repr(config)


def test_memory_store_pop_is_atomic_and_expiry_is_enforced():
    store = state.MemoryStore()
    store.set("once", "value", 30)
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda _x: store.pop("once"), range(8)))
    assert values.count("value") == 1 and values.count(None) == 7
    store.set("expired", "value", -1)
    assert store.pop("expired") is None


@pytest.mark.parametrize("mutation", [
    "signature", "none", "hs256", "missing_iss", "missing_sub", "missing_aud",
    "missing_exp", "missing_iat", "missing_nonce", "wrong_azp", "multi_aud_no_azp", "bad_at_hash",
])
def test_oidc_rejects_cryptographically_invalid_tokens(oidc_env, mutation):
    config, _requests, sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    claims = {"iss": ISSUER, "sub": "sub-alice", "aud": "dashboard",
              "iat": int(time.time()), "exp": int(time.time()) + 300, "nonce": query["nonce"][0]}
    if mutation.startswith("missing_"):
        claims.pop(mutation.removeprefix("missing_"))
        raw = sign(claims)
    elif mutation == "signature":
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        raw = jwt.encode(claims, other, algorithm="RS256", headers={"kid": "test"})
    elif mutation == "none":
        raw = jwt.encode(claims, "", algorithm="none", headers={"kid": "test"})
    elif mutation == "hs256":
        raw = jwt.encode(claims, "wrong-secret-" * 4, algorithm="HS256", headers={"kid": "test"})
    elif mutation == "wrong_azp":
        claims.update(aud=["dashboard", "other"], azp="wrong")
        raw = sign(claims)
    elif mutation == "multi_aud_no_azp":
        claims["aud"] = ["dashboard", "other"]
        raw = sign(claims)
    else:
        claims["at_hash"] = "invalid"
        raw = sign(claims)
    install(make_handler(raw_token=raw))
    callback = c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False)
    assert callback.headers["location"].endswith("#sso=failed")
    assert c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://dashboard.example"}).status_code in {401, 403}


@pytest.mark.parametrize("iat_offset, exp_offset, outcome", [
    (2, 300, "complete"),      # provider clock slightly ahead (seen with a real Keycloak)
    (-400, -30, "complete"),   # expired within the allowed skew
    (120, 300, "failed"),      # issued well in the future
    (-400, -120, "failed"),    # expired beyond the allowed skew
])
def test_oidc_tolerates_small_clock_skew_only(oidc_env, iat_offset, exp_offset, outcome):
    config, _requests, sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "sub-alice", "aud": "dashboard",
              "iat": now + iat_offset, "exp": now + exp_offset, "nonce": query["nonce"][0]}
    install(make_handler(raw_token=sign(claims)))
    callback = c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False)
    assert callback.headers["location"].endswith(f"#sso={outcome}")


def test_oidc_accepts_multiple_audience_with_correct_azp_and_at_hash(oidc_env):
    config, _requests, sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    claims = {"iss": ISSUER, "sub": "sub-alice", "aud": ["dashboard", "other"], "azp": "dashboard",
              "iat": int(time.time()), "exp": int(time.time()) + 300, "nonce": query["nonce"][0],
              "at_hash": base64.urlsafe_b64encode(hashlib.sha256(b"access").digest()[:16]).rstrip(b"=").decode()}
    install(make_handler(raw_token=sign(claims)))
    callback = c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False)
    assert callback.headers["location"].endswith("#sso=complete")
    assert c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://dashboard.example"}).status_code == 200


@pytest.mark.parametrize("store_factory", [state.MemoryStore, lambda: state.RedisStore(fakeredis.FakeRedis())])
def test_oidc_full_flow_works_with_memory_and_redis_store(oidc_env, monkeypatch, store_factory):
    config, _requests, _sign, make_handler, install = oidc_env
    store = store_factory()
    monkeypatch.setattr(state, "store", store)
    c = _client()
    _response, query = _login(c, make_handler(), install)
    install(make_handler({"nonce": query["nonce"][0]}))
    assert c.get("/api/gateway/auth/sso/callback", params={"code": "x", "state": query["state"][0]}, follow_redirects=False).status_code == 303
    assert c.post("/api/gateway/auth/sso/session", headers={"Origin": "https://dashboard.example"}).status_code == 200


@pytest.mark.parametrize("store_factory", [state.MemoryStore, lambda: state.RedisStore(fakeredis.FakeRedis())])
def test_store_pop_is_atomic_for_memory_and_redis(store_factory):
    store = store_factory()
    store.set("once", "value", 30)
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda _x: store.pop("once"), range(8)))
    assert values.count("value") == 1 and values.count(None) == 7


@pytest.mark.parametrize("expired_stage", ["state", "handoff"])
def test_expired_browser_transactions_cannot_create_sessions(oidc_env, monkeypatch, expired_stage):
    config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    install(make_handler({"nonce": query["nonce"][0]}))
    if expired_stage == "state":
        # Keep the browser cookie to verify server-side expiry, not cookie expiry.
        future = time.time() + oidc.TRANSACTION_TTL + 1
        monkeypatch.setattr(state.time, "time", lambda: future)
    callback = c.get("/api/gateway/auth/sso/callback",
                     params={"code": "x", "state": query["state"][0]}, follow_redirects=False)
    if expired_stage == "state":
        assert callback.headers["location"].endswith("#sso=failed")
    else:
        assert callback.headers["location"].endswith("#sso=complete")
        future = time.time() + oidc.HANDOFF_TTL + 1
        monkeypatch.setattr(state.time, "time", lambda: future)
    assert c.post("/api/gateway/auth/sso/session",
                  headers={"Origin": "https://dashboard.example"}).status_code == 401


def test_administrator_revocation_invalidates_pending_handoff(oidc_env):
    _config, _requests, _sign, make_handler, install = oidc_env
    c = _client()
    _response, query = _login(c, make_handler(), install)
    install(make_handler({"nonce": query["nonce"][0], "role": "admin", "scopes": ["admin"]}))
    result = c.get("/api/gateway/auth/sso/callback",
                   params={"code": "x", "state": query["state"][0]}, follow_redirects=False)
    assert result.headers["location"].endswith("#sso=complete")
    auth.revoke_user_tokens("alice")
    assert c.post("/api/gateway/auth/sso/session",
                  headers={"Origin": "https://dashboard.example"}).status_code == 403


def test_oidc_environment_requires_complete_configuration(monkeypatch):
    for name in list(oidc.os.environ):
        if name.startswith("SASE_OIDC_"):
            monkeypatch.delenv(name)
    assert oidc.load_settings() is None
    monkeypatch.setenv("SASE_OIDC_ISSUER", ISSUER)
    with pytest.raises(ValueError, match="Set all"):
        oidc.load_settings()


def test_http_development_exception_is_limited_to_loopback(oidc_env):
    config = oidc_env[0]
    local = oidc.Settings(**{
        **config.__dict__, "allow_local_http": True,
        "issuer": "http://localhost:9000",
        "redirect_uri": "http://localhost:5173/api/gateway/auth/sso/callback",
        "frontend_url": "http://localhost:5173/",
    })
    assert not local.secure
    with pytest.raises(ValueError):
        oidc.Settings(**{**local.__dict__, "issuer": "http://remote.example"})
