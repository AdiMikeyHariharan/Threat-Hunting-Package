"""OIDC code flow for one configured issuer, using the existing HTTP/JWT stack.

Only RS256 ID tokens are accepted. External subjects are explicitly linked to
local users; email, username and provider role claims never grant access.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import quote_plus, urlencode, urlsplit

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from . import state, users
from .auth import get_client_ip, is_token_revoked
from .telemetry import log_gateway_event

HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"}
TRANSACTION_TTL = 300
HANDOFF_TTL = 60
# Tolerated clock skew between the gateway and the provider for iat/exp. Without
# it, a provider clock a fraction of a second ahead makes iat look "in the future".
CLOCK_SKEW_SECONDS = 60
router = APIRouter(prefix="/auth/sso", tags=["SSO"])


def _validate_url(value: str, allow_local_http: bool = False) -> None:
    url = urlsplit(value)
    local = allow_local_http and url.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        not url.hostname or url.username or url.password or url.fragment
        or "\\" in value or any(c.isspace() or ord(c) < 32 for c in value)
        or (url.scheme != "https" and not (local and url.scheme == "http"))
    ):
        raise ValueError("OIDC URLs require HTTPS (HTTP is allowed only for explicit loopback development).")
    _ = url.port  # Reject malformed ports before using the URL.


@dataclass(frozen=True)
class Settings:
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    redirect_uri: str
    frontend_url: str
    subject_map: dict[str, str]
    auth_method: str = "client_secret_basic"
    allow_local_http: bool = False

    @property
    def origin(self) -> str:
        url = urlsplit(self.frontend_url)
        return f"{url.scheme}://{url.netloc}"

    @property
    def cookie_path(self) -> str:
        return "/" if self.secure else urlsplit(self.redirect_uri).path.rsplit("/", 1)[0]

    @property
    def secure(self) -> bool:
        return urlsplit(self.redirect_uri).scheme == "https"

    def cookie_name(self, purpose: str) -> str:
        # __Host- prevents sibling subdomains from planting a Domain cookie.
        return ("__Host-" if self.secure else "") + f"sase_oidc_{purpose}"

    def __post_init__(self) -> None:
        for value in (self.issuer, self.redirect_uri, self.frontend_url):
            _validate_url(value, self.allow_local_http)
            if urlsplit(value).query:
                raise ValueError("OIDC issuer, callback and frontend URLs cannot contain a query.")
        callback = urlsplit(self.redirect_uri)
        if f"{callback.scheme}://{callback.netloc}" != self.origin:
            raise ValueError("OIDC callback and frontend must share an origin; proxy the gateway under /api.")
        if not callback.path.endswith("/auth/sso/callback"):
            raise ValueError("OIDC redirect URI must end in /auth/sso/callback.")
        if not self.client_id or not self.client_secret:
            raise ValueError("OIDC client ID and secret are required.")
        if self.auth_method not in {"client_secret_basic", "client_secret_post"}:
            raise ValueError("Unsupported OIDC token endpoint authentication method.")
        if not isinstance(self.subject_map, dict) or not all(
            isinstance(sub, str) and sub and isinstance(name, str) and users.USERNAME_RE.fullmatch(name)
            for sub, name in self.subject_map.items()
        ):
            raise ValueError("SASE_OIDC_SUBJECT_MAP must map immutable OIDC subjects to local usernames.")


def load_settings() -> Settings | None:
    names = ("ISSUER", "CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URI", "FRONTEND_URL")
    values = [os.environ.get(f"SASE_OIDC_{name}", "") for name in names]
    if not any(values):
        return None
    if not all(values):
        raise ValueError("Set all SASE_OIDC_ISSUER, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI and FRONTEND_URL settings.")
    return Settings(
        *values,
        subject_map=json.loads(os.environ.get("SASE_OIDC_SUBJECT_MAP", "{}")),
        auth_method=os.environ.get("SASE_OIDC_TOKEN_AUTH_METHOD", "client_secret_basic"),
        allow_local_http=os.environ.get("SASE_OIDC_ALLOW_LOCAL_HTTP") == "true",
    )


settings = load_settings()


def _settings() -> Settings:
    if settings is None:
        raise HTTPException(503, "Enterprise SSO has not been configured.", headers=HEADERS)
    return settings


def _key(purpose: str, value: str) -> str:
    return f"oidc:{purpose}:" + hashlib.sha256(value.encode()).hexdigest()


def _base64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _client() -> httpx.AsyncClient:
    # Never forward credentials across redirects, and bound provider timeouts.
    return httpx.AsyncClient(timeout=10.0, follow_redirects=False)


async def _get_json(client: httpx.AsyncClient, url: str) -> dict:
    response = await client.get(url)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("Invalid OIDC response.")
    return data


async def _metadata(client: httpx.AsyncClient, config: Settings) -> dict:
    data = await _get_json(client, config.issuer.rstrip("/") + "/.well-known/openid-configuration")
    if data.get("issuer") != config.issuer:
        raise ValueError("OIDC discovery issuer mismatch.")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        _validate_url(data[name], config.allow_local_http)
    if "RS256" not in data.get("id_token_signing_alg_values_supported", []):
        raise ValueError("The OIDC provider must support RS256 ID tokens.")
    return data


def _cookie(response: Response, config: Settings, purpose: str, value: str, ttl: int) -> None:
    response.set_cookie(
        config.cookie_name(purpose), value, max_age=ttl, path=config.cookie_path,
        secure=config.secure, httponly=True, samesite="lax",
    )


def _clear_cookie(response: Response, config: Settings, purpose: str) -> None:
    response.delete_cookie(
        config.cookie_name(purpose), path=config.cookie_path,
        secure=config.secure, httponly=True, samesite="lax",
    )


def _audit(request: Request, status: int, reason: str, user: users.User | None = None) -> None:
    log_gateway_event(
        method=request.method, path=request.url.path, target_service="auth",
        status_code=status, decision="ALLOW" if status < 400 else "DENY",
        client_ip=get_client_ip(request), subject=user.username if user else None,
        role=user.role if user else None, auth_type="oidc", reason=reason,
    )


@router.get("/config")
def configuration() -> Response:
    return JSONResponse({"configured": settings is not None}, headers=HEADERS)


@router.get("/login")
async def login(request: Request) -> Response:
    config = _settings()
    count, _ = state.store.incr_window(f"oidc-login:{get_client_ip(request)}", 60, time.time())
    if count > 10:
        raise HTTPException(429, "Too many SSO attempts. Try again later.", headers={**HEADERS, "Retry-After": "60"})
    try:
        async with _client() as client:
            metadata = await _metadata(client, config)
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        _audit(request, 502, "OIDC discovery failed")
        raise HTTPException(502, "Identity provider is unavailable or misconfigured.", headers=HEADERS)
    oauth_state, binding, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(4))
    state.store.set(
        _key("state", oauth_state + ":" + binding),
        json.dumps({"nonce": nonce, "verifier": verifier}), TRANSACTION_TTL,
    )
    params = {
        "response_type": "code", "client_id": config.client_id,
        "redirect_uri": config.redirect_uri, "scope": "openid",
        "state": oauth_state, "nonce": nonce, "response_mode": "query",
        "code_challenge": _base64(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256",
    }
    endpoint = metadata["authorization_endpoint"]
    response = RedirectResponse(
        endpoint + ("&" if "?" in endpoint else "?") + urlencode(params), status_code=302, headers=HEADERS,
    )
    _cookie(response, config, "state", binding, TRANSACTION_TTL)
    _clear_cookie(response, config, "handoff")
    return response


async def _identity(client: httpx.AsyncClient, config: Settings, code: str, transaction: dict) -> str:
    metadata = await _metadata(client, config)
    data = {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": config.redirect_uri, "code_verifier": transaction["verifier"],
    }
    auth = None
    if config.auth_method == "client_secret_post":
        data.update(client_id=config.client_id, client_secret=config.client_secret)
    else:
        # RFC 6749 section 2.3.1 requires form encoding before HTTP Basic encoding.
        auth = httpx.BasicAuth(quote_plus(config.client_id), quote_plus(config.client_secret))
    response = await client.post(metadata["token_endpoint"], data=data, auth=auth)
    response.raise_for_status()
    token = response.json()
    header = jwt.get_unverified_header(token["id_token"])
    if header.get("alg") != "RS256" or header.get("crit"):
        raise ValueError("Unsupported ID token algorithm or critical header.")
    jwks = await _get_json(client, metadata["jwks_uri"])
    keys = [
        key for key in jwks["keys"]
        if key.get("kty") == "RSA" and key.get("use", "sig") == "sig"
        and key.get("alg", "RS256") == "RS256"
        and "verify" in key.get("key_ops", ["verify"])
        and (not header.get("kid") or key.get("kid") == header["kid"])
    ]
    if len(keys) != 1:
        raise ValueError("No unique signing key for ID token.")
    claims = jwt.decode(
        token["id_token"], jwt.PyJWK.from_dict(keys[0], algorithm="RS256").key,
        algorithms=["RS256"], issuer=config.issuer, audience=config.client_id,
        leeway=CLOCK_SKEW_SECONDS,
        options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
    )
    # Keep exact issuer matching independent of the installed PyJWT version.
    if claims["iss"] != config.issuer:
        raise ValueError("ID token issuer mismatch.")
    if not isinstance(claims["sub"], str) or not claims["sub"]:
        raise ValueError("Invalid subject.")
    if not isinstance(claims["nonce"], str) or not hmac.compare_digest(
        claims["nonce"].encode(), transaction["nonce"].encode()
    ):
        raise ValueError("ID token nonce mismatch.")
    audience = claims["aud"]
    if (isinstance(audience, list) and len(audience) > 1) or "azp" in claims:
        if claims.get("azp") != config.client_id:
            raise ValueError("ID token authorized party mismatch.")
    if "at_hash" in claims:
        expected = _base64(hashlib.sha256(token["access_token"].encode("ascii")).digest()[:16])
        if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(
            claims["at_hash"].encode(), expected.encode()
        ):
            raise ValueError("ID token access-token hash mismatch.")
    return claims["sub"]


@router.get("/callback")
async def callback(request: Request) -> Response:
    config = _settings()
    try:
        params = request.query_params
        if any(len(params.getlist(key)) > 1 for key in ("state", "code", "error", "iss")):
            raise ValueError("Duplicate callback parameters.")
        oauth_state = params.get("state", "")
        binding = request.cookies.get(config.cookie_name("state"), "")
        if not oauth_state or len(oauth_state) > 128 or not binding or len(binding) > 128:
            raise ValueError("Missing state or browser binding.")
        transaction = state.store.pop(_key("state", oauth_state + ":" + binding))
        if transaction is None:
            raise ValueError("Expired or already-used state.")
        if params.get("error") or not params.get("code") or len(params["code"]) > 4096:
            raise ValueError("Authorization was denied or no code was returned.")
        if "iss" in params and params["iss"] != config.issuer:
            raise ValueError("Authorization response issuer mismatch.")
        async with _client() as client:
            subject = await _identity(client, config, params["code"], json.loads(transaction))
        user = users.get_user(config.subject_map.get(subject, ""))
        if user is None or user.disabled:
            _audit(request, 403, "OIDC identity is not linked to an active local account")
            response = RedirectResponse(config.frontend_url + "#sso=denied", 303, headers=HEADERS)
        else:
            ticket = secrets.token_urlsafe(32)
            state.store.set(
                _key("handoff", ticket),
                json.dumps({"subject": subject, "username": user.username, "iat": time.time()}), HANDOFF_TTL,
            )
            response = RedirectResponse(config.frontend_url + "#sso=complete", 303, headers=HEADERS)
            _cookie(response, config, "handoff", ticket, HANDOFF_TTL)
            _audit(request, 200, "OIDC identity verified", user)
    except (httpx.HTTPError, jwt.PyJWTError, ValueError, KeyError, TypeError, AttributeError):
        # Provider messages, codes and tokens must not enter logs or redirect URLs.
        _audit(request, 401, "OIDC callback validation failed")
        response = RedirectResponse(config.frontend_url + "#sso=failed", 303, headers=HEADERS)
    _clear_cookie(response, config, "state")
    if not response.headers["location"].endswith("#sso=complete"):
        _clear_cookie(response, config, "handoff")
    return response


def consume_session(request: Request, response: Response) -> users.User:
    config = _settings()
    if request.headers.get("origin") != config.origin:
        raise HTTPException(403, "SSO session exchange requires the dashboard origin.", headers=HEADERS)
    ticket = request.cookies.get(config.cookie_name("handoff"), "")
    stored = state.store.pop(_key("handoff", ticket)) if ticket and len(ticket) <= 128 else None
    if stored is None:
        raise HTTPException(401, "SSO session expired or already used. Sign in again.", headers=HEADERS)
    handoff = json.loads(stored)
    user = users.get_user(handoff["username"])
    if (
        user is None or user.disabled
        or config.subject_map.get(handoff["subject"]) != user.username
        or is_token_revoked({"sub": user.username, "iat": handoff["iat"], "jti": ""})
    ):
        raise HTTPException(403, "SSO account is no longer active.", headers=HEADERS)
    _clear_cookie(response, config, "handoff")
    response.headers.update(HEADERS)
    _audit(request, 200, "SSO session issued", user)
    return user
