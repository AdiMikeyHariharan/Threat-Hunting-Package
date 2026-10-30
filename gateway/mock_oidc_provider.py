"""Local-only OIDC provider used for an interactive dashboard demo.

This provider intentionally has no production features. It keeps one demo
identity in memory, serves an HTML password prompt, and honors ``prompt=login``
so the dashboard's post-logout reauthentication behavior can be demonstrated.
"""

from __future__ import annotations

import base64
import hashlib
import html
import hmac
import os
import secrets
import time
from urllib.parse import parse_qs, urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response


ISSUER = os.environ.get("DEMO_OIDC_ISSUER", "http://127.0.0.1:8090").rstrip("/")
CLIENT_ID = os.environ.get("DEMO_OIDC_CLIENT_ID", "micro-sase-demo")
CLIENT_SECRET = os.environ.get("DEMO_OIDC_CLIENT_SECRET", "micro-sase-demo-secret")
REDIRECT_URI = os.environ.get(
    "DEMO_OIDC_REDIRECT_URI", "http://127.0.0.1:5173/api/gateway/auth/sso/callback"
)
DEMO_USERNAME = os.environ.get("DEMO_OIDC_USERNAME", "alice")
DEMO_PASSWORD = os.environ.get("DEMO_OIDC_PASSWORD", "demo-sso-password")
DEMO_SUBJECT = os.environ.get("DEMO_OIDC_SUBJECT", "demo-user")

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_kid = "micro-sase-demo"
_codes: dict[str, dict[str, str | float | bool]] = {}
_sessions: set[str] = set()
app = FastAPI(title="Micro-SASE Demo Identity Provider")


def _b64_int(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _form_values(request: Request, body: bytes) -> dict[str, str]:
    values = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: items[0] for key, items in values.items() if items}


def _valid_request(params: dict[str, str]) -> str | None:
    required = ("client_id", "redirect_uri", "state", "nonce", "code_challenge")
    if any(not params.get(name) for name in required):
        return "The authorization request is missing required parameters."
    if params["client_id"] != CLIENT_ID or params["redirect_uri"] != REDIRECT_URI:
        return "This demo provider does not recognize the client."
    if params.get("response_type") != "code" or params.get("code_challenge_method") != "S256":
        return "This demo provider requires authorization code flow with PKCE S256."
    if "openid" not in params.get("scope", "").split():
        return "The openid scope is required."
    return None


def _login_page(params: dict[str, str], error: str | None = None) -> HTMLResponse:
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}">'
        for key, value in params.items()
        if key in {"client_id", "redirect_uri", "state", "nonce", "response_type", "scope", "code_challenge", "code_challenge_method"}
    )
    message = f'<p class="error">{html.escape(error)}</p>' if error else ""
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Demo identity provider</title>
<style>
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0a1320; color: #e9f1fb; font: 16px system-ui, sans-serif; }}
main {{ width: min(420px, calc(100% - 40px)); padding: 32px; border: 1px solid #27405d; border-radius: 16px; background: #111d2d; box-shadow: 0 20px 60px #0006; }}
h1 {{ margin: 0 0 8px; font-size: 24px; }} p {{ color: #9eb1c8; line-height: 1.5; }}
label {{ display: block; margin: 18px 0 7px; color: #cdd9e7; }}
input {{ box-sizing: border-box; width: 100%; padding: 12px; border: 1px solid #385371; border-radius: 8px; background: #0b1624; color: inherit; font: inherit; }}
button {{ width: 100%; margin-top: 22px; padding: 12px; border: 0; border-radius: 8px; background: #39d6ed; color: #08202a; font-weight: 700; font: inherit; cursor: pointer; }}
.eyebrow {{ color: #39d6ed; font-size: 12px; letter-spacing: .12em; text-transform: uppercase; font-weight: 700; }}
.hint {{ font-size: 13px; }} .error {{ color: #ff9e9e; }}
</style></head><body><main>
<div class="eyebrow">Local demo identity provider</div>
<h1>Password required</h1>
<p>This mock provider is used only to demonstrate the Micro-SASE SSO flow. Enter the demo identity credentials.</p>
{message}
<form method="post" action="/authorize">
{hidden}
<label for="username">Username</label><input id="username" name="username" value="{html.escape(DEMO_USERNAME)}" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
<p class="hint">Demo password: <code>{html.escape(DEMO_PASSWORD)}</code></p>
<button type="submit">Continue to Micro-SASE</button>
</form></main></body></html>"""
    return HTMLResponse(page, status_code=401 if error else 200)


def _complete(params: dict[str, str]) -> RedirectResponse:
    code = secrets.token_urlsafe(32)
    _codes[code] = {
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "nonce": params["nonce"],
        "code_challenge": params["code_challenge"],
        "subject": DEMO_SUBJECT,
        "expires_at": time.time() + 60,
        "used": False,
    }
    location = params["redirect_uri"] + "?" + urlencode({"code": code, "state": params["state"]})
    return RedirectResponse(location, status_code=302)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "demo-oidc-provider"}


@app.get("/.well-known/openid-configuration")
def configuration() -> dict[str, object]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token",
        "jwks_uri": ISSUER + "/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@app.get("/jwks")
def jwks() -> dict[str, list[dict[str, object]]]:
    public = _key.public_key().public_numbers()
    return {"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": _kid,
        "n": _b64_int(public.n), "e": _b64_int(public.e), "key_ops": ["verify"],
    }]}


@app.get("/authorize")
async def authorize(request: Request) -> Response:
    params = dict(request.query_params)
    error = _valid_request(params)
    if error:
        return PlainTextResponse(error, status_code=400)
    if request.cookies.get("demo_oidc_session") in _sessions and params.get("prompt") != "login":
        return _complete(params)
    return _login_page(params, "Password required for this sign-in.") if params.get("prompt") == "login" else _login_page(params)


@app.post("/authorize")
async def submit_login(request: Request) -> Response:
    params = _form_values(request, await request.body())
    error = _valid_request(params)
    if error:
        return PlainTextResponse(error, status_code=400)
    if not hmac.compare_digest(params.get("username", ""), DEMO_USERNAME) or not hmac.compare_digest(
        params.get("password", ""), DEMO_PASSWORD
    ):
        return _login_page(params, "Invalid demo credentials.")
    session = secrets.token_urlsafe(24)
    _sessions.add(session)
    response = _complete(params)
    response.set_cookie("demo_oidc_session", session, max_age=3600, httponly=True, samesite="lax", path="/")
    return response


@app.post("/token")
async def token(request: Request) -> Response:
    form = _form_values(request, await request.body())
    authorization = request.headers.get("authorization", "")
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret", "")
    if authorization.startswith("Basic "):
        try:
            decoded = base64.b64decode(authorization[6:]).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            client_id = client_secret = ""
    if not hmac.compare_digest(client_id, CLIENT_ID) or not hmac.compare_digest(client_secret, CLIENT_SECRET):
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    code = _codes.get(form.get("code", ""))
    if not code or bool(code["used"]) or float(code["expires_at"]) < time.time():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if form.get("redirect_uri") != code["redirect_uri"] or not form.get("code_verifier"):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    if not hmac.compare_digest(challenge, str(code["code_challenge"])):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    code["used"] = True
    now = int(time.time())
    id_token = jwt.encode(
        {"iss": ISSUER, "sub": code["subject"], "aud": CLIENT_ID, "iat": now, "exp": now + 300, "nonce": code["nonce"]},
        _key, algorithm="RS256", headers={"kid": _kid},
    )
    return JSONResponse({"access_token": secrets.token_urlsafe(32), "token_type": "Bearer", "expires_in": 300, "id_token": id_token})
