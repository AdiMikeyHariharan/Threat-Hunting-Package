"""FastAPI Entrypoint for Micro-SASE Enterprise API Gateway.

Run with (mock backends run separately, see gateway/mock_backends.py):
    uvicorn gateway.mock_backends:app --port 8081
    uvicorn gateway.main:app --port 8080
"""

from __future__ import annotations

import secrets
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import oidc, users
from .auth import (
    IdentityContext,
    authenticate_request,
    create_access_token,
    create_refresh_token,
    decode_jwt_token,
    get_client_ip,
    is_token_revoked,
    list_api_keys,
    register_api_key,
    require_admin,
    revoke_api_key,
    revoke_token,
    revoke_user_tokens,
)
from .config import (
    ADMIN_ROLES,
    CORS_ORIGINS,
    JWT_EXPIRATION_MINUTES,
    MACHINE_ROLE_SCOPES,
    REGISTERED_SERVICES,
)
from .policy import PolicyError, load_policy, policy_snapshot
from .proxy import forward_request
from .quota import check_login_allowed, record_login_failure, record_login_success
from .sdwan import sdwan_router
from .telemetry import read_recent_telemetry, log_gateway_event
from .vault import VaultError, vault

app = FastAPI(
    title="Micro-SASE Enterprise API Gateway",
    version="1.0.0",
    description="Centralized Zero-Trust Reverse Proxy and Policy Enforcement Point (PEP)",
)

app.include_router(oidc.router)

# Explicit origin allow-list (SASE_CORS_ORIGINS); never a wildcard.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
                    "Retry-After", "X-SDWAN-Route", "X-SDWAN-Region", "X-SDWAN-Failover"],
)

# RFC 6749 5.1: responses carrying tokens must not be cached.
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


# --- Request & Response Models ---

# Length caps bound the PBKDF2 work an unauthenticated caller can trigger.
class TokenRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=users.MAX_PASSWORD_LENGTH)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(max_length=4096)


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = Field(default=None, max_length=4096)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(max_length=users.MAX_PASSWORD_LENGTH)
    new_password: str = Field(max_length=users.MAX_PASSWORD_LENGTH)


class CreateUserRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=users.MAX_PASSWORD_LENGTH)
    role: str
    scopes: list[str]


class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    scopes: Optional[list[str]] = None
    disabled: Optional[bool] = None


class SetPasswordRequest(BaseModel):
    password: str = Field(max_length=users.MAX_PASSWORD_LENGTH)


class ApiKeyRequest(BaseModel):
    service_id: str
    role: str = "operator"
    scopes: list[str] = ["read"]


# --- Root & Health ---

@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": "Micro-SASE Enterprise API Gateway",
        "registered_services": list(REGISTERED_SERVICES.keys()),
        "endpoints": {
            "login": "POST /auth/token  {username, password}",
            "sso_login": "GET /auth/sso/login",
            "sso_callback": "GET /auth/sso/callback",
            "sso_session": "POST /auth/sso/session",
            "refresh": "POST /auth/refresh  {refresh_token}",
            "logout": "POST /auth/logout",
            "register_api_key": "POST /auth/register-api-key  (admin only)",
            "proxy": "ANY /proxy/{service_name}/{path}",
            "audit_telemetry": "GET /telemetry/audit  (admin only)",
        },
    }


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "Micro-SASE Gateway PEP"}


# --- Authentication & Identity Management ---

@app.post("/auth/sso/session")
def sso_session(request: Request, response: Response) -> dict[str, Any]:
    """Exchange the one-use, HttpOnly SSO handoff cookie for a gateway session."""
    return _token_response(oidc.consume_session(request, response), response)


@app.post("/auth/token")
def issue_token(req: TokenRequest, request: Request, response: Response) -> dict[str, Any]:
    """Log in with username + password. The role comes from the user directory,
    never from the request body."""
    client_ip = get_client_ip(request)
    try:
        check_login_allowed(client_ip, req.username)
    except HTTPException as e:
        log_gateway_event(
            method="POST", path="/auth/token", target_service="auth",
            status_code=429, decision="DENY", client_ip=client_ip,
            subject=req.username, auth_type="password",
            reason="Login rate limit - too many failed attempts",
        )
        raise e

    user = users.verify_credentials(req.username, req.password)
    if user is None:
        record_login_failure(client_ip, req.username)
        log_gateway_event(
            method="POST", path="/auth/token", target_service="auth",
            status_code=401, decision="DENY", client_ip=client_ip,
            subject=req.username, auth_type="password",
            reason="Invalid username or password",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    record_login_success(client_ip, user.username)
    log_gateway_event(
        method="POST", path="/auth/token", target_service="auth",
        status_code=200, decision="ALLOW", client_ip=client_ip,
        subject=user.username, auth_type="password", role=user.role,
        reason="Login successful - JWT issued",
    )
    return _token_response(user, response)


def _token_response(user: users.User, response: Response) -> dict[str, Any]:
    response.headers.update(NO_STORE)
    return {
        "access_token": create_access_token(subject=user.username, role=user.role, scopes=user.scopes),
        "refresh_token": create_refresh_token(user.username),
        "token_type": "Bearer",
        "expires_in": JWT_EXPIRATION_MINUTES * 60,
        "subject": user.username,
        "role": user.role,
        "scopes": user.scopes,
        "instructions": "Pass as header: 'Authorization: Bearer <access_token>'. "
                        "Exchange refresh_token at POST /auth/refresh before it expires.",
    }


def _auth_event(request: Request, status_code: int, subject: str, reason: str, role: Optional[str] = None) -> None:
    log_gateway_event(
        method=request.method, path=request.url.path, target_service="auth",
        status_code=status_code, decision="ALLOW" if status_code < 400 else "DENY",
        client_ip=get_client_ip(request), subject=subject, auth_type="jwt", role=role, reason=reason,
    )


@app.post("/auth/refresh")
def refresh_session(req: RefreshRequest, request: Request, response: Response) -> dict[str, Any]:
    """Rotate a refresh token: the old one is revoked and a new pair is issued.
    Presenting an already-used refresh token revokes the whole session family."""
    claims = decode_jwt_token(req.refresh_token, expected_type="refresh")
    subject = claims["sub"]
    if is_token_revoked(claims):
        # A rotated token came back: it was stolen or replayed. Kill every session.
        revoke_user_tokens(subject)
        _auth_event(request, 401, subject, "Refresh token reuse detected - all sessions revoked")
        raise HTTPException(status_code=401, detail="Refresh token has been revoked.")
    user = users.get_user(subject)
    if user is None or user.disabled:
        _auth_event(request, 401, subject, "Refresh denied - account missing or disabled")
        raise HTTPException(status_code=401, detail="Account is not active.")
    revoke_token(claims)
    _auth_event(request, 200, subject, "Refresh token rotated", role=user.role)
    return _token_response(user, response)


@app.post("/auth/logout")
def logout(
    request: Request,
    req: Optional[LogoutRequest] = None,
    identity: IdentityContext = Depends(authenticate_request),
) -> dict[str, Any]:
    """Revoke the presented access token (and refresh token, if supplied)."""
    if identity.auth_type != "jwt":
        raise HTTPException(status_code=400, detail="Logout applies to JWT sessions only.")
    revoke_token(identity.token_claims)
    if req and req.refresh_token:
        refresh = decode_jwt_token(req.refresh_token, expected_type="refresh")
        if refresh["sub"] != identity.subject:
            raise HTTPException(status_code=400, detail="Refresh token belongs to another user.")
        revoke_token(refresh)
    _auth_event(request, 200, identity.subject, "Logout - tokens revoked", role=identity.role)
    return {"status": "logged_out"}


@app.post("/auth/change-password")
def change_password(
    req: ChangePasswordRequest,
    request: Request,
    identity: IdentityContext = Depends(authenticate_request),
) -> dict[str, Any]:
    """Change your own password. All existing sessions are revoked."""
    if identity.auth_type != "jwt" or users.verify_credentials(identity.subject, req.current_password) is None:
        _auth_event(request, 403, identity.subject, "Password change denied - wrong current password")
        raise HTTPException(status_code=403, detail="Current password is incorrect.")
    try:
        users.set_password(identity.subject, req.new_password)
    except users.UserError as e:
        raise HTTPException(status_code=400, detail=str(e))
    revoke_user_tokens(identity.subject)
    _auth_event(request, 200, identity.subject, "Password changed - sessions revoked", role=identity.role)
    return {"status": "password_changed", "detail": "Sign in again with the new password."}


@app.post("/auth/revoke/{username}")
def admin_revoke_sessions(username: str, request: Request, admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    """Admin only: invalidate every token issued to a user."""
    revoke_user_tokens(username)
    _audit_admin(admin, request, 200, "auth", f"All sessions revoked for '{username}'")
    return {"revoked": username}


@app.post("/auth/register-api-key")
def generate_api_key(
    req: ApiKeyRequest,
    admin: IdentityContext = Depends(require_admin),
) -> dict[str, Any]:
    """Admin only: generate a universal machine key (stored only as SHA-256 hash)."""
    allowed_scopes = MACHINE_ROLE_SCOPES.get(req.role)
    if allowed_scopes is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported machine role {req.role!r}.",
        )
    requested_scopes = set(req.scopes)
    if not requested_scopes or not requested_scopes.issubset(allowed_scopes):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Scopes for role {req.role!r} must be a non-empty subset of "
                f"{sorted(allowed_scopes)}."
            ),
        )
    raw_key = f"sase_{secrets.token_urlsafe(32)}"
    key_hash = register_api_key(
        raw_key=raw_key,
        service_id=req.service_id,
        role=req.role,
        scopes=req.scopes,
        created_by=admin.subject,
    )
    log_gateway_event(
        method="POST", path="/auth/register-api-key", target_service="auth",
        status_code=200, decision="ALLOW", client_ip=admin.client_ip,
        subject=admin.subject, auth_type=admin.auth_type, role=admin.role,
        reason=f"API key issued for service '{req.service_id}' with role '{req.role}'",
    )
    return {
        "api_key": raw_key,
        "key_sha256": key_hash,
        "service_id": req.service_id,
        "role": req.role,
        "created_by": admin.subject,
        "instructions": "Pass as header: 'X-API-Key: <api_key>'. Save it now - the plaintext key is NOT stored on the server.",
    }


@app.get("/auth/api-keys")
def api_keys_list(admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    """Admin only: list machine key metadata (hashes only)."""
    return {"api_keys": list_api_keys()}


@app.delete("/auth/api-keys/{key_sha256}")
def api_keys_revoke(key_sha256: str, request: Request, admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    """Admin only: revoke a machine key. It stops working immediately."""
    if not revoke_api_key(key_sha256):
        raise HTTPException(status_code=404, detail="No API key with that hash.")
    _audit_admin(admin, request, 200, "auth", f"API key {key_sha256[:12]}... revoked")
    return {"revoked": key_sha256}


@app.get("/auth/services")
def list_services(identity: IdentityContext = Depends(authenticate_request)) -> dict[str, Any]:
    """Registered services. Internal upstream URLs are shown to admins only."""
    if identity.auth_type == "jwt" and identity.role in ADMIN_ROLES:
        return {"services": REGISTERED_SERVICES}
    return {
        "services": {
            name: {"description": svc["description"], "allowed": identity.role in svc["allowed_roles"]}
            for name, svc in REGISTERED_SERVICES.items()
        }
    }


def _audit_admin(admin: IdentityContext, request: Request, status_code: int, target: str, reason: str) -> None:
    log_gateway_event(
        method=request.method, path=request.url.path, target_service=target,
        status_code=status_code, decision="ALLOW" if status_code < 400 else "DENY",
        client_ip=admin.client_ip, subject=admin.subject, auth_type=admin.auth_type,
        role=admin.role, reason=reason,
    )


# --- User Management (admin only) ---

@app.get("/users")
def users_list(admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    return {"users": users.list_users()}


@app.post("/users", status_code=201)
def users_create(req: CreateUserRequest, request: Request, admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    try:
        user = users.create_user(req.username, req.password, req.role, req.scopes)
    except users.UserError as e:
        _audit_admin(admin, request, 400, "users", f"User create rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    _audit_admin(admin, request, 201, "users", f"User '{user.username}' created with role '{user.role}'")
    return user.public()


@app.patch("/users/{username}")
def users_update(username: str, req: UpdateUserRequest, request: Request, admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    try:
        user = users.update_user(username, role=req.role, scopes=req.scopes, disabled=req.disabled)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found.")
    except users.UserError as e:
        _audit_admin(admin, request, 400, "users", f"User update rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    # Old tokens carry the old role/scopes; force re-authentication.
    revoke_user_tokens(username)
    _audit_admin(admin, request, 200, "users",
                 f"User '{username}' updated (role '{user.role}', disabled={user.disabled}); sessions revoked")
    return user.public()


@app.put("/users/{username}/password")
def users_set_password(username: str, req: SetPasswordRequest, request: Request, admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    try:
        users.set_password(username, req.password)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found.")
    except users.UserError as e:
        raise HTTPException(status_code=400, detail=str(e))
    revoke_user_tokens(username)
    _audit_admin(admin, request, 200, "users", f"Password reset for '{username}'; sessions revoked")
    return {"status": "password_reset", "username": username}


@app.delete("/users/{username}")
def users_delete(username: str, request: Request, admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    try:
        users.delete_user(username)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found.")
    except users.UserError as e:
        raise HTTPException(status_code=400, detail=str(e))
    revoke_user_tokens(username)
    _audit_admin(admin, request, 200, "users", f"User '{username}' deleted; sessions revoked")
    return {"deleted": username}


# --- Policy (admin only) ---

@app.get("/policy")
def policy_get(admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    """Admin only: the PBAC rules and QBAC quotas currently in force."""
    return policy_snapshot()


@app.post("/policy/reload")
def policy_reload(request: Request, admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    """Admin only: re-read the policy file. An invalid file is rejected and the
    running policy stays in force."""
    try:
        summary = load_policy()
    except PolicyError as e:
        _audit_admin(admin, request, 400, "policy", f"Policy reload rejected: {e}")
        raise HTTPException(status_code=400, detail=f"Policy not reloaded: {e}")
    _audit_admin(admin, request, 200, "policy", f"Policy reloaded: {summary}")
    return {"status": "reloaded", **summary}


# --- Telemetry & Audit Query ---

@app.get("/telemetry/audit")
def get_audit_logs(
    limit: int = Query(50, ge=1, le=1000),
    admin: IdentityContext = Depends(require_admin),
) -> dict[str, Any]:
    """Admin only: view recent telemetry audit logs produced by the PEP."""
    logs = read_recent_telemetry(limit=limit)
    return {"count": len(logs), "logs": logs}


# --- Credential Vault (Phase 3, admin only) ---

class VaultCredentialRequest(BaseModel):
    header: str = "Authorization"
    prefix: str = ""
    secret: str


def _audit_vault(admin: IdentityContext, method: str, path: str, status_code: int, reason: str) -> None:
    log_gateway_event(
        method=method, path=path, target_service="vault", status_code=status_code,
        decision="ALLOW" if status_code < 400 else "DENY", client_ip=admin.client_ip,
        subject=admin.subject, auth_type=admin.auth_type, role=admin.role, reason=reason,
    )


@app.put("/vault/credentials/{service_name}")
def vault_put(
    service_name: str,
    req: VaultCredentialRequest,
    admin: IdentityContext = Depends(require_admin),
) -> dict[str, Any]:
    """Store or replace the encrypted downstream credential for a service.
    The secret is never returned by any endpoint after this call."""
    path = f"/vault/credentials/{service_name}"
    if service_name not in REGISTERED_SERVICES:
        _audit_vault(admin, "PUT", path, 404, "Vault write for unregistered service")
        raise HTTPException(status_code=404, detail=f"Service '{service_name}' is not registered.")
    try:
        meta = vault.put(service_name, req.header, req.secret, req.prefix, actor=admin.subject)
    except VaultError as e:
        _audit_vault(admin, "PUT", path, 400, f"Vault write rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    _audit_vault(admin, "PUT", path, 200, f"Credential stored (v{meta['version']}, header '{meta['header']}')")
    return meta


@app.get("/vault/credentials")
def vault_list(admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    """List credential metadata. Secrets and ciphertext are never returned."""
    return {"credentials": vault.list(), "current_key_id": vault.current_key_id}


@app.delete("/vault/credentials/{service_name}")
def vault_delete(service_name: str, admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    path = f"/vault/credentials/{service_name}"
    if not vault.delete(service_name):
        raise HTTPException(status_code=404, detail=f"No credential stored for '{service_name}'.")
    _audit_vault(admin, "DELETE", path, 200, "Credential deleted")
    return {"deleted": service_name}


@app.post("/vault/rotate")
def vault_rotate(admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    """Re-encrypt all credentials under the current SASE_VAULT_KEY."""
    try:
        result = vault.rotate()
    except VaultError as e:
        _audit_vault(admin, "POST", "/vault/rotate", 500, f"Key rotation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    _audit_vault(admin, "POST", "/vault/rotate", 200,
                 f"Re-encrypted {result['rotated']}/{result['total']} credentials")
    return result


# --- SD-WAN Virtual Routing & Health Management (Phase 4, admin only) ---

@app.get("/sdwan/status")
def sdwan_status(admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    """Admin only: inspect health, latency, and circuit breaker status of virtual links."""
    return {"status": "ok", "routes": sdwan_router.status()}


@app.post("/sdwan/reset")
def sdwan_reset(admin: IdentityContext = Depends(require_admin)) -> dict[str, Any]:
    """Admin only: reset all circuit breakers and health counters to CLOSED."""
    sdwan_router.reset()
    log_gateway_event(
        method="POST", path="/sdwan/reset", target_service="sdwan",
        status_code=200, decision="ALLOW", client_ip=admin.client_ip,
        subject=admin.subject, auth_type=admin.auth_type, role=admin.role,
        reason="Admin reset all SD-WAN circuit breakers",
    )
    return {"status": "ok", "message": "All SD-WAN circuit breakers reset."}


# --- Zero-Trust Policy Enforcement Point (PEP) Proxy ---

@app.api_route(
    "/proxy/{service_name}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_endpoint_with_path(
    service_name: str,
    path: str,
    request: Request,
    identity: IdentityContext = Depends(authenticate_request),
) -> Response:
    """ZTNA Reverse Proxy entrypoint with full path."""
    return await forward_request(
        request=request,
        service_name=service_name,
        path=path,
        identity=identity,
    )


@app.api_route(
    "/proxy/{service_name}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_endpoint_root(
    service_name: str,
    request: Request,
    identity: IdentityContext = Depends(authenticate_request),
) -> Response:
    """ZTNA Reverse Proxy entrypoint for root service path."""
    return await forward_request(
        request=request,
        service_name=service_name,
        path="",
        identity=identity,
    )
