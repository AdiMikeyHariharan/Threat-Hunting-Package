"""Authentication and Zero-Trust Identity Verification for Micro-SASE Gateway.

Supports:
1. Human Authentication: short-lived JWT access tokens + rotating refresh tokens,
   with revocation (logout, per-user revoke, refresh-token reuse detection)
2. Machine Authentication: SHA-256 Hashed Universal API Keys
3. Role-Based Access Control (RBAC) verification
4. Client IP resolution that trusts X-Forwarded-For only from known proxies
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException, Request, status

from . import state
from .config import (
    ADMIN_ROLES,
    API_KEY_STORE,
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_EXPIRATION_MINUTES,
    JWT_ISSUER,
    JWT_SECRET_KEY,
    MACHINE_ROLE_SCOPES,
    REFRESH_TOKEN_EXPIRATION_MINUTES,
    REGISTERED_SERVICES,
    TRUSTED_PROXIES,
)
from .filestore import JsonFileStore
from .telemetry import log_gateway_event


@dataclass
class IdentityContext:
    """Zero-Trust Verified Identity Context passed down to PEP."""
    subject: str               # username or service-id
    auth_type: str             # "jwt" or "api_key"
    role: str                  # e.g., "admin", "developer", "finance", "machine"
    scopes: list[str]          # permissions list
    client_ip: str             # IP of the requester
    token_claims: dict         # raw claims or key metadata


# Store of hashed universal API keys (Machine-to-Machine), persisted to disk.
# Maps SHA-256(raw_key) -> metadata. Plaintext keys are never written anywhere.
_HASHED_API_KEYS: dict[str, dict] = {}


def _load_key_store(data: dict) -> None:
    _HASHED_API_KEYS.clear()
    _HASHED_API_KEYS.update(data)


def _save_key_store() -> None:
    _KEY_STORE.write(_HASHED_API_KEYS)


# Shared by every gateway process on the host, so a revocation applies everywhere.
_KEY_STORE = JsonFileStore(API_KEY_STORE, _load_key_store)
try:
    _KEY_STORE.sync()
except (json.JSONDecodeError, OSError) as e:
    print(f"[auth] Could not load API key store {API_KEY_STORE}: {e}")


def hash_key(raw_key: str) -> str:
    """Compute SHA-256 hash of a raw API key to avoid plaintext storage."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def register_api_key(
    raw_key: str, service_id: str, role: str, scopes: list[str], created_by: str = "system"
) -> str:
    """Register an API key by storing only its SHA-256 hash."""
    hashed = hash_key(raw_key)
    with _KEY_STORE.transaction():
        _HASHED_API_KEYS[hashed] = {
            "service_id": service_id,
            "role": role,
            "scopes": scopes,
            "created_by": created_by,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_key_store()
    return hashed


def list_api_keys() -> list[dict]:
    """Key metadata for admins. Only hashes exist server-side; no secrets returned."""
    _KEY_STORE.sync()
    return [{"key_sha256": h, **meta} for h, meta in _HASHED_API_KEYS.items()]


def revoke_api_key(key_hash: str) -> bool:
    with _KEY_STORE.transaction():
        if _HASHED_API_KEYS.pop(key_hash, None) is None:
            return False
        _save_key_store()
    return True


# --- Client IP ---------------------------------------------------------------

def _is_trusted_proxy(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in TRUSTED_PROXIES)


def get_client_ip(request: Request) -> str:
    """The real client IP. X-Forwarded-For is honoured only when the direct peer
    is a trusted proxy; it is read right-to-left, skipping trusted hops, so a
    client cannot spoof its address by sending its own X-Forwarded-For."""
    peer = request.client.host if request.client else "unknown"
    if not _is_trusted_proxy(peer):
        return peer
    hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    for hop in reversed(hops):
        if not _is_trusted_proxy(hop):
            try:
                return str(ipaddress.ip_address(hop))
            except ValueError:
                return peer
    return hops[0] if hops else peer


# --- JWTs --------------------------------------------------------------------

def _issue(subject: str, token_type: str, lifetime_minutes: int, extra: dict) -> str:
    now = time.time()
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": subject,
        "typ": token_type,
        "jti": uuid.uuid4().hex,
        # Fractional iat so a revocation never spares tokens from the same second.
        "iat": now,
        "exp": int(now + lifetime_minutes * 60),
        **extra,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_access_token(subject: str, role: str, scopes: Optional[list[str]] = None) -> str:
    """Generate a short-lived signed JWT access token for a human user."""
    return _issue(subject, "access", JWT_EXPIRATION_MINUTES, {"role": role, "scopes": scopes or ["read"]})


def create_refresh_token(subject: str) -> str:
    """Generate a refresh token. It carries no role: refresh re-reads the user directory."""
    return _issue(subject, "refresh", REFRESH_TOKEN_EXPIRATION_MINUTES, {})


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def decode_jwt_token(token: str, expected_type: str = "access") -> dict:
    """Verify signature, standard claims and token type. Does NOT check revocation."""
    try:
        claims = jwt.decode(
            token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE, issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "jti", "iss", "aud", "typ"]},
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token has expired. Please re-authenticate.")
    except jwt.InvalidTokenError:
        raise _unauthorized("Invalid JWT token signature or format.")
    if claims.get("typ") != expected_type:
        raise _unauthorized(f"Expected a {expected_type} token.")
    return claims


def is_token_revoked(claims: dict) -> bool:
    if state.store.get(f"revoked-jti:{claims['jti']}") is not None:
        return True
    revoked_before = state.store.get(f"revoked-before:{claims['sub']}")
    return revoked_before is not None and float(claims["iat"]) <= float(revoked_before)


def verify_jwt_token(token: str, expected_type: str = "access") -> dict:
    """Verify and decode a signed JWT, rejecting revoked tokens."""
    claims = decode_jwt_token(token, expected_type)
    if is_token_revoked(claims):
        raise _unauthorized("Token has been revoked. Please re-authenticate.")
    return claims


def revoke_token(claims: dict) -> None:
    """Deny-list one token until it would have expired anyway."""
    ttl = max(1.0, float(claims["exp"]) - time.time())
    state.store.set(f"revoked-jti:{claims['jti']}", "1", ttl)


def revoke_user_tokens(subject: str) -> None:
    """Invalidate every token issued to `subject` up to now (password change,
    role change, disable/delete, refresh-token reuse)."""
    state.store.set(
        f"revoked-before:{subject}", repr(time.time()), REFRESH_TOKEN_EXPIRATION_MINUTES * 60
    )


def authenticate_request(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> IdentityContext:
    """Policy Enforcement Point (PEP) Identity Extractor.

    Authenticates the request using either:
      1. Bearer JWT (Human/Developer)
      2. X-API-Key (Machine/Universal Key)
    """
    client_ip = get_client_ip(request)

    # Option A: Machine Universal Key Authentication
    if x_api_key:
        key_hash = hash_key(x_api_key.strip())
        _KEY_STORE.sync()
        key_data = _HASHED_API_KEYS.get(key_hash)
        if not key_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Universal API Key.",
            )
        if key_data.get("role") not in MACHINE_ROLE_SCOPES:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has an invalid or deprecated machine role.",
            )
        scopes = key_data.get("scopes")
        allowed_scopes = MACHINE_ROLE_SCOPES[key_data["role"]]
        if (
            not isinstance(scopes, list)
            or not scopes
            or not all(isinstance(scope, str) for scope in scopes)
            or not set(scopes).issubset(allowed_scopes)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has invalid or deprecated machine scopes.",
            )
        return IdentityContext(
            subject=key_data["service_id"],
            auth_type="api_key",
            role=key_data["role"],
            scopes=scopes,
            client_ip=client_ip,
            token_claims=key_data,
        )

    # Option B: Bearer JWT Authentication
    if authorization:
        parts = authorization.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header must follow: 'Bearer <token>'",
            )
        token = parts[1]
        claims = verify_jwt_token(token)
        return IdentityContext(
            subject=claims.get("sub", "anonymous"),
            auth_type="jwt",
            role=claims.get("role", "guest"),
            scopes=claims.get("scopes", []),
            client_ip=client_ip,
            token_claims=claims,
        )

    # Neither provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Zero-Trust Authentication required. Provide Bearer JWT in Authorization header or X-API-Key.",
    )


def require_admin(
    request: Request,
    identity: IdentityContext = Depends(authenticate_request),
) -> IdentityContext:
    """Dependency for admin-only endpoints (e.g. issuing machine API keys)."""
    if identity.auth_type != "jwt" or identity.role not in ADMIN_ROLES:
        detail = f"Admin role required. Your role: '{identity.role}'."
        log_gateway_event(
            method=request.method, path=request.url.path, target_service="admin-api",
            status_code=403, decision="DENY", client_ip=identity.client_ip,
            subject=identity.subject, auth_type=identity.auth_type, role=identity.role,
            reason=detail,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
    return identity


def enforce_rbac(identity: IdentityContext, service_name: str) -> None:
    """Enforces Role-Based Access Control against the target service."""
    service = REGISTERED_SERVICES.get(service_name)
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_name}' is not registered in the SASE gateway routing table.",
        )

    allowed_roles = service.get("allowed_roles", [])
    if identity.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied by PEP: Role '{identity.role}' does not have permission to access service '{service_name}'. Allowed roles: {allowed_roles}",
        )
