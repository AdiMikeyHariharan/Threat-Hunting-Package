"""Authentication and Zero-Trust Identity Verification for Micro-SASE Gateway.

Supports:
1. Human Authentication: OAuth2 / JWT verification and claims extraction
2. Machine Authentication: SHA-256 Hashed Universal API Keys
3. Role-Based Access Control (RBAC) verification
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException, Request, status

from .config import (
    ADMIN_ROLES,
    API_KEY_STORE,
    JWT_ALGORITHM,
    JWT_EXPIRATION_MINUTES,
    JWT_SECRET_KEY,
    REGISTERED_SERVICES,
)
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
_KEY_LOCK = threading.Lock()


def _load_key_store() -> None:
    if API_KEY_STORE.exists():
        try:
            _HASHED_API_KEYS.update(json.loads(API_KEY_STORE.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError) as e:
            print(f"[auth] Could not load API key store {API_KEY_STORE}: {e}")


def _save_key_store() -> None:
    API_KEY_STORE.parent.mkdir(parents=True, exist_ok=True)
    tmp = API_KEY_STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(_HASHED_API_KEYS, indent=2), encoding="utf-8")
    tmp.replace(API_KEY_STORE)  # atomic swap so a crash can't corrupt the store


_load_key_store()


def hash_key(raw_key: str) -> str:
    """Compute SHA-256 hash of a raw API key to avoid plaintext storage."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def register_api_key(
    raw_key: str, service_id: str, role: str, scopes: list[str], created_by: str = "system"
) -> str:
    """Register an API key by storing only its SHA-256 hash."""
    hashed = hash_key(raw_key)
    with _KEY_LOCK:
        _HASHED_API_KEYS[hashed] = {
            "service_id": service_id,
            "role": role,
            "scopes": scopes,
            "created_by": created_by,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_key_store()
    return hashed


def create_access_token(subject: str, role: str, scopes: Optional[list[str]] = None) -> str:
    """Generate a signed JWT token for user/developer authentication."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "scopes": scopes or ["read"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRATION_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> dict:
    """Verify and decode a signed JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please re-authenticate.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT token signature or format.",
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
    client_ip = request.client.host if request.client else "unknown"

    # Option A: Machine Universal Key Authentication
    if x_api_key:
        key_hash = hash_key(x_api_key.strip())
        key_data = _HASHED_API_KEYS.get(key_hash)
        if not key_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Universal API Key.",
            )
        return IdentityContext(
            subject=key_data["service_id"],
            auth_type="api_key",
            role=key_data["role"],
            scopes=key_data["scopes"],
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
    if identity.role not in ADMIN_ROLES:
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
