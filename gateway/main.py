"""FastAPI Entrypoint for Micro-SASE Enterprise API Gateway.

Run with:
    uvicorn gateway.main:app --port 8080 --reload
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .auth import (
    IdentityContext,
    authenticate_request,
    create_access_token,
    register_api_key,
    require_admin,
)
from .config import REGISTERED_SERVICES
from .proxy import forward_request, require_internal_caller
from .quota import check_login_allowed, record_login_failure
from .sdwan import sdwan_router
from .telemetry import read_recent_telemetry, log_gateway_event
from .users import verify_credentials
from .vault import VaultError, vault

app = FastAPI(
    title="Micro-SASE Enterprise API Gateway",
    version="1.0.0",
    description="Centralized Zero-Trust Reverse Proxy and Policy Enforcement Point (PEP)",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Request & Response Models ---

class TokenRequest(BaseModel):
    username: str
    password: str


class ApiKeyRequest(BaseModel):
    service_id: str
    role: str = "machine"
    scopes: list[str] = ["read"]


# --- Root & Health ---

@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": "Micro-SASE Enterprise API Gateway",
        "phase": "Phase 1 - Core Ingress, ZTNA Authentication & Reverse Proxy PEP",
        "registered_services": list(REGISTERED_SERVICES.keys()),
        "endpoints": {
            "login": "POST /auth/token  {username, password}",
            "register_api_key": "POST /auth/register-api-key  (admin only)",
            "proxy": "ANY /proxy/{service_name}/{path}",
            "audit_telemetry": "GET /telemetry/audit  (admin only)",
        },
    }


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "Micro-SASE Gateway PEP"}


# --- Authentication & Identity Management ---

@app.post("/auth/token")
def issue_token(req: TokenRequest, request: Request) -> dict[str, Any]:
    """Log in with username + password. The role comes from the user directory,
    never from the request body."""
    client_ip = request.client.host if request.client else "unknown"
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

    user = verify_credentials(req.username, req.password)
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

    token = create_access_token(subject=user.username, role=user.role, scopes=user.scopes)
    log_gateway_event(
        method="POST", path="/auth/token", target_service="auth",
        status_code=200, decision="ALLOW", client_ip=client_ip,
        subject=user.username, auth_type="password", role=user.role,
        reason="Login successful - JWT issued",
    )
    return {
        "access_token": token,
        "token_type": "Bearer",
        "subject": user.username,
        "role": user.role,
        "scopes": user.scopes,
        "instructions": "Pass as header: 'Authorization: Bearer <access_token>'",
    }


@app.post("/auth/register-api-key")
def generate_api_key(
    req: ApiKeyRequest,
    admin: IdentityContext = Depends(require_admin),
) -> dict[str, Any]:
    """Admin only: generate a universal machine key (stored only as SHA-256 hash)."""
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


@app.get("/auth/services")
def list_services(identity: IdentityContext = Depends(authenticate_request)) -> dict[str, Any]:
    """Inspect registered downstream services and their RBAC requirements (authenticated)."""
    return {"services": REGISTERED_SERVICES}


# --- Telemetry & Audit Query ---

@app.get("/telemetry/audit")
def get_audit_logs(
    limit: int = 50,
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


# --- Built-in Mock Downstream Services (Simulates fragmenting microservices) ---

def _credential_fingerprint(request: Request, header: str) -> dict[str, Any]:
    """What a real backend would verify. Returns only a hash prefix, never the value."""
    value = request.headers.get(header)
    return {
        "header": header,
        "received": value is not None,
        "sha256_prefix": hashlib.sha256(value.encode()).hexdigest()[:12] if value else None,
    }


@app.api_route("/mock-service/billing/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], dependencies=[Depends(require_internal_caller)])
def mock_billing(request: Request, path: str = "") -> dict[str, Any]:
    """Mock downstream billing service (expects a vault-injected Authorization header)."""
    return {
        "downstream_service": "Billing Service",
        "status": "success",
        "path_received": path,
        "upstream_credential": _credential_fingerprint(request, "Authorization"),
        "verified_headers_from_gateway": {
            "x-sase-subject": request.headers.get("x-sase-subject"),
            "x-sase-role": request.headers.get("x-sase-role"),
            "x-sase-auth-type": request.headers.get("x-sase-auth-type"),
            "x-sase-client-ip": request.headers.get("x-sase-client-ip"),
        },
        "payload": {
            "invoices": [
                {"id": "INV-1001", "amount": "$4,500.00", "status": "PAID"},
                {"id": "INV-1002", "amount": "$1,250.00", "status": "PENDING"},
            ]
        },
    }


@app.api_route("/mock-service/inventory/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], dependencies=[Depends(require_internal_caller)])
def mock_inventory(request: Request, path: str = "") -> dict[str, Any]:
    """Mock downstream inventory service."""
    return {
        "downstream_service": "Inventory Service",
        "status": "success",
        "path_received": path,
        "verified_headers_from_gateway": {
            "x-sase-subject": request.headers.get("x-sase-subject"),
            "x-sase-role": request.headers.get("x-sase-role"),
            "x-sase-auth-type": request.headers.get("x-sase-auth-type"),
        },
        "payload": {
            "items": [
                {"sku": "SRV-BLADE-01", "stock": 42, "location": "US-East-Rack3"},
                {"sku": "FW-APPLIANCE-10", "stock": 7, "location": "EU-Central-Rack1"},
            ]
        },
    }


@app.api_route("/mock-service/admin-panel/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], dependencies=[Depends(require_internal_caller)])
def mock_admin(request: Request, path: str = "") -> dict[str, Any]:
    """Mock downstream admin panel."""
    return {
        "downstream_service": "Admin Privileged Operations",
        "status": "success",
        "path_received": path,
        "verified_headers_from_gateway": {
            "x-sase-subject": request.headers.get("x-sase-subject"),
            "x-sase-role": request.headers.get("x-sase-role"),
        },
        "payload": {
            "system_status": "NORMAL",
            "cluster_nodes": 8,
            "secret_firewall_rules": "DROP ALL EXCEPT SASE-PEP",
        },
    }


# --- Secondary SD-WAN Failover Mock Backends ---

@app.api_route("/mock-service/billing-backup/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], dependencies=[Depends(require_internal_caller)])
def mock_billing_backup(request: Request, path: str = "") -> dict[str, Any]:
    """Mock secondary backup billing service (US-West Region failover)."""
    return {
        "downstream_service": "Billing Service (Secondary Backup Route)",
        "region": "us-west",
        "status": "success",
        "path_received": path,
        "verified_headers_from_gateway": {
            "x-sase-subject": request.headers.get("x-sase-subject"),
            "x-sase-role": request.headers.get("x-sase-role"),
            "x-sase-auth-type": request.headers.get("x-sase-auth-type"),
        },
        "payload": {
            "invoices": [
                {"id": "INV-1001", "amount": "$4,500.00", "status": "PAID"},
                {"id": "INV-1002", "amount": "$1,250.00", "status": "PENDING"},
            ],
            "backup_route_active": True,
        },
    }


@app.api_route("/mock-service/inventory-backup/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], dependencies=[Depends(require_internal_caller)])
def mock_inventory_backup(request: Request, path: str = "") -> dict[str, Any]:
    """Mock secondary backup inventory service (EU-Central Region failover)."""
    return {
        "downstream_service": "Inventory Service (Secondary Backup Route)",
        "region": "eu-central",
        "status": "success",
        "path_received": path,
        "verified_headers_from_gateway": {
            "x-sase-subject": request.headers.get("x-sase-subject"),
            "x-sase-role": request.headers.get("x-sase-role"),
        },
        "payload": {
            "items": [
                {"sku": "SRV-BLADE-01", "stock": 42, "location": "EU-Central-Rack1"},
            ],
            "backup_route_active": True,
        },
    }
