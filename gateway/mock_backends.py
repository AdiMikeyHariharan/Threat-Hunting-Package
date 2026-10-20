"""Mock downstream microservices for the Micro-SASE gateway demo.

These run as their own process, separate from the gateway, so requests make a
real network hop:

    export SASE_INTERNAL_TOKEN="<same value as the gateway>"
    uvicorn gateway.mock_backends:app --port 8081

Every route requires the internal gateway token, so the services can only be
reached through the PEP. Direct calls are rejected and logged as bypass attempts.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status

from .config import INTERNAL_GATEWAY_TOKEN
from .telemetry import log_gateway_event


def require_internal_caller(
    request: Request,
    x_sase_internal: Optional[str] = Header(None),
) -> None:
    """Dependency for backend routes: only accept traffic forwarded by the PEP."""
    if not x_sase_internal or not hmac.compare_digest(x_sase_internal, INTERNAL_GATEWAY_TOKEN):
        detail = "Direct access to backend services is not allowed. Go through /proxy/."
        log_gateway_event(
            method=request.method, path=request.url.path, target_service="backend-direct",
            status_code=403, decision="DENY",
            client_ip=request.client.host if request.client else "unknown",
            reason="PEP bypass attempt - " + detail,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


app = FastAPI(
    title="Micro-SASE Mock Backends",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


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
