"""Configuration settings for the Micro-SASE Enterprise API Gateway.

Secrets and file locations can be overridden with environment variables:

    SASE_JWT_SECRET        signing key for JWTs (REQUIRED in production)
    SASE_AUDIT_LOG         path of the JSONL audit log
    SASE_API_KEY_STORE     path of the JSON file holding hashed API keys
"""

from __future__ import annotations

import os
import secrets
import warnings
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
LOGS_DIR = ROOT_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

GATEWAY_AUDIT_LOG = Path(os.environ.get("SASE_AUDIT_LOG", LOGS_DIR / "gateway_audit.jsonl"))
API_KEY_STORE = Path(
    os.environ.get("SASE_API_KEY_STORE", ROOT_DIR / "gateway" / "data" / "api_keys.json")
)

# JWT configuration
_env_secret = os.environ.get("SASE_JWT_SECRET")
if _env_secret:
    JWT_SECRET_KEY = _env_secret
else:
    # Dev fallback: a random per-process secret. Tokens become invalid when the
    # gateway restarts, which is safer than a hardcoded key checked into git.
    JWT_SECRET_KEY = secrets.token_urlsafe(48)
    warnings.warn(
        "SASE_JWT_SECRET not set - using a random per-process JWT secret. "
        "Set SASE_JWT_SECRET for stable tokens across restarts.",
        stacklevel=1,
    )
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

# Only these roles may call admin endpoints (e.g. issuing machine API keys).
ADMIN_ROLES = {"admin"}

# Downstream registered services (Service Discovery / SD-WAN virtual routes)
REGISTERED_SERVICES: dict[str, dict] = {
    "billing": {
        "url": "http://127.0.0.1:8080/mock-service/billing",
        "endpoints": [
            {
                "name": "primary",
                "url": "http://127.0.0.1:8080/mock-service/billing",
                "priority": 1,
                "region": "us-east",
            },
            {
                "name": "secondary",
                "url": "http://127.0.0.1:8080/mock-service/billing-backup",
                "priority": 2,
                "region": "us-west",
            },
        ],
        "allowed_roles": ["admin", "finance", "billing-service"],
        "description": "Enterprise Billing & Invoice Service",
    },
    "inventory": {
        "url": "http://127.0.0.1:8080/mock-service/inventory",
        "endpoints": [
            {
                "name": "primary",
                "url": "http://127.0.0.1:8080/mock-service/inventory",
                "priority": 1,
                "region": "us-east",
            },
            {
                "name": "secondary",
                "url": "http://127.0.0.1:8080/mock-service/inventory-backup",
                "priority": 2,
                "region": "eu-central",
            },
        ],
        "allowed_roles": ["admin", "developer", "inventory-service", "operator"],
        "description": "Warehouse and Resource Inventory API",
    },
    "admin-panel": {
        "url": "http://127.0.0.1:8080/mock-service/admin-panel",
        "endpoints": [
            {
                "name": "primary",
                "url": "http://127.0.0.1:8080/mock-service/admin-panel",
                "priority": 1,
                "region": "us-east",
            },
        ],
        "allowed_roles": ["admin"],
        "description": "Privileged Admin Operations & Configuration",
    },
}
