"""Configuration settings for the Micro-SASE Enterprise API Gateway.

Secrets and file locations can be overridden with environment variables:

    SASE_JWT_SECRET        signing key for JWTs (REQUIRED in production, >= 32 bytes)
    SASE_AUDIT_LOG         path of the JSONL audit log
    SASE_API_KEY_STORE     path of the JSON file holding hashed API keys
    SASE_USER_STORE        path of the JSON file holding the user directory
    SASE_POLICY_FILE       YAML file with PBAC rules and QBAC quotas
    SASE_REDIS_URL         Redis URL for shared limiter / revocation state
                           (unset = in-memory, single process)
    SASE_INTERNAL_TOKEN    shared secret between gateway and backends (REQUIRED
                           when backends run as a separate process)
    SASE_BACKEND_URL       base URL of the mock backend service
    SASE_TRUSTED_PROXIES   comma-separated IPs/CIDRs whose X-Forwarded-For is trusted
    SASE_CORS_ORIGINS      comma-separated browser origins allowed by CORS
"""

from __future__ import annotations

import ipaddress
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
USER_STORE = Path(os.environ.get("SASE_USER_STORE", ROOT_DIR / "gateway" / "data" / "users.json"))
POLICY_FILE = Path(os.environ.get("SASE_POLICY_FILE", ROOT_DIR / "gateway" / "policy.yml"))
REDIS_URL = os.environ.get("SASE_REDIS_URL", "")

# JWT configuration
_env_secret = os.environ.get("SASE_JWT_SECRET")
if _env_secret:
    # RFC 7518 3.2: an HS256 key must be at least as long as the hash output.
    if len(_env_secret.encode("utf-8")) < 32:
        raise RuntimeError("SASE_JWT_SECRET must be at least 32 bytes long.")
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
JWT_ISSUER = "micro-sase-gateway"
JWT_AUDIENCE = "micro-sase"
# Access tokens are short-lived; sessions continue via rotating refresh tokens.
JWT_EXPIRATION_MINUTES = 15
REFRESH_TOKEN_EXPIRATION_MINUTES = 8 * 60

# Shared secret between the gateway and its backends. Backends reject any
# request without it, so they can't be reached by skipping the PEP.
_env_internal = os.environ.get("SASE_INTERNAL_TOKEN")
if _env_internal:
    INTERNAL_GATEWAY_TOKEN = _env_internal
else:
    # Only works when backends run in the same process (tests, demo script).
    INTERNAL_GATEWAY_TOKEN = secrets.token_urlsafe(32)
    warnings.warn(
        "SASE_INTERNAL_TOKEN not set - using a random per-process token. Set the same "
        "value for the gateway and gateway.mock_backends when they run separately.",
        stacklevel=1,
    )

# Only these proxies may tell us the real client IP via X-Forwarded-For.
TRUSTED_PROXIES = [
    ipaddress.ip_network(p.strip(), strict=False)
    for p in os.environ.get("SASE_TRUSTED_PROXIES", "").split(",")
    if p.strip()
]

CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "SASE_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if o.strip()
]

# Only these roles may call admin endpoints (e.g. issuing machine API keys).
ADMIN_ROLES = {"admin"}

# Human roles and the maximum scopes an admin may grant each of them.
HUMAN_ROLE_SCOPES: dict[str, set[str]] = {
    "admin": {"read", "write", "invoice", "admin"},
    "developer": {"read", "write"},
    "finance": {"read", "invoice"},
}

# API keys are service identities, not substitutes for human administrator
# sessions.  Keep the roles and maximum scopes server-controlled so the key
# registration endpoint cannot mint a permanent human/admin credential.
MACHINE_ROLE_SCOPES: dict[str, set[str]] = {
    "billing-service": {"read", "invoice"},
    "inventory-service": {"read", "write"},
    "operator": {"read", "write"},
}

# Mock backends run as their own process (uvicorn gateway.mock_backends:app --port 8081).
BACKEND_URL = os.environ.get("SASE_BACKEND_URL", "http://127.0.0.1:8081").rstrip("/")

# Downstream registered services (Service Discovery / SD-WAN virtual routes)
REGISTERED_SERVICES: dict[str, dict] = {
    "billing": {
        "url": f"{BACKEND_URL}/mock-service/billing",
        "endpoints": [
            {
                "name": "primary",
                "url": f"{BACKEND_URL}/mock-service/billing",
                "priority": 1,
                "region": "us-east",
            },
            {
                "name": "secondary",
                "url": f"{BACKEND_URL}/mock-service/billing-backup",
                "priority": 2,
                "region": "us-west",
            },
        ],
        "allowed_roles": ["admin", "finance", "billing-service"],
        "description": "Enterprise Billing & Invoice Service",
    },
    "inventory": {
        "url": f"{BACKEND_URL}/mock-service/inventory",
        "endpoints": [
            {
                "name": "primary",
                "url": f"{BACKEND_URL}/mock-service/inventory",
                "priority": 1,
                "region": "us-east",
            },
            {
                "name": "secondary",
                "url": f"{BACKEND_URL}/mock-service/inventory-backup",
                "priority": 2,
                "region": "eu-central",
            },
        ],
        "allowed_roles": ["admin", "developer", "inventory-service", "operator"],
        "description": "Warehouse and Resource Inventory API",
    },
    "admin-panel": {
        "url": f"{BACKEND_URL}/mock-service/admin-panel",
        "endpoints": [
            {
                "name": "primary",
                "url": f"{BACKEND_URL}/mock-service/admin-panel",
                "priority": 1,
                "region": "us-east",
            },
        ],
        "allowed_roles": ["admin"],
        "description": "Privileged Admin Operations & Configuration",
    },
}
