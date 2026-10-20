"""Permission-Based Access Control (PBAC) for Micro-SASE Gateway.

RBAC (Phase 1) answers: "may this ROLE talk to this SERVICE at all?"
PBAC (Phase 2) answers: "may this IDENTITY perform THIS METHOD on THIS PATH?"

Each service has an ordered list of permission rules. The first rule whose
methods + path pattern match the request decides which scope is required.
If no rule matches, the request is DENIED (default-deny, zero trust).

Rules and QBAC quotas are loaded from the YAML policy file (SASE_POLICY_FILE,
default gateway/policy.yml) and can be reloaded at runtime by an admin.
"""

from __future__ import annotations

import fnmatch
import threading
from dataclasses import dataclass
from pathlib import Path

import yaml
from fastapi import HTTPException, status

from . import quota
from .auth import IdentityContext
from .config import POLICY_FILE, REGISTERED_SERVICES

_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "*"}


class PolicyError(Exception):
    """Raised when the policy file is missing or invalid."""


@dataclass(frozen=True)
class PermissionRule:
    methods: frozenset[str]     # e.g. {"GET", "HEAD"}; {"*"} = any method
    path: str                   # glob relative to the service, e.g. "invoices/*"
    required_scope: str         # scope the identity must hold
    description: str = ""

    def matches(self, method: str, path: str) -> bool:
        method_ok = "*" in self.methods or method.upper() in self.methods
        return method_ok and fnmatch.fnmatchcase(path, self.path)


# Ordered per-service permission tables, populated by load_policy().
SERVICE_PERMISSIONS: dict[str, list[PermissionRule]] = {}
_reload_lock = threading.Lock()


def _parse_quota(name: str, raw) -> "quota.QuotaPolicy":
    if not isinstance(raw, dict):
        raise PolicyError(f"quota {name!r} must be a mapping")
    try:
        policy = quota.QuotaPolicy(
            burst=int(raw["burst"]),
            refill_per_sec=float(raw["refill_per_sec"]),
            window_limit=int(raw["window_limit"]),
            window_seconds=int(raw["window_seconds"]),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise PolicyError(f"quota {name!r} is invalid: {e}") from e
    if min(policy.burst, policy.refill_per_sec, policy.window_limit, policy.window_seconds) <= 0:
        raise PolicyError(f"quota {name!r} values must be positive")
    return policy


def parse_policy(doc) -> tuple[dict, dict, "quota.QuotaPolicy"]:
    """Validate a policy document. Returns (permissions, role_quotas, default_quota)."""
    if not isinstance(doc, dict):
        raise PolicyError("policy must be a mapping with 'services' and 'quotas'")
    services = doc.get("services")
    if not isinstance(services, dict):
        raise PolicyError("'services' must be a mapping")
    permissions: dict[str, list[PermissionRule]] = {}
    for service, rules in services.items():
        if service not in REGISTERED_SERVICES:
            raise PolicyError(f"service {service!r} is not registered")
        if not isinstance(rules, list):
            raise PolicyError(f"rules for {service!r} must be a list")
        parsed = []
        for i, r in enumerate(rules):
            where = f"{service}[{i}]"
            if not isinstance(r, dict):
                raise PolicyError(f"{where} must be a mapping")
            methods, path, scope = r.get("methods"), r.get("path"), r.get("scope")
            if not isinstance(methods, list) or not methods:
                raise PolicyError(f"{where}.methods must be a non-empty list")
            methods = {str(m).upper() for m in methods}
            if not methods <= _HTTP_METHODS:
                raise PolicyError(f"{where}.methods has unknown method(s) {sorted(methods - _HTTP_METHODS)}")
            if not isinstance(path, str) or not isinstance(scope, str) or not scope:
                raise PolicyError(f"{where} needs string 'path' and 'scope'")
            parsed.append(PermissionRule(frozenset(methods), path, scope, str(r.get("description", ""))))
        permissions[service] = parsed

    quotas = doc.get("quotas")
    if not isinstance(quotas, dict) or not isinstance(quotas.get("roles", {}), dict):
        raise PolicyError("'quotas' must be a mapping with 'default' and 'roles'")
    default = _parse_quota("default", quotas.get("default"))
    roles = {role: _parse_quota(role, q) for role, q in quotas.get("roles", {}).items()}
    return permissions, roles, default


def load_policy(path: Path | None = None) -> dict:
    """Load and apply the policy file. On any error the running policy is kept."""
    path = Path(path or POLICY_FILE)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise PolicyError(f"cannot read policy file {path}: {e}") from e
    permissions, roles, default = parse_policy(doc)
    with _reload_lock:
        # Mutate in place so modules holding a reference see the new policy.
        SERVICE_PERMISSIONS.clear()
        SERVICE_PERMISSIONS.update(permissions)
        quota.ROLE_QUOTAS.clear()
        quota.ROLE_QUOTAS.update(roles)
        quota.DEFAULT_QUOTA = default
    return {"services": len(permissions), "rules": sum(map(len, permissions.values())), "roles": len(roles)}


def policy_snapshot() -> dict:
    """Current policy in the same shape as the policy file."""
    return {
        "services": {
            svc: [
                {"methods": sorted(r.methods), "path": r.path, "scope": r.required_scope,
                 "description": r.description}
                for r in rules
            ]
            for svc, rules in SERVICE_PERMISSIONS.items()
        },
        "quotas": {
            "default": vars(quota.DEFAULT_QUOTA),
            "roles": {role: vars(q) for role, q in quota.ROLE_QUOTAS.items()},
        },
    }


def find_rule(service_name: str, method: str, path: str) -> PermissionRule | None:
    path = path.strip("/")
    for rule in SERVICE_PERMISSIONS.get(service_name, []):
        if rule.matches(method, path):
            return rule
    return None


def enforce_pbac(identity: IdentityContext, service_name: str, method: str, path: str) -> PermissionRule:
    """Raise 403 unless a rule matches AND the identity holds its required scope."""
    rule = find_rule(service_name, method, path)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"PBAC default-deny: no permission rule allows {method} /{path.strip('/')} on '{service_name}'.",
        )
    if rule.required_scope not in identity.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"PBAC: {method} /{path.strip('/')} on '{service_name}' requires scope "
                f"'{rule.required_scope}'. Your scopes: {identity.scopes}"
            ),
        )
    return rule


# Fail closed: the gateway does not start with a missing or invalid policy.
load_policy()
