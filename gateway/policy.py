"""Permission-Based Access Control (PBAC) for Micro-SASE Gateway.

RBAC (Phase 1) answers: "may this ROLE talk to this SERVICE at all?"
PBAC (Phase 2) answers: "may this IDENTITY perform THIS METHOD on THIS PATH?"

Each service has an ordered list of permission rules. The first rule whose
methods + path pattern match the request decides which scope is required.
If no rule matches, the request is DENIED (default-deny, zero trust).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from fastapi import HTTPException, status

from .auth import IdentityContext


@dataclass(frozen=True)
class PermissionRule:
    methods: frozenset[str]     # e.g. {"GET", "HEAD"}; {"*"} = any method
    path: str                   # glob relative to the service, e.g. "invoices/*"
    required_scope: str         # scope the identity must hold
    description: str = ""

    def matches(self, method: str, path: str) -> bool:
        method_ok = "*" in self.methods or method.upper() in self.methods
        return method_ok and fnmatch.fnmatchcase(path, self.path)


def _rule(methods: str, path: str, scope: str, desc: str = "") -> PermissionRule:
    return PermissionRule(frozenset(m.strip().upper() for m in methods.split(",")), path, scope, desc)


# Ordered per-service permission tables. Paths are relative to /proxy/{service}/
SERVICE_PERMISSIONS: dict[str, list[PermissionRule]] = {
    "billing": [
        _rule("GET,HEAD", "invoices", "read", "List invoices"),
        _rule("GET,HEAD", "invoices/*", "read", "Read one invoice"),
        _rule("POST", "invoices", "invoice", "Create invoice"),
        _rule("POST,PUT,PATCH", "invoices/*", "invoice", "Modify invoice"),
        _rule("DELETE", "invoices/*", "admin", "Delete invoice"),
    ],
    "inventory": [
        _rule("GET,HEAD", "*", "read", "Read inventory"),
        _rule("POST,PUT,PATCH", "*", "write", "Modify inventory"),
        _rule("DELETE", "*", "admin", "Delete inventory items"),
    ],
    "admin-panel": [
        _rule("*", "*", "admin", "All admin operations"),
    ],
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
