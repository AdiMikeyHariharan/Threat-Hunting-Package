"""Structured Telemetry and Audit Logging for Micro-SASE Gateway.

Writes JSONL audit events to logs/gateway_audit.jsonl so downstream SIEM
and threat hunting modules can ingest and monitor access patterns in real time.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .config import GATEWAY_AUDIT_LOG


def log_gateway_event(
    method: str,
    path: str,
    target_service: str,
    status_code: int,
    decision: str,  # "ALLOW" or "DENY"
    client_ip: str,
    subject: Optional[str] = None,
    auth_type: Optional[str] = None,
    role: Optional[str] = None,
    latency_ms: float = 0.0,
    reason: Optional[str] = None,
) -> dict:
    """Format and record a structured audit event."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "sase_gateway_access",
        "decision": decision,
        "status_code": status_code,
        "method": method,
        "path": path,
        "target_service": target_service,
        "subject": subject or "anonymous",
        "auth_type": auth_type or "none",
        "role": role or "unauthenticated",
        "client_ip": client_ip,
        "latency_ms": round(latency_ms, 2),
        "reason": reason or ("Allowed by PEP" if decision == "ALLOW" else "Blocked by PEP"),
    }

    try:
        with open(GATEWAY_AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        print(f"[telemetry_error] Failed to write audit event: {e}")

    return event


def read_recent_telemetry(limit: int = 50) -> list[dict]:
    """Retrieve the latest telemetry audit logs in reverse order."""
    if not GATEWAY_AUDIT_LOG.exists():
        return []

    lines = []
    try:
        with open(GATEWAY_AUDIT_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(json.loads(line))
        return lines[-limit:][::-1]
    except Exception:
        return []
