"""Structured Telemetry and Audit Logging for Micro-SASE Gateway.

Writes JSONL audit events to logs/gateway_audit.jsonl so downstream SIEM
and threat hunting modules can ingest and monitor access patterns in real time.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from collections import deque
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from fastapi import Request, Response

from .config import GATEWAY_AUDIT_LOG

log = logging.getLogger(__name__)

_REQUEST_ID: ContextVar[str | None] = ContextVar("sase_request_id", default=None)
_REQUEST_STARTED: ContextVar[float | None] = ContextVar("sase_request_started", default=None)
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|"
    r"client[_-]?secret|access[_-]?token|refresh[_-]?token|password)\s*[:=]\s*)"
    r"(?:Bearer\s+)?[^\s,;]+"
)
_REDACTED = "<redacted>"
_AUDIT_WRITE_LOCK = threading.Lock()


def _new_request_id(candidate: Optional[str] = None) -> str:
    """Accept a safe upstream correlation ID or create one at the gateway edge."""
    if candidate and _REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate
    return uuid.uuid4().hex


def begin_request(request_id: Optional[str] = None) -> tuple[str, Token, Token]:
    """Bind request correlation and start time for all events in this request."""
    resolved = _new_request_id(request_id)
    return (
        resolved,
        _REQUEST_ID.set(resolved),
        _REQUEST_STARTED.set(time.perf_counter()),
    )


def end_request(tokens: tuple[str, Token, Token]) -> None:
    """Restore the previous context after a request completes."""
    _REQUEST_ID.reset(tokens[1])
    _REQUEST_STARTED.reset(tokens[2])


async def request_context_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Give every gateway request a safe correlation ID and expose it to clients."""
    request_id, *tokens = begin_request(request.headers.get("x-request-id"))
    try:
        response = await call_next(request)
    finally:
        end_request((request_id, tokens[0], tokens[1]))
    response.headers["X-Request-ID"] = request_id
    return response


def current_request_id() -> Optional[str]:
    return _REQUEST_ID.get()


def _clean_text(value: object, default: str, max_length: int = 512) -> str:
    text = str(value) if value is not None else default
    # JSON escapes control characters, but removing them prevents confusing
    # multi-line values in console viewers and downstream log shippers.
    text = "".join(char for char in text if ord(char) >= 32 or char in "\t")
    return text.strip()[:max_length] or default


def _safe_reason(value: object, default: str) -> str:
    reason = _clean_text(value, default)
    reason = re.sub(r"(?i)\bBearer\s+\S+", f"Bearer {_REDACTED}", reason)
    reason = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{_REDACTED}", reason)
    return reason


def _clean_path(path: str) -> str:
    # Callers should already pass a path, but never allow query strings or
    # fragments to become part of the audit record if one slips through.
    return _clean_text(path.split("?", 1)[0].split("#", 1)[0], "/", 2048)


def _outcome(decision: str, status_code: int) -> str:
    if status_code >= 500:
        return "error"
    if status_code == 429:
        return "rate_limited"
    return "allowed" if decision == "ALLOW" and status_code < 400 else "denied"


def _severity(decision: str, status_code: int) -> str:
    if status_code >= 500:
        return "error"
    if decision == "DENY" or status_code >= 400:
        return "warning"
    return "info"


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
    latency_ms: Optional[float] = None,
    reason: Optional[str] = None,
    request_id: Optional[str] = None,
) -> dict:
    """Format and record one structured, correlated gateway audit event."""
    status_code = int(status_code)
    decision = str(decision).upper()
    event_id = uuid.uuid4().hex
    resolved_request_id = request_id or current_request_id() or uuid.uuid4().hex
    started = _REQUEST_STARTED.get()
    measured_latency = (
        (time.perf_counter() - started) * 1000
        if latency_ms is None and started is not None
        else (latency_ms or 0.0)
    )
    default_reason = "Allowed by PEP" if decision == "ALLOW" else "Blocked by PEP"
    event = {
        "schema_version": 1,
        "event_id": event_id,
        "request_id": _clean_text(resolved_request_id, event_id, 128),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event_type": "sase_gateway_access",
        "service": "micro-sase-gateway",
        "decision": decision,
        "status_code": status_code,
        "status_class": f"{status_code // 100}xx",
        "outcome": _outcome(decision, status_code),
        "severity": _severity(decision, status_code),
        "method": _clean_text(method, "UNKNOWN", 16).upper(),
        "path": _clean_path(path),
        "target_service": _clean_text(target_service, "unknown", 128),
        "subject": _clean_text(subject, "anonymous", 128),
        "auth_type": _clean_text(auth_type, "none", 32),
        "role": _clean_text(role, "unauthenticated", 64),
        "client_ip": _clean_text(client_ip, "unknown", 128),
        "latency_ms": round(max(0.0, float(measured_latency)), 2),
        "reason": _safe_reason(reason, default_reason),
    }

    try:
        GATEWAY_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        with _AUDIT_WRITE_LOCK:
            with open(GATEWAY_AUDIT_LOG, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        # Telemetry must never turn a valid gateway response into a 500, but
        # the failure itself should be visible to the process logger.
        log.exception("gateway_audit_write_failed", extra={"event_id": event_id})

    return event


def read_recent_telemetry(limit: int = 50) -> list[dict]:
    """Retrieve the latest telemetry audit logs in reverse order."""
    if limit <= 0 or not GATEWAY_AUDIT_LOG.exists():
        return []

    events: deque[dict] = deque(maxlen=limit)
    try:
        with open(GATEWAY_AUDIT_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("gateway_audit_malformed_line_skipped")
                    continue
                if isinstance(event, dict):
                    events.append(event)
        return list(reversed(events))
    except OSError:
        log.exception("gateway_audit_read_failed")
        return []
