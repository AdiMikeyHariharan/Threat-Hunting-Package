"""Quota-Based Access Control (QBAC) and rate limiting for Micro-SASE Gateway.

Two independent limits are applied to every proxied request, keyed by
(identity, service):

1. Burst rate  - token bucket. Smooths spikes ("max N requests, refilling at
                 R per second"). Stops scripts hammering a service.
2. Usage quota - fixed window. Hard cap on total requests per window (e.g.
                 per hour). Stops slow, sustained over-usage.

A separate limiter protects /auth/token against password guessing, keyed by
client IP and by username (so rotating IPs against one account still trips it).

State is in-memory and per-process. For multiple gateway replicas this would
move to Redis; the interface stays the same.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass

from fastapi import HTTPException, status

from .auth import IdentityContext


@dataclass(frozen=True)
class QuotaPolicy:
    burst: int              # token bucket capacity
    refill_per_sec: float   # tokens added per second
    window_limit: int       # max requests per window
    window_seconds: int     # window length


# Per-role policies. Machines get more headroom than humans; unknown roles get the least.
ROLE_QUOTAS: dict[str, QuotaPolicy] = {
    "admin":             QuotaPolicy(burst=50, refill_per_sec=10.0, window_limit=5000, window_seconds=3600),
    "developer":         QuotaPolicy(burst=20, refill_per_sec=5.0,  window_limit=1000, window_seconds=3600),
    "finance":           QuotaPolicy(burst=20, refill_per_sec=5.0,  window_limit=1000, window_seconds=3600),
    "operator":          QuotaPolicy(burst=20, refill_per_sec=5.0,  window_limit=1000, window_seconds=3600),
    "billing-service":   QuotaPolicy(burst=100, refill_per_sec=20.0, window_limit=20000, window_seconds=3600),
    "inventory-service": QuotaPolicy(burst=100, refill_per_sec=20.0, window_limit=20000, window_seconds=3600),
}
DEFAULT_QUOTA = QuotaPolicy(burst=10, refill_per_sec=1.0, window_limit=200, window_seconds=3600)

# Login protection: attempts allowed per window, per IP and per username.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60


def _now() -> float:
    """Clock indirection so tests can control time."""
    return time.monotonic()


_lock = threading.Lock()
_buckets: dict[tuple, list[float]] = {}           # key -> [tokens, last_refill]
_windows: dict[tuple, list[float]] = {}           # key -> [window_start, count]


def reset() -> None:
    """Clear all limiter state (used by tests)."""
    with _lock:
        _buckets.clear()
        _windows.clear()


def _take_token(key: tuple, burst: int, refill: float) -> float:
    """Try to consume one token. Returns 0 if allowed, else seconds until a token is available."""
    now = _now()
    tokens, last = _buckets.get(key, [float(burst), now])
    tokens = min(float(burst), tokens + (now - last) * refill)
    if tokens >= 1.0:
        _buckets[key] = [tokens - 1.0, now]
        return 0.0
    _buckets[key] = [tokens, now]
    return (1.0 - tokens) / refill if refill > 0 else float("inf")


def _count_in_window(key: tuple, limit: int, window: int) -> tuple[int, float]:
    """Increment the window counter. Returns (remaining, seconds_until_reset); remaining < 0 = over quota."""
    now = _now()
    start, count = _windows.get(key, [now, 0])
    if now - start >= window:
        start, count = now, 0
    count += 1
    _windows[key] = [start, count]
    return limit - count, window - (now - start)


def _too_many(detail: str, retry_after: float, headers: dict[str, str] | None = None) -> HTTPException:
    h = {"Retry-After": str(max(1, math.ceil(retry_after)))}
    h.update(headers or {})
    return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail, headers=h)


def enforce_quota(identity: IdentityContext, service_name: str) -> dict[str, str]:
    """Apply burst + window limits. Returns rate-limit headers for the response, or raises 429."""
    policy = ROLE_QUOTAS.get(identity.role, DEFAULT_QUOTA)
    key = (identity.auth_type, identity.subject, service_name)

    with _lock:
        wait = _take_token(("burst",) + key, policy.burst, policy.refill_per_sec)
        if wait > 0:
            raise _too_many(
                f"QBAC: burst rate limit exceeded for '{identity.subject}' on '{service_name}' "
                f"(max {policy.burst} burst, {policy.refill_per_sec}/s sustained).",
                wait,
            )
        remaining, reset_in = _count_in_window(("window",) + key, policy.window_limit, policy.window_seconds)

    headers = {
        "X-RateLimit-Limit": str(policy.window_limit),
        "X-RateLimit-Remaining": str(max(0, remaining)),
        "X-RateLimit-Reset": str(math.ceil(reset_in)),
    }
    if remaining < 0:
        raise _too_many(
            f"QBAC: usage quota exhausted for '{identity.subject}' on '{service_name}' "
            f"({policy.window_limit} requests per {policy.window_seconds}s).",
            reset_in,
            headers,
        )
    return headers


def _login_keys(client_ip: str, username: str) -> tuple[tuple, tuple]:
    return ("login-ip", client_ip), ("login-user", username.lower())


def check_login_allowed(client_ip: str, username: str) -> None:
    """Raise 429 if this IP or this username has too many recent FAILED logins.

    Read-only: successful logins never count against the limit.
    """
    now = _now()
    with _lock:
        for key in _login_keys(client_ip, username):
            start, count = _windows.get(key, [now, 0])
            if now - start >= LOGIN_WINDOW_SECONDS:
                continue
            if count >= LOGIN_MAX_ATTEMPTS:
                reset_in = LOGIN_WINDOW_SECONDS - (now - start)
                raise _too_many(
                    f"Too many failed login attempts. Try again in {math.ceil(reset_in)}s.",
                    reset_in,
                )


def record_login_failure(client_ip: str, username: str) -> None:
    with _lock:
        for key in _login_keys(client_ip, username):
            _count_in_window(key, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS)
