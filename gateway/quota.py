"""Quota-Based Access Control (QBAC) and rate limiting for Micro-SASE Gateway.

Two independent limits are applied to every proxied request, keyed by
(identity, service):

1. Burst rate  - token bucket. Smooths spikes ("max N requests, refilling at
                 R per second"). Stops scripts hammering a service.
2. Usage quota - fixed window. Hard cap on total requests per window (e.g.
                 per hour). Stops slow, sustained over-usage.

A separate limiter protects /auth/token against password guessing, keyed by
client IP and by username (so rotating IPs against one account still trips it).
The per-username lock is skipped for devices (IPs) the user has recently
logged in from successfully, so an attacker cannot lock a real user out.

Limits are loaded from the policy file (see gateway/policy.py). State lives in
gateway.state: in-memory by default, Redis when SASE_REDIS_URL is set.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

from fastapi import HTTPException, status

from . import state
from .auth import IdentityContext


@dataclass(frozen=True)
class QuotaPolicy:
    burst: int              # token bucket capacity
    refill_per_sec: float   # tokens added per second
    window_limit: int       # max requests per window
    window_seconds: int     # window length


# Per-role policies, populated from the policy file at startup (gateway/policy.py).
ROLE_QUOTAS: dict[str, QuotaPolicy] = {}
DEFAULT_QUOTA = QuotaPolicy(burst=10, refill_per_sec=1.0, window_limit=200, window_seconds=3600)

# Login protection: attempts allowed per window, per IP and per username.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60
# A successful login marks (user, IP) as a known device for this long.
KNOWN_DEVICE_SECONDS = 30 * 24 * 3600


def _now() -> float:
    """Clock indirection so tests can control time. Wall clock, so replicas agree."""
    return time.time()


def reset() -> None:
    """Clear all limiter state (used by tests)."""
    state.store.reset()


def _too_many(detail: str, retry_after: float, headers: dict[str, str] | None = None) -> HTTPException:
    h = {"Retry-After": str(max(1, math.ceil(retry_after)))}
    h.update(headers or {})
    return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail, headers=h)


def enforce_quota(identity: IdentityContext, service_name: str) -> dict[str, str]:
    """Apply burst + window limits. Returns rate-limit headers for the response, or raises 429."""
    policy = ROLE_QUOTAS.get(identity.role, DEFAULT_QUOTA)
    key = f"{identity.auth_type}:{identity.subject}:{service_name}"
    now = _now()

    wait = state.store.take_token("burst:" + key, policy.burst, policy.refill_per_sec, now)
    if wait > 0:
        raise _too_many(
            f"QBAC: burst rate limit exceeded for '{identity.subject}' on '{service_name}' "
            f"(max {policy.burst} burst, {policy.refill_per_sec}/s sustained).",
            wait,
        )
    count, start = state.store.incr_window("window:" + key, policy.window_seconds, now)
    remaining = policy.window_limit - count
    reset_in = policy.window_seconds - (now - start)

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


def _ip_key(client_ip: str) -> str:
    return f"login-ip:{client_ip}"


def _user_key(username: str) -> str:
    return f"login-user:{username.lower()}"


def _device_key(client_ip: str, username: str) -> str:
    return f"known-device:{username.lower()}:{client_ip}"


def check_login_allowed(client_ip: str, username: str) -> None:
    """Raise 429 if this IP or this username has too many recent FAILED logins.

    Read-only: successful logins never count against the limit. The username
    lock does not apply on devices the user has logged in from before.
    """
    now = _now()
    keys = [_ip_key(client_ip)]
    if state.store.get(_device_key(client_ip, username)) is None:
        keys.append(_user_key(username))
    for key in keys:
        count, start = state.store.peek_window(key, LOGIN_WINDOW_SECONDS, now)
        if count >= LOGIN_MAX_ATTEMPTS:
            reset_in = LOGIN_WINDOW_SECONDS - (now - start)
            raise _too_many(
                f"Too many failed login attempts. Try again in {math.ceil(reset_in)}s.",
                reset_in,
            )


def record_login_failure(client_ip: str, username: str) -> None:
    now = _now()
    for key in (_ip_key(client_ip), _user_key(username)):
        state.store.incr_window(key, LOGIN_WINDOW_SECONDS, now)


def record_login_success(client_ip: str, username: str) -> None:
    state.store.set(_device_key(client_ip, username), "1", KNOWN_DEVICE_SECONDS)
