"""Software-Defined Wide Area Network (SD-WAN) Application-Layer Router (Phase 4).

Provides:
1. Multi-Path Virtual Routing:
   Services have multiple upstream links with assigned priority, weight, and region.
2. Circuit Breaker Pattern:
   - CLOSED: Normal operation; requests flow through the primary route.
   - OPEN: If an endpoint fails >= failure_threshold times consecutively, the circuit
     trips to OPEN to prevent cascading timeouts and resource exhaustion.
   - HALF-OPEN: After recovery_timeout, one probe request is allowed through. If successful,
     the circuit heals back to CLOSED.
3. Automatic Dynamic Failover:
   If the primary path is unavailable or fails during proxy execution, the router
   instantly fails over to the next healthy secondary link without client disruption.
4. Latency-Aware Routing Metrics:
   Tracks Exponential Moving Average (EMA) latency per virtual path.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .config import REGISTERED_SERVICES


def _now() -> float:
    return time.monotonic()


@dataclass
class UpstreamEndpoint:
    service: str
    name: str
    url: str
    priority: int = 1
    region: str = "default"
    # Circuit Breaker state
    circuit_state: str = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    last_state_change: float = field(default_factory=_now)
    latency_ema_ms: float = 0.0
    total_requests: int = 0
    total_failures: int = 0

    def is_available(self, recovery_timeout: float = 30.0) -> bool:
        """Check if this endpoint can accept traffic according to circuit rules."""
        now = _now()
        if self.circuit_state == "CLOSED":
            return True
        if self.circuit_state == "OPEN":
            # Check if recovery timeout has elapsed -> transition to HALF_OPEN
            if (now - self.last_failure_time) >= recovery_timeout:
                self.circuit_state = "HALF_OPEN"
                self.last_state_change = now
                self.success_count = 0
                return True
            return False
        if self.circuit_state == "HALF_OPEN":
            return True
        return False


class SDWANRouter:
    """Application-layer SD-WAN multi-path controller and circuit breaker."""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
        half_open_successes: int = 2,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_successes = half_open_successes
        self._lock = threading.Lock()
        self._endpoints: dict[str, list[UpstreamEndpoint]] = {}
        self._load_registry()

    def _load_registry(self) -> None:
        """Initialize virtual upstream paths from configuration."""
        with self._lock:
            self._endpoints.clear()
            for service_name, config in REGISTERED_SERVICES.items():
                endpoints_cfg = config.get("endpoints")
                if not endpoints_cfg:
                    # Fallback single endpoint if not configured
                    endpoints_cfg = [
                        {
                            "name": "primary",
                            "url": config.get("url", ""),
                            "priority": 1,
                            "region": "default",
                        }
                    ]

                ep_list = []
                for ep in endpoints_cfg:
                    ep_list.append(
                        UpstreamEndpoint(
                            service=service_name,
                            name=ep.get("name", "primary"),
                            url=ep.get("url", "").rstrip("/"),
                            priority=ep.get("priority", 1),
                            region=ep.get("region", "default"),
                        )
                    )
                self._endpoints[service_name] = ep_list

    def get_candidate_paths(self, service_name: str) -> list[UpstreamEndpoint]:
        """Return ordered list of available upstream paths for a service.

        Healthy endpoints (CLOSED/HALF_OPEN) are returned first, ordered by priority
        and latency.
        """
        with self._lock:
            endpoints = self._endpoints.get(service_name, [])
            if not endpoints:
                # Reload if registry changed dynamically
                self._load_registry()
                endpoints = self._endpoints.get(service_name, [])

            # Refresh states (e.g. check if OPEN -> HALF_OPEN)
            available = []
            tripped = []
            for ep in endpoints:
                if ep.is_available(self.recovery_timeout):
                    available.append(ep)
                else:
                    tripped.append(ep)

            # Sort available by priority (lower is better), then latency
            available.sort(key=lambda x: (x.priority, x.latency_ema_ms))
            return available + tripped

    def record_success(self, endpoint: UpstreamEndpoint, latency_ms: float) -> None:
        """Record successful transaction, updating latency EMA and healing circuits."""
        with self._lock:
            endpoint.total_requests += 1
            now = _now()
            # Update EMA latency
            if endpoint.latency_ema_ms == 0.0:
                endpoint.latency_ema_ms = latency_ms
            else:
                endpoint.latency_ema_ms = 0.7 * endpoint.latency_ema_ms + 0.3 * latency_ms

            if endpoint.circuit_state == "HALF_OPEN":
                endpoint.success_count += 1
                if endpoint.success_count >= self.half_open_successes:
                    endpoint.circuit_state = "CLOSED"
                    endpoint.failure_count = 0
                    endpoint.last_state_change = now
            elif endpoint.circuit_state == "CLOSED":
                endpoint.failure_count = 0

    def record_failure(self, endpoint: UpstreamEndpoint, error_detail: str) -> None:
        """Record upstream link failure, tripping circuit if threshold exceeded."""
        with self._lock:
            now = _now()
            endpoint.total_requests += 1
            endpoint.total_failures += 1
            endpoint.failure_count += 1
            endpoint.last_failure_time = now

            if endpoint.circuit_state in ("CLOSED", "HALF_OPEN"):
                if (
                    endpoint.circuit_state == "HALF_OPEN"
                    or endpoint.failure_count >= self.failure_threshold
                ):
                    endpoint.circuit_state = "OPEN"
                    endpoint.last_state_change = now

    def reset(self) -> None:
        """Reset all circuit breaker states (for tests or manual administrative recovery)."""
        with self._lock:
            for eps in self._endpoints.values():
                for ep in eps:
                    ep.circuit_state = "CLOSED"
                    ep.failure_count = 0
                    ep.success_count = 0
                    ep.last_failure_time = 0.0
                    ep.latency_ema_ms = 0.0

    def status(self) -> dict[str, Any]:
        """Return operational health status and metrics of all virtual links."""
        with self._lock:
            out = {}
            for svc, eps in self._endpoints.items():
                out[svc] = [
                    {
                        "name": ep.name,
                        "url": ep.url,
                        "region": ep.region,
                        "priority": ep.priority,
                        "circuit_state": ep.circuit_state,
                        "failure_count": ep.failure_count,
                        "total_requests": ep.total_requests,
                        "total_failures": ep.total_failures,
                        "latency_ema_ms": round(ep.latency_ema_ms, 2),
                    }
                    for ep in eps
                ]
            return out


# Global SD-WAN router instance
sdwan_router = SDWANRouter()
