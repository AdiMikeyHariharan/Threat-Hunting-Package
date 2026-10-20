"""Reverse Proxy and Policy Enforcement Point (PEP) forwarding engine."""

from __future__ import annotations

import time
from typing import Optional

import httpx
from fastapi import HTTPException, Request, Response, status

from .auth import IdentityContext, enforce_rbac
from .config import INTERNAL_GATEWAY_TOKEN
from .policy import enforce_pbac
from .quota import enforce_quota
from .sdwan import UpstreamEndpoint, sdwan_router
from .telemetry import log_gateway_event
from .vault import VaultError, vault

# Transport used for upstream calls. None = real network. Tests and the demo
# script set an httpx.ASGITransport to run gateway.mock_backends in-process.
UPSTREAM_TRANSPORT: Optional[httpx.AsyncBaseTransport] = None


async def _dispatch_http(
    target_url: str,
    method: str,
    headers: dict[str, str],
    params: list[tuple[str, str]],
    body: bytes,
) -> httpx.Response:
    """Dispatch the HTTP request to the selected upstream link."""
    async with httpx.AsyncClient(transport=UPSTREAM_TRANSPORT, timeout=10.0) as client:
        return await client.request(
            method=method,
            url=target_url,
            headers=headers,
            params=params,
            content=body,
        )


async def forward_request(
    request: Request,
    service_name: str,
    path: str,
    identity: IdentityContext,
) -> Response:
    """Zero-Trust Policy Enforcement and SD-WAN Reverse Proxy Dispatcher.

    1. RBAC  - may this role reach this service at all?
    2. PBAC  - may this identity perform this method on this path?
    3. QBAC  - is this identity within its burst rate and usage quota?
    4. Vault - injects at-rest encrypted downstream credentials in memory.
    5. SD-WAN - selects best healthy virtual link; fails over automatically
       if primary link fails; trips circuit breaker on repeated outages.
    6. Strips caller credentials and injects verified X-SASE-* headers.
    7. Forwards to the downstream service and logs audit telemetry.
    """
    start_time = time.perf_counter()
    method = request.method
    client_ip = identity.client_ip

    # 1-3. Policy Enforcement
    try:
        enforce_rbac(identity, service_name)
        rule = enforce_pbac(identity, service_name, method, path)
        rate_headers = enforce_quota(identity, service_name)
    except HTTPException as e:
        latency = (time.perf_counter() - start_time) * 1000
        log_gateway_event(
            method=method,
            path=f"/proxy/{service_name}/{path}",
            target_service=service_name,
            status_code=e.status_code,
            decision="DENY",
            client_ip=client_ip,
            subject=identity.subject,
            auth_type=identity.auth_type,
            role=identity.role,
            latency_ms=latency,
            reason=e.detail,
        )
        raise e

    # Build downstream headers (Strip client secrets and any client-supplied
    # X-SASE-* headers so identity can't be spoofed, then inject verified ones)
    excluded_headers = {
        "host", "authorization", "x-api-key", "content-length", "cookie", "proxy-authorization",
        # hop-by-hop headers (RFC 9110 7.6.1) are never forwarded
        "connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade",
    }
    downstream_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in excluded_headers and not k.lower().startswith("x-sase-")
    }
    downstream_headers["x-sase-internal"] = INTERNAL_GATEWAY_TOKEN
    downstream_headers["x-sase-authenticated"] = "true"
    downstream_headers["x-sase-subject"] = identity.subject
    downstream_headers["x-sase-role"] = identity.role
    downstream_headers["x-sase-auth-type"] = identity.auth_type
    downstream_headers["x-sase-client-ip"] = client_ip

    # Vault: attach downstream credential (decrypted in memory only)
    try:
        injected = vault.header_for(service_name)
    except VaultError as e:
        log_gateway_event(
            method=method, path=f"/proxy/{service_name}/{path}", target_service=service_name,
            status_code=503, decision="DENY", client_ip=client_ip,
            subject=identity.subject, auth_type=identity.auth_type, role=identity.role,
            latency_ms=(time.perf_counter() - start_time) * 1000,
            reason=f"Vault error: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Downstream credential unavailable.",
        )
    if injected:
        vault_header, vault_value = injected
        for k in [k for k in downstream_headers if k.lower() == vault_header.lower()]:
            del downstream_headers[k]
        downstream_headers[vault_header] = vault_value
    vault_note = f"; vault credential '{injected[0]}' injected" if injected else ""

    # Read request body & params
    body = await request.body()
    # Preserve repeated parameters such as ?tag=a&tag=b.
    query_params = list(request.query_params.multi_items())

    # 4. SD-WAN Virtual Routing & Dynamic Failover
    available_candidates = sdwan_router.get_available_candidate_paths(service_name)

    if not available_candidates:
        latency = (time.perf_counter() - start_time) * 1000
        error_msg = f"SD-WAN: All upstream routes for '{service_name}' are unavailable (circuit OPEN)."
        log_gateway_event(
            method=method,
            path=f"/proxy/{service_name}/{path}",
            target_service=service_name,
            status_code=503,
            decision="DENY",
            client_ip=client_ip,
            subject=identity.subject,
            auth_type=identity.auth_type,
            role=identity.role,
            latency_ms=latency,
            reason=error_msg,
        )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=error_msg)

    last_error = None
    attempted_routes: list[str] = []

    # Retrying a state-changing request after a 5xx or transport failure can
    # duplicate an operation that committed before the failure was observed.
    # Automatic cross-route retries are therefore limited to safe methods.
    retryable = method.upper() in {"GET", "HEAD", "OPTIONS"}
    for ep in available_candidates:
        if not sdwan_router.reserve(ep):
            continue
        attempted_routes.append(ep.name)
        target_url = f"{ep.url}/{path.lstrip('/')}" if path else ep.url
        t0 = time.perf_counter()
        try:
            resp = await _dispatch_http(
                target_url=target_url,
                method=method,
                headers=downstream_headers,
                params=query_params,
                body=body,
            )
            ep_latency = (time.perf_counter() - t0) * 1000

            # 5xx responses indicate downstream failure -> fail over to next link
            upstream_failed = resp.status_code >= 500
            if upstream_failed:
                sdwan_router.record_failure(ep, f"HTTP {resp.status_code}")
                last_error = f"HTTP {resp.status_code} from route '{ep.name}'"
                if retryable:
                    continue
            else:
                sdwan_router.record_success(ep, ep_latency)

            total_latency = (time.perf_counter() - start_time) * 1000
            is_failover = len(attempted_routes) > 1
            failover_note = (
                f"; SD-WAN failover from {attempted_routes[0]} to {ep.name}"
                if is_failover
                else f"; SD-WAN route '{ep.name}' ({ep.region})"
            )

            # Log audit telemetry
            log_gateway_event(
                method=method,
                path=f"/proxy/{service_name}/{path}",
                target_service=service_name,
                status_code=resp.status_code,
                decision="DENY" if upstream_failed else "ALLOW",
                client_ip=client_ip,
                subject=identity.subject,
                auth_type=identity.auth_type,
                role=identity.role,
                latency_ms=total_latency,
                reason=(
                    f"Upstream failure returned without retrying unsafe method {method}"
                    if upstream_failed
                    else f"Forwarded - PBAC rule '{rule.description}' (scope '{rule.required_scope}'){vault_note}{failover_note}"
                ),
            )

            response_headers = dict(resp.headers)
            response_headers.pop("content-encoding", None)
            response_headers.pop("content-length", None)
            response_headers.update(rate_headers)
            response_headers["X-SDWAN-Route"] = ep.name
            response_headers["X-SDWAN-Region"] = ep.region
            response_headers["X-SDWAN-Failover"] = "true" if is_failover else "false"

            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=response_headers,
                media_type=resp.headers.get("content-type"),
            )
        except httpx.RequestError as exc:
            ep_latency = (time.perf_counter() - t0) * 1000
            sdwan_router.record_failure(ep, str(exc))
            last_error = f"Connection error on route '{ep.name}': {exc}"
            if retryable:
                continue
            break

    # All candidate links failed
    total_latency = (time.perf_counter() - start_time) * 1000
    error_msg = f"SD-WAN: All upstream paths failed for '{service_name}'. Attempted: {attempted_routes}. Last error: {last_error}"
    log_gateway_event(
        method=method,
        path=f"/proxy/{service_name}/{path}",
        target_service=service_name,
        status_code=502,
        decision="DENY",
        client_ip=client_ip,
        subject=identity.subject,
        auth_type=identity.auth_type,
        role=identity.role,
        latency_ms=total_latency,
        reason=error_msg,
    )
    raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error_msg)
