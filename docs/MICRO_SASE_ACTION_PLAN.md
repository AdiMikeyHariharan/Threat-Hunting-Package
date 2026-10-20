# Micro-SASE Enterprise API Gateway: Action Plan & Architecture Reference

This document provides a comprehensive roadmap, technical specification, and implementation record for the **Micro-SASE (Secure Access Service Edge) Enterprise API Gateway** and its Identity and Access Management (IAM / ZTNA) architecture.

---

## 1. System Vision & Objective

Modern enterprise architectures suffer from **credential sprawl**, fragmented cloud services, and vulnerable direct endpoints. The goal of this system is to act as a centralized **Policy Enforcement Point (PEP)** and reverse proxy between clients (developers, operators, automated microservices) and downstream cloud services.

### Core Tenets:
1. **Zero-Trust Network Access (ZTNA):** Never trust, always verify. Every request must authenticate and satisfy authorization before reaching any internal service.
2. **Dual Identity Engine:**
   - **Human Users:** Username + password login (PBKDF2-hashed) that issues a short-lived signed JWT access token with a server-assigned role, plus a rotating refresh token. (This is a simplified OAuth2-style flow — not a full OAuth2 authorization server.)
   - **Machine-to-Machine (M2M):** Authenticated via high-entropy Universal Keys stored solely as SHA-256 hashes (plaintext keys are never stored).
3. **Multi-Layered Authorization:**
   - **RBAC (Role-Based Access Control):** Broad service-level boundary gating.
   - **PBAC (Permission-Based Access Control):** Fine-grained route and HTTP-method policy matching against explicit permission scopes.
   - **QBAC (Quota-Based Access Control):** Token-bucket burst-rate limiting and fixed-window volume caps to prevent over-usage and DoS.
4. **Credential Isolation:** Client credentials are stripped at the ingress. The gateway overwrites any client-supplied `X-SASE-*` headers with verified identity headers, plus an internal gateway token that backends require, so backends never see client credentials.
5. **Full Telemetry & SIEM Synergy:** Every decision (`ALLOW` or `DENY`) is recorded as structured JSONL audit logs, ingested by the repository's SIEM Threat Hunter (Phase 5).

---

## 2. Request Lifecycle & Evaluation Pipeline

Every proxied request follows a strict deterministic pipeline:

```
                  [ Incoming Request ]
                            │
                            ▼
              ┌───────────────────────────┐
              │ 1. Identity & Auth Check  │ ──► 401 Unauthorized (Invalid JWT / API Key)
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │    2. Service RBAC Check  │ ──► 403 Forbidden (Role not permitted for service)
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │     3. Route PBAC Check   │ ──► 403 Forbidden (Scope missing or method/path disallowed)
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │     4. QBAC Rate Check    │ ──► 429 Too Many Requests (Burst or Quota exhausted)
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │ 5. Header Sanitization &  │
              │    Internal Token Injection│
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │ 6. Async Downstream Proxy │ ──► 502 Bad Gateway (Downstream unreachable)
              └─────────────┬─────────────┘
                            ▼
              ┌───────────────────────────┐
              │ 7. Audit Telemetry Egress │ ──► Appended to logs/gateway_audit.jsonl
              └───────────────────────────┘
```

> **Performance Rule:** Checks run cheapest and most specific first. Quotas and rate buckets are **never consumed** by requests that were rejected during RBAC or PBAC validation.

---

## 3. Implementation Roadmap

| Phase | Milestone | Focus Area | Status |
|---|---|---|:---:|
| **Phase 1** | **Core Reverse Proxy & Dual Ingress Identity** | Reverse proxy, JWT issuance & verification, SHA-256 hashed API keys, hardened login, backend bypass prevention. | **COMPLETE** |
| **Phase 2** | **Fine-Grained PBAC & QBAC Rate Limiting** | Method/path glob matching, scope verification, token-bucket burst limit, hourly usage quotas, login brute-force lockout. | **COMPLETE** |
| **Phase 3** | **At-Rest Encrypted Credential Vault** | AES-256-GCM authenticated encryption with AAD binding, zero-leak credential injection, key rotation. | **COMPLETE** |
| **Phase 4** | **SD-WAN Virtual Routing & Health-Aware Failover** | Multi-path upstream routing, latency tracking, circuit breaking, active health checks across virtual links. | **COMPLETE** |
| **Phase 5** | **SIEM & Anomaly Hunter Integration** | Ingesting gateway telemetry into `siem_hunter`, detecting credential stuffing, password spraying, and PBAC privilege abuse. | **COMPLETE** |
| **Phase 6** | **Production Hardening** | Shared Redis state, token revocation & refresh rotation, user management, YAML policy, trusted proxies, out-of-process backends, dependency updates. | **COMPLETE** |

---

## 4. Phase 1 Breakdown (Completed)

### 4.1 Objectives
- Establish the centralized Policy Enforcement Point (`/proxy/{service}/{path}`).
- Eliminate client credential exposure to backend services.
- Provide cryptographically secure, hardened authentication for humans and machines.
- Prevent architectural bypass of internal microservices.

### 4.2 Delivered Components
1. **User Directory & Password Hashing (`gateway/users.py`):**
   - Implements PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023) and 16-byte random salts; older hashes are upgraded transparently at next login.
   - Server-assigned roles and scopes: clients can never elevate their own privileges during login.
   - Constant-time hash comparison (`hmac.compare_digest`) to prevent timing side-channel attacks.
2. **Dual Auth Engine (`gateway/auth.py`):**
   - **Humans:** Signed JWTs using `HS256` with 15-minute expiry; `iss`, `aud`, `typ`, `jti`, `iat`, `exp` and `sub` are all required and validated (see Phase 6).
   - **Machines:** Universal keys formatted as `sase_<urlsafe_token>`. Only the SHA-256 hash is saved to `gateway/data/api_keys.json` with atomic disk writes.
   - **Admin Guard (`require_admin`):** Only authenticated accounts with role `admin` can register API keys or inspect audit telemetry.
3. **Reverse Proxy & Anti-Bypass Guard (`gateway/proxy.py`):**
   - Strips client-provided `Authorization`, `X-API-Key`, and spoofed `X-SASE-*` headers.
   - Injects verified `X-SASE-Subject`, `X-SASE-Role`, `X-SASE-Auth-Type`, and an internal per-process token (`INTERNAL_GATEWAY_TOKEN`).
   - Mock backend services (`gateway/mock_backends.py`, a separate process) reject direct incoming requests missing this token, preventing gateway bypass.
4. **Structured Audit Telemetry (`gateway/telemetry.py`):**
   - Writes uniform JSON events to `logs/gateway_audit.jsonl` recording timestamps, HTTP methods, paths, subjects, roles, decisions, status codes, latencies, and denial reasons.

---

## 5. Phase 2 Breakdown (Completed)

### 5.1 Objectives
- Move from coarse role-level routing to fine-grained, least-privilege permission models.
- Prevent burst flooding and sustained quota exhaustion across services.
- Mitigate credential-stuffing and password brute-force attacks at the login endpoint.

### 5.2 Delivered Components
1. **PBAC Policy Engine (`gateway/policy.py`):**
   - Rules and quotas are loaded from `gateway/policy.yml` (see Phase 6).
   - Uses an ordered rule table per service matching HTTP methods (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, or `*`) and URI glob patterns (e.g. `invoices/*`).
   - Default-Deny: Any route or method not explicitly permitted is blocked with `403 Forbidden`.
   - Checks that the identity holds the required scope (`read`, `write`, `invoice`, `admin`).
2. **QBAC Rate Limiter & Quotas (`gateway/quota.py`):**
   - **Token Bucket Algorithm:** Regulates short bursts (e.g. 20 burst / 5 refill/sec for developers; 100 burst / 20 refill/sec for machine services).
   - **Usage Quotas:** Enforces fixed-window caps (e.g. 1,000 req/hr for humans; 20,000 req/hr for daemons).
   - Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (widely used de-facto convention), and `Retry-After` on 429 (standard HTTP).
3. **Brute-Force Login Limiter (`check_login_allowed`):**
   - Tracks failed login attempts across dual keys: client IP address and target username.
   - Reaching 5 failed attempts locks out authentication for 60 seconds. Successful logins never increment the counter.

---

## 6. Phase 3: At-Rest Encrypted Credential Vault (Completed)

### 6.1 Objective
Eliminate developer possession of downstream service credentials (e.g., AWS IAM keys, Stripe secret keys, database tokens). The developer authenticates to the SASE Gateway; the Gateway retrieves the encrypted credential from its vault and attaches it before proxying.

### 6.2 Architecture Specification
```
[ Developer ] --(Bearer JWT)--> [ SASE Gateway ]
                                        │
                                        ▼
                           ┌─────────────────────────┐
                           │   Encrypted Vault       │
                           │     (AES-256-GCM)       │
                           │                         │
                           │   "billing" -> API_KEY  │
                           └────────────┬────────────┘
                                        │ Decrypts secret in memory
                                        ▼
[ Downstream AWS / Stripe ] <--(Injects Real Secret)
```

### 6.3 Delivered Components
1. **AES-256-GCM Crypto Engine (`gateway/vault.py`):**
   - Authenticated encryption with fresh 96-bit random nonces per secret.
   - **Associated Authenticated Data (AAD):** Binds the ciphertext cryptographically to `sase-vault:v1:{service}:{header}`. Any attempt to tamper with or copy ciphertext across services fails decryption.
   - **Zero-Leak Design:** Secrets are decrypted purely in transient memory during request dispatch. Listing endpoints return metadata only (`version`, `key_id`, `updated_at`, `updated_by`). Plaintext secrets are never written to audit logs or HTTP responses.
2. **Key Rotation & Migration:**
   - Tracks `key_id` (SHA-256 prefix of key) on every encrypted record.
   - Supports seamless rotation: active encryption uses `SASE_VAULT_KEY` while old keys in `SASE_VAULT_OLD_KEYS` remain valid for decryption until `POST /vault/rotate` is called.
3. **Admin Vault API (`gateway/main.py`):**
   - `PUT /vault/credentials/{service}`: Store or update downstream secrets.
   - `GET /vault/credentials`: List all stored credential metadata.
   - `DELETE /vault/credentials/{service}`: Delete stored credentials.
   - `POST /vault/rotate`: Atomically re-encrypt all stored records under the current master key.
4. **Proxy Injection (`gateway/proxy.py`):**
   - Retrieves credential for the target service after RBAC/PBAC/QBAC pass.
   - Overwrites any client-supplied header of the same name.
   - Appends audit note (`vault credential '<header>' injected`) without logging values.

---

## 7. Phase 4: SD-WAN Virtual Routing & Failover (Completed)

### 7.1 Objective
Implement software-defined wide area network principles at the application layer. Rather than static single-point URLs, downstream microservices are registered across virtual multi-path links (Primary vs. Secondary / Multi-Region) with autonomous health tracking, circuit breakers, and sub-millisecond dynamic failover.

### 7.2 Implementation Checklist
- [x] Multi-endpoint registration per service (`REGISTERED_SERVICES` with priority, region, and weight).
- [x] Circuit breaker state machine (`CLOSED` -> `OPEN` -> `HALF_OPEN`) with configurable thresholds.
- [x] Exponential Moving Average (EMA) latency tracking per virtual path (`0.7 * ema + 0.3 * latency`).
- [x] Seamless transparent downstream failover upon HTTP 5xx or transport exceptions.
- [x] Informational SD-WAN response headers (`X-SDWAN-Route`, `X-SDWAN-Region`, `X-SDWAN-Failover`).
- [x] Administrative telemetry inspection (`GET /sdwan/status`) and manual recovery (`POST /sdwan/reset`).

### 7.3 Delivered Architecture & Components

```
                     [ Authenticated & Quota-Passed Request ]
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │    SD-WAN Controller   │
                            │  (gateway/sdwan.py)    │
                            └───────────┬────────────┘
                                        │ Selects best healthy route:
                                        │ 1. CLOSED / HALF_OPEN state
                                        │ 2. Lowest priority number (1 > 2)
                                        │ 3. Lowest EMA latency
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │               Dispatch Attempt (Primary)            │
             └──────────────────────────┬──────────────────────────┘
                                        │
                      ┌─────────────────┴─────────────────┐
                      │                                   │
                 [HTTP 200 OK]                    [5xx Outage / Error]
                      │                                   │
                      ▼                                   ▼
          Record Latency EMA                 Record Failure on Primary
          Client receives response:          Trip Circuit if count >= 3
          • X-SDWAN-Route: primary           Instant Dynamic Failover:
          • X-SDWAN-Failover: false          Dispatch to Secondary Route
                                                          │
                                                          ▼
                                              Client receives response:
                                              • X-SDWAN-Route: secondary
                                              • X-SDWAN-Region: us-west
                                              • X-SDWAN-Failover: true
```

1. **Virtual Multi-Path Registry (`gateway/config.py`):**
   - Services define an `endpoints` array of virtual paths.
   - Example (`billing`):
     - `primary`: `/mock-service/billing`, Priority 1, Region `us-east`
     - `secondary`: `/mock-service/billing-backup`, Priority 2, Region `us-west`
2. **Circuit Breaker State Engine (`gateway/sdwan.py`):**
   - **`CLOSED`**: Standard operation. All traffic routes through the optimal link. Consecutive errors increment `failure_count`.
   - **`OPEN`**: Tripped when `failure_count >= failure_threshold` (default: 3). Traffic immediately bypasses the faulty link, shielding broken backends from cascading request storms.
   - **`HALF_OPEN`**: Automatically entered after `recovery_timeout` (default: 30s) elapses. A trial request is permitted. If it succeeds twice consecutively (`half_open_successes = 2`), the circuit heals back to `CLOSED`. A single failure in `HALF_OPEN` trips it directly back to `OPEN`.
3. **Dynamic Transparent Failover (`gateway/proxy.py`):**
   - If the selected primary link fails (HTTP 500+ or network transport error `httpx.RequestError`), the gateway intercepts the failure before returning to the caller.
   - It updates circuit health counters, marks `is_failover = True`, and seamlessly dispatches to the next healthy candidate link.
   - Returns telemetry headers (`X-SDWAN-Route`, `X-SDWAN-Region`, `X-SDWAN-Failover: true`) and records the failover event in `logs/gateway_audit.jsonl`.
4. **Admin Operations API (`gateway/main.py`):**
   - `GET /sdwan/status`: Returns circuit states, total requests, failure counts, and EMA latencies across all registered virtual links.
   - `POST /sdwan/reset`: Allows administrators to manually reset all tripped breakers and error counters to `CLOSED`.

---

## 8. Phase 5: SIEM Threat Hunting Integration (Completed)

### 8.1 Objective
Close the loop between the Micro-SASE Gateway and the repository's `siem_hunter` threat-hunting engine. Feed raw structured JSONL telemetry from `logs/gateway_audit.jsonl` into the SIEM pipeline, normalizing fields, evaluating detection signatures, correlating sliding-window threshold rules, and performing statistical anomaly volume hunting with full MITRE ATT&CK kill chain enrichment.

### 8.2 Delivered Architecture & Components

```
                   [ Micro-SASE Gateway Ingress & PEP ]
                                    │
                                    ▼
                      logs/gateway_audit.jsonl (JSONL)
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   siem_hunter/parser    │ ──► Normalises:
                       │   (parse_json_line)     │     client_ip -> src_ip
                       └────────────┬────────────┘     subject   -> user
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │  siem_hunter/pipeline   │ ──► Timestamp Ordering
                       └────────────┬────────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 │                                     │
                 ▼                                     ▼
     ┌──────────────────────┐             ┌────────────────────────┐
     │  Sigma / Rule Engine │             │   Anomaly Detector     │
     │  (rules/*.yml)       │             │   (Modified Z-Score)   │
     └───────────┬──────────┘             └────────────┬───────────┘
                 │                                     │
                 ▼                                     ▼
        Signature Matches &                   Statistical Outliers
        Threshold Correlations                     (MAD-Scaled)
                 │                                     │
                 └──────────────────┬──────────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │  MITRE ATT&CK Enrichment │ ──► Resolves technique IDs
                       │  (siem_hunter/attack)   │     to names and tactics
                       └────────────┬────────────┘
                                    │
                                    ▼
                          logs/detections.json
```

1. **Parser Field Normalization (`siem_hunter/parser.py`):**
   - Gateway JSON lines are automatically mapped to standard SIEM fields:
     - `client_ip` -> `src_ip`
     - `subject` -> `user`
   - Preserves original gateway fields (`decision`, `status_code`, `path`, `target_service`, `reason`) while allowing universal rule evaluation and anomaly baselining.
2. **SASE Detection Rules Catalog (`rules/sase_gateway_rules.yml`):**
   - **`SASE-SPRAY-0001` (High / Threshold):** Detects password spraying when an attacker rotates distinct usernames from a single source IP (`threshold.distinct = user`, count >= 3, window = 300s). Mapped to **T1110.003** (Brute Force: Password Spraying).
   - **`SASE-BRUTE-0001` (Medium / Threshold):** Detects rapid credential brute-forcing targeting a single user identity (count >= 4, window = 300s). Mapped to **T1110.001** (Brute Force: Password Guessing).
   - **`SASE-PBAC-ABUSE-0001` (High / Threshold):** Detects privilege probing and API enumeration when an identity encounters repeated 403 Forbidden violations across distinct paths (`threshold.distinct = path`, count >= 3, window = 300s). Mapped to **T1087** (Account Discovery / Reconnaissance).
   - **`SASE-BYPASS-0001` (Critical / Signature):** Immediate detection when an attacker attempts to skip the PEP reverse proxy and call backend microservices directly. Mapped to **T1190** (Exploit Public-Facing Application).
   - **`SASE-BURST-EXHAUSTION-0001` (Medium / Threshold):** Detects repeated 429 Too Many Requests errors from an entity hammering services beyond token-bucket burst capacity. Mapped to **T1499** (Endpoint Denial of Service).
3. **Statistical Anomaly Scorer Integration (`siem_hunter/anomaly.py`):**
   - Computes robust modified Z-scores using Median Absolute Deviation (MAD):
     $$M_i = 0.6745 \times \frac{x_i - \text{median}}{\text{MAD}}$$
   - Flags entity outliers exceeding threshold (3.5) without needing pre-existing signatures.
4. **Automated Pipeline Execution & Reporting (`siem_hunter/pipeline.py`):**
   - Supports end-to-end execution: `python -m siem_hunter.cli --log logs/gateway_audit.jsonl --format json --rules rules --out logs/detections.json`.

## 8.3 SIEM Dashboard Login and Authorization

The React dashboard uses the Micro-SASE human login at `/api/gateway/auth/token`.
The SIEM FastAPI routes validate the gateway-signed JWT with the same verifier
used by the gateway, then enforce role permissions on the server. Browser state
only carries the token and display identity; it cannot grant permissions.

| Gateway role | SIEM dashboard permissions |
|---|---|
| `admin` (Charlie) | Read samples/rules, analyze and upload logs, inspect live gateway telemetry |
| `developer` (Alice) | Read samples/rules, analyze samples, upload logs |
| `finance` (Bob) | Read samples/rules and run sample analysis; upload is denied |

Unauthenticated requests receive HTTP 401; authenticated roles outside an
endpoint's permission receive HTTP 403. Live gateway analysis is admin-only
because it exposes audit data. The dashboard keeps the session in
`sessionStorage`, sends the bearer token to protected SIEM endpoints, clears
the session on logout or token expiry, and hides upload controls for the
read-only finance role. Gateway health and login remain reachable before sign-in.

---

## 8a. Phase 6: Production Hardening (Completed)

Closes the limitations recorded in earlier phases and brings dependencies and token handling up to current practice.

| Area | Delivered | Where |
|---|---|---|
| Shared state | Token buckets, quota windows, login lockout and revocation lists live in `gateway/state.py`: in-memory by default, Redis (atomic Lua scripts) when `SASE_REDIS_URL` is set, so replicas share counters. Wall-clock time so replicas agree. | `gateway/state.py`, `gateway/quota.py` |
| Token revocation | Access tokens last 15 min and carry a `jti`. `POST /auth/logout` deny-lists the presented tokens; `POST /auth/revoke/{user}` (admin) and any password/role/disable change invalidate every token issued to that user. | `gateway/auth.py`, `gateway/main.py` |
| Refresh tokens | `POST /auth/refresh` rotates the refresh token (8 h lifetime) and re-reads role/scopes from the directory. Replaying a rotated refresh token is treated as theft and revokes all of that user's sessions. Refresh tokens are rejected as access tokens and vice versa (`typ` claim). The dashboard refreshes in the background and revokes on sign-out. | `gateway/main.py`, `frontend/src/App.jsx` |
| User management | Persistent user store (`SASE_USER_STORE`, file mode 0600). Admin API: `GET/POST /users`, `PATCH /users/{u}` (role, scopes, disabled), `PUT /users/{u}/password`, `DELETE /users/{u}`. Self-service `POST /auth/change-password`. Roles limited to `HUMAN_ROLE_SCOPES`; 12–256 char passwords not containing the username; the last active admin cannot be removed. | `gateway/users.py` |
| Policy as config | PBAC rules and QBAC quotas in `gateway/policy.yml`. Validated on load (unknown services, methods, non-positive quotas are rejected); the gateway refuses to start on an invalid file. `GET /policy` and `POST /policy/reload` (admin); a bad reload keeps the running policy. | `gateway/policy.py` |
| Lockout abuse | The per-username lock no longer applies on devices (IPs) where that user logged in successfully in the last 30 days, so an attacker elsewhere cannot lock the real user out. The attacker's own IP is still locked. | `gateway/quota.py` |
| Client IP | `X-Forwarded-For` is honoured only when the direct peer is in `SASE_TRUSTED_PROXIES`, read right-to-left skipping trusted hops; otherwise ignored (no spoofing). Used by the gateway, audit log and SIEM API. | `gateway/auth.get_client_ip` |
| Separate backends | Mock services run as their own app (`uvicorn gateway.mock_backends:app --port 8081`) reached over real HTTP; the internal token is shared through `SASE_INTERNAL_TOKEN`. Tests and the demo run them in-process via `proxy.UPSTREAM_TRANSPORT`. | `gateway/mock_backends.py`, `gateway/proxy.py` |
| Machine keys | `GET /auth/api-keys` and `DELETE /auth/api-keys/{sha256}` (admin) so a leaked key can be revoked immediately. | `gateway/main.py` |
| Hardening | CORS limited to `SASE_CORS_ORIGINS` (was `*`); `SASE_JWT_SECRET` must be ≥ 32 bytes (RFC 7518 §3.2); token responses send `Cache-Control: no-store`; login/password fields are length-capped before hashing; `Cookie`, `Proxy-Authorization` and hop-by-hop headers are stripped before forwarding; non-admins no longer see internal upstream URLs in `/auth/services`; audit query `limit` capped at 1000. | various |
| Dependencies | Python 3.9 (end-of-life) replaced by 3.12; `pip-audit` clean. Frontend Vite 5 → 7.3 and `npm audit fix`: 0 known vulnerabilities (was 7). | `requirements*.txt`, `frontend/package.json` |

---

## 9. Verification & Test Coverage Matrix

The implementation is verified through unit tests and automated regression suites.

| Test File | Test Case Count | Scenarios Verified |
|---|:---:|---|
| [`tests/test_gateway_phase1.py`](../tests/test_gateway_phase1.py) | 19 | Unauthenticated 401s, forged signatures, password verification, server-side role assignment, machine SHA-256 keys, admin-only barriers, backend bypass prevention, header spoofing sanitization. |
| [`tests/test_gateway_phase2.py`](../tests/test_gateway_phase2.py) | 20 | Scope enforcement per method/path, default-deny rule fallback, token bucket burst enforcement, refill over time, quota exhaustion, 5-strike login lockout, audit coverage of denials. |
| [`tests/test_gateway_phase3.py`](../tests/test_gateway_phase3.py) | 22 | AES-256-GCM encryption/decryption, AAD service binding, tamper resistance, zero-leak in logs/responses, admin API barriers, atomic key rotation. |
| [`tests/test_gateway_phase4.py`](../tests/test_gateway_phase4.py) | 15 | Default primary link dispatch, safe-method failover, unsafe-method replay prevention, query preservation, circuit breaking, single half-open probes, latency tracking, and admin status/reset endpoints. |
| [`tests/test_gateway_siem.py`](../tests/test_gateway_siem.py) | 9 | Gateway JSON parsing normalization, backend bypass critical signature, password spray threshold, single-account brute force, PBAC privilege probing, QBAC rate exhaustion, private-IP filtering, statistical volume anomalies, and full pipeline reporting. |
| [`tests/test_gateway_hardening.py`](../tests/test_gateway_hardening.py) | 42 | Phase 6: hardened claims, refresh rotation & reuse detection, logout/admin revocation (gateway and SIEM API), short-secret startup refusal, user CRUD & validation, last-admin guard, hash upgrade, API key revocation, YAML policy load/reload/rejection, known-device lockout, trusted-proxy XFF, header stripping, CORS, Redis store (fakeredis). |
| [`tests/test_gateway_oidc.py`](../tests/test_gateway_oidc.py) | 49 | OIDC SSO: PKCE login, state/browser binding and replay, ID token signature/claim/nonce/azp/at_hash validation, clock-skew tolerance, one-time handoff, origin check, Memory and Redis stores. |
| [`tests/test_filestore.py`](../tests/test_filestore.py) | 4 | Shared file stores across separate processes: no lost concurrent updates, cross-process reload, concurrent first-start seeding, API key revoked on another replica. |
| [`tests/test_siem_api_auth.py`](../tests/test_siem_api_auth.py) | 5 | SIEM authentication, role permissions, admin-only live analysis, and upload-size enforcement. |
| [`tests/test_rule_engine.py`](../tests/test_rule_engine.py) | 13 | Existing SIEM rule engine and threshold correlation suite. |
| [`tests/test_parser.py`](../tests/test_parser.py) | 7 | Syslog and JSON parsing. |
| [`tests/test_attack.py`](../tests/test_attack.py) | 4 | MITRE ATT&CK technique resolution. |
| [`tests/test_anomaly.py`](../tests/test_anomaly.py) | 3 | Modified Z-score MAD anomaly calculations. |
| [`tests/test_elastic.py`](../tests/test_elastic.py) | 1 | Elastic export. |
| [`tests/test_pipeline.py`](../tests/test_pipeline.py) | 1 | End-to-end pipeline run. |
| **Total Test Suite** | **214** | **Run with `python -m pytest tests/ -q` (Python 3.10+, `pip install -r requirements-dev.txt`).** |

---

## 9a. Known Limitations (current prototype)

Resolved in Phase 6: in-memory single-process rate limits, hardcoded users, PBAC/quotas in code, per-username lockout abuse, `X-Forwarded-For` handling, in-process mock backends, and unrevocable JWTs.

| Limitation | Impact | Planned fix |
|---|---|---|
| SD-WAN circuit state is per process; user/API-key/vault stores are files shared only by replicas on one host (flock + reload on change, `gateway/filestore.py`) | Replicas on different hosts don't share circuit health or directory changes (network filesystems with unreliable `flock` are not supported) | Move stores to a database; share circuit state via Redis |
| `POST /policy/reload` applies to one replica | Other replicas keep the old policy until reloaded or restarted | Broadcast reloads (Redis pub/sub) or watch the file |
| Gateway↔backend trust is a shared bearer secret | A leaked `SASE_INTERNAL_TOKEN` allows bypass | mTLS between gateway and services |
| OIDC requires deployment configuration; MFA is provider-controlled | SSO needs a registered confidential client and explicit subject mappings; gateway sessions do not poll provider disablement | [Configure OIDC SSO](OIDC_SSO.md), enforce MFA at the provider, and revoke local sessions for immediate removal |
| Known-device lockout exemption is keyed by IP | Users behind a shared NAT with an attacker can still be locked out; no CAPTCHA or progressive delay | Device cookies, CAPTCHA, IP reputation |
| Refresh token is kept in browser `sessionStorage` | Readable by XSS on the dashboard origin (mitigated by rotation + reuse detection) | Backend-for-frontend with an HttpOnly cookie |

---

## 10. Configuration & Environment Variables Reference

| Variable | Default Value | Description |
|---|---|---|
| `SASE_JWT_SECRET` | Auto-generated per process (warning emitted) | Secret key used to sign and verify human JWT tokens. Must be set in production; at least 32 bytes or the gateway refuses to start. |
| `SASE_INTERNAL_TOKEN` | Auto-generated per process (warning emitted) | Shared secret the gateway sends to backends. Set the same value for the gateway and `gateway.mock_backends` when they run separately. |
| `SASE_BACKEND_URL` | `http://127.0.0.1:8081` | Base URL of the mock backend service. |
| `SASE_REDIS_URL` | Empty (in-memory) | Redis URL for shared rate-limit, lockout and revocation state, e.g. `redis://localhost:6379/0`. |
| `SASE_USER_STORE` | `gateway/data/users.json` | Persistent user directory (PBKDF2 hashes only). Demo users are seeded only when it does not exist. |
| `SASE_POLICY_FILE` | `gateway/policy.yml` | PBAC rules and QBAC quotas. |
| `SASE_TRUSTED_PROXIES` | Empty | Comma-separated IPs/CIDRs of load balancers whose `X-Forwarded-For` is trusted. |
| `SASE_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Browser origins allowed to call the gateway and SIEM API. |
| `SASE_PBKDF2_ITERATIONS` | `600000` | PBKDF2 work factor for new hashes (tests lower it for speed). |
| `SASE_OIDC_*` | Unset (SSO disabled) | Enterprise SSO: `ISSUER`, `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI`, `FRONTEND_URL`, `SUBJECT_MAP` (+ optional `TOKEN_AUTH_METHOD`, `ALLOW_LOCAL_HTTP`). See [OIDC_SSO.md](OIDC_SSO.md). |
| `SASE_VAULT_KEY` | Auto-generated into `gateway/data/vault.key` | Base64-encoded 32-byte master key for AES-256-GCM vault encryption. |
| `SASE_VAULT_OLD_KEYS` | Empty | Comma-separated list of previous base64 keys accepted for decryption during rotation. |
| `SASE_VAULT_STORE` | `gateway/data/vault.json` | Path to persistent encrypted JSON store of downstream secrets. |
| `SASE_AUDIT_LOG` | `logs/gateway_audit.jsonl` | Absolute or relative file path for structured audit logging. |
| `SASE_API_KEY_STORE` | `gateway/data/api_keys.json` | Path to persistent store of hashed machine universal keys. |
| `SASE_PW_ALICE` | `alice-dev-pass` | Password for demo user `alice` (Role: `developer`), used when seeding. |
| `SASE_PW_BOB` | `bob-finance-pass` | Password for demo user `bob` (Role: `finance`). |
| `SASE_PW_CHARLIE` | `charlie-admin-pass` | Password for demo user `charlie` (Role: `admin`). |

---

## 11. Quick Start Commands

```bash
# 1. Create the environment (Python 3.10+; 3.12 recommended)
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

# 2. Run the end-to-end interactive demo script (Phases 1-5, in-process backends)
python scripts/gateway_demo.py

# 3. Run the automated test suite
python -m pytest tests/ -q

# 4. Start the backends and the gateway as separate services
export SASE_JWT_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
export SASE_INTERNAL_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
# optional: export SASE_REDIS_URL=redis://localhost:6379/0
uvicorn gateway.mock_backends:app --port 8081 &
uvicorn gateway.main:app --port 8080
```
Interactive OpenAPI/Swagger documentation is available at:
`http://localhost:8080/docs`
