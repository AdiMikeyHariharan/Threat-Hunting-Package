# Micro-SASE Enterprise API Gateway: Action Plan & Architecture Reference

This document provides a comprehensive roadmap, technical specification, and implementation record for the **Micro-SASE (Secure Access Service Edge) Enterprise API Gateway** and its Identity and Access Management (IAM / ZTNA) architecture.

---

## 1. System Vision & Objective

Modern enterprise architectures suffer from **credential sprawl**, fragmented cloud services, and vulnerable direct endpoints. The goal of this system is to act as a centralized **Policy Enforcement Point (PEP)** and reverse proxy between clients (developers, operators, automated microservices) and downstream cloud services.

### Core Tenets:
1. **Zero-Trust Network Access (ZTNA):** Never trust, always verify. Every request must authenticate and satisfy authorization before reaching any internal service.
2. **Dual Identity Engine:**
   - **Human Users:** Username + password login (PBKDF2-hashed) that issues a signed JWT bearer token with a server-assigned role. (This is a simplified OAuth2-style flow — not a full OAuth2 authorization server.)
   - **Machine-to-Machine (M2M):** Authenticated via high-entropy Universal Keys stored solely as SHA-256 hashes (plaintext keys are never stored).
3. **Multi-Layered Authorization:**
   - **RBAC (Role-Based Access Control):** Broad service-level boundary gating.
   - **PBAC (Permission-Based Access Control):** Fine-grained route and HTTP-method policy matching against explicit permission scopes.
   - **QBAC (Quota-Based Access Control):** Token-bucket burst-rate limiting and fixed-window volume caps to prevent over-usage and DoS.
4. **Credential Isolation:** Client credentials are stripped at the ingress. The gateway overwrites any client-supplied `X-SASE-*` headers with verified identity headers, plus an internal gateway token that backends require, so backends never see client credentials.
5. **Full Telemetry & SIEM Synergy:** Every decision (`ALLOW` or `DENY`) is recorded as structured JSONL audit logs, designed to be ingested by the repository's SIEM Threat Hunter (wiring planned for Phase 5).

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

## 3. Five-Phase Implementation Roadmap

| Phase | Milestone | Focus Area | Status |
|---|---|---|:---:|
| **Phase 1** | **Core Reverse Proxy & Dual Ingress Identity** | Reverse proxy, JWT issuance & verification, SHA-256 hashed API keys, hardened login, backend bypass prevention. | **COMPLETE** |
| **Phase 2** | **Fine-Grained PBAC & QBAC Rate Limiting** | Method/path glob matching, scope verification, token-bucket burst limit, hourly usage quotas, login brute-force lockout. | **COMPLETE** |
| **Phase 3** | **At-Rest Encrypted Credential Vault** | AES-256-GCM authenticated encryption with AAD binding, zero-leak credential injection, key rotation. | **COMPLETE** |
| **Phase 4** | **SD-WAN Virtual Routing & Health-Aware Failover** | Multi-path upstream routing, latency tracking, circuit breaking, active health checks across virtual links. | **COMPLETE** |
| **Phase 5** | **SIEM & Anomaly Hunter Integration** | Ingesting gateway telemetry into `siem_hunter`, detecting credential stuffing, password spraying, and PBAC privilege abuse. | **COMPLETE** |

---

## 4. Phase 1 Breakdown (Completed)

### 4.1 Objectives
- Establish the centralized Policy Enforcement Point (`/proxy/{service}/{path}`).
- Eliminate client credential exposure to backend services.
- Provide cryptographically secure, hardened authentication for humans and machines.
- Prevent architectural bypass of internal microservices.

### 4.2 Delivered Components
1. **User Directory & Password Hashing (`gateway/users.py`):**
   - Implements PBKDF2-HMAC-SHA256 with 200,000 iterations and 16-byte random salts.
   - Server-assigned roles and scopes: clients can never elevate their own privileges during login.
   - Constant-time hash comparison (`hmac.compare_digest`) to prevent timing side-channel attacks.
2. **Dual Auth Engine (`gateway/auth.py`):**
   - **Humans:** Signed JWTs using `HS256`, 60-minute expiry, and claims validation.
   - **Machines:** Universal keys formatted as `sase_<urlsafe_token>`. Only the SHA-256 hash is saved to `gateway/data/api_keys.json` with atomic disk writes.
   - **Admin Guard (`require_admin`):** Only authenticated accounts with role `admin` can register API keys or inspect audit telemetry.
3. **Reverse Proxy & Anti-Bypass Guard (`gateway/proxy.py`):**
   - Strips client-provided `Authorization`, `X-API-Key`, and spoofed `X-SASE-*` headers.
   - Injects verified `X-SASE-Subject`, `X-SASE-Role`, `X-SASE-Auth-Type`, and an internal per-process token (`INTERNAL_GATEWAY_TOKEN`).
   - Mock backend services reject direct incoming requests missing this token, preventing gateway bypass.
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

## 9. Verification & Test Coverage Matrix

The implementation is verified through unit tests and automated regression suites.

| Test File | Test Case Count | Scenarios Verified |
|---|:---:|---|
| [`tests/test_gateway_phase1.py`](../tests/test_gateway_phase1.py) | 16 | Unauthenticated 401s, forged signatures, password verification, server-side role assignment, machine SHA-256 keys, admin-only barriers, backend bypass prevention, header spoofing sanitization. |
| [`tests/test_gateway_phase2.py`](../tests/test_gateway_phase2.py) | 20 | Scope enforcement per method/path, default-deny rule fallback, token bucket burst enforcement, refill over time, quota exhaustion, 5-strike login lockout, audit coverage of denials. |
| [`tests/test_gateway_phase3.py`](../tests/test_gateway_phase3.py) | 22 | AES-256-GCM encryption/decryption, AAD service binding, tamper resistance, zero-leak in logs/responses, admin API barriers, atomic key rotation. |
| [`tests/test_gateway_phase4.py`](../tests/test_gateway_phase4.py) | 12 | Default primary link dispatch, dynamic failover on 5xx/connection errors, 3-strike circuit breaker trips, half-open probe recovery, latency EMA smoothing, all-paths-exhausted 503 handling, admin status/reset endpoints. |
| [`tests/test_gateway_siem.py`](../tests/test_gateway_siem.py) | 8 | Gateway JSON parsing normalization, backend bypass critical signature, password spray threshold, single-account brute force, PBAC privilege probing, QBAC rate exhaustion, statistical volume anomalies, full pipeline JSON report generation. |
| [`tests/test_rule_engine.py`](../tests/test_rule_engine.py) | 11 | Existing SIEM rule engine and threshold correlation suite. |
| [`tests/test_anomaly.py`](../tests/test_anomaly.py) | 3 | Modified Z-score MAD anomaly calculations. |
| [`tests/test_attack.py`](../tests/test_attack.py) | 4 | MITRE ATT&CK technique resolution. |
| [`tests/test_parser.py`](../tests/test_parser.py) | 4 | Syslog and JSON parsing. |
| **Total Test Suite** | **100** | **All passing (100% pass rate)** |

---

## 9a. Known Limitations (current prototype)

| Limitation | Impact | Planned fix |
|---|---|---|
| Rate-limit state is in-memory, single process | Counters reset on restart; split across replicas | Redis-backed limiter |
| Users are a hardcoded demo list | No user management or password reset | User admin endpoints / external IdP |
| PBAC rules and quotas live in code | Changes need a redeploy | Load from YAML / admin API |
| Per-username login lockout | An attacker can lock a real user out for 60s | Progressive delays, CAPTCHA, or IP reputation |
| Client IP is the direct TCP peer | Behind a load balancer, all clients share one IP | Trust `X-Forwarded-For` only from known proxies |
| Mock backends run inside the gateway process | Not representative of real network hops | Separate services (Phase 4) |
| JWTs can't be revoked before expiry | A stolen token works for up to 60 min | Short expiry + refresh tokens / denylist |

---

## 10. Configuration & Environment Variables Reference

| Variable | Default Value | Description |
|---|---|---|
| `SASE_JWT_SECRET` | Auto-generated per process (warning emitted) | Secret key used to sign and verify human JWT tokens. Must be set in production. |
| `SASE_VAULT_KEY` | Auto-generated into `gateway/data/vault.key` | Base64-encoded 32-byte master key for AES-256-GCM vault encryption. |
| `SASE_VAULT_OLD_KEYS` | Empty | Comma-separated list of previous base64 keys accepted for decryption during rotation. |
| `SASE_VAULT_STORE` | `gateway/data/vault.json` | Path to persistent encrypted JSON store of downstream secrets. |
| `SASE_AUDIT_LOG` | `logs/gateway_audit.jsonl` | Absolute or relative file path for structured audit logging. |
| `SASE_API_KEY_STORE` | `gateway/data/api_keys.json` | Path to persistent store of hashed machine universal keys. |
| `SASE_PW_ALICE` | `alice-dev-pass` | Password for demo user `alice` (Role: `developer`). |
| `SASE_PW_BOB` | `bob-finance-pass` | Password for demo user `bob` (Role: `finance`). |
| `SASE_PW_CHARLIE` | `charlie-admin-pass` | Password for demo user `charlie` (Role: `admin`). |

---

## 11. Quick Start Commands

```bash
# 1. Activate project environment
source .venv/bin/activate

# 2. Run the end-to-end interactive demo script (Phases 1, 2, 3, 4 & 5)
python scripts/test_gateway_demo.py

# 3. Run the automated test suite
python -m pytest tests/ -q

# 4. Start the SASE Gateway service live
export SASE_JWT_SECRET="production-sample-secret-key-at-least-32-bytes"
uvicorn gateway.main:app --port 8080 --reload
```
Interactive OpenAPI/Swagger documentation is available at:
`http://localhost:8080/docs`
