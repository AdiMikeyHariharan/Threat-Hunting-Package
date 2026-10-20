# OIDC single sign-on

The gateway supports a single OpenID Connect issuer using the authorization
code flow, PKCE S256, and RS256-signed ID tokens. It discovers the provider's
authorization, token, and JWKS endpoints. The client secret stays on the server.

## Configure the identity provider

Register a **confidential web application** with your OIDC provider:

- Enable the authorization code grant and PKCE S256.
- Use RS256 for ID tokens and allow the `openid` scope.
- Register the exact callback URL:
  `https://dashboard.example.com/api/gateway/auth/sso/callback`.
- Use `client_secret_basic` token endpoint authentication, or set
  `SASE_OIDC_TOKEN_AUTH_METHOD=client_secret_post` if the provider requires it.

Use the provider's exact, tenant-specific issuer URL. The discovery document and
ID token must both match it; multi-tenant issuer templates are not supported.

## Configure the gateway

Set these variables in the backend process environment, then restart it:

```bash
export SASE_OIDC_ISSUER='https://identity.example.com/realms/company'
export SASE_OIDC_CLIENT_ID='micro-sase'
export SASE_OIDC_CLIENT_SECRET='<client secret from your provider>'
export SASE_OIDC_REDIRECT_URI='https://dashboard.example.com/api/gateway/auth/sso/callback'
export SASE_OIDC_FRONTEND_URL='https://dashboard.example.com/'
export SASE_OIDC_SUBJECT_MAP='{"<immutable provider subject>":"alice"}'
```

The subject map explicitly links the provider's immutable `sub` claim to an
existing gateway username. Create/manage local users through the admin `/users`
API and assign their roles/scopes there. Obtain the subject from your identity
provider's administration tools for this registered client; do not substitute an
email address or display name. Unknown, deleted, and disabled users are denied.
Email, username, group, and role claims from the provider do not assign local
privileges. An empty subject map denies all SSO sign-ins.

The dashboard and callback must have the same public origin. Serve the dashboard
and proxy `/api` to the backend on that origin, as the Vite development proxy
already does. The frontend checks `/api/gateway/auth/sso/config` at runtime; no
frontend rebuild or `VITE_SSO_LOGIN_URL` is required. An existing
`VITE_SSO_LOGIN_URL` override must point to this gateway on the same origin.

All URLs require HTTPS. For loopback development only:

```bash
export SASE_OIDC_REDIRECT_URI='http://localhost:5173/api/gateway/auth/sso/callback'
export SASE_OIDC_FRONTEND_URL='http://localhost:5173/'
export SASE_OIDC_ALLOW_LOCAL_HTTP=true
```

Register that exact development callback with the provider too. The HTTP
exception applies only to `localhost`, `127.0.0.1`, and `::1`; it does not permit
HTTP for remote hosts. Keep it disabled in production.

Partial or invalid OIDC configuration fails at backend startup. When all required
OIDC settings are absent, the SSO button stays disabled and the login/callback/
session endpoints return 503. Existing password authentication remains available.

## Endpoints and session handling

| Endpoint (under `/api/gateway`) | Purpose |
|---|---|
| `GET /auth/sso/config` | Reports whether the server has OIDC configured; exposes no credentials. |
| `GET /auth/sso/login` | Creates a five-minute, browser-bound state/nonce/PKCE transaction and redirects to the provider. |
| `GET /auth/sso/callback` | Consumes state once, exchanges the authorization code, validates the ID token, and resolves the local user. |
| `POST /auth/sso/session` | Consumes a 60-second HttpOnly handoff cookie once and returns the existing gateway session format. Requires the dashboard's exact `Origin` header. |

The callback redirects to the configured frontend with a non-secret
`#sso=complete`, `#sso=denied`, or `#sso=failed` marker. It never puts access,
refresh, or ID tokens in redirect URLs. The dashboard completes the cookie
exchange automatically and uses its existing JWT refresh/logout flow.
Transaction and handoff cookies are host-only, HttpOnly, and SameSite=Lax.
HTTPS cookies use the `__Host-` prefix, Secure flag, and root path to prevent
sibling subdomains from planting domain cookies. Local HTTP development cookies
are scoped to the SSO path. Authentication responses are not cacheable.
State is bound to a separate browser cookie, and consumption is atomic.

The gateway verifies the provider's JWKS signature, exact issuer, audience,
expiry, issued-at time, subject, nonce, authorized party (`azp`, when required),
and `at_hash` when present. Expiry and issued-at allow 60 seconds of clock skew
between the gateway and the provider (`oidc.CLOCK_SKEW_SECONDS`); keep both
clocks NTP-synced. It fetches the provider's current JWKS during each
callback, so signing-key rotation does not require a gateway restart. Only the
configured discovery issuer supplies endpoints; token headers cannot select
key URLs. Provider errors and credentials are excluded from gateway audit events.

Use `SASE_REDIS_URL` for multiple workers or replicas so callback state, handoff
tickets, and revocation data are shared. All replicas also need the same OIDC
settings, local user directory, and `SASE_JWT_SECRET`. The default memory store
is for a single process; restarting it invalidates outstanding sign-ins.

Authorization codes necessarily arrive in the callback query. Disable query
logging for that route at your ingress/proxy and ASGI server (for Uvicorn, use
`--no-access-log` if you do not have a redacting access-log configuration).

## Current boundaries

- Logout revokes the gateway session; it does not sign the user out of the
  identity provider. OIDC front/back-channel and provider-initiated logout are
  not implemented.
- MFA and conditional-access requirements must be enforced by the identity
  provider's policy. The gateway does not independently enforce an authentication
  assurance level.
- Gateway refresh tokens continue to use the local user directory. Provider
  account disablement is not polled during an existing gateway session; disable
  the local user or revoke its gateway sessions when immediate removal is needed.
- The dashboard still keeps gateway tokens in `sessionStorage`. The HttpOnly
  cookie is a one-time handoff, not a replacement for the existing bearer session.

The protocol implementation follows
[OIDC ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
and [PKCE](https://www.rfc-editor.org/rfc/rfc7636.html).

Run the provider-mocked integration tests with:

```bash
.venv/bin/python -m pytest tests/test_gateway_oidc.py -q
```
