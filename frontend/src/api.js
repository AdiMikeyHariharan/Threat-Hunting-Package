// Thin API client for the FastAPI backend (proxied through Vite at /api).

function authHeaders(token, extra = {}) {
  return { ...extra, ...(token ? { Authorization: `Bearer ${token}` } : {}) };
}

async function handleAuthFailure(res) {
  if (res.status === 401) window.dispatchEvent(new Event("siem:session-expired"));
}

export async function getSamples(token) {
  const res = await fetch("/api/samples", { headers: authHeaders(token) });
  await handleAuthFailure(res);
  if (!res.ok) throw new Error("failed to load samples");
  return res.json();
}

export async function getRules(token) {
  const res = await fetch("/api/rules", { headers: authHeaders(token) });
  await handleAuthFailure(res);
  if (!res.ok) throw new Error("failed to load rules");
  return res.json();
}

export async function analyzeSample(source, token) {
  const res = await fetch(`/api/analyze?source=${encodeURIComponent(source)}`, { headers: authHeaders(token) });
  await handleAuthFailure(res);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "analysis failed");
  }
  return res.json();
}

export async function analyzeUpload(file, token) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch("/api/analyze", { method: "POST", headers: authHeaders(token), body: form });
  await handleAuthFailure(res);
  if (!res.ok) throw new Error("upload analysis failed");
  return res.json();
}

// --- Micro-SASE IAM & Gateway API Client ---

export async function getSsoConfiguration() {
  const res = await fetch("/api/gateway/auth/sso/config", { cache: "no-store" });
  if (!res.ok) throw new Error("Unable to check SSO configuration.");
  return res.json();
}

export function beginSsoLogin() {
  const loginUrl = import.meta.env.VITE_SSO_LOGIN_URL?.trim() || "/api/gateway/auth/sso/login";
  const target = new URL(loginUrl, window.location.origin);
  if (target.origin !== window.location.origin || target.username || target.password) {
    throw new Error("The SSO endpoint must be on the dashboard's origin.");
  }
  window.location.assign(target.toString());
}

// Share an in-flight exchange across React StrictMode's effect setup/cleanup.
// The handoff cookie can only be consumed once, including across gateway replicas.
let ssoExchange = null;
export function completeSsoLogin() {
  if (!ssoExchange) {
    ssoExchange = fetch("/api/gateway/auth/sso/session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    }).then(async (res) => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || "SSO sign-in failed. Please try again.");
      return data;
    }).finally(() => { ssoExchange = null; });
  }
  return ssoExchange;
}

export async function loginGateway(username, password) {
  const res = await fetch("/api/gateway/auth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `Login failed (HTTP ${res.status})`);
  }
  return data;
}

// Access tokens are short-lived; the refresh token is rotated on every use.
export async function refreshGateway(refreshToken) {
  const res = await fetch("/api/gateway/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Session refresh failed (HTTP ${res.status})`);
  return data;
}

// Revokes the tokens server-side so they can't be replayed after sign-out.
export async function logoutGateway(accessToken, refreshToken) {
  await fetch("/api/gateway/auth/logout", {
    method: "POST",
    headers: authHeaders(accessToken, { "Content-Type": "application/json" }),
    body: JSON.stringify({ refresh_token: refreshToken }),
  }).catch(() => {});
}

export async function callGatewayProxy(service, path, token, method = "GET", body = null) {
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";

  const cleanPath = path ? `/${path.replace(/^\//, "")}` : "";
  const res = await fetch(`/api/gateway/proxy/${service}${cleanPath}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const responseHeaders = {
    "X-SDWAN-Route": res.headers.get("X-SDWAN-Route") || "none",
    "X-SDWAN-Region": res.headers.get("X-SDWAN-Region") || "none",
    "X-SDWAN-Failover": res.headers.get("X-SDWAN-Failover") || "false",
    "X-RateLimit-Remaining": res.headers.get("X-RateLimit-Remaining") || "N/A",
    "X-RateLimit-Limit": res.headers.get("X-RateLimit-Limit") || "N/A",
  };

  const data = await res.json().catch(() => ({ message: res.statusText }));
  return {
    status: res.status,
    ok: res.ok,
    headers: responseHeaders,
    data,
  };
}

export async function callDirectBackendBypass(service, path = "") {
  const cleanPath = path ? `/${path.replace(/^\//, "")}` : "";
  // Backends run as their own service; Vite proxies /backend-direct to it.
  const res = await fetch(`/backend-direct/mock-service/${service}${cleanPath}`);
  const data = await res.json().catch(() => ({}));
  return {
    status: res.status,
    ok: res.ok,
    data,
  };
}

export async function getSDWANStatus(token) {
  const res = await fetch("/api/gateway/sdwan/status", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error(`Failed to load SD-WAN status (HTTP ${res.status})`);
  return res.json();
}

export async function resetSDWAN(token) {
  const res = await fetch("/api/gateway/sdwan/reset", {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error(`Failed to reset SD-WAN (HTTP ${res.status})`);
  return res.json();
}

export async function analyzeLiveGateway(token) {
  const res = await fetch("/api/analyze-live-gateway", { headers: authHeaders(token) });
  await handleAuthFailure(res);
  if (!res.ok) throw new Error("Failed to analyze live gateway");
  return res.json();
}
