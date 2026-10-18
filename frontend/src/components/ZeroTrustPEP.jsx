import { useState, useEffect } from "react";
import {
  callGatewayProxy,
  callDirectBackendBypass,
  analyzeLiveGateway,
} from "../api.js";

const ROLE_PERMISSIONS = {
  developer: {
    title: "Developer / Engineering",
    services: [
      { name: "inventory", allowed: true, reason: "Assigned to Developer role" },
      { name: "billing", allowed: false, reason: "Requires Finance or Admin role" },
      { name: "admin-panel", allowed: false, reason: "Requires Security Admin role" },
    ],
    quotas: "20 burst req / 5.0 refilled/s · 1,000 req/hr",
  },
  finance: {
    title: "Finance & Accounting",
    services: [
      { name: "inventory", allowed: false, reason: "Requires Developer role" },
      { name: "billing", allowed: true, reason: "Assigned to Finance role (Vault injected)" },
      { name: "admin-panel", allowed: false, reason: "Requires Security Admin role" },
    ],
    quotas: "20 burst req / 5.0 refilled/s · 1,000 req/hr",
  },
  admin: {
    title: "Security Administrator",
    services: [
      { name: "inventory", allowed: true, reason: "Full Administrative Access" },
      { name: "billing", allowed: true, reason: "Full Administrative Access (Vault injected)" },
      { name: "admin-panel", allowed: true, reason: "Full Administrative Access" },
    ],
    quotas: "50 burst req / 10.0 refilled/s · 5,000 req/hr",
  },
};

export default function ZeroTrustPEP({ session, onRefreshSIEM }) {
  const [loading, setLoading] = useState(false);
  const [pepResponse, setPepResponse] = useState(null);
  const [recentAlert, setRecentAlert] = useState(null);

  const roleInfo = ROLE_PERMISSIONS[session?.role] || {
    title: "Standard Identity",
    services: [],
    quotas: "10 burst req / 1.0 refilled/s",
  };

  async function testEndpoint(service, path = "", method = "GET", body = null) {
    setLoading(true);
    try {
      const res = await callGatewayProxy(service, path, session?.access_token, method, body);
      setPepResponse({
        endpoint: `/proxy/${service}${path ? `/${path}` : ""}`,
        method,
        ...res,
      });
    } catch (err) {
      setPepResponse({
        endpoint: `/proxy/${service}${path ? `/${path}` : ""}`,
        method,
        status: "Error",
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
      checkLiveSIEM();
    }
  }

  async function testBypass() {
    setLoading(true);
    try {
      const res = await callDirectBackendBypass("billing", "invoices");
      setPepResponse({
        endpoint: "/mock-service/billing/invoices (Direct Bypass Attempt)",
        method: "GET",
        status: res.status,
        headers: {},
        data: res.data,
      });
    } catch (err) {
      setPepResponse({
        endpoint: "/mock-service/billing/invoices (Direct Bypass Attempt)",
        method: "GET",
        status: 403,
        headers: {},
        data: { detail: err.message },
      });
    } finally {
      setLoading(false);
      checkLiveSIEM();
    }
  }

  async function testBurstFlood() {
    setLoading(true);
    let lastRes = null;
    let denied429 = 0;
    for (let i = 0; i < 25; i++) {
      const r = await callGatewayProxy("inventory", "items", session?.access_token);
      if (r.status === 429) denied429++;
      lastRes = r;
    }
    setPepResponse({
      endpoint: "/proxy/inventory/items (Burst Flood: 25 requests in 1 second)",
      method: "GET",
      status: lastRes?.status || 429,
      headers: lastRes?.headers || {},
      data: {
        note: `Sent 25 rapid requests. Rate limiter blocked ${denied429} requests with HTTP 429 Too Many Requests.`,
        last_response: lastRes?.data,
      },
    });
    setLoading(false);
    checkLiveSIEM();
  }

  async function checkLiveSIEM() {
    try {
      if (session?.role === "admin" && session?.access_token) {
        const res = await analyzeLiveGateway(session.access_token);
        if (res.detections && res.detections.length > 0) {
          setRecentAlert(res.detections[res.detections.length - 1]);
        }
      }
      if (onRefreshSIEM) onRefreshSIEM();
    } catch (e) {
      // ignore
    }
  }

  return (
    <div className="pep-console">
      {/* Real-time SIEM Security Alert Banner */}
      {recentAlert && (
        <div className={`iam-alert-banner sev-${recentAlert.severity}`}>
          <div className="alert-content">
            <span className="alert-icon">🚨</span>
            <div>
              <strong>SIEM Security Event Detected: {recentAlert.rule_id}</strong> — {recentAlert.title}
              <div className="alert-sub">
                Target Entity: <code>{recentAlert.entity}</code> | Severity:{" "}
                <span className="badge">{recentAlert.severity.toUpperCase()}</span> | MITRE:{" "}
                {recentAlert.mitre?.map((m) => `${m.id} (${m.name})`).join(", ")}
              </div>
            </div>
          </div>
          <button className="dismiss-btn" onClick={() => setRecentAlert(null)}>
            ✕
          </button>
        </div>
      )}

      {/* Main Grid: Security Context vs Protected Microservices Tester */}
      <div className="pep-main-grid">
        {/* Left Panel: Verified Enterprise Security Context */}
        <div className="pep-card identity-context-card">
          <div className="card-header">
            <h3>🔐 Active Security Context</h3>
            <span className="badge verified">Verified Identity</span>
          </div>

          <div className="user-profile-summary">
            <div className="profile-hero">
              <span className="profile-avatar-large">
                {session.role === "admin" ? "🛡️" : session.role === "finance" ? "💼" : "👩‍💻"}
              </span>
              <div>
                <h4 className="profile-name">{session.subject}</h4>
                <span className={`role-badge-lg ${session.role}`}>{session.role.toUpperCase()}</span>
              </div>
            </div>
          </div>

          <div className="sec-props-table">
            <div className="sec-prop-row">
              <span className="prop-k">Assigned Role</span>
              <strong className="prop-v">{roleInfo.title}</strong>
            </div>
            <div className="sec-prop-row">
              <span className="prop-k">Granted Scopes</span>
              <div className="scopes-wrap">
                {session.scopes?.map((sc) => (
                  <span key={sc} className="scope-tag">{sc}</span>
                )) || <span className="text-muted">None</span>}
              </div>
            </div>
            <div className="sec-prop-row">
              <span className="prop-k">Auth Mechanism</span>
              <span className="prop-v">OAuth2 / Signed Bearer JWT (HS256)</span>
            </div>
            <div className="sec-prop-row">
              <span className="prop-k">QBAC Headroom</span>
              <span className="prop-v mono-text">{roleInfo.quotas}</span>
            </div>
            <div className="sec-prop-row">
              <span className="prop-k">Token Hash</span>
              <code className="token-hash-snippet">
                {session.access_token.slice(0, 16)}...{session.access_token.slice(-10)}
              </code>
            </div>
          </div>

          {/* Entitlement Matrix for this user */}
          <div className="entitlement-matrix">
            <span className="label-sm">Role Entitlement Matrix:</span>
            <div className="matrix-list">
              {roleInfo.services.map((svc) => (
                <div key={svc.name} className={`matrix-row ${svc.allowed ? "allowed" : "denied"}`}>
                  <div className="matrix-left">
                    <span className="indicator">{svc.allowed ? "✔" : "✖"}</span>
                    <strong>/proxy/{svc.name}</strong>
                  </div>
                  <span className="matrix-reason">{svc.reason}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Panel: Zero-Trust Policy Enforcement Point (PEP) Tester */}
        <div className="pep-card action-testing-card">
          <div className="card-header">
            <h3>⚡ Policy Enforcement Point (PEP) Dispatcher</h3>
            <span className="badge">Reverse Proxy Ingress</span>
          </div>

          <p className="hint-text">
            Execute real-time requests as <strong>{session.subject}</strong> ({session.role}). The gateway
            evaluates your token through RBAC, PBAC scopes, QBAC rate limiting, and SD-WAN failover:
          </p>

          <div className="enterprise-actions-list">
            {/* Inventory */}
            <div className="action-row-item">
              <div className="action-info">
                <strong>📦 Inventory &amp; Logistics Microservice</strong>
                <p>Path: <code>GET /proxy/inventory/items</code> · Required: Developer or Admin</p>
              </div>
              <button
                className="dispatch-btn"
                onClick={() => testEndpoint("inventory", "items")}
                disabled={loading}
              >
                Dispatch Request →
              </button>
            </div>

            {/* Billing */}
            <div className="action-row-item">
              <div className="action-info">
                <strong>💳 Financial Invoicing &amp; Billing API</strong>
                <p>Path: <code>GET /proxy/billing/invoices</code> · Decrypts &amp; injects Vault secret</p>
              </div>
              <button
                className="dispatch-btn"
                onClick={() => testEndpoint("billing", "invoices")}
                disabled={loading}
              >
                Dispatch Request →
              </button>
            </div>

            {/* Admin Panel */}
            <div className="action-row-item">
              <div className="action-info">
                <strong>⚙️ Core Cluster Admin Operations</strong>
                <p>Path: <code>GET /proxy/admin-panel/config</code> · Gated strictly to Admin</p>
              </div>
              <button
                className="dispatch-btn"
                onClick={() => testEndpoint("admin-panel", "config")}
                disabled={loading}
              >
                Dispatch Request →
              </button>
            </div>

            {/* Bypass Test */}
            <div className="action-row-item threat-action">
              <div className="action-info">
                <strong>⚡ Direct Backend Architecture Bypass</strong>
                <p>Attempts direct connection bypassing /proxy/ · Triggers <strong>CRITICAL SIEM Alert</strong></p>
              </div>
              <button
                className="dispatch-btn danger"
                onClick={testBypass}
                disabled={loading}
              >
                Simulate Bypass →
              </button>
            </div>

            {/* QBAC Flood */}
            <div className="action-row-item rate-action">
              <div className="action-info">
                <strong>💥 QBAC Rate-Limit Flood (Burst Stress)</strong>
                <p>Sends 25 rapid requests in 1 second · Exceeds bucket capacity &amp; trips HTTP 429</p>
              </div>
              <button
                className="dispatch-btn warning"
                onClick={testBurstFlood}
                disabled={loading}
              >
                Fire Burst Flood →
              </button>
            </div>
          </div>

          {/* PEP Response Display */}
          {pepResponse && (
            <div className="pep-result-card">
              <div className="result-header">
                <div>
                  <span className={`status-pill st-${pepResponse.status}`}>
                    HTTP {pepResponse.status}
                  </span>
                  <strong className="endpoint-label">{pepResponse.endpoint}</strong>
                </div>
                <span className="method-tag">{pepResponse.method}</span>
              </div>

              {pepResponse.headers && (
                <div className="headers-grid">
                  <div className="hdr-item">
                    <span>SD-WAN Route:</span>
                    <strong>{pepResponse.headers["X-SDWAN-Route"]}</strong>
                  </div>
                  <div className="hdr-item">
                    <span>Region:</span>
                    <strong>{pepResponse.headers["X-SDWAN-Region"]}</strong>
                  </div>
                  <div className="hdr-item">
                    <span>Dynamic Failover:</span>
                    <strong className={pepResponse.headers["X-SDWAN-Failover"] === "true" ? "warn" : ""}>
                      {pepResponse.headers["X-SDWAN-Failover"]}
                    </strong>
                  </div>
                  <div className="hdr-item">
                    <span>Quota Remaining:</span>
                    <strong>{pepResponse.headers["X-RateLimit-Remaining"]}</strong>
                  </div>
                </div>
              )}

              <div className="body-preview">
                <span className="label-sm">Downstream Response Payload:</span>
                <pre>{JSON.stringify(pepResponse.data, null, 2)}</pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
