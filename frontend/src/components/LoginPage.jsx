import { useState, useEffect } from "react";
import { loginGateway } from "../api.js";

const DEMO_PERSONAS = [
  {
    name: "Alice",
    role: "Developer",
    badge: "developer",
    color: "#38bdf8",
    avatar: "👩‍💻",
    user: "alice",
    pass: "alice-dev-pass",
    description: "Can access Inventory microservices; blocked from Billing & Admin panel.",
  },
  {
    name: "Bob",
    role: "Finance Analyst",
    badge: "finance",
    color: "#f59e0b",
    avatar: "💼",
    user: "bob",
    pass: "bob-finance-pass",
    description: "Can access Billing invoices with Vault secret injection; blocked from Dev & Admin.",
  },
  {
    name: "Charlie",
    role: "Security Admin",
    badge: "admin",
    color: "#a855f7",
    avatar: "🛡️",
    user: "charlie",
    pass: "charlie-admin-pass",
    description: "Super-admin access to all services, Vault key rotation, and SD-WAN management.",
  },
  {
    name: "Attacker",
    role: "Malicious Threat",
    badge: "unauthorized",
    color: "#ef4444",
    avatar: "🦹",
    user: "intruder",
    pass: "bad-password-123",
    description: "Tests failed passwords to demonstrate the 5-strike lockout & SIEM detection.",
  },
];

export default function LoginPage({ onLoginSuccess }) {
  const [username, setUsername] = useState("alice");
  const [password, setPassword] = useState("alice-dev-pass");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lockoutTimer, setLockoutTimer] = useState(0);
  const [failedAttempts, setFailedAttempts] = useState(0);

  // Countdown timer for lockout
  useEffect(() => {
    if (lockoutTimer <= 0) return;
    const interval = setInterval(() => {
      setLockoutTimer((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(interval);
  }, [lockoutTimer]);

  async function handleSubmit(e) {
    if (e) e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError("Please enter both username and password.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const session = await loginGateway(username.trim(), password.trim());
      setFailedAttempts(0);
      setLockoutTimer(0);
      onLoginSuccess(session);
    } catch (err) {
      const msg = err.message || "Authentication failed.";
      setError(msg);
      setFailedAttempts((prev) => prev + 1);

      // Check if lockout triggered (HTTP 429)
      if (msg.includes("429") || msg.toLowerCase().includes("too many") || msg.toLowerCase().includes("lockout")) {
        setLockoutTimer(60);
      }
    } finally {
      setLoading(false);
    }
  }

  function selectPersona(persona) {
    setUsername(persona.user);
    setPassword(persona.pass);
    setError(null);
  }

  return (
    <div className="login-screen">
      <div className="login-container">
        {/* Header Branding */}
        <div className="login-brand">
          <div className="login-logo-glow">
            <span className="login-logo-icon">◈</span>
          </div>
          <h2>Zero-Trust Access Portal</h2>
          <p className="login-subtitle">
            Micro-SASE Enterprise Gateway · Identity Verification &amp; SIEM Defense
          </p>
        </div>

        {/* Error / Lockout Banner */}
        {error && (
          <div className={`login-alert ${lockoutTimer > 0 ? "critical-lockout" : ""}`}>
            <span className="alert-badge-icon">{lockoutTimer > 0 ? "🔒" : "⚠"}</span>
            <div className="alert-body">
              <strong>{lockoutTimer > 0 ? "Lockout Active (QBAC Rate Guard)" : "Authentication Denied"}</strong>
              <p>{error}</p>
              {lockoutTimer > 0 && (
                <div className="lockout-countdown">
                  Cooldown period active: <strong>{lockoutTimer}s</strong> remaining before next attempt.
                  <br />
                  <span className="siem-notice">
                    📡 Security event recorded in <code>logs/gateway_audit.jsonl</code> &amp; SIEM Hunter.
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Persona Quick-Switcher */}
        <div className="personas-section">
          <div className="personas-header">
            <span>Select Demo Persona (1-Click Fill):</span>
          </div>
          <div className="personas-grid">
            {DEMO_PERSONAS.map((p) => {
              const isSelected = username === p.user;
              return (
                <button
                  key={p.name}
                  type="button"
                  className={`persona-card ${isSelected ? "selected" : ""} ${p.badge}`}
                  onClick={() => selectPersona(p)}
                >
                  <div className="persona-top">
                    <span className="persona-avatar">{p.avatar}</span>
                    <span className="persona-badge" style={{ borderColor: p.color, color: p.color }}>
                      {p.role}
                    </span>
                  </div>
                  <strong className="persona-name">{p.name}</strong>
                  <span className="persona-desc">{p.description}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Login Form */}
        <form className="login-card-form" onSubmit={handleSubmit}>
          <div className="field-group">
            <label htmlFor="login-username">Username</label>
            <div className="input-wrap">
              <span className="input-icon">👤</span>
              <input
                id="login-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. alice, bob, charlie"
                autoComplete="username"
                disabled={loading || lockoutTimer > 0}
              />
            </div>
          </div>

          <div className="field-group">
            <label htmlFor="login-password">Password</label>
            <div className="input-wrap">
              <span className="input-icon">🔑</span>
              <input
                id="login-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                autoComplete="current-password"
                disabled={loading || lockoutTimer > 0}
              />
            </div>
          </div>

          <button
            type="submit"
            className="login-submit-btn"
            disabled={loading || lockoutTimer > 0}
          >
            {loading ? (
              <span className="btn-spinner">Authenticating with Gateway…</span>
            ) : lockoutTimer > 0 ? (
              `Locked Out (${lockoutTimer}s)`
            ) : (
              "Sign In to Protected Workspace →"
            )}
          </button>
        </form>

        {/* Security Policy Footer Note */}
        <div className="login-security-footer">
          <div className="sec-pill">
            <span className="dot"></span> Zero-Trust Policy Enforcement Point
          </div>
          <div className="sec-pill">
            <span className="dot"></span> PBKDF2-HMAC-SHA256 (200,000 Iterations)
          </div>
          <div className="sec-pill">
            <span className="dot"></span> Real-Time SIEM Attack Correlation
          </div>
        </div>
      </div>
    </div>
  );
}
