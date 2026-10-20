import { useEffect, useState } from "react";
import { beginSsoLogin, getSsoConfiguration, loginGateway } from "../api.js";

const DEMO_PERSONAS = [
  { name: "Alice", role: "Developer", badge: "developer", avatar: "A", user: "alice", pass: "alice-dev-pass" },
  { name: "Bob", role: "Finance", badge: "finance", avatar: "B", user: "bob", pass: "bob-finance-pass" },
  { name: "Charlie", role: "Security Admin", badge: "admin", avatar: "C", user: "charlie", pass: "charlie-admin-pass" },
  { name: "Attack test", role: "Unauthorized", badge: "unauthorized", avatar: "!", user: "intruder", pass: "bad-password-123" },
];

const DEMO_LOGIN_ENABLED =
  import.meta.env.DEV || import.meta.env.VITE_ENABLE_DEMO_LOGIN === "true";

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 2.5 20 6v5.2c0 5.1-3.3 8.8-8 10.3-4.7-1.5-8-5.2-8-10.3V6l8-3.5Z" />
      <path d="m8.8 12 2.1 2.1 4.5-4.7" />
    </svg>
  );
}

export default function LoginPage({ onLoginSuccess, ssoError = null, ssoPending = false }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lockoutTimer, setLockoutTimer] = useState(0);
  const [showDemoLogin, setShowDemoLogin] = useState(false);
  const [sso, setSso] = useState({ configured: false });

  useEffect(() => {
    let active = true;
    getSsoConfiguration()
      .then((configuration) => { if (active) setSso(configuration); })
      .catch(() => { if (active) setSso({ configured: false }); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (lockoutTimer <= 0) return undefined;
    const interval = window.setInterval(() => {
      setLockoutTimer((previous) => Math.max(0, previous - 1));
    }, 1000);
    return () => window.clearInterval(interval);
  }, [lockoutTimer]);

  function handleSso() {
    setError(null);
    try {
      beginSsoLogin();
    } catch (ssoError) {
      setError(ssoError.message);
    }
  }

  async function handleSubmit(event) {
    event.preventDefault();
    if (!username.trim() || !password) {
      setError("Enter both your username and password.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const session = await loginGateway(username.trim(), password);
      setPassword("");
      onLoginSuccess(session);
    } catch (authError) {
      const message = authError.message || "Authentication failed.";
      setError(message);
      if (message.includes("429") || message.toLowerCase().includes("too many")) {
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

  const formDisabled = loading || lockoutTimer > 0 || ssoPending;
  const visibleError = error || ssoError;

  return (
    <main className="login-screen">
      <section className="login-shell" aria-labelledby="login-title">
        <aside className="login-context">
          <div className="login-wordmark">
            <span className="login-mark"><ShieldIcon /></span>
            <span>Micro-SASE</span>
          </div>

          <div className="login-intro">
            <span className="login-eyebrow">Secure access gateway</span>
            <h1 id="login-title">One identity.<br />Every protected service.</h1>
            <p>
              Authenticate through your organization’s identity provider. Access is
              continuously evaluated by the zero-trust policy engine.
            </p>
          </div>

          <div className="login-assurances" aria-label="Security controls">
            <div><span>01</span><p><strong>Identity verified</strong>Server-issued roles and scoped access</p></div>
            <div><span>02</span><p><strong>Policy enforced</strong>Every service request passes through the PEP</p></div>
            <div><span>03</span><p><strong>Activity monitored</strong>Authentication and access events feed the SIEM</p></div>
          </div>

          <p className="login-environment"><span></span> Gateway operational · TLS required in production</p>
        </aside>

        <div className="login-panel">
          <div className="login-panel-heading">
            <span className="login-mobile-mark"><ShieldIcon /></span>
            <p className="login-overline">Protected workspace</p>
            <h2>Sign in to continue</h2>
            <p>Use your company account to access the security operations console.</p>
          </div>

          {visibleError && (
            <div className="login-alert" role="alert" aria-live="polite">
              <span className="alert-badge-icon">{lockoutTimer > 0 ? "⌛" : "!"}</span>
              <div className="alert-body">
                <strong>{lockoutTimer > 0 ? "Sign-in temporarily limited" : "Unable to sign in"}</strong>
                <p>{visibleError}</p>
                {lockoutTimer > 0 && <p>Try again in {lockoutTimer} seconds.</p>}
              </div>
            </div>
          )}

          <button
            type="button"
            className="sso-button"
            onClick={handleSso}
            disabled={!sso.configured || ssoPending}
            aria-describedby={!sso.configured ? "sso-configuration-note" : undefined}
          >
            <span className="sso-symbol" aria-hidden="true"><ShieldIcon /></span>
            <span>{ssoPending ? "Completing sign-in…" : "Continue with enterprise SSO"}</span>
            <span className="sso-arrow" aria-hidden="true">→</span>
          </button>

          {!sso.configured && (
            <p className="sso-note" id="sso-configuration-note">
              SSO is unavailable until an administrator configures the secure login endpoint.
            </p>
          )}

          <div className="login-divider"><span>Secure organization sign-in</span></div>

          {DEMO_LOGIN_ENABLED && (
            <div className="demo-access">
              <button
                type="button"
                className="demo-toggle"
                onClick={() => setShowDemoLogin((visible) => !visible)}
                aria-expanded={showDemoLogin}
                aria-controls="demo-login-form"
              >
                <span><strong>Development access</strong><small>Local demo accounts only</small></span>
                <span aria-hidden="true">{showDemoLogin ? "−" : "+"}</span>
              </button>

              {showDemoLogin && (
                <div id="demo-login-form" className="demo-login-body">
                  <div className="personas-grid" aria-label="Demo personas">
                    {DEMO_PERSONAS.map((persona) => (
                      <button
                        key={persona.user}
                        type="button"
                        className={`persona-card ${username === persona.user ? "selected" : ""} ${persona.badge}`}
                        onClick={() => selectPersona(persona)}
                      >
                        <span className="persona-avatar">{persona.avatar}</span>
                        <span><strong>{persona.name}</strong><small>{persona.role}</small></span>
                      </button>
                    ))}
                  </div>

                  <form className="login-card-form" onSubmit={handleSubmit}>
                    <div className="field-group">
                      <label htmlFor="login-username">Username</label>
                      <input
                        id="login-username"
                        type="text"
                        value={username}
                        onChange={(event) => setUsername(event.target.value)}
                        autoComplete="username"
                        spellCheck="false"
                        disabled={formDisabled}
                      />
                    </div>
                    <div className="field-group">
                      <label htmlFor="login-password">Password</label>
                      <div className="password-field">
                        <input
                          id="login-password"
                          type={showPassword ? "text" : "password"}
                          value={password}
                          onChange={(event) => setPassword(event.target.value)}
                          autoComplete="current-password"
                          disabled={formDisabled}
                        />
                        <button type="button" onClick={() => setShowPassword((shown) => !shown)}>
                          {showPassword ? "Hide" : "Show"}
                        </button>
                      </div>
                    </div>
                    <button type="submit" className="login-submit-btn" disabled={formDisabled}>
                      {loading ? "Verifying…" : lockoutTimer > 0 ? `Try again in ${lockoutTimer}s` : "Sign in with demo account"}
                    </button>
                  </form>
                </div>
              )}
            </div>
          )}

          <p className="login-privacy">
            By continuing, you acknowledge that access attempts are logged and monitored.
          </p>
        </div>
      </section>
    </main>
  );
}
