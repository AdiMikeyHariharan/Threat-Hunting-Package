import { useState, useEffect } from "react";
import { getSDWANStatus, resetSDWAN } from "../api.js";

export default function SDWANConsole({ session }) {
  const [sdwanData, setSdwanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(null);

  const isAdmin = session?.role === "admin";

  useEffect(() => {
    if (isAdmin && session?.access_token) {
      loadData();
    }
  }, [isAdmin, session]);

  async function loadData() {
    setLoading(true);
    try {
      const data = await getSDWANStatus(session.access_token);
      setSdwanData(data.routes);
    } catch (err) {
      // not admin or error
    } finally {
      setLoading(false);
    }
  }

  async function handleReset() {
    if (!session?.access_token) return;
    try {
      const res = await resetSDWAN(session.access_token);
      setMessage(res.message || "All circuit breakers reset.");
      await loadData();
      setTimeout(() => setMessage(null), 4000);
    } catch (err) {
      setMessage(`Reset failed: ${err.message}`);
    }
  }

  if (!isAdmin) {
    return (
      <div className="admin-barrier-screen">
        <div className="barrier-box">
          <span className="barrier-icon">🚫</span>
          <h3>Administrative Clearance Required</h3>
          <p>
            SD-WAN Virtual Routing &amp; Circuit Breaker Infrastructure is restricted to identities
            with the <strong>admin</strong> security role.
          </p>
          <div className="barrier-meta">
            <span>Your Active Role:</span> <span className={`user-role-badge ${session?.role}`}>{session?.role}</span>
          </div>
          <p className="barrier-sub">
            All unauthorized access attempts to administrative infrastructure are logged to the SIEM
            under MITRE ATT&amp;CK Technique <strong>T1087 (Account Discovery)</strong>.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="sdwan-console">
      <div className="sdwan-hero-card">
        <div className="hero-top">
          <div>
            <h3>🌐 SD-WAN Virtual Routing &amp; Infrastructure Health</h3>
            <p className="hero-sub">
              Multi-path dynamic upstream routing, Exponential Moving Average (EMA) latency tracking,
              and automated circuit breaker failover.
            </p>
          </div>
          <button className="reset-circuits-action-btn" onClick={handleReset} disabled={loading}>
            {loading ? "Refreshing…" : "Reset All Circuit Breakers"}
          </button>
        </div>

        {message && <div className="sdwan-toast-banner">{message}</div>}

        <div className="circuit-legend">
          <div className="legend-item">
            <span className="dot green"></span>
            <strong>CLOSED:</strong> Healthy route accepting full traffic.
          </div>
          <div className="legend-item">
            <span className="dot red"></span>
            <strong>OPEN:</strong> Tripped after 3 consecutive failures. Traffic automatically routed to secondary backup.
          </div>
          <div className="legend-item">
            <span className="dot amber"></span>
            <strong>HALF-OPEN:</strong> Probing route recovery after 30s timeout.
          </div>
        </div>
      </div>

      {sdwanData && (
        <div className="routes-grid">
          {Object.entries(sdwanData).map(([service, endpoints]) => (
            <div key={service} className="service-route-card">
              <div className="svc-header">
                <span className="svc-tag">Microservice</span>
                <h4>{service.toUpperCase()}</h4>
              </div>

              <div className="endpoints-list">
                {endpoints.map((ep) => (
                  <div key={ep.name} className={`endpoint-row-card state-${ep.circuit_state.toLowerCase()}`}>
                    <div className="ep-top">
                      <div className="ep-identity">
                        <strong className="ep-name">
                          {ep.name === "primary" ? "⭐ PRIMARY LINK" : "🔁 SECONDARY BACKUP"}
                        </strong>
                        <span className="ep-region">{ep.region.toUpperCase()}</span>
                      </div>
                      <span className={`circuit-state-badge ${ep.circuit_state.toLowerCase()}`}>
                        {ep.circuit_state}
                      </span>
                    </div>

                    <div className="ep-metrics">
                      <div className="metric">
                        <span>Latency (EMA):</span>
                        <strong>{ep.latency_ema_ms > 0 ? `${ep.latency_ema_ms}ms` : "Active"}</strong>
                      </div>
                      <div className="metric">
                        <span>Total Requests:</span>
                        <strong>{ep.total_requests}</strong>
                      </div>
                      <div className="metric">
                        <span>Failures:</span>
                        <strong className={ep.total_failures > 0 ? "text-danger" : ""}>
                          {ep.total_failures}
                        </strong>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
