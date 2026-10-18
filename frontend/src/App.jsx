import { useEffect, useState } from "react";
import { analyzeSample, analyzeUpload, getSamples } from "./api.js";
import SummaryCards from "./components/SummaryCards.jsx";
import DetectorBreakdown from "./components/DetectorBreakdown.jsx";
import DetectionsTable from "./components/DetectionsTable.jsx";
import ZeroTrustPEP from "./components/ZeroTrustPEP.jsx";
import SDWANConsole from "./components/SDWANConsole.jsx";
import LoginPage from "./components/LoginPage.jsx";

const ROLE_AVATARS = {
  developer: "👩‍💻",
  finance: "💼",
  admin: "🛡️",
};

export default function App() {
  const [session, setSession] = useState(null);
  const [activeTab, setActiveTab] = useState("pep"); // "pep", "siem", "sdwan"
  const [samples, setSamples] = useState([]);
  const [source, setSource] = useState("gateway_audit.jsonl");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Listen for session expiry events
  useEffect(() => {
    const onExpired = () => {
      setSession(null);
      setResult(null);
      setError("Session expired or unauthorized. Please sign in again.");
    };
    window.addEventListener("siem:session-expired", onExpired);
    return () => window.removeEventListener("siem:session-expired", onExpired);
  }, []);

  // When session is active, fetch samples and load default analysis with the token
  useEffect(() => {
    if (!session?.access_token) return;

    let isMounted = true;
    setError(null);

    getSamples(session.access_token)
      .then((data) => {
        if (!isMounted) return;
        const sampleList = data.samples || [];
        setSamples(sampleList);
        const wanted = new URLSearchParams(window.location.search).get("source");
        const initial =
          wanted && sampleList.includes(wanted)
            ? wanted
            : sampleList.includes("gateway_audit.jsonl")
            ? "gateway_audit.jsonl"
            : sampleList[0] || "auth.log";
        setSource(initial);
        return run(initial, session.access_token);
      })
      .catch((e) => {
        if (isMounted) setError(e.message);
      });

    return () => {
      isMounted = false;
    };
  }, [session?.access_token]);

  async function run(src = source, tokenOverride = null) {
    const token = tokenOverride || session?.access_token;
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const data = await analyzeSample(src, token);
      setResult(data);
      setSource(src);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function onUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    setError(null);
    try {
      const data = await analyzeUpload(file, session?.access_token);
      setResult(data);
      setSource(file.name);
      setActiveTab("siem");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // --- 1. If not authenticated, render the Enterprise Zero-Trust Login Screen ---
  if (!session) {
    return (
      <LoginPage
        onLoginSuccess={(newSession) => {
          setError(null);
          setSession(newSession);
          setActiveTab("pep");
        }}
      />
    );
  }

  // --- 2. Authenticated Enterprise Workspace ---
  const avatar = ROLE_AVATARS[session.role] || "👤";

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">◈</span>
          <div>
            <h1>Micro-SASE &amp; SIEM Threat Hunter</h1>
            <p className="subtitle">
              Enterprise Zero-Trust Ingress · Policy Enforcement Point · Threat Detection &amp; Response (ITDR)
            </p>
          </div>
        </div>

        <div className="topbar-right">
          {/* Live System Health Pills */}
          <div className="health-indicators">
            <span className="health-pill">
              <span className="dot green"></span> PEP Online
            </span>
            <span className="health-pill">
              <span className="dot green"></span> SIEM Active
            </span>
          </div>

          {/* User Identity Profile Pill */}
          <div className="user-identity-pill">
            <span className="user-avatar-circle">{avatar}</span>
            <div className="user-info-text">
              <strong>{session.subject}</strong>
              <span className={`user-role-badge ${session.role}`}>{session.role}</span>
            </div>
          </div>

          <button className="user-signout-btn" onClick={() => setSession(null)}>
            Sign Out
          </button>

          {activeTab === "siem" && (
            <div className="controls">
              <label className="ctrl">
                <span>Log source</span>
                <select
                  value={source}
                  onChange={(e) => {
                    setSource(e.target.value);
                    run(e.target.value);
                  }}
                >
                  {samples.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </label>
              <button className="run-btn" onClick={() => run(source)} disabled={loading}>
                {loading ? "Analysing…" : "Re-Analyse"}
              </button>
              <label className="upload-btn">
                Upload log
                <input type="file" onChange={onUpload} hidden />
              </label>
            </div>
          )}
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="nav-tabs">
        <button
          className={`tab-btn ${activeTab === "pep" ? "active" : ""}`}
          onClick={() => setActiveTab("pep")}
        >
          <span>⚡</span> Protected Microservices &amp; PEP
        </button>
        <button
          className={`tab-btn ${activeTab === "siem" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("siem");
            run(source);
          }}
        >
          <span>🛡️</span> SIEM Threat Hunting SOC
        </button>
        <button
          className={`tab-btn ${activeTab === "sdwan" ? "active" : ""}`}
          onClick={() => setActiveTab("sdwan")}
        >
          <span>🌐</span> SD-WAN Virtual Routing &amp; Vault {session.role !== "admin" && "🔒"}
        </button>
      </nav>

      {error && <div className="error-banner">⚠ {error}</div>}

      {/* View 1: Zero-Trust Policy Enforcement Point (PEP) */}
      {activeTab === "pep" && (
        <ZeroTrustPEP
          session={session}
          onRefreshSIEM={() => run("gateway_audit.jsonl")}
        />
      )}

      {/* View 2: SIEM Threat Hunting SOC Dashboard */}
      {activeTab === "siem" && (
        <>
          {result && (
            <main className="content">
              <div className="run-meta">
                Analysed <strong>{result.source}</strong> ({result.summary.events} events, {result.summary.detections} detections)
              </div>
              <SummaryCards summary={result.summary} />
              <DetectorBreakdown byDetector={result.summary.by_detector} />
              <DetectionsTable detections={result.detections} />
            </main>
          )}

          {!result && !error && (
            <div className="loading-state">Loading dashboard…</div>
          )}
        </>
      )}

      {/* View 3: SD-WAN Virtual Routing & Vault Console */}
      {activeTab === "sdwan" && (
        <SDWANConsole session={session} />
      )}

      <footer className="foot">
        Threat-Hunting-Package · Enterprise Micro-SASE Gateway &amp; Sigma/Wazuh SIEM Detection Engine
      </footer>
    </div>
  );
}
