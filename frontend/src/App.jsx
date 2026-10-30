import { useEffect, useRef, useState } from "react";
import {
  analyzeSample, analyzeUpload, completeSsoLogin, getMe, getSamples, logoutGateway, refreshGateway,
} from "./api.js";
import { createSessionSync } from "./session.js";
import SummaryCards from "./components/SummaryCards.jsx";
import DetectorBreakdown from "./components/DetectorBreakdown.jsx";
import DetectionsTable from "./components/DetectionsTable.jsx";
import ZeroTrustPEP from "./components/ZeroTrustPEP.jsx";
import SDWANConsole from "./components/SDWANConsole.jsx";
import LoginPage from "./components/LoginPage.jsx";

const ROLE_AVATARS = {
  developer: "DEV",
  finance: "FIN",
  admin: "ADM",
};

function withExpiry(tokens) {
  return { ...tokens, expires_at: Date.now() + (tokens.expires_in || 0) * 1000 };
}

// Shown on the login screen after a sign-out the user didn't click themselves.
const SIGN_OUT_NOTICES = {
  idle: "You were signed out after 15 minutes of inactivity.",
  expired: "Your session ended. Please sign in again.",
  revoked: "Your access was removed or changed by an administrator. Please sign in again.",
};
const SESSION_CHECK_MS = 30_000;

export default function App() {
  const [ssoResult] = useState(() => new URLSearchParams(window.location.hash.slice(1)).get("sso"));
  const [ssoPending, setSsoPending] = useState(ssoResult === "complete");
  const [ssoError, setSsoError] = useState(null);
  const [ssoPrompt, setSsoPrompt] = useState(null);
  const [session, setSession] = useState(() => {
    if (new URLSearchParams(window.location.hash.slice(1)).has("sso")) return null;
    try {
      const stored = window.sessionStorage.getItem("siem:session");
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });
  const [activeTab, setActiveTab] = useState("pep"); // "pep", "siem", "sdwan"
  const [samples, setSamples] = useState([]);
  const [source, setSource] = useState("gateway_audit.jsonl");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  const [isLeader, setIsLeader] = useState(false);

  // One session per browser, shared by every dashboard tab (see session.js).
  const syncRef = useRef(null);
  if (!syncRef.current) syncRef.current = createSessionSync();
  const sync = syncRef.current;
  const sessionRef = useRef(session);
  sessionRef.current = session;

  function startSession(tokens) {
    const next = withExpiry(tokens);
    setNotice(null);
    setSsoError(null);
    setSsoPrompt(null);
    setSession(next);
    sync.publishSession(next);
  }

  function endSession(revoke, reason) {
    const current = sessionRef.current;
    if (current && revoke) logoutGateway(current.access_token, current.refresh_token);
    setSsoError(null);
    setSsoPrompt("login");
    setResult(null);
    setNotice(SIGN_OUT_NOTICES[reason] || null);
    setSession(null);
  }

  // Sign out every tab in this browser: revoke the tokens once, then tell the others.
  function signOutEverywhere(reason) {
    const sessionId = sessionRef.current?.session_id;
    endSession(true, reason);
    sync.announceSignOut(reason, sessionId);
  }

  useEffect(() => {
    const offs = [
      // Another tab signed in or rotated tokens.
      sync.on("session", ({ session: next }) => {
        const current = sessionRef.current;
        if (current && current.session_id !== next.session_id) {
          logoutGateway(current.access_token, current.refresh_token); // replaced by a new sign-in
        }
        setNotice(null);
        setSsoError(null);
        setSsoPrompt(null);
        setSession(next);
      }),
      // Another tab signed out. It already revoked the shared session; revoke ours
      // only if this tab somehow held a different one.
      sync.on("signed-out", ({ reason, sessionId }) => {
        const current = sessionRef.current;
        if (!current) return;
        endSession(current.session_id !== sessionId, reason);
      }),
      // A newly opened tab asks whether anyone is signed in.
      sync.on("hello", () => {
        if (sessionRef.current) sync.publishSession(sessionRef.current);
      }),
    ];
    if (!sessionRef.current) sync.requestSession();
    return () => offs.forEach((off) => off());
  }, []);

  // Exactly one tab (the leader) refreshes tokens and watches the session.
  useEffect(() => sync.lead(() => setIsLeader(true)), []);

  // Any keyboard or pointer activity, in any tab, keeps the session alive.
  useEffect(() => {
    const onActivity = () => sync.recordActivity();
    const events = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"];
    events.forEach((name) => window.addEventListener(name, onActivity, { passive: true }));
    return () => events.forEach((name) => window.removeEventListener(name, onActivity));
  }, []);

  useEffect(() => {
    if (!ssoResult) return undefined;
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    if (ssoResult !== "complete") {
      setSsoError(ssoResult === "denied"
        ? "Your company account is not linked to an active gateway user. Contact your administrator."
        : "SSO sign-in failed or was cancelled. Please try again.");
      return undefined;
    }
    let active = true;
    completeSsoLogin()
      .then((tokens) => { if (active) startSession(tokens); })
      .catch((err) => { if (active) setSsoError(err.message); })
      .finally(() => { if (active) setSsoPending(false); });
    return () => { active = false; };
  }, [ssoResult]);

  // Any API call that comes back 401 ends the session in every tab.
  useEffect(() => {
    const onExpired = () => { if (sessionRef.current) signOutEverywhere("expired"); };
    window.addEventListener("siem:session-expired", onExpired);
    return () => window.removeEventListener("siem:session-expired", onExpired);
  }, []);

  useEffect(() => {
    try {
      if (session) {
        window.sessionStorage.setItem("siem:session", JSON.stringify(session));
      } else {
        window.sessionStorage.removeItem("siem:session");
      }
    } catch {
      // The app remains usable when browser storage is unavailable.
    }
  }, [session]);

  // Leader only: refresh a minute before the access token expires (unless idle),
  // and check every 30 s that the session is still valid and the user still active.
  useEffect(() => {
    if (!isLeader || !session?.refresh_token || !session?.expires_at) return undefined;
    const refreshTimer = window.setTimeout(async () => {
      if (sync.isIdle()) return signOutEverywhere("idle");
      try {
        startSession(await refreshGateway(session.refresh_token));
      } catch (err) {
        signOutEverywhere(/not active/i.test(err.message) ? "revoked" : "expired");
      }
    }, Math.max(0, session.expires_at - Date.now() - 60_000));
    const watch = window.setInterval(async () => {
      if (sync.isIdle()) return signOutEverywhere("idle");
      // 401 = disabled, deleted, role changed or revoked; a network error is not a sign-out.
      if ((await getMe(session.access_token)) === 401) signOutEverywhere("revoked");
    }, SESSION_CHECK_MS);
    return () => {
      window.clearTimeout(refreshTimer);
      window.clearInterval(watch);
    };
  }, [isLeader, session?.access_token, session?.expires_at]);

  function signOut() {
    signOutEverywhere("user");
  }

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
    // Load once per sign-in, not on every background token refresh.
  }, [session?.subject]);

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
        ssoError={ssoError}
        ssoPending={ssoPending}
        ssoPrompt={ssoPrompt}
        notice={notice}
        onLoginSuccess={(newSession) => {
          setError(null);
          startSession(newSession);
          setActiveTab("pep");
        }}
      />
    );
  }

  // --- 2. Authenticated Enterprise Workspace ---
  const avatar = ROLE_AVATARS[session.role] || "USER";

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
            <span className="user-avatar-circle avatar-label">{avatar}</span>
            <div className="user-info-text">
              <strong>{session.subject}</strong>
              <span className={`user-role-badge ${session.role}`}>{session.role}</span>
            </div>
          </div>

          <button className="user-signout-btn" onClick={signOut}>
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
              {["admin", "developer"].includes(session.role) && (
                <label className="upload-btn">
                  Upload log
                  <input type="file" onChange={onUpload} hidden />
                </label>
              )}
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
          <span className="tab-marker" aria-hidden="true">PEP</span> Protected Microservices &amp; PEP
        </button>
        <button
          className={`tab-btn ${activeTab === "siem" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("siem");
            run(source);
          }}
        >
          <span className="tab-marker" aria-hidden="true">SIEM</span> SIEM Threat Hunting SOC
        </button>
        <button
          className={`tab-btn ${activeTab === "sdwan" ? "active" : ""}`}
          onClick={() => setActiveTab("sdwan")}
        >
          <span className="tab-marker" aria-hidden="true">SD-WAN</span> SD-WAN Virtual Routing &amp; Vault {session.role !== "admin" && <span className="tab-restricted">Restricted</span>}
        </button>
      </nav>

      {error && <div className="error-banner"><strong>Error:</strong> {error}</div>}

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
