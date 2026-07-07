import { useEffect, useState } from "react";
import { analyzeSample, analyzeUpload, getSamples } from "./api.js";
import SummaryCards from "./components/SummaryCards.jsx";
import DetectorBreakdown from "./components/DetectorBreakdown.jsx";
import DetectionsTable from "./components/DetectionsTable.jsx";

export default function App() {
  const [samples, setSamples] = useState([]);
  const [source, setSource] = useState("auth.log");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Load sample list, then auto-run the first analysis so the dashboard is
  // populated on first paint.
  useEffect(() => {
    getSamples()
      .then((data) => {
        setSamples(data.samples);
        // Allow deep-linking a specific sample via ?source=<file>.
        const wanted = new URLSearchParams(window.location.search).get("source");
        const initial =
          wanted && data.samples.includes(wanted)
            ? wanted
            : data.samples[0] || "auth.log";
        setSource(initial);
        return run(initial);
      })
      .catch((e) => setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function run(src) {
    setLoading(true);
    setError(null);
    try {
      setResult(await analyzeSample(src));
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
      setResult(await analyzeUpload(file));
      setSource(file.name);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">◈</span>
          <div>
            <h1>SIEM Threat Hunter</h1>
            <p className="subtitle">
              Detection-rule engine · frequency correlation · anomaly hunting ·
              MITRE ATT&amp;CK
            </p>
          </div>
        </div>
        <div className="controls">
          <label className="ctrl">
            <span>Log source</span>
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              {samples.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <button className="run-btn" onClick={() => run(source)} disabled={loading}>
            {loading ? "Analysing…" : "Analyse"}
          </button>
          <label className="upload-btn">
            Upload log
            <input type="file" onChange={onUpload} hidden />
          </label>
        </div>
      </header>

      {error && <div className="error-banner">⚠ {error}</div>}

      {result && (
        <main className="content">
          <div className="run-meta">
            Analysed <strong>{result.source}</strong>
          </div>
          <SummaryCards summary={result.summary} />
          <DetectorBreakdown byDetector={result.summary.by_detector} />
          <DetectionsTable detections={result.detections} />
        </main>
      )}

      {!result && !error && (
        <div className="loading-state">Loading dashboard…</div>
      )}

      <footer className="foot">
        siem-threat-hunter · React + FastAPI over the Python engine
      </footer>
    </div>
  );
}
