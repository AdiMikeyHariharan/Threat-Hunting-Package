// Top-row KPI cards summarising one analysis run.

const SEVERITIES = ["critical", "high", "medium", "low"];

export default function SummaryCards({ summary }) {
  if (!summary) return null;
  const sev = summary.by_severity || {};
  return (
    <div className="cards">
      <div className="card">
        <div className="card-value">{summary.detections}</div>
        <div className="card-label">Findings</div>
      </div>
      <div className="card">
        <div className="card-value">{summary.events}</div>
        <div className="card-label">Events analysed</div>
      </div>
      <div className="card">
        <div className="card-value">{summary.elapsed_ms} ms</div>
        <div className="card-label">Pipeline time</div>
      </div>
      <div className="card severity-card">
        <div className="card-label">By severity</div>
        <div className="sev-pills">
          {SEVERITIES.map((s) => (
            <span key={s} className={`pill sev-${s}`}>
              {s[0].toUpperCase()} {sev[s] || 0}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
