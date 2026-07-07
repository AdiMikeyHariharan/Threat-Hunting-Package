// Horizontal bar breakdown of findings by detector type — no chart library,
// just CSS so the project stays dependency-light.

const LABELS = {
  rule: "Signature rules",
  threshold: "Frequency correlation",
  anomaly: "Anomaly hunter",
};

const COLORS = {
  rule: "#3b82f6",
  threshold: "#f59e0b",
  anomaly: "#a855f7",
};

export default function DetectorBreakdown({ byDetector }) {
  if (!byDetector) return null;
  const entries = Object.entries(byDetector);
  const max = Math.max(1, ...entries.map(([, v]) => v));

  return (
    <div className="panel">
      <h3 className="panel-title">Detections by engine component</h3>
      <div className="bars">
        {entries.length === 0 && <div className="muted">No detections.</div>}
        {entries.map(([key, value]) => (
          <div className="bar-row" key={key}>
            <div className="bar-label">{LABELS[key] || key}</div>
            <div className="bar-track">
              <div
                className="bar-fill"
                style={{
                  width: `${(value / max) * 100}%`,
                  background: COLORS[key] || "#64748b",
                }}
              />
            </div>
            <div className="bar-value">{value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
