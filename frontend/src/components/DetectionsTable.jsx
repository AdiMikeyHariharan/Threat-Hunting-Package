// The core findings table. Rows expand to reveal ATT&CK context and the raw
// event ids / detection context the engine produced.

import { useState } from "react";

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const DETECTOR_LABEL = {
  rule: "signature",
  threshold: "correlation",
  anomaly: "anomaly",
};

function Row({ d }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr className="det-row" onClick={() => setOpen((o) => !o)}>
        <td>
          <span className={`badge sev-${d.severity}`}>{d.severity}</span>
        </td>
        <td className="det-title">{d.title}</td>
        <td>
          <span className="badge detector">{DETECTOR_LABEL[d.detector] || d.detector}</span>
        </td>
        <td className="mono">{d.entity || "—"}</td>
        <td className="mono">{d.event_ids.length}</td>
        <td className="mitre-cell">
          {d.mitre.length === 0 && <span className="muted">—</span>}
          {d.mitre.map((m) => (
            <a
              key={m.id}
              className="chip"
              href={m.url}
              target="_blank"
              rel="noreferrer"
              title={`${m.name} — ${m.tactic}`}
              onClick={(e) => e.stopPropagation()}
            >
              {m.id}
            </a>
          ))}
        </td>
        <td className="expand-caret">{open ? "▾" : "▸"}</td>
      </tr>
      {open && (
        <tr className="det-detail-row">
          <td colSpan={7}>
            <div className="det-detail">
              <div>
                <span className="k">Rule</span>
                <span className="v mono">{d.rule_id}</span>
              </div>
              {d.timestamp && (
                <div>
                  <span className="k">Time</span>
                  <span className="v mono">{d.timestamp}</span>
                </div>
              )}
              {d.mitre.length > 0 && (
                <div>
                  <span className="k">ATT&CK</span>
                  <span className="v">
                    {d.mitre.map((m) => `${m.id} · ${m.name} (${m.tactic})`).join(" | ")}
                  </span>
                </div>
              )}
              <div>
                <span className="k">Context</span>
                <pre className="v ctx">{JSON.stringify(d.context, null, 2)}</pre>
              </div>
              <div>
                <span className="k">Event IDs</span>
                <span className="v mono small">{d.event_ids.join(", ")}</span>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function DetectionsTable({ detections }) {
  const sorted = [...detections].sort(
    (a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9)
  );
  return (
    <div className="panel">
      <h3 className="panel-title">Findings ({detections.length})</h3>
      <table className="det-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Detection</th>
            <th>Source</th>
            <th>Entity</th>
            <th>Events</th>
            <th>ATT&CK</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((d, i) => (
            <Row d={d} key={`${d.rule_id}-${i}`} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
