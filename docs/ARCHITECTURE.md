# Architecture & Design Rationale

This document explains *what* was extracted, *how* it was enhanced, and *why*
each design decision was made. It doubles as a skeleton you can expand into the
written report.

---

## 1. The feature that was extracted

Every SIEM (Splunk, Elastic Security, QRadar, Wazuh) is built around a
**detection rule engine**: a component that evaluates normalised log events
against a library of rules and raises alerts. The most inspectable, open
version of this is the **Wazuh** ruleset combined with the vendor-neutral
**Sigma** rule format. This project re-implements that engine's core in
`siem_hunter/rule_engine.py`:

* **Selections** — named groups of field/value matchers.
* **Field modifiers** — `contains`, `startswith`, `endswith`, `re`, `gte`,
  `lte`, equality; list values act as OR. (Directly modelled on Sigma modifiers.)
* **Condition language** — a boolean mini-grammar over selection names
  (`and` / `or` / `not`, parentheses, `all of them`, `N of them`), evaluated by
  a small recursive-descent parser.

This is the honest "extract a feature" deliverable: a standalone, testable
re-creation of the detection core, decoupled from any specific SIEM's storage
or UI.

---

## 2. The three enhancements

A stock signature engine has well-known blind spots. Each enhancement targets
one:

| Blind spot in a stock engine | Enhancement | Where |
|---|---|---|
| Alerts are just a severity label with no context on attacker intent. | **MITRE ATT&CK enrichment** — resolve technique ids to name + tactic + link. | `attack.py` |
| A single event ("one failed login") is benign; the *pattern* is the threat. | **Frequency/threshold correlation** — stateful sliding-window rules. | `rule_engine.py` (`type: threshold`) |
| Signatures only catch known attacks; hunting needs to find the *unknown*. | **Statistical anomaly detector** — robust volume outliers via median + MAD. | `anomaly.py` |

### 2.1 Frequency correlation (Wazuh-style)

A threshold rule buffers matching events per `group_by` key in a sliding time
window (`deque`, evicting events older than `window_seconds`). When `count`
events fall inside the window, one detection fires referencing all of them, and
the window is cleared to avoid re-alerting on every subsequent event. This is
how real SIEMs turn brute-force noise into a single actionable finding.

### 2.2 Statistical anomaly hunting

Rather than a black-box ML model (hard to defend in a report), the hunter uses
the **modified z-score**:

```
Mi = 0.6745 * (xi − median) / MAD          MAD = median(|xi − median|)
```

MAD (Median Absolute Deviation) is used instead of standard deviation because
it is **robust**: one extremely noisy host cannot inflate the baseline and mask
the others. Entities with `Mi ≥ 3.5` (the conventional cut-off) are reported.
The statistic is fully explainable — every anomaly detection records the
median, MAD, and score it was based on.

---

## 3. Data flow

```
                 ┌─────────────┐
  raw log lines  │   parser    │  syslog / JSON  →  normalised Event{fields}
  ───────────────▶ (normalise) │
                 └──────┬──────┘
                        │  events sorted by timestamp
                        ▼
        ┌───────────────────────────────┐
        │          RuleEngine            │
        │  • signature rules (per event) │──► Detection (rule)
        │  • threshold rules (windowed)  │──► Detection (threshold)
        └───────────────┬───────────────┘
                        │  every event also observed by ↓
                        ▼
                 ┌─────────────┐
                 │  Anomaly    │  finalize() over whole run
                 │  hunter     │──────────────────────────────► Detection (anomaly)
                 └──────┬──────┘
                        ▼
                 ┌─────────────┐
                 │  reporting  │  JSON report + ATT&CK-enriched summary
                 └─────────────┘

        Every stage emits structured JSON logs (one run_id per run).
```

---

## 4. The logging mechanism (the "proper logging" requirement)

A SIEM's own telemetry must be as trustworthy as the data it ingests, so the
project treats its logs as a first-class artifact (`logging_config.py`):

* **Structured JSON**, one object per line → greppable and re-ingestable by a
  real SIEM.
* **`run_id`** generated per process and bound to *every* line via
  `contextvars`, so one analysis run is trivially correlated.
* **ISO-8601 UTC timestamps**, log level, and **module + function** callsite on
  every record.
* **Rotating file handler** (5 MB × 5 backups) so long runs don't lose history.
* **Per-stage events**: `ingestion_complete` (parsed/skipped counts),
  `rule_loaded` / `rules_loaded_total`, each `detection`, `anomaly_scan_complete`,
  and `pipeline_complete` (event count, per-detector totals, elapsed_ms).
* Dev-friendly **colourised console** mirror, suppressible with `--quiet`.

---

## 5. Report skeleton

Suggested section mapping for the written submission:

1. **Introduction** — what a SIEM detection engine is; the hunting gap.
2. **Background / Literature** — Sigma format, Wazuh ruleset, MITRE ATT&CK,
   robust statistics (median/MAD) for anomaly detection.
3. **Feature extraction** — §1 above; show a rule and how it is evaluated.
4. **Enhancements** — §2; contrast stock vs enhanced behaviour on the sample.
5. **Logging & auditability** — §4; include a screenshot of `siem_hunter.jsonl`.
6. **Evaluation** — run on `sample_data/auth.log`; the 9 findings; note that the
   anomaly hunter *independently* flags the brute-force IP (defence in depth).
7. **Limitations & future work** — per-window anomaly baselining, more log
   sources, rule unit-test harness.
8. **Conclusion.**

---

## 6. Limitations (be honest in the report)

* The ATT&CK table is the **full Enterprise matrix** (697 techniques) compiled
  from the official MITRE STIX bundle via `scripts/build_attack_map.py`; re-run
  that script to refresh against a newer ATT&CK release.
* The anomaly detector baselines volume across the whole run, not per rolling
  window — fine for batch analysis, not streaming.
* Only syslog (`auth.log`) and generic JSON parsers ship; other sources need a
  new parser function (rules are unaffected).
