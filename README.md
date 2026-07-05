# siem-threat-hunter

A threat-hunting engine that **extracts one core SIEM capability — the detection
rule engine (as found in [Wazuh](https://wazuh.com) and the vendor-neutral
[Sigma](https://github.com/SigmaHQ/sigma) standard) — and enhances it** with
three additions that a stock rule engine lacks:

1. **MITRE ATT&CK enrichment** — every detection is resolved to its technique
   name + tactic, so a finding is placed on the kill chain automatically.
2. **Frequency / threshold correlation** — Wazuh-style stateful rules that turn
   many benign single events ("one failed login") into one meaningful finding
   ("brute force from one IP").
3. **A statistical anomaly hunter** — an unsupervised outlier detector
   (median + MAD modified z-score) that surfaces *unknown* threats no signature
   was written for.

Everything runs through an **extensive structured-logging mechanism** (JSON,
run-correlated, rotating) so the pipeline is itself fully auditable — which is
the whole point of a SIEM.

> Built as a semester threat-hunting project. See
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design rationale and a
> report skeleton.

---

## Why this satisfies the assignment

| Requirement | How it is met |
|---|---|
| Extract a feature from a well-known SIEM | `siem_hunter/rule_engine.py` re-implements the Sigma/Wazuh detection-rule core: named selections, field modifiers, and a boolean `condition` language. |
| Enhance it | ATT&CK enrichment (`attack.py`), stateful frequency correlation (`rule_engine.py` threshold rules), and a statistical anomaly hunter (`anomaly.py`). |
| Extensive & proper logging | `logging_config.py`: structured JSON to a rotating file + readable console, one `run_id` per run bound to every line, ISO-UTC timestamps, module/function callsite, and per-stage summary/timing logs. |

---

## Quick start

```bash
cd siem-threat-hunter
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Analyse the bundled sample auth.log
python -m siem_hunter.cli \
    --log sample_data/auth.log \
    --rules rules \
    --format syslog \
    --out logs/detections.json
```

You should see 9 findings, including an SSH brute-force correlation, a root
login, and the anomaly hunter independently flagging the same attacker IP.

Structured logs are written to `logs/siem_hunter.jsonl` (one JSON object per
line); the detection report is written to `logs/detections.json`.

### CLI options

```
--log            log file to analyse (required)
--rules          directory of YAML rules            (default: rules)
--format         syslog | json                      (default: syslog)
--out            detection report path              (default: logs/detections.json)
--anomaly-field  entity field to baseline on        (default: src_ip)
--log-level      DEBUG | INFO | WARNING | ERROR     (default: INFO)
--quiet          suppress console logs (file still written)
```

---

## Writing rules

Rules are YAML in the [Sigma](https://github.com/SigmaHQ/sigma) style. A file
may contain multiple rules separated by `---`.

**Signature rule:**

```yaml
id: SSH-INVALID-USER-0001
title: SSH login attempt for non-existent (invalid) user
level: medium            # low | medium | high | critical
type: detection
detection:
  selection:
    program: sshd
    message|contains: "Invalid user"
  condition: selection
mitre: [T1110, T1078]
```

**Frequency (threshold) rule — the correlation enhancement:**

```yaml
id: SSH-BRUTE-0001
title: SSH brute force - repeated failed logins from one source
level: high
type: threshold
detection:
  selection:
    program: sshd
    message|contains: "Failed password"
  condition: selection
group_by: src_ip
threshold:
  count: 5
  window_seconds: 60
mitre: [T1110.001, T1021.004]
```

**Field modifiers:** `field|contains`, `|startswith`, `|endswith`, `|re`
(regex), `|gte`, `|lte`, or bare `field:` for equality. A list value means
"any of these" (OR).

**Condition language:** selection names combined with `and` / `or` / `not`,
parentheses, and the quantifiers `all of them` / `N of them`. Malformed
conditions are rejected at load time, not mid-run.

---

## Tests

```bash
pip install pytest
python -m pytest -q          # 18 tests: parser, engine, threshold, anomaly, ATT&CK
```

---

## Project layout

```
siem_hunter/
  logging_config.py   structured JSON logging setup (run_id, rotating file)
  models.py           Event / Detection dataclasses
  parser.py           syslog + JSON log normalisation
  rule_engine.py      *** extracted feature *** selections, condition lang, threshold correlation
  attack.py           MITRE ATT&CK enrichment (enhancement)
  anomaly.py          statistical outlier hunter (enhancement)
  pipeline.py         ingest -> detect -> hunt -> report orchestration
  cli.py              command-line entry point
rules/                bundled Sigma-style detection rules
sample_data/          example auth.log with a planted attack
tests/                pytest suite
docs/ARCHITECTURE.md  design rationale + report skeleton
```
