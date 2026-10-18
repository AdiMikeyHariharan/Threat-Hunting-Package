# siem-threat-hunter

A threat-hunting engine that **extracts one core SIEM capability — the detection
rule engine (as found in [Wazuh](https://wazuh.com) and the vendor-neutral
[Sigma](https://github.com/SigmaHQ/sigma) standard) — and enhances it** with
three additions that a stock rule engine lacks:

1. **MITRE ATT&CK enrichment** — every detection is resolved against the **full
   ATT&CK Enterprise matrix** (697 techniques, compiled from the official MITRE
   STIX bundle) into its technique name + tactic, placing each finding on the
   kill chain automatically.
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
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the SIEM detection engine design rationale, and
> [`docs/MICRO_SASE_ACTION_PLAN.md`](docs/MICRO_SASE_ACTION_PLAN.md) for the Micro-SASE Enterprise API Gateway & IAM architecture roadmap.

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

## Web dashboard (visual UI)

The findings can be explored visually in a **React (Vite) dashboard** backed by a
**FastAPI** server that wraps the same Python engine — the engine stays the
single source of truth; the API just exposes it over HTTP.

```bash
# 1. Backend (from the project root, venv active)
pip install -r requirements.txt
uvicorn web.backend.app:app --port 8000

# 2. Frontend (in a second terminal)
cd frontend
npm install
npm run dev          # opens http://localhost:5173
```

The dashboard shows KPI cards (findings / events / pipeline time / severity
mix), a per-engine-component breakdown (signature vs correlation vs anomaly),
and a findings table where each row expands to reveal the ATT&CK techniques,
correlation context, and underlying event ids. You can switch sample logs or
upload your own from the top bar.

API endpoints: `GET /api/analyze?source=<file>`, `POST /api/analyze` (file
upload), `GET /api/samples`, `GET /api/rules`, `GET /api/health`.

### Sign in and SIEM permissions

The dashboard signs in through the Micro-SASE gateway (`/api/gateway/auth/token`).
Use the existing demo IAM users from `docs/MICRO_SASE_ACTION_PLAN.md` (Alice,
Bob, or Charlie). Protected SIEM routes validate the gateway JWT on the server:
admins have full access, developers can analyze and upload, and finance users
can read the rule/sample catalogue and analyze bundled samples. Only admins can
analyze the live gateway audit log. The browser session lasts until sign out or
the gateway token expires.

## Detection catalogue

The bundled rules mirror detection content real SOCs run (SigmaHQ, Elastic
Security, Splunk ESCU), adapted to Linux auth/syslog + network telemetry. Every
rule is aligned to a current MITRE ATT&CK technique.

| Rule | Detects | Type | Sev | ATT&CK |
|---|---|---|---|---|
| SSH-BRUTE-0001 | SSH brute force (repeated fails, one IP) | correlation | High | T1110.001 |
| PWD-SPRAY-0001 | Password spraying (one IP, many accounts) | correlation | High | T1110.003 |
| CRED-STUFF-0001 | Credential stuffing (one account, many IPs) | correlation | High | T1110.004 |
| PORT-SCAN-0001 | Port scan (many distinct ports, one IP) | correlation | High | T1046 |
| SSH-INVALID-USER-0001 | Login for non-existent user (enumeration) | signature | Medium | T1110 |
| SSH-ROOT-LOGIN-0001 | Successful root SSH login | signature | High | T1078 |
| OFFHOURS-ROOT-0001 | Root login outside business hours | signature | High | T1078 |
| PRIVGRP-0001 | User added to sudo/wheel/admin group | signature | High | T1098 |
| SUDO-ROOT-SHELL-0001 | Interactive root shell via sudo | signature | High | T1548.003 |
| ROOT-ACCOUNT-0001 | UID=0 (root-equivalent) account created | signature | Critical | T1136.001 |
| NEW-ACCOUNT-0001 | New local account created | signature | Medium | T1136.001 |
| FW-DISABLE-0001 | Host firewall disabled / flushed | signature | High | T1686 |
| PASSWD-CHANGE-0001 | Local account password changed | signature | Medium | T1098 |
| SUDO-ABUSE-0001 | sudo authentication failure | signature | Medium | T1548.003 |
| ANOMALY-VOLUME-0001 | Statistical volume outlier (no signature) | anomaly | Med/High | — |

See them fire end to end: `python -m siem_hunter.cli --log
sample_data/enterprise_sim.log --rules rules`.

> **Note on ATT&CK currency:** the firewall rule maps to **T1686**, not the
> commonly-cited `T1562.004` — the recent ATT&CK release renumbered "Disable or
> Modify System Firewall" and moved it under the new *Defense Impairment*
> tactic. Because enrichment runs against the live compiled table, stale ids are
> caught rather than silently mis-reported.

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

**Distinct-value threshold — port-scan detection:** add `distinct: <field>` to a
threshold rule and it fires on the count of *distinct* values (not raw volume).
Connections to many different ports from one source = a scan; repeated
connections to one port do not trigger it.

```yaml
id: PORT-SCAN-0001
title: Port scan - many distinct ports probed from one source
level: high
type: threshold
detection:
  selection:
    message|contains: "connection from"
  condition: selection
group_by: src_ip
threshold:
  count: 15
  window_seconds: 10
  distinct: dst_port        # 15+ distinct ports in 10s from one IP
mitre: [T1046]
```

**Field modifiers:** `field|contains`, `|startswith`, `|endswith`, `|re`
(regex), `|gte`, `|lte`, or bare `field:` for equality. A list value means
"any of these" (OR).

**Condition language:** selection names combined with `and` / `or` / `not`,
parentheses, and the quantifiers `all of them` / `N of them`. Malformed
conditions are rejected at load time, not mid-run.

---

## Simulate a real attack (nmap)

`scripts/simulate_scan.py` performs an **end-to-end** demo (not synthetic data):
it binds a range of local ports, runs a real `nmap` connect-scan against them,
and logs the actual connections — which the engine then flags as a port scan.

```bash
python scripts/simulate_scan.py                                  # runs nmap vs localhost
python -m siem_hunter.cli --log sample_data/portscan.log --rules rules
#  -> PORT-SCAN-0001 (High) fires, mapped to T1046 Network Service Discovery
```

Only `127.0.0.1` is scanned, so it is self-contained and safe. Regenerate the
full ATT&CK lookup any time with `python scripts/build_attack_map.py`.

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
