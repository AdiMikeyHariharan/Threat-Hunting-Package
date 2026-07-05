"""siem_hunter — a lightweight, inspectable detection-and-hunting engine.

The project extracts one core SIEM capability — the detection rule engine
found in Wazuh / Sigma — as a standalone component, then enhances it with:

  * MITRE ATT&CK technique/tactic enrichment on every detection,
  * frequency (threshold) correlation for brute-force style activity, and
  * a statistical anomaly scorer for hunting unknown / novel threats.

Every stage emits structured JSON logs so the pipeline is itself auditable.
"""

__version__ = "1.0.0"
