"""MITRE ATT&CK enrichment — enhancement #1.

Stock open-source rules usually stop at a severity label. We enhance every
detection by resolving the technique ids a rule declares (``mitre: [T1110]``)
into the full technique name and its tactic(s), so an analyst immediately sees
*where in the kill chain* a finding sits.

The lookup is the **full MITRE ATT&CK Enterprise matrix**, compiled from the
official STIX bundle into ``data/attack_enterprise.json`` by
``scripts/build_attack_map.py``. Re-run that script to refresh against a newer
ATT&CK release. If the data file is absent, we fall back to a tiny built-in map
so the engine still runs.
"""

from __future__ import annotations

import json
from pathlib import Path

from .logging_config import get_logger

log = get_logger(__name__)

_DATA_FILE = Path(__file__).resolve().parent / "data" / "attack_enterprise.json"
_FALLBACK_URL = "https://attack.mitre.org/techniques/{tid}/"

# Minimal built-in map used only if the compiled data file is missing.
_FALLBACK: dict[str, dict[str, str]] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Stealth, Persistence, "
              "Privilege Escalation, Initial Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1136": {"name": "Create Account", "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism",
              "tactic": "Privilege Escalation"},
}


def _load_table() -> dict[str, dict[str, str]]:
    try:
        table = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
        log.info("attack_table_loaded", source=_DATA_FILE.name,
                 techniques=len(table))
        return table
    except FileNotFoundError:
        log.warning("attack_table_missing_using_fallback",
                    hint="run scripts/build_attack_map.py")
        return _FALLBACK
    except (json.JSONDecodeError, OSError) as exc:
        log.error("attack_table_load_error", error=str(exc))
        return _FALLBACK


# Loaded once at import.
_ATTACK = _load_table()


def enrich(technique_ids: list[str]) -> list[dict[str, str]]:
    """Resolve a list of technique ids into structured ATT&CK context."""
    enriched: list[dict[str, str]] = []
    for tid in technique_ids:
        entry = _ATTACK.get(tid)
        if entry is None:
            log.warning("attack_id_unmapped", technique_id=tid)
            entry = {"name": "Unknown Technique", "tactic": "Unknown"}
        enriched.append(
            {
                "id": tid,
                "name": entry["name"],
                "tactic": entry["tactic"],
                "url": entry.get("url", _FALLBACK_URL.format(tid=tid.split(".")[0])),
            }
        )
    return enriched
