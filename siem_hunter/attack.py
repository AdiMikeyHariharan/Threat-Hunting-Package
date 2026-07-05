"""MITRE ATT&CK enrichment — enhancement #1.

Stock open-source rules usually stop at a severity label. We enhance every
detection by resolving the technique IDs a rule declares (``mitre: [T1110]``)
into the full technique name and its tactic(s), so an analyst immediately sees
*where in the kill chain* a finding sits.

The table below is a curated subset of the ATT&CK Enterprise matrix covering
the techniques our bundled rules reference. In a production build this would be
loaded from the official MITRE CTI STIX bundle; the interface here is
deliberately the same (look up by technique id) so swapping the source is a
one-function change.
"""

from __future__ import annotations

from .logging_config import get_logger

log = get_logger(__name__)

# id -> (name, tactic)
_ATTACK: dict[str, tuple[str, str]] = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1078": ("Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation, Defense Evasion"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation, Defense Evasion"),
    "T1136": ("Create Account", "Persistence"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence, Privilege Escalation"),
    "T1531": ("Account Access Removal", "Impact"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1046": ("Network Service Discovery", "Discovery"),
}

ATTACK_URL = "https://attack.mitre.org/techniques/{tid}/"


def enrich(technique_ids: list[str]) -> list[dict[str, str]]:
    """Resolve a list of technique ids into structured ATT&CK context."""
    enriched: list[dict[str, str]] = []
    for tid in technique_ids:
        name, tactic = _ATTACK.get(tid, ("Unknown Technique", "Unknown"))
        if name == "Unknown Technique":
            log.warning("attack_id_unmapped", technique_id=tid)
        enriched.append(
            {
                "id": tid,
                "name": name,
                "tactic": tactic,
                "url": ATTACK_URL.format(tid=tid.split(".")[0]),
            }
        )
    return enriched
