"""Build the full MITRE ATT&CK Enterprise technique lookup from official STIX.

Downloads the MITRE ATT&CK Enterprise STIX 2.1 bundle and compiles every
(sub)technique into a compact lookup the engine loads at runtime:

    { "T1110": {"name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"}, ... }

Run:  python scripts/build_attack_map.py
Output: siem_hunter/data/attack_enterprise.json

Re-run whenever you want to refresh against a newer ATT&CK release.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

# Official MITRE CTI mirror (versionless = latest published release).
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

OUT = Path(__file__).resolve().parents[1] / "siem_hunter" / "data" / "attack_enterprise.json"


def _fallback_label(phase_name: str) -> str:
    """Used only if a phase has no matching tactic object: 'foo-bar' -> 'Foo Bar'."""
    return " ".join(w.capitalize() for w in phase_name.split("-"))


def build() -> dict[str, dict[str, str]]:
    print(f"downloading STIX bundle …\n  {STIX_URL}", file=sys.stderr)
    with urllib.request.urlopen(STIX_URL, timeout=180) as resp:
        bundle = json.load(resp)

    objects = bundle.get("objects", [])

    # Authoritative shortname -> tactic display name, from the bundle itself,
    # so e.g. 'command-and-control' -> 'Command and Control' (exact casing).
    tactic_names = {
        o["x_mitre_shortname"]: o["name"]
        for o in objects
        if o.get("type") == "x-mitre-tactic" and o.get("x_mitre_shortname")
    }

    techniques = [
        o for o in objects
        if o.get("type") == "attack-pattern"
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
    ]

    # First pass: id -> raw name (needed to prefix sub-techniques with parent).
    raw_name: dict[str, str] = {}
    for o in techniques:
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                raw_name[ref["external_id"]] = o.get("name", "")

    mapping: dict[str, dict[str, str]] = {}
    for o in techniques:
        ext = next(
            (r for r in o.get("external_references", [])
             if r.get("source_name") == "mitre-attack" and r.get("external_id")),
            None,
        )
        if not ext:
            continue
        tid = ext["external_id"]
        name = o.get("name", "")
        # For a sub-technique (T1110.001) show "Parent: Sub" for readability.
        if "." in tid:
            parent = raw_name.get(tid.split(".")[0])
            if parent:
                name = f"{parent}: {name}"

        tactics = [
            tactic_names.get(p["phase_name"], _fallback_label(p["phase_name"]))
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        mapping[tid] = {
            "name": name,
            "tactic": ", ".join(tactics) if tactics else "Unknown",
            "url": ext.get("url", f"https://attack.mitre.org/techniques/{tid}/"),
        }

    return mapping


def main() -> int:
    mapping = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(mapping, indent=0, sort_keys=True), encoding="utf-8")
    subs = sum(1 for k in mapping if "." in k)
    print(f"wrote {len(mapping)} techniques ({len(mapping) - subs} base + {subs} "
          f"sub) -> {OUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
