from siem_hunter.attack import enrich


def test_enrich_resolves_known_technique():
    (t,) = enrich(["T1110.001"])
    assert t["name"] == "Brute Force: Password Guessing"
    assert t["tactic"] == "Credential Access"
    assert t["url"].endswith("/T1110/")  # sub-technique links to parent page


def test_enrich_handles_unknown_id():
    (t,) = enrich(["T9999"])
    assert t["name"] == "Unknown Technique"
