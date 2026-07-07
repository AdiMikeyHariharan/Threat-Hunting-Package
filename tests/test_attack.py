from siem_hunter.attack import enrich


def test_enrich_resolves_known_technique():
    (t,) = enrich(["T1110.001"])
    assert t["name"] == "Brute Force: Password Guessing"
    assert t["tactic"] == "Credential Access"
    assert "T1110" in t["url"]


def test_enrich_resolves_base_technique():
    (t,) = enrich(["T1078"])
    assert t["name"] == "Valid Accounts"
    assert "Persistence" in t["tactic"]


def test_full_table_is_loaded():
    # The compiled table should carry the whole Enterprise matrix, not a subset.
    from siem_hunter.attack import _ATTACK

    assert len(_ATTACK) > 500


def test_enrich_handles_unknown_id():
    (t,) = enrich(["T9999"])
    assert t["name"] == "Unknown Technique"
