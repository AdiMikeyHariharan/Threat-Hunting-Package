from datetime import datetime, timedelta, timezone

import pytest

from siem_hunter.models import Event
from siem_hunter.rule_engine import (
    Rule,
    RuleEngine,
    _match_selection,
    load_rules,
)


# ----- field matchers / condition language --------------------------------- #
def test_contains_modifier_is_case_insensitive(make_event):
    ev = make_event({"message": "Failed PASSWORD for root"})
    assert _match_selection(ev, {"message|contains": "failed password"})


def test_numeric_gte_modifier(make_event):
    ev = make_event({"pid": 5000})
    assert _match_selection(ev, {"pid|gte": 1000})
    assert not _match_selection(ev, {"pid|gte": 9000})


def test_list_value_is_or(make_event):
    ev = make_event({"user": "postgres"})
    assert _match_selection(ev, {"user": ["oracle", "postgres", "admin"]})


def _rule(condition, selections, rule_type="detection", **kw):
    return Rule(id="R", title="t", severity="low", rule_type=rule_type,
                selections=selections, condition=condition, **kw)


def test_condition_and_not(make_event):
    ev = make_event({"program": "sshd", "message": "Accepted", "user": "root"})
    rule = _rule("selection and target",
                 {"selection": {"message|contains": "Accepted"},
                  "target": {"user": "root"}})
    assert rule.matches_event(ev)

    ev2 = make_event({"program": "sshd", "message": "Accepted", "user": "alice"})
    assert not rule.matches_event(ev2)


def test_condition_or_and_quantifier(make_event):
    ev = make_event({"a": "1", "b": "x"})
    rule = _rule("1 of them",
                 {"s1": {"a": "1"}, "s2": {"b": "nope"}})
    assert rule.matches_event(ev)


def test_invalid_condition_rejected_at_load(tmp_path):
    (tmp_path / "bad.yml").write_text(
        "id: BAD\ntitle: t\nlevel: low\n"
        "detection:\n  sel:\n    a: b\n  condition: sel and missing\n"
    )
    assert load_rules(tmp_path) == []  # bad rule dropped, not crashed


# ----- threshold correlation ----------------------------------------------- #
def _failed(ip, offset_s):
    ts = datetime(2026, 3, 10, 13, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_s)
    return Event(timestamp=ts, source="auth.log",
                 raw=f"fail-{ip}-{offset_s}",
                 fields={"program": "sshd", "message": "Failed password",
                         "src_ip": ip})


def test_threshold_fires_at_count_within_window():
    rule = _rule("selection",
                 {"selection": {"program": "sshd", "message|contains": "Failed password"}},
                 rule_type="threshold", group_by="src_ip",
                 threshold_count=5, window_seconds=60)
    engine = RuleEngine([rule])

    dets = []
    for i in range(5):
        dets += engine.evaluate(_failed("45.83.19.7", i * 2))
    assert len(dets) == 1
    assert dets[0].detector == "threshold"
    assert dets[0].entity == "45.83.19.7"
    assert dets[0].context["count"] == 5


def test_threshold_does_not_fire_outside_window():
    rule = _rule("selection",
                 {"selection": {"program": "sshd", "message|contains": "Failed password"}},
                 rule_type="threshold", group_by="src_ip",
                 threshold_count=3, window_seconds=10)
    engine = RuleEngine([rule])
    # 3 events spread over 40s -> never 3 inside a 10s window.
    dets = []
    for i in range(3):
        dets += engine.evaluate(_failed("1.1.1.1", i * 20))
    assert dets == []


def test_bundled_rules_load():
    import pathlib
    rules = load_rules(pathlib.Path(__file__).parent.parent / "rules")
    ids = {r.id for r in rules}
    assert "SSH-BRUTE-0001" in ids
    assert "SUDO-ABUSE-0001" in ids  # proves multi-doc file parsing
