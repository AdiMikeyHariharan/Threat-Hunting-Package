"""The detection rule engine — the SIEM feature this project extracts.

This is a self-contained re-implementation of the rule-matching core shared by
Wazuh and the Sigma standard. It supports:

Signature rules (``type: detection``)
    Named *selections* of field matchers, combined by a small boolean
    ``condition`` language (``and`` / ``or`` / ``not`` / parentheses /
    ``all of them`` / ``N of them``). Field matchers support Sigma-style
    modifiers via ``field|modifier`` keys: ``contains``, ``startswith``,
    ``endswith``, ``re`` (regex) and ``gte``/``lte`` for numbers, plus plain
    equality. A list value means "any of these" (implicit OR).

Frequency rules (``type: threshold``)  -- enhancement
    A Wazuh-style correlation: buffer events matching ``selection`` per
    ``group_by`` key and fire once ``count`` of them occur within
    ``window_seconds``. This turns single benign lines ("one failed login")
    into a meaningful finding ("many failed logins from one IP" = brute force).

Both rule types can declare ``mitre:`` technique ids, resolved by
:mod:`siem_hunter.attack`.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import attack
from .logging_config import get_logger
from .models import Detection, Event

log = get_logger(__name__)

_VALID_SEVERITY = {"low", "medium", "high", "critical"}


# --------------------------------------------------------------------------- #
# Field matching                                                              #
# --------------------------------------------------------------------------- #
def _match_field(event: Event, key: str, expected: Any) -> bool:
    """Evaluate a single ``field|modifier: value`` clause against an event."""
    if "|" in key:
        field_name, modifier = key.split("|", 1)
    else:
        field_name, modifier = key, "eq"

    actual = event.get(field_name)
    if actual is None:
        return False

    # A list of expected values is an implicit OR.
    if isinstance(expected, list):
        return any(_apply_modifier(actual, modifier, exp) for exp in expected)
    return _apply_modifier(actual, modifier, expected)


def _apply_modifier(actual: Any, modifier: str, expected: Any) -> bool:
    if modifier == "eq":
        return str(actual) == str(expected)
    if modifier == "contains":
        return str(expected).lower() in str(actual).lower()
    if modifier == "startswith":
        return str(actual).lower().startswith(str(expected).lower())
    if modifier == "endswith":
        return str(actual).lower().endswith(str(expected).lower())
    if modifier == "re":
        return re.search(str(expected), str(actual)) is not None
    if modifier in ("gte", "lte"):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return a >= e if modifier == "gte" else a <= e
    log.warning("unknown_field_modifier", modifier=modifier)
    return False


def _match_selection(event: Event, selection: dict[str, Any]) -> bool:
    """A selection matches when *all* of its field clauses match (implicit AND)."""
    return all(_match_field(event, k, v) for k, v in selection.items())


# --------------------------------------------------------------------------- #
# Condition mini-language                                                      #
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"\(|\)|\ball of them\b|\b\d+ of them\b|\band\b|\bor\b|\bnot\b|[\w*]+")


def _tokenize(condition: str) -> list[str]:
    return _TOKEN_RE.findall(condition.strip())


class _ConditionParser:
    """Recursive-descent parser for the Sigma-style condition string.

    Grammar (loosely)::

        expr   := term ( 'or' term )*
        term   := factor ( 'and' factor )*
        factor := 'not' factor | '(' expr ')' | quantifier | NAME
        quantifier := 'all of them' | N 'of them'
    """

    def __init__(self, tokens: list[str], selection_names: list[str]):
        self.tokens = tokens
        self.pos = 0
        self.selection_names = selection_names

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self, results: dict[str, bool]) -> bool:
        value = self._expr(results)
        if self.pos != len(self.tokens):
            raise ValueError(f"trailing tokens in condition near {self._peek()!r}")
        return value

    def _expr(self, results: dict[str, bool]) -> bool:
        value = self._term(results)
        while self._peek() == "or":
            self._next()
            value = self._term(results) or value
        return value

    def _term(self, results: dict[str, bool]) -> bool:
        value = self._factor(results)
        while self._peek() == "and":
            self._next()
            value = self._factor(results) and value
        return value

    def _factor(self, results: dict[str, bool]) -> bool:
        tok = self._peek()
        if tok == "not":
            self._next()
            return not self._factor(results)
        if tok == "(":
            self._next()
            value = self._expr(results)
            if self._next() != ")":
                raise ValueError("unbalanced parentheses in condition")
            return value
        if tok == "all of them":
            self._next()
            return all(results[n] for n in self.selection_names)
        if tok and tok.endswith("of them"):
            self._next()
            n = int(tok.split()[0])
            return sum(results[s] for s in self.selection_names) >= n
        # Otherwise a selection name.
        name = self._next()
        if name not in results:
            raise ValueError(f"condition references unknown selection {name!r}")
        return results[name]


# --------------------------------------------------------------------------- #
# Rule model                                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    id: str
    title: str
    severity: str
    rule_type: str                       # "detection" | "threshold"
    selections: dict[str, dict[str, Any]]
    condition: str
    mitre: list[str] = field(default_factory=list)
    # threshold-only:
    group_by: str | None = None
    threshold_count: int = 0
    window_seconds: int = 0

    def matches_event(self, event: Event) -> bool:
        """True if this rule's condition holds for a single event."""
        results = {name: _match_selection(event, sel)
                   for name, sel in self.selections.items()}
        parser = _ConditionParser(_tokenize(self.condition),
                                  list(self.selections.keys()))
        return parser.parse(results)


def _validate_rule(data: dict[str, Any], path: Path) -> Rule:
    required = ("id", "title", "level", "detection")
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"{path.name}: missing required keys {missing}")

    level = str(data["level"]).lower()
    if level not in _VALID_SEVERITY:
        raise ValueError(f"{path.name}: invalid level {level!r}")

    detection = data["detection"]
    if "condition" not in detection:
        raise ValueError(f"{path.name}: detection block needs a 'condition'")

    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise ValueError(f"{path.name}: detection block has no selections")

    rule_type = str(data.get("type", "detection")).lower()
    rule = Rule(
        id=str(data["id"]),
        title=str(data["title"]),
        severity=level,
        rule_type=rule_type,
        selections=selections,
        condition=str(detection["condition"]),
        mitre=[str(t) for t in data.get("mitre", [])],
    )

    if rule_type == "threshold":
        th = data.get("threshold", {})
        rule.group_by = data.get("group_by")
        rule.threshold_count = int(th.get("count", 0))
        rule.window_seconds = int(th.get("window_seconds", 0))
        if not rule.group_by or rule.threshold_count <= 0 or rule.window_seconds <= 0:
            raise ValueError(
                f"{path.name}: threshold rule needs group_by, "
                f"threshold.count and threshold.window_seconds"
            )
    elif rule_type != "detection":
        raise ValueError(f"{path.name}: unknown rule type {rule_type!r}")

    # Fail fast on malformed conditions at load time, not mid-stream.
    _ConditionParser(_tokenize(rule.condition), list(selections.keys())).parse(
        {name: False for name in selections}
    )
    return rule


def load_rules(rules_dir: str | Path) -> list[Rule]:
    """Load and validate every ``*.yml`` / ``*.yaml`` rule in a directory."""
    rules_dir = Path(rules_dir)
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("*.y*ml")):
        try:
            # A file may hold multiple rules separated by '---'.
            documents = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8"))
                         if d]
        except yaml.YAMLError as exc:
            log.error("rule_load_failed", path=str(path), error=str(exc))
            continue
        for data in documents:
            try:
                rule = _validate_rule(data, path)
            except ValueError as exc:
                log.error("rule_load_failed", path=str(path), error=str(exc))
                continue
            rules.append(rule)
            log.info("rule_loaded", rule_id=rule.id, title=rule.title,
                     type=rule.rule_type, severity=rule.severity)
    log.info("rules_loaded_total", count=len(rules), directory=str(rules_dir))
    return rules


# --------------------------------------------------------------------------- #
# Engine                                                                       #
# --------------------------------------------------------------------------- #
class RuleEngine:
    """Evaluates events against signature and frequency rules."""

    def __init__(self, rules: list[Rule]):
        self.signature_rules = [r for r in rules if r.rule_type == "detection"]
        self.threshold_rules = [r for r in rules if r.rule_type == "threshold"]
        # Per threshold-rule sliding windows: rule_id -> group_key -> deque[Event]
        self._windows: dict[str, dict[str, deque[Event]]] = {
            r.id: defaultdict(deque) for r in self.threshold_rules
        }

    def evaluate(self, event: Event) -> list[Detection]:
        """Return every detection produced by this event.

        Events must be fed in timestamp order for threshold windows to be
        correct (the pipeline guarantees this).
        """
        detections: list[Detection] = []
        detections.extend(self._eval_signatures(event))
        detections.extend(self._eval_thresholds(event))
        return detections

    def _eval_signatures(self, event: Event) -> list[Detection]:
        out = []
        for rule in self.signature_rules:
            try:
                if rule.matches_event(event):
                    out.append(self._build_detection(rule, [event], event,
                                                      entity=self._entity(event)))
                    log.info("detection", rule_id=rule.id, detector="rule",
                             severity=rule.severity, event_id=event.event_id,
                             entity=self._entity(event))
            except ValueError as exc:  # bad condition slipped through
                log.error("rule_eval_error", rule_id=rule.id, error=str(exc))
        return out

    def _eval_thresholds(self, event: Event) -> list[Detection]:
        out = []
        for rule in self.threshold_rules:
            if not _match_selection_condition(rule, event):
                continue
            key = event.get(rule.group_by)
            if key is None:
                continue

            window = self._windows[rule.id][key]
            window.append(event)
            # Evict events outside the sliding window.
            cutoff = event.timestamp.timestamp() - rule.window_seconds
            while window and window[0].timestamp.timestamp() < cutoff:
                window.popleft()

            if len(window) >= rule.threshold_count:
                events = list(window)
                out.append(
                    self._build_detection(
                        rule, events, event, entity=str(key),
                        extra_context={
                            "group_by": rule.group_by,
                            "group_value": key,
                            "count": len(events),
                            "window_seconds": rule.window_seconds,
                        },
                    )
                )
                log.warning("detection", rule_id=rule.id, detector="threshold",
                            severity=rule.severity, entity=str(key),
                            count=len(events), window_seconds=rule.window_seconds)
                window.clear()  # avoid re-alerting on every subsequent event
        return out

    def _build_detection(self, rule: Rule, events: list[Event], anchor: Event,
                         entity: str | None,
                         extra_context: dict[str, Any] | None = None) -> Detection:
        context = {"source": anchor.source}
        if extra_context:
            context.update(extra_context)
        return Detection(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            detector="threshold" if rule.rule_type == "threshold" else "rule",
            event_ids=[e.event_id for e in events],
            entity=entity,
            timestamp=anchor.timestamp,
            mitre_techniques=attack.enrich(rule.mitre),
            context=context,
        )

    @staticmethod
    def _entity(event: Event) -> str | None:
        return event.get("src_ip") or event.get("user")


def _match_selection_condition(rule: Rule, event: Event) -> bool:
    """Shared selection+condition evaluation used by threshold rules."""
    results = {name: _match_selection(event, sel)
               for name, sel in rule.selections.items()}
    return _ConditionParser(_tokenize(rule.condition),
                            list(rule.selections.keys())).parse(results)
