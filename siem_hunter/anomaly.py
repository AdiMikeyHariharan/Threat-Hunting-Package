"""Statistical anomaly scorer — enhancement #2.

Signature rules only catch what someone already wrote a rule for. Threat
*hunting* also needs to surface activity that is simply unusual for this
dataset, with no prior signature. This detector does that with a transparent,
explainable statistic rather than a black-box model, which matters for an
academic write-up.

Method
------
For a chosen entity field (default ``src_ip``) we count each entity's events,
then flag entities whose volume is a statistical outlier using the **modified
z-score** (median + Median Absolute Deviation)::

    Mi = 0.6745 * (xi - median) / MAD

MAD is used instead of the mean/standard-deviation because it is robust: a
single very noisy host will not inflate the baseline and hide the others.
Entities with ``|Mi| >= threshold`` (default 3.5, the conventional cut-off)
are reported as anomalies.
"""

from __future__ import annotations

from collections import defaultdict
from statistics import median

from .logging_config import get_logger
from .models import Detection, Event

log = get_logger(__name__)

_MAD_SCALE = 0.6745
_ANOMALY_RULE_ID = "ANOMALY-VOLUME-0001"


class AnomalyDetector:
    """Volume-based outlier detector over one entity field."""

    def __init__(self, entity_field: str = "src_ip", threshold: float = 3.5,
                 min_entities: int = 4):
        self.entity_field = entity_field
        self.threshold = threshold
        # Below this many distinct entities the statistic is not meaningful.
        self.min_entities = min_entities
        self._counts: dict[str, int] = defaultdict(int)
        self._events: dict[str, list[Event]] = defaultdict(list)

    def observe(self, event: Event) -> None:
        """Fold one event into the running per-entity tallies."""
        entity = event.get(self.entity_field)
        if entity is None:
            return
        self._counts[entity] += 1
        self._events[entity].append(event)

    def finalize(self) -> list[Detection]:
        """Compute outliers over everything observed and emit detections."""
        if len(self._counts) < self.min_entities:
            log.info("anomaly_skipped_insufficient_entities",
                     entities=len(self._counts), required=self.min_entities)
            return []

        counts = list(self._counts.values())
        med = median(counts)
        mad = median([abs(c - med) for c in counts]) or 1.0  # avoid /0

        detections: list[Detection] = []
        for entity, count in sorted(self._counts.items(),
                                    key=lambda kv: kv[1], reverse=True):
            score = _MAD_SCALE * (count - med) / mad
            if score < self.threshold:
                continue

            events = self._events[entity]
            severity = "high" if score >= 2 * self.threshold else "medium"
            detections.append(
                Detection(
                    rule_id=_ANOMALY_RULE_ID,
                    title=f"Anomalous {self.entity_field} activity volume",
                    severity=severity,
                    detector="anomaly",
                    event_ids=[e.event_id for e in events],
                    entity=str(entity),
                    timestamp=events[-1].timestamp,
                    context={
                        "entity_field": self.entity_field,
                        "event_count": count,
                        "dataset_median": med,
                        "mad": mad,
                        "modified_z_score": round(score, 2),
                        "threshold": self.threshold,
                    },
                )
            )
            log.warning("detection", rule_id=_ANOMALY_RULE_ID, detector="anomaly",
                        severity=severity, entity=str(entity), count=count,
                        modified_z_score=round(score, 2))

        log.info("anomaly_scan_complete", entities=len(self._counts),
                 anomalies=len(detections), median=med, mad=mad)
        return detections
