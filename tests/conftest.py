"""Shared test fixtures / helpers."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from siem_hunter.models import Event


@pytest.fixture
def make_event():
    def _make(fields, raw="raw-line", ts=None, source="test"):
        return Event(
            timestamp=ts or datetime(2026, 3, 10, 13, 58, tzinfo=timezone.utc),
            source=source,
            raw=raw,
            fields=fields,
        )
    return _make
