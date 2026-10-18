"""Shared test fixtures / helpers."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Gateway: isolate side effects BEFORE any test imports gateway (config reads env at import).
_GW_TMP = Path(tempfile.mkdtemp(prefix="sase_test_"))
os.environ["SASE_AUDIT_LOG"] = str(_GW_TMP / "audit.jsonl")
os.environ["SASE_API_KEY_STORE"] = str(_GW_TMP / "api_keys.json")
os.environ.setdefault("SASE_JWT_SECRET", "test-only-secret")
os.environ["SASE_VAULT_STORE"] = str(_GW_TMP / "vault.json")
os.environ["SASE_VAULT_KEY"] = "dGVzdC1vbmx5LXZhdWx0LWtleS0zMi1ieXRlcyEhISE="  # 32 test bytes

from siem_hunter.models import Event  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_gateway_limits():
    """Rate-limit and SD-WAN circuit state are process-global; give every test a clean slate."""
    try:
        from gateway import quota, sdwan
    except ImportError:
        yield
        return
    quota.reset()
    sdwan.sdwan_router.reset()
    yield
    quota.reset()
    sdwan.sdwan_router.reset()


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
