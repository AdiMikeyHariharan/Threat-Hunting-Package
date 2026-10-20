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
os.environ.setdefault("SASE_JWT_SECRET", "test-only-jwt-secret-at-least-32-bytes")
os.environ["SASE_VAULT_STORE"] = str(_GW_TMP / "vault.json")
os.environ["SASE_VAULT_KEY"] = "dGVzdC1vbmx5LXZhdWx0LWtleS0zMi1ieXRlcyEhISE="  # 32 test bytes
os.environ["SASE_USER_STORE"] = str(_GW_TMP / "users.json")
os.environ["SASE_INTERNAL_TOKEN"] = "test-only-internal-gateway-token"
os.environ["SASE_PBKDF2_ITERATIONS"] = "1000"  # keep the suite fast; production uses 600k
os.environ.pop("SASE_REDIS_URL", None)

import httpx  # noqa: E402

from gateway import mock_backends, proxy  # noqa: E402
from siem_hunter.models import Event  # noqa: E402

# Run the separately-deployed mock backends in-process for tests.
proxy.UPSTREAM_TRANSPORT = httpx.ASGITransport(app=mock_backends.app)


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
