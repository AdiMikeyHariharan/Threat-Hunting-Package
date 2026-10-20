"""Shared file stores across gateway replicas (separate processes on one host)."""

import json
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient

from gateway import auth
from gateway.filestore import JsonFileStore
from gateway.main import app
from gateway.users import DEMO_USERS

ROOT = Path(__file__).resolve().parents[1]
client = TestClient(app)


def _increment(path: str, times: int) -> None:
    cache: dict = {}
    store = JsonFileStore(Path(path), lambda data: cache.update(data))
    for _ in range(times):
        with store.transaction():
            cache["n"] = cache.get("n", 0) + 1
            store.write(cache)


def test_concurrent_writers_in_separate_processes_lose_no_updates(tmp_path):
    path = tmp_path / "counter.json"
    with ProcessPoolExecutor(max_workers=4) as pool:
        list(pool.map(_increment, [str(path)] * 4, [25] * 4))
    assert json.loads(path.read_text())["n"] == 100
    assert not list(tmp_path.glob("*.tmp")) and not list(tmp_path.glob(".counter-*"))


def test_reader_picks_up_another_processes_write(tmp_path):
    path = tmp_path / "data.json"
    seen: dict = {}
    reader = JsonFileStore(path, lambda data: (seen.clear(), seen.update(data)))
    _increment(str(path), 3)  # "other replica"
    reader.sync()
    assert seen == {"n": 3}
    reader.sync()  # unchanged file: no reload needed
    assert seen == {"n": 3}


def test_replicas_starting_together_seed_users_once(tmp_path):
    store = tmp_path / "users.json"
    env = {**os.environ, "SASE_USER_STORE": str(store)}
    procs = [
        subprocess.Popen([sys.executable, "-c", "import gateway.users"], cwd=ROOT, env=env,
                         stderr=subprocess.PIPE, text=True)
        for _ in range(4)
    ]
    errors = [p.communicate()[1] for p in procs]
    assert all(p.returncode == 0 for p in procs), errors
    assert sorted(json.loads(store.read_text())) == sorted(DEMO_USERS)


def test_api_key_revoked_on_another_replica_stops_working_here():
    admin = {"Authorization": "Bearer " + client.post(
        "/auth/token", json={"username": "charlie", "password": DEMO_USERS["charlie"][0]}
    ).json()["access_token"]}
    issued = client.post("/auth/register-api-key", json={"service_id": "svc-multi", "role": "billing-service",
                                                         "scopes": ["read"]}, headers=admin).json()
    key = {"X-API-Key": issued["api_key"]}
    assert client.get("/proxy/billing/invoices", headers=key).status_code == 200

    # Another gateway process revokes the key by rewriting the shared store.
    other: dict = {}
    replica = JsonFileStore(auth.API_KEY_STORE, lambda data: (other.clear(), other.update(data)))
    with replica.transaction():
        del other[issued["key_sha256"]]
        replica.write(other)

    assert client.get("/proxy/billing/invoices", headers=key).status_code == 401
