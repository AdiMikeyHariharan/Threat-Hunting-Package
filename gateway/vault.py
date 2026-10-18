"""Encrypted credential vault for downstream services (Phase 3).

Developers never hold downstream secrets (cloud API keys, DB tokens...). An
admin stores each secret in the vault once; the gateway decrypts it in memory
only at forwarding time and attaches it to the outbound request.

Crypto
------
* AES-256-GCM (authenticated encryption) with a fresh 96-bit nonce per secret.
* The service name and header name are bound as Associated Data (AAD). A
  ciphertext copied onto a different service/header fails to decrypt, so an
  attacker who can edit the vault file can't swap secrets between services.
* Each record stores the id of the key that encrypted it, enabling rotation.

Keys (environment)
------------------
    SASE_VAULT_KEY        base64 32-byte master key (current; used to encrypt)
    SASE_VAULT_OLD_KEYS   comma-separated base64 keys still accepted for decrypt
                          (during rotation)
    SASE_VAULT_STORE      path of the encrypted vault file

If SASE_VAULT_KEY is not set, a dev key is generated into gateway/data/vault.key
with a warning. Keeping the key next to the ciphertext is NOT safe for
production - it only exists so the demo works out of the box.

Generate a key:  python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import warnings
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import ROOT_DIR

VAULT_STORE = Path(os.environ.get("SASE_VAULT_STORE", ROOT_DIR / "gateway" / "data" / "vault.json"))
_DEV_KEY_FILE = ROOT_DIR / "gateway" / "data" / "vault.key"

# Headers the vault may never set: they belong to the gateway or HTTP framing.
_FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "cookie"}
_HEADER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,63}$")


class VaultError(Exception):
    """Raised for vault configuration or integrity problems."""


def _decode_key(b64: str) -> bytes:
    try:
        key = base64.b64decode(b64.strip(), validate=True)
    except Exception as e:  # binascii.Error, ValueError
        raise VaultError("Vault key is not valid base64") from e
    if len(key) != 32:
        raise VaultError(f"Vault key must be 32 bytes (AES-256); got {len(key)}")
    return key


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:12]


def _load_keys() -> tuple[str, dict[str, bytes]]:
    """Return (current_key_id, {key_id: key}) from env, or a dev key file."""
    env_key = os.environ.get("SASE_VAULT_KEY")
    if env_key:
        current = _decode_key(env_key)
    else:
        if _DEV_KEY_FILE.exists():
            current = _decode_key(_DEV_KEY_FILE.read_text())
        else:
            current = AESGCM.generate_key(bit_length=256)
            _DEV_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
            _DEV_KEY_FILE.write_text(base64.b64encode(current).decode())
            os.chmod(_DEV_KEY_FILE, 0o600)
        warnings.warn(
            "SASE_VAULT_KEY not set - using dev key file gateway/data/vault.key. "
            "Do NOT use this in production.",
            stacklevel=1,
        )

    keys = {_key_id(current): current}
    for old in filter(None, os.environ.get("SASE_VAULT_OLD_KEYS", "").split(",")):
        k = _decode_key(old)
        keys.setdefault(_key_id(k), k)
    return _key_id(current), keys


def _aad(service: str, header: str) -> bytes:
    return f"sase-vault:v1:{service}:{header.lower()}".encode()


def validate_header_name(header: str) -> str:
    if not _HEADER_RE.match(header):
        raise VaultError(f"Invalid header name: {header!r}")
    low = header.lower()
    if low in _FORBIDDEN_HEADERS or low.startswith("x-sase-"):
        raise VaultError(f"Header {header!r} is reserved and cannot be set by the vault")
    return header


class CredentialVault:
    def __init__(self, store: Path = VAULT_STORE) -> None:
        self.store = store
        self._lock = threading.Lock()
        self.current_key_id, self._keys = _load_keys()
        self._records: dict[str, dict] = {}
        if store.exists():
            try:
                self._records = json.loads(store.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                raise VaultError(f"Cannot read vault store {store}: {e}") from e

    # -- persistence ---------------------------------------------------------
    def _save(self) -> None:
        self.store.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.store.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._records, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.store)

    # -- crypto --------------------------------------------------------------
    def _encrypt(self, service: str, header: str, plaintext: str) -> dict:
        nonce = os.urandom(12)
        ct = AESGCM(self._keys[self.current_key_id]).encrypt(
            nonce, plaintext.encode("utf-8"), _aad(service, header)
        )
        return {
            "key_id": self.current_key_id,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }

    def _decrypt(self, service: str, rec: dict) -> str:
        key = self._keys.get(rec["key_id"])
        if key is None:
            raise VaultError(
                f"Credential for '{service}' was encrypted with unknown key '{rec['key_id']}'. "
                "Add the old key to SASE_VAULT_OLD_KEYS."
            )
        try:
            pt = AESGCM(key).decrypt(
                base64.b64decode(rec["nonce"]),
                base64.b64decode(rec["ciphertext"]),
                _aad(service, rec["header"]),
            )
        except InvalidTag as e:
            raise VaultError(f"Integrity check failed for '{service}' credential (tampered or moved)") from e
        return pt.decode("utf-8")

    # -- public API ----------------------------------------------------------
    def put(self, service: str, header: str, secret: str, prefix: str = "", actor: str = "system") -> dict:
        validate_header_name(header)
        if not secret:
            raise VaultError("Secret must not be empty")
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            prev = self._records.get(service)
            self._records[service] = {
                "header": header,
                "prefix": prefix,
                "version": (prev["version"] + 1) if prev else 1,
                "created_at": prev["created_at"] if prev else now,
                "updated_at": now,
                "updated_by": actor,
                **self._encrypt(service, header, secret),
            }
            self._save()
            return self.describe(service)

    def delete(self, service: str) -> bool:
        with self._lock:
            if service not in self._records:
                return False
            del self._records[service]
            self._save()
            return True

    def has(self, service: str) -> bool:
        return service in self._records

    def header_for(self, service: str) -> tuple[str, str] | None:
        """Decrypt in memory and return (header_name, header_value), or None."""
        rec = self._records.get(service)
        if rec is None:
            return None
        return rec["header"], rec["prefix"] + self._decrypt(service, rec)

    def describe(self, service: str) -> dict:
        """Metadata only - never the secret or ciphertext."""
        rec = self._records[service]
        return {
            "service": service,
            "header": rec["header"],
            "prefix": rec["prefix"],
            "version": rec["version"],
            "key_id": rec["key_id"],
            "created_at": rec["created_at"],
            "updated_at": rec["updated_at"],
            "updated_by": rec["updated_by"],
        }

    def list(self) -> list[dict]:
        return [self.describe(s) for s in sorted(self._records)]

    def rotate(self) -> dict:
        """Re-encrypt every record under the current key (all-or-nothing)."""
        with self._lock:
            updates = {
                service: self._encrypt(service, rec["header"], self._decrypt(service, rec))
                for service, rec in self._records.items()
                if rec["key_id"] != self.current_key_id
            }
            for service, enc in updates.items():
                self._records[service].update(enc)
            if updates:
                self._save()
        return {"rotated": len(updates), "total": len(self._records), "current_key_id": self.current_key_id}


vault = CredentialVault()
