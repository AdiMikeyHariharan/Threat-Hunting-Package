"""User directory for human authentication.

Passwords are stored only as salted PBKDF2-SHA256 hashes. Roles are assigned
by the server here - a client can never choose its own role.

The directory is persisted to SASE_USER_STORE (default gateway/data/users.json)
and managed through the admin /users API. On first start (no store file yet)
the demo users are seeded; their passwords can be overridden with environment
variables (SASE_PW_ALICE, SASE_PW_BOB, SASE_PW_CHARLIE).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import HUMAN_ROLE_SCOPES, USER_STORE
from .filestore import JsonFileStore

# OWASP Password Storage Cheat Sheet (2023+) recommendation for PBKDF2-HMAC-SHA256.
# Each record stores its own count, so older hashes are upgraded at next login.
_PBKDF2_ITERATIONS = int(os.environ.get("SASE_PBKDF2_ITERATIONS", "600000"))

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256


class UserError(ValueError):
    """Raised for invalid user-management requests."""


@dataclass
class User:
    username: str
    role: str
    scopes: list[str]
    password_salt: bytes = field(repr=False)
    password_hash: bytes = field(repr=False)
    iterations: int = _PBKDF2_ITERATIONS
    disabled: bool = False
    created_at: str = ""
    updated_at: str = ""

    def public(self) -> dict:
        """Metadata safe to return from the API (no hash or salt)."""
        return {
            "username": self.username, "role": self.role, "scopes": self.scopes,
            "disabled": self.disabled, "created_at": self.created_at, "updated_at": self.updated_at,
        }


def _hash_password(password: str, salt: bytes, iterations: int = _PBKDF2_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_USERS: dict[str, User] = {}


def _save() -> None:
    data = {
        u.username: {
            "role": u.role, "scopes": u.scopes, "salt": u.password_salt.hex(),
            "hash": u.password_hash.hex(), "iterations": u.iterations, "disabled": u.disabled,
            "created_at": u.created_at, "updated_at": u.updated_at,
        }
        for u in _USERS.values()
    }
    _store.write(data)


def _load(data: dict) -> None:
    _USERS.clear()
    for name, rec in data.items():
        _USERS[name] = User(
            username=name, role=rec["role"], scopes=list(rec["scopes"]),
            password_salt=bytes.fromhex(rec["salt"]), password_hash=bytes.fromhex(rec["hash"]),
            iterations=int(rec.get("iterations", _PBKDF2_ITERATIONS)),
            disabled=bool(rec.get("disabled", False)),
            created_at=rec.get("created_at", ""), updated_at=rec.get("updated_at", ""),
        )


# Shared by every gateway process on the host; other replicas' edits are picked up.
_store = JsonFileStore(USER_STORE, _load)


def validate_password(username: str, password: str) -> None:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise UserError(
            f"Password must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters long."
        )
    if username.lower() in password.lower():
        raise UserError("Password must not contain the username.")


def _validate_role(role: str, scopes: list[str]) -> None:
    allowed = HUMAN_ROLE_SCOPES.get(role)
    if allowed is None:
        raise UserError(f"Unsupported role {role!r}. Choose one of {sorted(HUMAN_ROLE_SCOPES)}.")
    if not scopes or not set(scopes) <= allowed:
        raise UserError(f"Scopes for role {role!r} must be a non-empty subset of {sorted(allowed)}.")


def _active_admins(excluding: str | None = None) -> int:
    return sum(
        1 for u in _USERS.values()
        if u.role == "admin" and not u.disabled and u.username != excluding
    )


def add_user(username: str, password: str, role: str, scopes: list[str]) -> User:
    """Low-level insert (no policy checks). Used for seeding."""
    salt = secrets.token_bytes(16)
    now = _now_iso()
    user = User(
        username=username, role=role, scopes=list(scopes), password_salt=salt,
        password_hash=_hash_password(password, salt), created_at=now, updated_at=now,
    )
    with _store.transaction():
        _USERS[username] = user
        _save()
    return user


def create_user(username: str, password: str, role: str, scopes: list[str]) -> User:
    if not USERNAME_RE.match(username):
        raise UserError("Username must be 3-32 chars: lowercase letters, digits, '.', '_' or '-'.")
    _validate_role(role, scopes)
    validate_password(username, password)
    with _store.transaction():
        if username in _USERS:
            raise UserError(f"User {username!r} already exists.")
        return add_user(username, password, role, scopes)


def get_user(username: str) -> User | None:
    _store.sync()
    return _USERS.get(username)


def list_users() -> list[dict]:
    _store.sync()
    return [u.public() for u in sorted(_USERS.values(), key=lambda u: u.username)]


def update_user(
    username: str,
    role: str | None = None,
    scopes: list[str] | None = None,
    disabled: bool | None = None,
) -> User:
    with _store.transaction():
        user = _USERS.get(username)
        if user is None:
            raise KeyError(username)
        new_role = role if role is not None else user.role
        new_scopes = scopes if scopes is not None else user.scopes
        _validate_role(new_role, new_scopes)
        new_disabled = user.disabled if disabled is None else disabled
        if user.role == "admin" and (new_role != "admin" or new_disabled) and _active_admins(username) == 0:
            raise UserError("Cannot demote or disable the last active admin.")
        user.role, user.scopes, user.disabled = new_role, list(new_scopes), new_disabled
        user.updated_at = _now_iso()
        _save()
        return user


def set_password(username: str, password: str) -> None:
    validate_password(username, password)
    with _store.transaction():
        user = _USERS.get(username)
        if user is None:
            raise KeyError(username)
        user.password_salt = secrets.token_bytes(16)
        user.iterations = _PBKDF2_ITERATIONS
        user.password_hash = _hash_password(password, user.password_salt)
        user.updated_at = _now_iso()
        _save()


def delete_user(username: str) -> None:
    with _store.transaction():
        user = _USERS.get(username)
        if user is None:
            raise KeyError(username)
        if user.role == "admin" and not user.disabled and _active_admins(username) == 0:
            raise UserError("Cannot delete the last active admin.")
        del _USERS[username]
        _save()


def verify_credentials(username: str, password: str) -> User | None:
    """Return the user if the password matches, else None (constant-time compare)."""
    user = get_user(username)
    if user is None:
        # Still do the work so response time doesn't reveal which usernames exist.
        _hash_password(password, b"\x00" * 16)
        return None
    candidate = _hash_password(password, user.password_salt, user.iterations)
    if not hmac.compare_digest(candidate, user.password_hash) or user.disabled:
        return None
    if user.iterations < _PBKDF2_ITERATIONS:
        # Transparent upgrade of hashes created with an older work factor.
        with _store.transaction():
            # Re-read: the transaction may have reloaded another replica's edits.
            user = _USERS.get(username) or user
            user.iterations = _PBKDF2_ITERATIONS
            user.password_hash = _hash_password(password, user.password_salt)
            _save()
    return user


# --- Demo seed users ---------------------------------------------------------
DEMO_USERS = {
    "alice": (os.environ.get("SASE_PW_ALICE", "alice-dev-pass"), "developer", ["read", "write"]),
    "bob": (os.environ.get("SASE_PW_BOB", "bob-finance-pass"), "finance", ["read", "invoice"]),
    "charlie": (os.environ.get("SASE_PW_CHARLIE", "charlie-admin-pass"), "admin", ["read", "write", "admin"]),
}

# Seed on first start only; the lock stops replicas starting together from racing.
with _store.transaction():
    if not _store.exists():
        for _name, (_pw, _role, _scopes) in DEMO_USERS.items():
            add_user(_name, _pw, _role, _scopes)
