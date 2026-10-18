"""User directory for human authentication.

Passwords are stored only as salted PBKDF2-SHA256 hashes. Roles are assigned
by the server here - a client can never choose its own role.

Demo users are seeded at import time. Their passwords can be overridden with
environment variables (SASE_PW_ALICE, SASE_PW_BOB, SASE_PW_CHARLIE).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field

_PBKDF2_ITERATIONS = 200_000


@dataclass
class User:
    username: str
    role: str
    scopes: list[str]
    password_salt: bytes = field(repr=False)
    password_hash: bytes = field(repr=False)


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)


_USERS: dict[str, User] = {}


def add_user(username: str, password: str, role: str, scopes: list[str]) -> User:
    salt = secrets.token_bytes(16)
    user = User(
        username=username,
        role=role,
        scopes=scopes,
        password_salt=salt,
        password_hash=_hash_password(password, salt),
    )
    _USERS[username] = user
    return user


def verify_credentials(username: str, password: str) -> User | None:
    """Return the user if the password matches, else None (constant-time compare)."""
    user = _USERS.get(username)
    if user is None:
        # Still do the work so response time doesn't reveal which usernames exist.
        _hash_password(password, b"\x00" * 16)
        return None
    candidate = _hash_password(password, user.password_salt)
    return user if hmac.compare_digest(candidate, user.password_hash) else None


# --- Demo seed users ---------------------------------------------------------
DEMO_USERS = {
    "alice": (os.environ.get("SASE_PW_ALICE", "alice-dev-pass"), "developer", ["read", "write"]),
    "bob": (os.environ.get("SASE_PW_BOB", "bob-finance-pass"), "finance", ["read", "invoice"]),
    "charlie": (os.environ.get("SASE_PW_CHARLIE", "charlie-admin-pass"), "admin", ["read", "write", "admin"]),
}

for _name, (_pw, _role, _scopes) in DEMO_USERS.items():
    add_user(_name, _pw, _role, _scopes)
