"""JSON file persistence that several gateway processes on one host can share.

Used by the user directory, the API key store and the credential vault:

* Writes go to a unique temp file and are renamed into place atomically, so
  concurrent writers can't trip over each other's temp file.
* Read-modify-write runs under an exclusive flock on `<file>.lock`, so two
  replicas editing at once can't lose each other's changes.
* `sync()` reloads the in-memory copy when another process replaced the file
  (inode/mtime/size changed). Callers sync before every read, so e.g. a key
  revoked on one replica stops working on the others immediately.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional


class JsonFileStore:
    def __init__(self, path: Path, loader: Callable[[dict], None]) -> None:
        self.path = Path(path)
        self._loader = loader          # rebuilds the caller's cache from file data
        self._lock = threading.RLock()
        self._depth = 0                # transaction nesting (flock isn't re-entrant)
        self._signature: Optional[tuple] = None

    def _stat(self) -> Optional[tuple]:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return None
        return st.st_ino, st.st_mtime_ns, st.st_size

    def exists(self) -> bool:
        return self.path.exists()

    def sync(self) -> None:
        """Reload if the file changed since we last read or wrote it."""
        with self._lock:
            sig = self._stat()
            if sig is None or sig == self._signature:
                return
            self._loader(json.loads(self.path.read_text(encoding="utf-8")))
            self._signature = sig

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Exclusive cross-process section; the cache is fresh on entry."""
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path.with_suffix(".lock"), "a") as lock_file:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
                self._depth = 1
                try:
                    self.sync()
                    yield
                finally:
                    self._depth = 0
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

    def write(self, data: dict) -> None:
        """Atomically replace the file. Call inside transaction()."""
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.stem}-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self._signature = self._stat()
