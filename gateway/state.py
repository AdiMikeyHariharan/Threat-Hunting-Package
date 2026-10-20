"""Shared state for rate limiting, login lockout and token revocation.

The default store is in-memory (single process). Set SASE_REDIS_URL to share
state across gateway replicas; both stores expose the same small interface:

    take_token(key, burst, refill, now)  token bucket; 0 if allowed, else wait seconds
    incr_window(key, window, now)        fixed window counter -> (count, window_start)
    peek_window(key, window, now)        same, without incrementing
    set(key, value, ttl) / get(key)      expiring string values
    pop(key)                            atomically consume a one-use value

Callers pass `now` (wall-clock seconds) so every replica agrees on time and
tests can control the clock. TTL expiry of set/get uses the real clock.
"""

from __future__ import annotations

import math
import threading
import time
from typing import Optional

from .config import REDIS_URL


class MemoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, list[float]] = {}   # key -> [tokens, last_refill]
        self._windows: dict[str, list[float]] = {}   # key -> [window_start, count]
        self._values: dict[str, tuple[str, float]] = {}  # key -> (value, expires_at)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
            self._windows.clear()
            self._values.clear()

    def take_token(self, key: str, burst: int, refill: float, now: float) -> float:
        with self._lock:
            tokens, last = self._buckets.get(key, [float(burst), now])
            tokens = min(float(burst), tokens + max(0.0, now - last) * refill)
            if tokens >= 1.0:
                self._buckets[key] = [tokens - 1.0, now]
                return 0.0
            self._buckets[key] = [tokens, now]
            return (1.0 - tokens) / refill if refill > 0 else float("inf")

    def incr_window(self, key: str, window: float, now: float) -> tuple[int, float]:
        with self._lock:
            start, count = self._windows.get(key, [now, 0])
            if now - start >= window:
                start, count = now, 0
            count += 1
            self._windows[key] = [start, count]
            return int(count), start

    def peek_window(self, key: str, window: float, now: float) -> tuple[int, float]:
        with self._lock:
            start, count = self._windows.get(key, [now, 0])
            if now - start >= window:
                return 0, now
            return int(count), start

    def set(self, key: str, value: str, ttl: float) -> None:
        with self._lock:
            now = time.time()
            # Abandoned OIDC transactions must expire even if never read again.
            for expired in [k for k, (_, expiry) in self._values.items() if expiry <= now]:
                del self._values[expired]
            self._values[key] = (value, now + ttl)

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            item = self._values.get(key)
            if item is None:
                return None
            if item[1] <= time.time():
                del self._values[key]
                return None
            return item[0]

    def pop(self, key: str) -> Optional[str]:
        with self._lock:
            item = self._values.pop(key, None)
            return item[0] if item is not None and item[1] > time.time() else None


# Lua keeps each read-modify-write atomic across replicas.
_TAKE_TOKEN_LUA = """
local burst, refill, now = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local b = redis.call('HMGET', KEYS[1], 't', 'ts')
local tokens = tonumber(b[1]) or burst
local last = tonumber(b[2]) or now
tokens = math.min(burst, tokens + math.max(0, now - last) * refill)
local wait = 0
if tokens >= 1 then
  tokens = tokens - 1
elseif refill > 0 then
  wait = (1 - tokens) / refill
else
  wait = -1
end
redis.call('HSET', KEYS[1], 't', tostring(tokens), 'ts', tostring(now))
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
return tostring(wait)
"""

_INCR_WINDOW_LUA = """
local now, window = tonumber(ARGV[1]), tonumber(ARGV[2])
local w = redis.call('HMGET', KEYS[1], 's', 'c')
local start, count = tonumber(w[1]), tonumber(w[2]) or 0
if (not start) or (now - start >= window) then
  start = now
  count = 0
end
count = count + 1
redis.call('HSET', KEYS[1], 's', tostring(start), 'c', count)
redis.call('EXPIRE', KEYS[1], math.ceil(window) + 1)
return {count, tostring(start)}
"""


class RedisStore:
    PREFIX = "sase:"

    def __init__(self, client) -> None:
        self._r = client
        self._take = client.register_script(_TAKE_TOKEN_LUA)
        self._incr = client.register_script(_INCR_WINDOW_LUA)
        self._pop = client.register_script(
            "local v = redis.call('GET', KEYS[1]); redis.call('DEL', KEYS[1]); return v"
        )

    def reset(self) -> None:
        keys = list(self._r.scan_iter(match=self.PREFIX + "*"))
        if keys:
            self._r.delete(*keys)

    def take_token(self, key: str, burst: int, refill: float, now: float) -> float:
        # Once fully refilled the bucket equals a fresh one, so it can expire.
        ttl = math.ceil(burst / refill) + 1 if refill > 0 else 86400
        wait = float(self._take(keys=[self.PREFIX + key], args=[burst, refill, now, ttl]))
        return float("inf") if wait < 0 else wait

    def incr_window(self, key: str, window: float, now: float) -> tuple[int, float]:
        count, start = self._incr(keys=[self.PREFIX + key], args=[now, window])
        return int(count), float(start)

    def peek_window(self, key: str, window: float, now: float) -> tuple[int, float]:
        start, count = self._r.hmget(self.PREFIX + key, "s", "c")
        if start is None or now - float(start) >= window:
            return 0, now
        return int(count or 0), float(start)

    def set(self, key: str, value: str, ttl: float) -> None:
        self._r.set(self.PREFIX + key, value, ex=max(1, math.ceil(ttl)))

    def get(self, key: str) -> Optional[str]:
        value = self._r.get(self.PREFIX + key)
        return value.decode("utf-8") if isinstance(value, bytes) else value

    def pop(self, key: str) -> Optional[str]:
        value = self._pop(keys=[self.PREFIX + key])
        return value.decode("utf-8") if isinstance(value, bytes) else value


def _make_store():
    if not REDIS_URL:
        return MemoryStore()
    import redis  # optional dependency, only needed when SASE_REDIS_URL is set

    return RedisStore(redis.Redis.from_url(REDIS_URL))


store = _make_store()
