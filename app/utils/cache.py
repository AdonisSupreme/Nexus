"""Cache implementations with a local fallback and Redis-style diagnostics."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(slots=True)
class CacheStats:
    hits: int = 0
    misses: int = 0
    writes: int = 0
    evictions: int = 0


class LocalTTLCache:
    """Small in-memory TTL cache for development and degraded mode."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self.stats = CacheStats()
        self.backend = "local-memory"

    def get(self, key: str) -> Any | None:
        now = time.time()
        with self._lock:
            item = self._store.get(key)
            if item is None:
                self.stats.misses += 1
                return None
            expires_at, value = item
            if expires_at < now:
                self.stats.misses += 1
                self.stats.evictions += 1
                self._store.pop(key, None)
                return None
            self.stats.hits += 1
            return value

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        with self._lock:
            self._store[key] = (time.time() + max(ttl_seconds, 1), value)
            self.stats.writes += 1

    def clear(self) -> None:
        with self._lock:
            self.stats.evictions += len(self._store)
            self._store.clear()

    def diagnostics(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "keys": len(self._store),
            "hits": self.stats.hits,
            "misses": self.stats.misses,
            "writes": self.stats.writes,
            "evictions": self.stats.evictions,
        }


def cache_connection_metadata(url: str | None) -> dict[str, Any]:
    """Return safe connection metadata for diagnostics without exposing secrets."""
    if not url:
        return {"configured": False}

    parsed = urlparse(url)
    return {
        "configured": True,
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
    }
