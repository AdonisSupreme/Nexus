"""Prometheus-style metrics with no external dependency."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class HistogramSample:
    count: int = 0
    total: float = 0.0
    maximum: float = 0.0


class MetricsRegistry:
    """Minimal text metrics registry compatible with Prometheus scraping."""

    def __init__(self) -> None:
        self._counters: dict[str, float] = defaultdict(float)
        self._gauges: dict[str, float] = defaultdict(float)
        self._histograms: dict[str, HistogramSample] = defaultdict(HistogramSample)
        self._lock = threading.Lock()
        self.started_at = time.time()

    def incr(self, name: str, value: float = 1.0) -> None:
        with self._lock:
            self._counters[name] += value

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            bucket = self._histograms[name]
            bucket.count += 1
            bucket.total += value
            bucket.maximum = max(bucket.maximum, value)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "uptime_seconds": time.time() - self.started_at,
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {
                    key: {
                        "count": value.count,
                        "total": value.total,
                        "maximum": value.maximum,
                        "average": (value.total / value.count) if value.count else 0.0,
                    }
                    for key, value in self._histograms.items()
                },
            }

    def render_prometheus(self) -> str:
        lines: list[str] = []
        snap = self.snapshot()
        lines.append("# TYPE sentinelops_uptime_seconds gauge")
        lines.append(f"sentinelops_uptime_seconds {snap['uptime_seconds']:.6f}")

        for name, value in sorted(snap["counters"].items()):
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")

        for name, value in sorted(snap["gauges"].items()):
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")

        for name, value in sorted(snap["histograms"].items()):
            lines.append(f"# TYPE {name}_count counter")
            lines.append(f"{name}_count {value['count']}")
            lines.append(f"# TYPE {name}_sum counter")
            lines.append(f"{name}_sum {value['total']:.6f}")
            lines.append(f"# TYPE {name}_max gauge")
            lines.append(f"{name}_max {value['maximum']:.6f}")

        return "\n".join(lines) + "\n"
