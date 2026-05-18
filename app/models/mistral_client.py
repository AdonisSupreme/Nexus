"""Async Mistral client with retries and circuit breaking."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from app.config.settings import settings
from app.utils.logging import get_logger

try:
    import httpx
except Exception:  # pragma: no cover - optional dependency
    httpx = None


@dataclass(slots=True)
class CircuitBreakerState:
    failures: int = 0
    threshold: int = settings.MISTRAL_CIRCUIT_BREAKER_THRESHOLD
    opened_at: float | None = None
    cooldown_seconds: float = 30.0

    def is_open(self) -> bool:
        if self.opened_at is None:
            return False
        if (time.time() - self.opened_at) > self.cooldown_seconds:
            self.failures = 0
            self.opened_at = None
            return False
        return True

    def record_success(self) -> None:
        self.failures = 0
        self.opened_at = None

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.threshold:
            self.opened_at = time.time()


class MistralClient:
    """Thin async client over Mistral's chat, classification, and moderation APIs."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self.base_url = settings.MISTRAL_API_BASE_URL.rstrip("/")
        self.api_key = settings.MISTRAL_API_KEY.get_secret_value() if settings.MISTRAL_API_KEY else None
        self.circuit_breaker = CircuitBreakerState()
        self._client: Any | None = None
        self.available = bool(self.api_key and httpx is not None)

    async def startup(self) -> None:
        if not self.available:
            return
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=settings.MISTRAL_TIMEOUT_SECONDS,
        )

    async def shutdown(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(self, method: str, endpoint: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        if not self.available or self._client is None:
            return None
        if self.circuit_breaker.is_open():
            self.logger.warning("Mistral circuit breaker open, skipping %s", endpoint)
            return None

        for attempt in range(settings.MISTRAL_MAX_RETRIES + 1):
            try:
                response = await self._client.request(method=method, url=endpoint, json=payload)
                response.raise_for_status()
                self.circuit_breaker.record_success()
                return response.json()
            except Exception as exc:  # pragma: no cover - network interaction
                self.circuit_breaker.record_failure()
                self.logger.warning("Mistral request failed on %s attempt=%s error=%s", endpoint, attempt + 1, exc)
                if attempt >= settings.MISTRAL_MAX_RETRIES:
                    return None
                await asyncio.sleep(0.5 * (attempt + 1))
        return None

    async def chat_complete(
        self,
        messages: list[dict[str, str]],
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str | None:
        payload = {
            "model": settings.MISTRAL_MODEL,
            "messages": messages,
            "temperature": settings.MISTRAL_TEMPERATURE if temperature is None else temperature,
            "max_tokens": settings.MISTRAL_MAX_TOKENS if max_tokens is None else max_tokens,
            "stream": False,
        }
        data = await self._request("POST", "/v1/chat/completions", payload)
        if not data:
            return None
        try:
            return data["choices"][0]["message"]["content"].strip()
        except Exception:
            return None

    async def classify_text(self, text: str, labels: list[str]) -> dict[str, Any] | None:
        if not settings.ENABLE_CLASSIFIER_ENDPOINTS or not settings.MISTRAL_CLASSIFICATION_MODEL:
            return None
        payload = {
            "model": settings.MISTRAL_CLASSIFICATION_MODEL,
            "inputs": [text],
            "categories": labels,
        }
        return await self._request("POST", "/v1/classifications", payload)

    async def moderate_text(self, text: str) -> dict[str, Any] | None:
        if not settings.ENABLE_MODERATION_GUARDRAILS:
            return None
        payload = {
            "model": settings.MISTRAL_MODERATION_MODEL,
            "input": text,
        }
        return await self._request("POST", "/v1/moderations", payload)

    def diagnostics(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "base_url": self.base_url,
            "model": settings.MISTRAL_MODEL,
            "classification_model": settings.MISTRAL_CLASSIFICATION_MODEL,
            "moderation_model": settings.MISTRAL_MODERATION_MODEL if settings.ENABLE_MODERATION_GUARDRAILS else None,
            "circuit_breaker": {
                "failures": self.circuit_breaker.failures,
                "threshold": self.circuit_breaker.threshold,
                "open": self.circuit_breaker.is_open(),
            },
        }
