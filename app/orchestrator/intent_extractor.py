"""Intent classification for operational queries."""

from __future__ import annotations

from collections import defaultdict

from app.models.mistral_client import MistralClient
from app.schemas.intent_schema import ClassificationResult, IntentSource, QueryIntent
from app.utils.logging import get_logger


INTENT_KEYWORDS: dict[QueryIntent, set[str]] = {
    QueryIntent.INCIDENT_RESPONSE: {"down", "failing", "failed", "incident", "error", "outage", "unreachable", "timeout"},
    QueryIntent.SERVICE_CONTROL: {"restart", "start", "stop", "service", "control", "license"},
    QueryIntent.ENVIRONMENT_MANAGEMENT: {"deploy", "deployment", "patch", "space", "backup", "log", "environment"},
    QueryIntent.DISASTER_RECOVERY: {"dr", "failover", "switchover", "rollback", "recovery", "disaster"},
    QueryIntent.VERIFICATION_HEALTH: {"health", "verify", "validation", "monitor", "status", "check"},
    QueryIntent.ADMINISTRATIVE: {"user", "create", "access", "role", "change", "escalation", "management"},
}


class IntentExtractor:
    """Hybrid intent extraction with heuristics first and Mistral as an optional enhancer."""

    def __init__(self, mistral_client: MistralClient) -> None:
        self.mistral_client = mistral_client
        self.logger = get_logger(__name__)

    def _heuristic_classify(self, query: str) -> ClassificationResult:
        lowered = query.lower()
        scores: defaultdict[QueryIntent, float] = defaultdict(float)

        for intent, keywords in INTENT_KEYWORDS.items():
            for keyword in keywords:
                if keyword in lowered:
                    scores[intent] += 1.0

        if not scores:
            return ClassificationResult(
                intent=QueryIntent.GENERAL_GUIDANCE,
                confidence=0.35,
                rationale="No strong operational keyword match; defaulting to general guidance.",
                source=IntentSource.HEURISTIC,
                candidates=[],
            )

        best_intent, best_score = max(scores.items(), key=lambda item: item[1])
        total = sum(scores.values()) or 1.0
        candidates = [{intent.value: round(score / total, 3)} for intent, score in sorted(scores.items(), key=lambda item: item[1], reverse=True)]
        confidence = min(0.9, 0.35 + (best_score / total))

        return ClassificationResult(
            intent=best_intent,
            confidence=round(confidence, 3),
            rationale=f"Matched operational keywords for {best_intent.value}.",
            source=IntentSource.HEURISTIC,
            candidates=candidates,
        )

    async def classify(self, query: str, use_remote_classifier: bool = True) -> ClassificationResult:
        heuristic = self._heuristic_classify(query)
        if not use_remote_classifier:
            return heuristic

        labels = [intent.value for intent in QueryIntent]
        remote = await self.mistral_client.classify_text(text=query, labels=labels)
        if not remote:
            return heuristic

        try:
            result = remote.get("results", remote.get("data", remote))
            if isinstance(result, list):
                first = result[0]
            else:
                first = result

            if "categories" in first:
                ranked = sorted(first["categories"], key=lambda item: item.get("score", 0.0), reverse=True)
                best = ranked[0]
                return ClassificationResult(
                    intent=QueryIntent(best["label"]),
                    confidence=float(best.get("score", 0.0)),
                    rationale="Mistral classification endpoint selected the highest-scoring intent.",
                    source=IntentSource.MISTRAL_CLASSIFIER,
                    candidates=[{item["label"]: float(item.get("score", 0.0))} for item in ranked],
                )
        except Exception as exc:
            self.logger.warning("Falling back to heuristic intent detection: %s", exc)

        return heuristic
