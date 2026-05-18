"""Intent and routing schemas."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class QueryIntent(str, Enum):
    INCIDENT_RESPONSE = "incident_response"
    SERVICE_CONTROL = "service_control"
    ENVIRONMENT_MANAGEMENT = "environment_management"
    DISASTER_RECOVERY = "disaster_recovery"
    VERIFICATION_HEALTH = "verification_health"
    ADMINISTRATIVE = "administrative"
    GENERAL_GUIDANCE = "general_guidance"


class IntentSource(str, Enum):
    HEURISTIC = "heuristic"
    MISTRAL_CLASSIFIER = "mistral_classifier"
    MISTRAL_CHAT = "mistral_chat"
    FALLBACK = "fallback"


class ClassificationRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=4000)
    use_remote_classifier: bool = Field(default=True)


class ClassificationResult(BaseModel):
    intent: QueryIntent
    confidence: float = Field(..., ge=0.0, le=1.0)
    rationale: str
    source: IntentSource
    candidates: list[dict[str, float]] = Field(default_factory=list)
