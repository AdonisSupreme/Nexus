"""Confidence and safety gating for generated responses."""

from __future__ import annotations

from app.config.settings import settings
from app.schemas.response_schema import RetrievedEvidence


class ConfidenceGate:
    """Score confidence and surface warnings before synthesis."""

    def evaluate(self, evidence: list[RetrievedEvidence]) -> tuple[float, list[str]]:
        if not evidence:
            return 0.1, ["No SOP evidence matched the query."]

        top_score = evidence[0].score
        source_count = len(evidence)
        base_confidence = min(0.95, (top_score * 0.7) + min(source_count, 3) * 0.08)

        warnings: list[str] = []
        if top_score < settings.LOW_CONFIDENCE_THRESHOLD:
            warnings.append("Low retrieval confidence. Treat the response as advisory and verify manually.")
        if source_count == 1:
            warnings.append("Only one SOP source matched. Cross-check related procedures before acting.")
        if any("pending_manual_reconciliation" in item.alignment_status for item in evidence):
            warnings.append("The matched SOPs are still pending reconciliation against the new manual.")

        return round(base_confidence, 3), warnings
