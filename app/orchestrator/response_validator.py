"""Response validation and deterministic fallback shaping."""

from __future__ import annotations

from app.schemas.response_schema import Citation, RetrievedEvidence


class ResponseValidator:
    """Ensure answers remain bounded and useful."""

    _contextual_prefixes = ("after ", "before ", "during ", "when ", "if ", "while ")

    def build_fallback_answer(self, evidence: list[RetrievedEvidence], warnings: list[str], scope: str = "all") -> str:
        if not evidence:
            if scope.startswith("nexus_"):
                return (
                    "Nexus does not have enough SOP-backed guidance that clearly matches this incident or service context. "
                    "I would not use an unrelated procedure here. Continue with the evidence Nexus has already retained, "
                    "confirm the affected service, failure domain, and recovery state, then capture an operator verdict so the learning loop can improve."
                )
            return (
                "I could not find strong SOP-backed guidance for that query in the current corpus. "
                "Please verify the exact system, symptom, and environment, then escalate according to the relevant administrative procedure."
            )

        primary = evidence[0]
        sections = ", ".join(primary.sections)
        answer = (
            f"The strongest SOP match is {primary.sop_id} ({primary.title}). "
            f"It points mainly to these sections: {sections}."
        )
        if warnings:
            answer += " " + " ".join(warnings[:2])
        return answer

    def recommended_steps(self, evidence: list[RetrievedEvidence], citations: list[Citation]) -> list[str]:
        steps: list[str] = []
        seen: set[str] = set()
        for citation in citations:
            if citation.section not in {"actions", "checks", "verification_steps", "escalation"}:
                continue
            score = float(getattr(citation, "score", 1.0))
            if score <= 0.05:
                continue
            text = citation.excerpt.strip()
            if text.lower().startswith(self._contextual_prefixes):
                continue
            if text in seen:
                continue
            seen.add(text)
            steps.append(text)
            if len(steps) >= 5:
                break

        if not steps and evidence:
            steps.append(f"Review SOP {evidence[0].sop_id} in full before making operational changes.")
        return steps

    def validate(self, answer: str | None, evidence: list[RetrievedEvidence], warnings: list[str], scope: str = "all") -> str:
        if not answer or not answer.strip():
            return self.build_fallback_answer(evidence=evidence, warnings=warnings, scope=scope)

        cleaned = answer.strip()
        if len(cleaned) < 20:
            return self.build_fallback_answer(evidence=evidence, warnings=warnings, scope=scope)
        return cleaned
