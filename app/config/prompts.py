"""Prompt builders for evidence-grounded operational responses."""

from __future__ import annotations

from app.schemas.intent_schema import ClassificationResult
from app.schemas.response_schema import RetrievedEvidence


def build_query_messages(
    query: str,
    intent: ClassificationResult,
    evidence: list[RetrievedEvidence],
    warnings: list[str],
) -> list[dict[str, str]]:
    evidence_lines: list[str] = []
    for item in evidence:
        evidence_lines.append(
            f"- SOP {item.sop_id} | {item.title} | class={item.class_code} | sections={', '.join(item.sections)}"
        )
        for excerpt in item.excerpts[:3]:
            evidence_lines.append(f"  excerpt: {excerpt}")

    warning_lines = "\n".join(f"- {warning}" for warning in warnings) or "- none"

    system_prompt = (
        "You are SentinelOps AI, an operational intelligence assistant for ICT operations. "
        "You must stay grounded in retrieved SOP evidence, avoid inventing facts, and explicitly "
        "warn when confidence is limited or manual reconciliation is still pending. "
        "Keep answers crisp, operational, and safe."
    )

    user_prompt = (
        f"Operator query: {query}\n"
        f"Detected intent: {intent.intent.value} ({intent.confidence:.2f})\n"
        f"Known warnings:\n{warning_lines}\n"
        "Retrieved evidence:\n"
        f"{chr(10).join(evidence_lines) if evidence_lines else '- none'}\n\n"
        "Instructions:\n"
        "1. Answer only from retrieved evidence.\n"
        "2. If evidence is weak, say so directly.\n"
        "3. Give 2-5 next steps.\n"
        "4. Mention escalation when appropriate.\n"
        "5. Do not expose system internals."
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
