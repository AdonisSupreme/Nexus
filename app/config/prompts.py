"""Prompt builders for evidence-grounded operational responses."""

from __future__ import annotations

from app.schemas.intent_schema import ClassificationResult
from app.schemas.response_schema import RetrievedEvidence, SystemContext


def build_query_messages(
    query: str,
    intent: ClassificationResult,
    evidence: list[RetrievedEvidence],
    warnings: list[str],
    scope: str = "all",
    system_context: SystemContext | None = None,
) -> list[dict[str, str]]:
    evidence_lines: list[str] = []
    for item in evidence:
        evidence_lines.append(
            f"- SOP {item.sop_id} | {item.title} | class={item.class_code} | sections={', '.join(item.sections)}"
        )
        for excerpt in item.excerpts[:3]:
            evidence_lines.append(f"  excerpt: {excerpt}")

    warning_lines = "\n".join(f"- {warning}" for warning in warnings) or "- none"

    if scope.startswith("nexus_"):
        affected = ", ".join(system_context.affected_systems) if system_context and system_context.affected_systems else "not supplied"
        environment = system_context.environment if system_context and system_context.environment else "not supplied"
        system_prompt = (
            "You are Sentinel Nexus iNterpret intelligence inside SentinelOps. "
            "Speak like a calm senior incident commander writing to an operator, not like a report generator. "
            "Use natural paragraphs with clear operational meaning. Stay grounded in the supplied incident facts and "
            "retrieved SOP evidence. Only use an SOP when it explicitly matches the affected service, business flow, "
            "failure domain, environment, or system context. If no SOP is truly relevant, say Nexus does not have enough "
            "SOP-backed guidance for this incident and continue with evidence-based interpretation only. "
            "Do not borrow unrelated IDC, DR, database, or service-control procedures just because words overlap."
        )
        scope_instructions = (
            f"Nexus scope: {scope}\n"
            f"Affected systems: {affected}\n"
            f"Environment: {environment}\n"
            "Nexus response style:\n"
            "1. Start with the operational meaning in plain language.\n"
            "2. Explain what Nexus knows, what it infers, and what remains uncertain.\n"
            "3. Reference SOPs only when they match this exact incident context.\n"
            "4. If SOP confidence is weak or irrelevant, say so plainly and do not cite unrelated SOP IDs.\n"
            "5. End with the safest next operator move.\n"
            "6. Avoid markdown tables, decorative headings, and generic checklist dumps."
        )
    else:
        system_prompt = (
            "You are SentinelOps AI, an operational intelligence assistant for ICT operations. "
            "You must stay grounded in retrieved SOP evidence, avoid inventing facts, and explicitly "
            "warn when confidence is limited or manual reconciliation is still pending. "
            "Keep answers crisp, operational, and safe."
        )
        scope_instructions = (
            "Instructions:\n"
            "1. Answer only from retrieved evidence.\n"
            "2. If evidence is weak, say so directly.\n"
            "3. Give 2-5 next steps.\n"
            "4. Mention escalation when appropriate.\n"
            "5. Do not expose system internals."
        )

    user_prompt = (
        f"Operator query: {query}\n"
        f"Detected intent: {intent.intent.value} ({intent.confidence:.2f})\n"
        f"Known warnings:\n{warning_lines}\n"
        "Retrieved evidence:\n"
        f"{chr(10).join(evidence_lines) if evidence_lines else '- none'}\n\n"
        f"{scope_instructions}"
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
