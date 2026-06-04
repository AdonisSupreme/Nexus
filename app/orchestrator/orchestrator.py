"""End-to-end query orchestration."""

from __future__ import annotations

import re
from uuid import uuid4

from app.config.prompts import build_query_messages
from app.config.settings import settings
from app.models.mistral_client import MistralClient
from app.orchestrator.confidence_gate import ConfidenceGate
from app.orchestrator.context_builder import ContextBuilder
from app.orchestrator.intent_extractor import IntentExtractor
from app.orchestrator.response_validator import ResponseValidator
from app.rag.indexer import KnowledgeIndexer
from app.rag.retriever import HybridRetriever
from app.schemas.response_schema import ChatRequest, ChatResponse
from app.utils.audit import audit_logger
from app.utils.logging import get_logger


class OperationalOrchestrator:
    """Coordinate intent detection, retrieval, synthesis, and validation."""

    def __init__(
        self,
        indexer: KnowledgeIndexer,
        retriever: HybridRetriever,
        mistral_client: MistralClient,
    ) -> None:
        self.indexer = indexer
        self.retriever = retriever
        self.mistral_client = mistral_client
        self.intent_extractor = IntentExtractor(mistral_client=mistral_client)
        self.context_builder = ContextBuilder()
        self.confidence_gate = ConfidenceGate()
        self.response_validator = ResponseValidator()
        self.logger = get_logger(__name__)

    async def handle_query(self, request: ChatRequest) -> ChatResponse:
        trace_id = str(uuid4())
        intent = await self.intent_extractor.classify(query=request.query)
        retrieved_chunks = self.retriever.search(request.query, top_k=settings.MAX_SOP_RETRIEVAL)
        relevance_notes: list[str] = []
        if request.scope.startswith("nexus_"):
            retrieved_chunks, relevance_notes = self._filter_nexus_sop_context(
                request=request,
                chunks=retrieved_chunks,
            )
        evidence, citations = self.context_builder.build(retrieved_chunks)
        confidence, warnings = self.confidence_gate.evaluate(evidence=evidence)
        warnings.extend(relevance_notes)

        answer: str | None = None
        llm_attempted = bool(evidence and self.mistral_client.available)
        if llm_attempted:
            messages = build_query_messages(
                query=request.query,
                intent=intent,
                evidence=evidence,
                warnings=warnings,
                scope=request.scope,
                system_context=request.system_context,
            )
            answer = await self.mistral_client.chat_complete(messages=messages)

        validated_answer = self.response_validator.validate(
            answer=answer,
            evidence=evidence,
            warnings=warnings,
            scope=request.scope,
        )
        next_steps = self.response_validator.recommended_steps(evidence=evidence, citations=citations)

        audit_logger.log_intent_classification(
            user=request.user_context.username or request.user_context.user_id or "unknown",
            query=request.query,
            detected_intent=intent.intent.value,
            confidence=intent.confidence,
        )
        audit_logger.log_sop_retrieval(
            user=request.user_context.username or request.user_context.user_id or "unknown",
            query=request.query,
            intent=intent.intent.value,
            sop_ids=[item.sop_id for item in evidence],
            confidence=confidence,
            response_id=trace_id,
        )

        trace = None
        if request.trace:
            trace = {
                "chunk_ids": [chunk.chunk_id for chunk in retrieved_chunks],
                "provider": self.mistral_client.diagnostics(),
                "inference": {
                    "evidence_count": len(evidence),
                    "llm_attempted": llm_attempted,
                    "llm_answer_received": bool(answer and answer.strip()),
                    "fallback_used": not bool(answer and answer.strip()),
                    "nexus_scope": request.scope.startswith("nexus_"),
                    "sop_relevance_notes": relevance_notes,
                },
                "warnings": warnings,
            }

        return ChatResponse(
            answer=validated_answer,
            intent=intent,
            confidence=confidence,
            citations=citations,
            recommended_next_steps=next_steps,
            retrieved_sops=evidence,
            warnings=warnings,
            trace_id=trace_id,
            trace=trace,
        )

    def _filter_nexus_sop_context(self, request: ChatRequest, chunks: list[object]) -> tuple[list[object], list[str]]:
        """Keep Nexus briefs from grounding on procedures for the wrong system."""

        if not chunks:
            return [], []

        anchors = self._nexus_anchor_terms(request)
        if not anchors:
            return chunks, []

        filtered = []
        for chunk in chunks:
            sop_id = str(getattr(chunk, "sop_id", ""))
            sop = self.indexer.normalized_sops.get(sop_id)
            haystack_parts = [
                getattr(chunk, "title", ""),
                getattr(chunk, "text", ""),
                *(sop.services if sop else []),
                *(sop.systems if sop else []),
                *(sop.aliases if sop else []),
                *(sop.environments if sop else []),
            ]
            haystack = self._normalize_for_match(" ".join(str(part) for part in haystack_parts))
            if any(anchor in haystack for anchor in anchors):
                filtered.append(chunk)

        if filtered:
            return filtered, []
        return [], [
            (
                "No SOP evidence explicitly matched the Nexus incident service, affected systems, "
                "environment, or business-flow context. Use Nexus evidence only and avoid unrelated procedures."
            )
        ]

    def _nexus_anchor_terms(self, request: ChatRequest) -> set[str]:
        raw_terms: set[str] = set()
        raw_terms.update(request.system_context.affected_systems or [])
        if request.system_context.environment:
            raw_terms.add(request.system_context.environment)

        for line in request.query.splitlines():
            lowered = line.lower()
            if any(
                marker in lowered
                for marker in (
                    "incident:",
                    "failure domain:",
                    "business flow:",
                    "affected services:",
                    "probable root cause:",
                    "root candidates:",
                    "service:",
                    "environment:",
                )
            ):
                raw_terms.add(line.split(":", 1)[-1] if ":" in line else line)

        anchors: set[str] = set()
        for term in raw_terms:
            normalized = self._normalize_for_match(str(term))
            if not normalized:
                continue
            anchors.add(normalized)
            for token in normalized.split():
                if len(token) >= 3 and token not in {"the", "and", "for", "with", "risk", "open", "low", "high"}:
                    anchors.add(token)
        return anchors

    @staticmethod
    def _normalize_for_match(value: str) -> str:
        return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", value.lower())).strip()
