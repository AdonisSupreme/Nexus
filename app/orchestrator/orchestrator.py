"""End-to-end query orchestration."""

from __future__ import annotations

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
        evidence, citations = self.context_builder.build(retrieved_chunks)
        confidence, warnings = self.confidence_gate.evaluate(evidence=evidence)

        answer: str | None = None
        if evidence and self.mistral_client.available:
            messages = build_query_messages(
                query=request.query,
                intent=intent,
                evidence=evidence,
                warnings=warnings,
            )
            answer = await self.mistral_client.chat_complete(messages=messages)

        validated_answer = self.response_validator.validate(
            answer=answer,
            evidence=evidence,
            warnings=warnings,
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
