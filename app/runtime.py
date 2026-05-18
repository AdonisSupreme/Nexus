"""Application service container."""

from __future__ import annotations

import json
from datetime import datetime
from uuid import uuid4

from app.config.settings import settings
from app.models.mistral_client import MistralClient
from app.nexus.service import NexusService
from app.orchestrator.orchestrator import OperationalOrchestrator
from app.rag.embedder import EmbeddingService
from app.rag.indexer import KnowledgeIndexer
from app.rag.retriever import HybridRetriever
from app.schemas.response_schema import AlignmentReport, EngineState, IndexStats, KnowledgeJob, SOPGraphNode
from app.utils.cache import LocalTTLCache, cache_connection_metadata
from app.utils.logging import get_logger
from app.utils.metrics import MetricsRegistry


class ApplicationServices:
    """Own the runtime dependencies for the API."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self.metrics = MetricsRegistry()
        self.cache = LocalTTLCache()
        self.embedding_service = EmbeddingService()
        self.indexer = KnowledgeIndexer(embedding_service=self.embedding_service)
        self.retriever = HybridRetriever(indexer=self.indexer)
        self.mistral_client = MistralClient()
        self.nexus = NexusService()
        self.orchestrator = OperationalOrchestrator(
            indexer=self.indexer,
            retriever=self.retriever,
            mistral_client=self.mistral_client,
        )
        self.jobs: dict[str, KnowledgeJob] = {}

    async def startup(self) -> None:
        await self.mistral_client.startup()
        loaded = self.indexer.load_from_disk()
        if not loaded:
            self.indexer.ingest()
        self.retriever.rebuild()
        self.nexus.startup()
        self.metrics.gauge("sentinelops_sops_total", len(self.indexer.normalized_sops))
        self.metrics.gauge("sentinelops_chunks_total", len(self.indexer.chunks))
        self.metrics.gauge("sentinelops_nexus_services_total", len(self.nexus.state.services))
        self.metrics.gauge("sentinelops_nexus_incidents_total", len(self.nexus.state.incidents))

    async def shutdown(self) -> None:
        await self.mistral_client.shutdown()

    def _record_job(self, kind: str, status: str, details: dict[str, object], warnings: list[str] | None = None, errors: list[str] | None = None) -> KnowledgeJob:
        now = datetime.utcnow()
        job = KnowledgeJob(
            job_id=str(uuid4()),
            kind=kind,
            status=status,
            started_at=now,
            finished_at=now,
            details=details,
            warnings=warnings or [],
            errors=errors or [],
        )
        self.jobs[job.job_id] = job
        target = settings.JOBS_DIR / f"{job.job_id}.json"
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(job.model_dump(mode="json"), handle, indent=2, ensure_ascii=False)
        return job

    def validate_knowledge(self) -> KnowledgeJob:
        result = self.indexer.validate_sources()
        status = "completed" if result.invalid_sops == 0 else "completed_with_errors"
        return self._record_job(
            kind="validate",
            status=status,
            details=result.model_dump(mode="json"),
        )

    def ingest_knowledge(self) -> KnowledgeJob:
        result = self.indexer.ingest()
        self.retriever.rebuild()
        self.metrics.gauge("sentinelops_sops_total", len(self.indexer.normalized_sops))
        self.metrics.gauge("sentinelops_chunks_total", len(self.indexer.chunks))
        return self._record_job(
            kind="ingest",
            status="completed",
            details=result,
            warnings=["All SOPs remain pending manual reconciliation until the new procedure manual is exported into machine-readable form."],
        )

    def reindex_knowledge(self) -> KnowledgeJob:
        result = self.indexer.ingest()
        self.retriever.rebuild()
        return self._record_job(
            kind="reindex",
            status="completed",
            details=result,
        )

    def alignment_report(self) -> AlignmentReport:
        return self.indexer.generate_alignment_report()

    def get_job(self, job_id: str) -> KnowledgeJob | None:
        job = self.jobs.get(job_id)
        if job:
            return job
        target = settings.JOBS_DIR / f"{job_id}.json"
        if not target.exists():
            return None
        with open(target, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return KnowledgeJob.model_validate(payload)

    def search_chunks(self, query: str, top_k: int) -> list[dict[str, object]]:
        chunks = self.retriever.search(query=query, top_k=top_k)
        return [chunk.to_dict(include_vector=False) for chunk in chunks]

    def get_sop(self, sop_id: str) -> dict[str, object] | None:
        sop = self.indexer.normalized_sops.get(sop_id)
        return sop.to_dict() if sop else None

    def get_sop_graph(self, sop_id: str) -> list[SOPGraphNode]:
        return [
            SOPGraphNode(
                chunk_id=chunk.chunk_id,
                sop_id=chunk.sop_id,
                section=chunk.section,
                sequence=chunk.sequence,
                text=chunk.text,
                score=chunk.score,
            )
            for chunk in self.indexer.chunks
            if chunk.sop_id == sop_id
        ]

    def engine_state(self) -> EngineState:
        return EngineState(
            status="ready",
            environment=settings.ENVIRONMENT,
            providers={
                "mistral": self.mistral_client.diagnostics(),
                "embeddings": self.embedding_service.diagnostics(),
                "postgres": cache_connection_metadata(
                    settings.nexus_database_dsn
                ),
                "redis": cache_connection_metadata(
                    settings.REDIS_URL.get_secret_value() if settings.REDIS_URL else None
                ),
                "qdrant": cache_connection_metadata(settings.QDRANT_URL),
            },
            index=IndexStats(
                sops=len(self.indexer.normalized_sops),
                chunks=len(self.indexer.chunks),
                vector_backend=settings.VECTOR_STORE_TYPE,
                cache_backend=self.cache.backend,
                normalized_at=self.indexer.last_ingest_at,
            ),
            cache=self.cache.diagnostics(),
            circuit_breaker=self.mistral_client.diagnostics()["circuit_breaker"],
            last_ingest_at=self.indexer.last_ingest_at,
        )
