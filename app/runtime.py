"""Application service container."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime
from uuid import uuid4

from app.config.settings import settings
from app.models.mistral_client import MistralClient
from app.nexus.service import NexusService
from app.orchestrator.orchestrator import OperationalOrchestrator
from app.rag.embedder import EmbeddingService
from app.rag.indexer import KnowledgeIndexer
from app.rag.retriever import HybridRetriever
from app.schemas.sop_schema import AlignmentStatus, NormalizedSOP, ProcedureStep, SOPClass, SOPProvenance, Severity
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
        self.nexus.startup()
        self.refresh_managed_sops()
        self.retriever.rebuild()
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
        self.refresh_managed_sops()
        self.retriever.rebuild()
        return self._record_job(
            kind="reindex",
            status="completed",
            details=result,
        )

    def refresh_managed_sops(self) -> int:
        try:
            managed_sops = self.nexus.list_managed_sops(include_deprecated=False)
        except Exception as exc:
            self.logger.warning("Managed Nexus SOP registry is not available: %s", exc)
            return 0

        if not managed_sops:
            self.retriever.rebuild()
            return 0

        managed_ids = {sop.sop_id for sop in managed_sops}
        self.indexer.chunks = [chunk for chunk in self.indexer.chunks if chunk.sop_id not in managed_ids]

        for sop in managed_sops:
            try:
                normalized = self._managed_sop_to_normalized(sop)
            except Exception as exc:
                self.logger.warning("Skipping invalid managed Nexus SOP %s: %s", sop.sop_id, exc)
                continue
            self.indexer.normalized_sops[normalized.id] = normalized
            chunks = self.indexer.chunker.chunk_sop(normalized)
            vectors = self.embedding_service.embed_texts([chunk.text for chunk in chunks])
            for chunk, vector in zip(chunks, vectors):
                chunk.vector = vector
            self.indexer.chunks.extend(chunks)

        self.retriever.rebuild()
        return len(managed_sops)

    def _managed_sop_to_normalized(self, sop) -> NormalizedSOP:
        now = sop.updated_at or datetime.utcnow()
        raw_payload = sop.model_dump(mode="json")
        source_hash = hashlib.sha256(json.dumps(raw_payload, sort_keys=True).encode("utf-8")).hexdigest()

        def steps(section: str) -> list[ProcedureStep]:
            return [
                ProcedureStep(
                    text=line,
                    sequence=index,
                    source_section=section,
                    atomic=True,
                    safety_critical=section in {"actions", "rollback", "escalation"},
                    markers=[],
                )
                for index, line in enumerate(sop.content.get(section, []), start=1)
            ]

        status = [AlignmentStatus.MANUALLY_ALIGNED if sop.status == "approved" else AlignmentStatus.PENDING_MANUAL_RECONCILIATION]
        if sop.status == "deprecated":
            status = [AlignmentStatus.DEPRECATED]

        return NormalizedSOP(
            id=sop.sop_id,
            class_code=SOPClass(sop.class_code),
            title=sop.title,
            severity=Severity(sop.severity),
            version=sop.version,
            services=sop.services,
            environments=sop.environments,
            aliases=sop.aliases,
            preconditions=steps("preconditions"),
            symptoms=steps("symptoms"),
            checks=steps("checks"),
            verification_steps=steps("verification_steps"),
            actions=steps("actions"),
            rollback=steps("rollback"),
            escalation=steps("escalation"),
            notes=steps("notes"),
            systems=sop.services,
            owners=[sop.owner_team] if sop.owner_team else [],
            artifacts=[],
            alignment_status=status,
            last_verified_at=sop.validation.checked_at or now,
            provenance=SOPProvenance(
                source_path=f"sentinelops-db://nexus_sop_registry/{sop.sop_id}",
                source_directory="sentinelops-db://nexus_sop_registry",
                source_format="postgres-jsonb",
                source_hash=source_hash,
                ingested_at=now,
                normalized_at=datetime.utcnow(),
            ),
            source_sections=sorted([section for section, lines in sop.content.items() if lines]),
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

    def list_indexed_sops(self) -> list[dict[str, object]]:
        """Expose the SOP corpus currently available to retrieval.

        Nexus has two SOP planes: database-managed SOPs that operators can
        govern from the Nexus page, and the indexed SOP corpus used by the
        RAG engine. This method makes the retrieval plane visible without
        pretending every indexed source is already managed in the DB registry.
        """

        try:
            managed_ids = {
                sop.sop_id
                for sop in self.nexus.list_managed_sops(include_deprecated=True)
            }
        except Exception:
            managed_ids = set()

        def step_texts(steps: list[ProcedureStep]) -> list[str]:
            return [step.text for step in steps]

        indexed: list[dict[str, object]] = []
        for sop in self.indexer.normalized_sops.values():
            content = {
                "preconditions": step_texts(sop.preconditions),
                "symptoms": step_texts(sop.symptoms),
                "checks": step_texts(sop.checks),
                "verification_steps": step_texts(sop.verification_steps),
                "actions": step_texts(sop.actions),
                "rollback": step_texts(sop.rollback),
                "escalation": step_texts(sop.escalation),
                "notes": step_texts(sop.notes),
            }
            chunk_count = sum(1 for chunk in self.indexer.chunks if chunk.sop_id == sop.id)
            active_sections = [
                section
                for section, lines in content.items()
                if lines
            ]
            indexed.append(
                {
                    "sop_id": sop.id,
                    "title": sop.title,
                    "class_code": sop.class_code.value,
                    "severity": sop.severity.value,
                    "version": sop.version,
                    "services": sop.services,
                    "environments": sop.environments,
                    "aliases": sop.aliases,
                    "systems": sop.systems,
                    "owners": sop.owners,
                    "source_sections": sop.source_sections or active_sections,
                    "content": content,
                    "alignment_status": [status.value for status in sop.alignment_status],
                    "last_verified_at": sop.last_verified_at.isoformat(),
                    "source_path": sop.provenance.source_path,
                    "source_directory": sop.provenance.source_directory,
                    "source_format": sop.provenance.source_format,
                    "chunk_count": chunk_count,
                    "managed": sop.id in managed_ids,
                }
            )

        return sorted(indexed, key=lambda item: (str(item["class_code"]), str(item["sop_id"])))

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
