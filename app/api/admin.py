"""Protected admin, ingestion, and diagnostics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from app.utils.auth import require_admin_token


router = APIRouter(dependencies=[Depends(require_admin_token)])


@router.post("/knowledge/validate")
async def validate_knowledge(request: Request) -> dict[str, object]:
    services = request.app.state.services
    job = services.validate_knowledge()
    return job.model_dump(mode="json")


@router.post("/knowledge/ingest")
async def ingest_knowledge(request: Request) -> dict[str, object]:
    services = request.app.state.services
    job = services.ingest_knowledge()
    return job.model_dump(mode="json")


@router.post("/knowledge/reindex")
async def reindex_knowledge(request: Request) -> dict[str, object]:
    services = request.app.state.services
    job = services.reindex_knowledge()
    return job.model_dump(mode="json")


@router.get("/knowledge/jobs/{job_id}")
async def get_job(job_id: str, request: Request) -> dict[str, object]:
    services = request.app.state.services
    job = services.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
    return job.model_dump(mode="json")


@router.get("/knowledge/alignment-report")
async def get_alignment_report(request: Request) -> dict[str, object]:
    services = request.app.state.services
    return services.alignment_report().model_dump(mode="json")


@router.get("/diagnostics/state")
async def diagnostics_state(request: Request) -> dict[str, object]:
    services = request.app.state.services
    return services.engine_state().model_dump(mode="json")


@router.get("/diagnostics/engine")
async def diagnostics_engine(request: Request) -> dict[str, object]:
    services = request.app.state.services
    return services.mistral_client.diagnostics()


@router.get("/diagnostics/index")
async def diagnostics_index(request: Request) -> dict[str, object]:
    services = request.app.state.services
    return {
        "sops": len(services.indexer.normalized_sops),
        "chunks": len(services.indexer.chunks),
        "last_ingest_at": services.indexer.last_ingest_at.isoformat() + "Z" if services.indexer.last_ingest_at else None,
    }


@router.get("/diagnostics/providers")
async def diagnostics_providers(request: Request) -> dict[str, object]:
    services = request.app.state.services
    return services.engine_state().providers


@router.get("/diagnostics/cache")
async def diagnostics_cache(request: Request) -> dict[str, object]:
    services = request.app.state.services
    return services.cache.diagnostics()


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics(request: Request) -> str:
    services = request.app.state.services
    return services.metrics.render_prometheus()
