"""Primary query and SOP inspection endpoints."""

from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request, status

from app.schemas.intent_schema import ClassificationRequest
from app.schemas.response_schema import ChatRequest, ChatResponse, SOPSearchRequest


router = APIRouter()


@router.post("/query", response_model=ChatResponse)
async def query(request_body: ChatRequest, request: Request) -> ChatResponse:
    services = request.app.state.services
    services.metrics.incr("sentinelops_queries_total")
    started = time.perf_counter()
    response = await services.orchestrator.handle_query(request_body)
    services.metrics.observe("sentinelops_query_duration_seconds", time.perf_counter() - started)
    return response


@router.post("/classify")
async def classify(request_body: ClassificationRequest, request: Request) -> dict[str, object]:
    services = request.app.state.services
    result = await services.orchestrator.intent_extractor.classify(
        query=request_body.query,
        use_remote_classifier=request_body.use_remote_classifier,
    )
    return result.model_dump(mode="json")


@router.post("/sops/search")
async def search_sops(request_body: SOPSearchRequest, request: Request) -> dict[str, object]:
    services = request.app.state.services
    results = services.search_chunks(query=request_body.query, top_k=request_body.top_k)
    filtered = [item for item in results if float(item.get("score", 0.0)) >= request_body.min_score]
    return {"results": filtered}


@router.get("/sops/{sop_id}")
async def get_sop(sop_id: str, request: Request) -> dict[str, object]:
    services = request.app.state.services
    sop = services.get_sop(sop_id)
    if sop is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SOP not found.")
    return sop


@router.get("/sops/{sop_id}/graph")
async def get_sop_graph(sop_id: str, request: Request) -> dict[str, object]:
    services = request.app.state.services
    sop = services.get_sop(sop_id)
    if sop is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SOP not found.")
    return {"nodes": [node.model_dump(mode="json") for node in services.get_sop_graph(sop_id)]}
