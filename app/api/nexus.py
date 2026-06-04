"""Sentinel Nexus API endpoints."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.nexus.models import (
    AgentControlResult,
    AgentDiagnosticResult,
    AgentHeartbeat,
    AgentProbeReport,
    BusinessFlowUpsertRequest,
    ChangeEventRequest,
    DatabaseConnectionTestRequest,
    DependencyClusterUpsertRequest,
    DependencyEdgeUpsertRequest,
    DiagnosticsRequest,
    IncidentVerdictRequest,
    ManagedSopUpsertRequest,
    ManagedSopValidationRequest,
    RestartActionRequest,
    RolloverAssessmentRequest,
    RolloverChallengeRequest,
    RolloverEnvironmentUpsertRequest,
    RolloverExecuteRequest,
    RolloverReminderRequest,
    ServiceControlChallengeRequest,
    ServiceControlExecuteRequest,
    ServiceUpsertRequest,
    SyncRequest,
    TaskHandoffRequest,
)
from app.utils.nexus_agent_auth import validate_nexus_agent_request
from app.utils.sentinelops_auth import require_nexus_access, require_nexus_admin, require_nexus_operator


router = APIRouter()


class TimelineChatTurn(BaseModel):
    role: Literal["operator", "nexus"]
    content: str = Field(..., min_length=1, max_length=5000)
    created_at: str | None = None


class ServiceTimelineChatRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=3000)
    history: list[TimelineChatTurn] = Field(default_factory=list, max_length=12)
    timezone: str | None = None


class ServiceTimelineChatResponse(BaseModel):
    answer: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    trace_id: str
    llm_used: bool
    suggestions: list[str] = Field(default_factory=list)
    facts: dict[str, object] = Field(default_factory=dict)


class AgentTokenGenerateRequest(BaseModel):
    rotate: bool = False


class AgentTokenStatusResponse(BaseModel):
    configured: bool
    source: str
    token_id: str | None = None
    token_prefix: str | None = None
    created_by: str | None = None
    created_at: datetime | None = None
    last_used_at: datetime | None = None
    usage_count: int = 0
    warning: str | None = None


class AgentTokenGenerateResponse(AgentTokenStatusResponse):
    token: str
    rotated: bool = False


@router.get("/nexus/incidents")
async def list_incidents(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    incidents = [incident.model_dump(mode="json") for incident in services.nexus.list_incidents()]
    return {"incidents": incidents}


@router.get("/nexus/fabric-summary")
async def get_fabric_summary(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    return services.nexus.get_fabric_summary().model_dump(mode="json")


@router.get("/nexus/agents/token", response_model=AgentTokenStatusResponse)
async def get_agent_token_status(request: Request, _: dict = Depends(require_nexus_admin)) -> dict[str, object]:
    services = request.app.state.services
    return services.nexus.get_agent_token_status()


@router.get("/nexus/agents")
async def list_light_agents(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    return {"agents": services.nexus.list_light_agents()}


@router.post("/nexus/agents/token", response_model=AgentTokenGenerateResponse)
async def generate_agent_token(
    request_body: AgentTokenGenerateRequest,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or "nexus-admin"
    try:
        return services.nexus.generate_agent_token(created_by=actor, rotate=request_body.rotate)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.post("/nexus/sync/network-sentinel")
async def sync_network_sentinel(
    request_body: SyncRequest,
    request: Request,
    _: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    return services.nexus.sync_network_sentinel(request_body).model_dump(mode="json")


@router.get("/nexus/catalog/services")
async def list_services(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    return {"services": [item.model_dump(mode="json") for item in services.nexus.list_services()]}


@router.post("/nexus/catalog/services")
async def upsert_service(
    request_body: ServiceUpsertRequest,
    request: Request,
    _: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    try:
        service = services.nexus.upsert_service(request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return service.model_dump(mode="json")


@router.delete("/nexus/catalog/services/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_service(service_id: str, request: Request, _: dict = Depends(require_nexus_admin)) -> None:
    services = request.app.state.services
    try:
        services.nexus.delete_service(service_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/nexus/catalog/services/{service_id}/database/test-connection")
async def test_catalog_database_connection(
    service_id: str,
    request_body: DatabaseConnectionTestRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or request_body.requested_by or "nexus-operator"
    payload = request_body.model_copy(update={"requested_by": request_body.requested_by or actor})
    try:
        result = await run_in_threadpool(services.nexus.test_database_fabric_connection, service_id, payload, user=actor)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@router.get("/nexus/catalog/clusters")
async def list_clusters(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    return {"clusters": [item.model_dump(mode="json") for item in services.nexus.list_clusters()]}


@router.post("/nexus/catalog/clusters")
async def upsert_cluster(
    request_body: DependencyClusterUpsertRequest,
    request: Request,
    _: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    try:
        cluster = services.nexus.upsert_cluster(request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return cluster.model_dump(mode="json")


@router.delete("/nexus/catalog/clusters/{cluster_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_cluster(cluster_id: str, request: Request, _: dict = Depends(require_nexus_admin)) -> None:
    services = request.app.state.services
    try:
        services.nexus.delete_cluster(cluster_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/nexus/catalog/business-flows")
async def list_business_flows(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    return {"business_flows": [item.model_dump(mode="json") for item in services.nexus.list_business_flows()]}


@router.post("/nexus/catalog/business-flows")
async def upsert_business_flow(
    request_body: BusinessFlowUpsertRequest,
    request: Request,
    _: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    try:
        flow = services.nexus.upsert_business_flow(request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return flow.model_dump(mode="json")


@router.delete("/nexus/catalog/business-flows/{flow_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_business_flow(flow_id: str, request: Request, _: dict = Depends(require_nexus_admin)) -> None:
    services = request.app.state.services
    try:
        services.nexus.delete_business_flow(flow_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/nexus/catalog/dependencies")
async def list_dependencies(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    return {"dependencies": [item.model_dump(mode="json") for item in services.nexus.list_edges()]}


@router.post("/nexus/catalog/dependencies")
async def upsert_dependency(
    request_body: DependencyEdgeUpsertRequest,
    request: Request,
    _: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    try:
        edge = services.nexus.upsert_edge(request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return edge.model_dump(mode="json")


@router.delete("/nexus/catalog/dependencies/{edge_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dependency(edge_id: str, request: Request, _: dict = Depends(require_nexus_admin)) -> None:
    services = request.app.state.services
    try:
        services.nexus.delete_edge(edge_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/nexus/rollover/environments")
async def list_rollover_environments(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    return {"environments": [item.model_dump(mode="json") for item in services.nexus.list_rollover_environments()]}


@router.post("/nexus/rollover/environments")
async def upsert_rollover_environment(
    request_body: RolloverEnvironmentUpsertRequest,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or "nexus-admin"
    try:
        environment = await run_in_threadpool(services.nexus.upsert_rollover_environment, request_body, user=actor)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return environment.model_dump(mode="json")


@router.delete("/nexus/rollover/environments/{environment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rollover_environment(
    environment_id: str,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> None:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or "nexus-admin"
    try:
        await run_in_threadpool(services.nexus.delete_rollover_environment, environment_id, user=actor)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.get("/nexus/rollover/environments/{environment_id}/services")
async def get_rollover_environment_services(
    environment_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    try:
        linked_services = services.nexus.get_rollover_environment_services(environment_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"services": [item.model_dump(mode="json") for item in linked_services]}


@router.post("/nexus/rollover/environments/{environment_id}/assess")
async def assess_rollover_environment(
    environment_id: str,
    request_body: RolloverAssessmentRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or request_body.requested_by or "nexus-operator"
    payload = request_body.model_copy(update={"requested_by": request_body.requested_by or actor})
    try:
        assessment = await run_in_threadpool(services.nexus.assess_rollover_environment, environment_id, payload, user=actor)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return assessment.model_dump(mode="json")


@router.post("/nexus/rollover/environments/{environment_id}/test-connection")
async def test_rollover_connection(
    environment_id: str,
    request_body: DatabaseConnectionTestRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or request_body.requested_by or "nexus-operator"
    payload = request_body.model_copy(update={"requested_by": request_body.requested_by or actor})
    try:
        result = await run_in_threadpool(services.nexus.test_rollover_connection, environment_id, payload, user=actor)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@router.post("/nexus/rollover/environments/{environment_id}/challenge")
async def request_rollover_challenge(
    environment_id: str,
    request_body: RolloverChallengeRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or request_body.requested_by or "nexus-operator"
    payload = request_body.model_copy(update={"requested_by": request_body.requested_by or actor})
    try:
        challenge = await run_in_threadpool(services.nexus.request_rollover_challenge, environment_id, payload, user=user)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return challenge.model_dump(mode="json")


@router.post("/nexus/rollover/environments/{environment_id}/execute")
async def execute_rollover(
    environment_id: str,
    request_body: RolloverExecuteRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or request_body.requested_by or "nexus-operator"
    payload = request_body.model_copy(update={"requested_by": request_body.requested_by or actor})
    try:
        execution = await run_in_threadpool(services.nexus.execute_rollover, environment_id, payload, user=user)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return execution.model_dump(mode="json")


@router.get("/nexus/rollover/executions")
async def list_rollover_executions(
    request: Request,
    environment_id: str | None = Query(None),
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    return {"executions": [item.model_dump(mode="json") for item in services.nexus.list_rollover_executions(environment_id)]}


@router.get("/nexus/rollover/reminders")
async def list_rollover_reminders(
    request: Request,
    environment_id: str | None = Query(None),
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    return {"reminders": [item.model_dump(mode="json") for item in services.nexus.list_rollover_reminders(environment_id)]}


@router.post("/nexus/rollover/environments/{environment_id}/reminders")
async def schedule_rollover_reminder(
    environment_id: str,
    request_body: RolloverReminderRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or request_body.created_by or "nexus-operator"
    payload = request_body.model_copy(update={"created_by": request_body.created_by or actor})
    try:
        reminder = await run_in_threadpool(services.nexus.schedule_rollover_reminder, environment_id, payload, user=actor)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return reminder.model_dump(mode="json")


@router.delete("/nexus/rollover/reminders/{reminder_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_rollover_reminder(
    reminder_id: str,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> None:
    services = request.app.state.services
    actor = user.get("username") or user.get("email") or "nexus-operator"
    try:
        await run_in_threadpool(services.nexus.cancel_rollover_reminder, reminder_id, user=actor)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.get("/nexus/sops")
async def list_managed_sops(
    request: Request,
    include_deprecated: bool = Query(False),
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    return {
        "sops": [
            item.model_dump(mode="json")
            for item in services.nexus.list_managed_sops(include_deprecated=include_deprecated)
        ]
    }


@router.get("/nexus/sops/indexed")
async def list_indexed_sops(
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    return {
        "sops": services.list_indexed_sops(),
        "summary": {
            "indexed": len(services.indexer.normalized_sops),
            "chunks": len(services.indexer.chunks),
        },
    }


@router.post("/nexus/sops")
async def upsert_managed_sop(
    request_body: ManagedSopUpsertRequest,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    payload = request_body.model_copy(
        update={"updated_by": request_body.updated_by or user.get("username") or user.get("email") or "nexus-admin"}
    )
    try:
        sop = services.nexus.upsert_managed_sop(payload)
        services.refresh_managed_sops()
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return sop.model_dump(mode="json")


@router.post("/nexus/sops/{sop_id}/validate")
async def validate_managed_sop(
    sop_id: str,
    request_body: ManagedSopValidationRequest,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    payload = request_body.model_copy(
        update={"requested_by": request_body.requested_by or user.get("username") or user.get("email") or "nexus-admin"}
    )
    try:
        sop = services.nexus.validate_managed_sop(sop_id, payload)
        services.refresh_managed_sops()
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return sop.model_dump(mode="json")


@router.delete("/nexus/sops/{sop_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_managed_sop(
    sop_id: str,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> None:
    services = request.app.state.services
    try:
        services.nexus.delete_managed_sop(sop_id, user.get("username") or user.get("email") or "nexus-admin")
        services.refresh_managed_sops()
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.get("/nexus/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    incident = services.nexus.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return incident.model_dump(mode="json")


@router.get("/nexus/services/{service_id}/graph-context")
async def get_graph_context(
    service_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    try:
        context = services.nexus.get_graph_context(service_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return context.model_dump(mode="json")


@router.get("/nexus/services/{service_id}/live-state")
async def get_service_live_state(
    service_id: str,
    request: Request,
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    try:
        return services.nexus.get_service_live_state(service_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.get("/nexus/services/{service_id}/signals")
async def get_service_signal_feed(
    service_id: str,
    request: Request,
    source: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=150, ge=1, le=300),
    since_hours: int = Query(default=24, ge=1, le=168),
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    try:
        return services.nexus.get_service_signal_feed(
            service_id,
            source=source,
            limit=limit,
            since_hours=since_hours,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.get("/nexus/services/{service_id}/log-tail")
async def get_service_log_tail(
    service_id: str,
    request: Request,
    lines: int = Query(default=120, ge=20, le=300),
    cursor: int | None = Query(default=None, ge=0),
    _: dict = Depends(require_nexus_access),
) -> dict[str, object]:
    services = request.app.state.services
    try:
        return services.nexus.get_service_log_tail(service_id, lines=lines, cursor=cursor)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.post("/nexus/services/{service_id}/timeline-chat", response_model=ServiceTimelineChatResponse)
async def ask_service_timeline(
    service_id: str,
    request_body: ServiceTimelineChatRequest,
    request: Request,
    user: dict = Depends(require_nexus_access),
) -> ServiceTimelineChatResponse:
    services = request.app.state.services
    service = next((item for item in services.nexus.list_services() if item.service_id == service_id), None)
    if service is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found.")

    smalltalk = _timeline_smalltalk_answer(request_body.question, service.service_name)
    if smalltalk:
        return ServiceTimelineChatResponse(
            answer=smalltalk,
            confidence=0.94,
            trace_id=str(uuid4()),
            llm_used=False,
            suggestions=[
                "What happened in the last 24 hours?",
                "Give more context on the incidents",
                "What changed before recovery?",
                "What should I check next?",
            ],
            facts={"service_id": service.service_id, "service_name": service.service_name, "intent": "conversational"},
        )

    history_payload = [turn.model_dump(mode="json") for turn in request_body.history[-10:]]
    incidents = [
        incident
        for incident in services.nexus.list_incidents()
        if service_id in incident.affected_services
        or incident.suspected_root_service == service_id
        or any(candidate.service_id == service_id for candidate in incident.root_cause_candidates)
    ]
    incidents.sort(key=lambda item: _as_naive_utc(item.start_time), reverse=True)
    timezone_name = request_body.timezone or "Africa/Harare"
    facts = _service_timeline_facts(service, incidents, timezone_name)
    facts["question_intent"] = _timeline_question_intent(request_body.question, history_payload)
    facts["period_analysis"] = _service_timeline_period_analysis(
        incidents,
        request_body.question,
        timezone_name,
        history_payload,
    )
    facts["operator_context_brief"] = _timeline_operator_context_brief(
        service=service,
        incidents=incidents,
        facts=facts,
        question=request_body.question,
        timezone_name=timezone_name,
    )
    prompt = _build_service_timeline_prompt(
        service=service.model_dump(mode="json"),
        incidents=[incident.model_dump(mode="json") for incident in incidents[:20]],
        facts=facts,
        question=request_body.question,
        history=history_payload,
        username=user.get("username") or user.get("email") or "operator",
        timezone=timezone_name,
    )

    llm_answer = None
    if services.mistral_client.available:
        llm_answer = await services.mistral_client.chat_complete(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are Sentinel Nexus Service Timeline Intelligence. Answer like a calm senior operator who "
                        "already reviewed the service timeline for the user. Use only the supplied service timeline "
                        "context and computed facts. Preserve chat memory, but never invent facts from it. Be precise "
                        "about the difference between active operational impact, recovered incidents awaiting verdict, "
                        "and fully resolved incidents. Do not give generic SOP advice unless the operator asks for a "
                        "procedure and the supplied context supports it. Use the exact years and local timestamps supplied "
                        "in context. For context/detail questions, explain evidence patterns, likely interpretation, "
                        "uncertainty, and why the incidents are related. Write in natural explanatory prose with compact "
                        "bullets only when they improve clarity. The supplied operator_context_brief is the minimum "
                        "depth expected for incident questions; do not answer with only headlines if Nexus has evidence."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=1400,
        )

    fallback = _fallback_service_timeline_answer(service.model_dump(mode="json"), incidents, facts, request_body.question)
    answer = fallback if _timeline_answer_too_thin(llm_answer, facts) else llm_answer or fallback
    llm_used = bool(llm_answer and answer == llm_answer)
    return ServiceTimelineChatResponse(
        answer=answer,
        confidence=0.82 if llm_used else 0.72 if llm_answer else 0.58,
        trace_id=str(uuid4()),
        llm_used=llm_used,
        suggestions=[
            "What is the current state?",
            "Explain the last incident like an operator brief",
            "Which evidence separated runtime from network impact?",
            "What verdict should I record and why?",
        ],
        facts=facts,
    )


@router.post("/nexus/change-events")
async def create_change_event(
    request_body: ChangeEventRequest,
    request: Request,
    user: dict = Depends(require_nexus_admin),
) -> dict[str, object]:
    services = request.app.state.services
    request_body.source = user.get("username") or user.get("email") or request_body.source
    try:
        event = services.nexus.record_change_event(request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return event.model_dump(mode="json")


@router.post("/nexus/incidents/{incident_id}/diagnostics")
async def request_diagnostics(
    incident_id: str,
    request_body: DiagnosticsRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    request_body.requested_by = user.get("username") or user.get("email") or request_body.requested_by
    try:
        bundle = await run_in_threadpool(services.nexus.request_diagnostics, incident_id, request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return bundle.model_dump(mode="json")


@router.post("/nexus/incidents/{incident_id}/actions/restart")
async def restart_action(
    incident_id: str,
    request_body: RestartActionRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    request_body.requested_by = user.get("username") or user.get("email") or request_body.requested_by
    try:
        action = await run_in_threadpool(services.nexus.handle_restart_action, incident_id, request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return action.model_dump(mode="json")


@router.post("/nexus/services/{service_id}/diagnostics")
async def request_service_diagnostics(
    service_id: str,
    request_body: DiagnosticsRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    request_body.requested_by = user.get("username") or user.get("email") or request_body.requested_by
    try:
        bundle = await run_in_threadpool(services.nexus.request_service_diagnostics, service_id, request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return bundle.model_dump(mode="json")


@router.post("/nexus/services/{service_id}/control/challenge")
async def request_service_control_challenge(
    service_id: str,
    request_body: ServiceControlChallengeRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    request_body.requested_by = user.get("username") or user.get("email") or request_body.requested_by
    try:
        challenge = await run_in_threadpool(services.nexus.request_service_control_challenge, service_id, request_body, user=user)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return challenge.model_dump(mode="json")


@router.post("/nexus/services/{service_id}/control/execute")
async def execute_service_control(
    service_id: str,
    request_body: ServiceControlExecuteRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    request_body.requested_by = user.get("username") or user.get("email") or request_body.requested_by
    try:
        action = await run_in_threadpool(services.nexus.execute_service_control, service_id, request_body, user=user)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return action.model_dump(mode="json")


@router.post("/nexus/incidents/{incident_id}/tasks")
async def create_task_handoff(
    incident_id: str,
    request_body: TaskHandoffRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    request_body.requested_by = user.get("username") or user.get("email") or request_body.requested_by
    try:
        task = services.nexus.create_task_handoff(incident_id, request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return task.model_dump(mode="json")


@router.post("/nexus/incidents/{incident_id}/verdict")
async def record_verdict(
    incident_id: str,
    request_body: IncidentVerdictRequest,
    request: Request,
    user: dict = Depends(require_nexus_operator),
) -> dict[str, object]:
    services = request.app.state.services
    request_body.requested_by = user.get("username") or user.get("email") or request_body.requested_by
    try:
        feedback = services.nexus.record_verdict(incident_id, request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return feedback.model_dump(mode="json")


@router.post("/nexus/agents/heartbeat")
async def record_heartbeat(request_body: AgentHeartbeat, request: Request) -> dict[str, object]:
    validate_nexus_agent_request(request, agent_id=request_body.agent_id, service_id=request_body.service_id)
    services = request.app.state.services
    heartbeat = await run_in_threadpool(services.nexus.record_heartbeat, request_body)
    return heartbeat.model_dump(mode="json")


@router.get("/nexus/agents/{agent_id}/config")
async def get_agent_config(
    agent_id: str,
    request: Request,
    service_id: str = Query(...),
) -> dict[str, object]:
    validate_nexus_agent_request(request, agent_id=agent_id, service_id=service_id)
    services = request.app.state.services
    try:
        config = services.nexus.get_agent_config(agent_id, service_id)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return config


@router.post("/nexus/agents/probe-report")
async def record_probe_report(request_body: AgentProbeReport, request: Request) -> dict[str, object]:
    validate_nexus_agent_request(request, agent_id=request_body.agent_id, service_id=request_body.service_id)
    services = request.app.state.services
    try:
        signals = await run_in_threadpool(services.nexus.record_probe_report, request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"signals": [signal.model_dump(mode="json") for signal in signals]}


@router.post("/nexus/agents/{agent_id}/diagnostic-results")
async def record_diagnostic_results(agent_id: str, request_body: AgentDiagnosticResult, request: Request) -> dict[str, object]:
    validate_nexus_agent_request(request, agent_id=request_body.agent_id, service_id=request_body.service_id)
    services = request.app.state.services
    if agent_id != request_body.agent_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Agent path and payload identifiers do not match.")
    try:
        bundle = await run_in_threadpool(services.nexus.record_diagnostic_result, request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return bundle.model_dump(mode="json")


@router.post("/nexus/agents/{agent_id}/control-results")
async def record_control_results(agent_id: str, request_body: AgentControlResult, request: Request) -> dict[str, object]:
    validate_nexus_agent_request(request, agent_id=request_body.agent_id, service_id=request_body.service_id)
    services = request.app.state.services
    if agent_id != request_body.agent_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Agent path and payload identifiers do not match.")
    try:
        action = await run_in_threadpool(services.nexus.record_control_result, request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return action.model_dump(mode="json")


def _incident_has_active_impact(incident: object) -> bool:
    return getattr(incident, "end_time", None) is None and getattr(incident, "status", None) in {"OPEN", "MONITORING"}


def _incident_awaits_verdict(incident: object) -> bool:
    status_value = getattr(incident, "status", None)
    return status_value == "AWAITING_VERDICT" or (getattr(incident, "end_time", None) is not None and status_value != "RESOLVED")


def _incident_operational_state(incident: object | None) -> str | None:
    if incident is None:
        return None
    if _incident_has_active_impact(incident):
        return "active_operational_impact"
    if _incident_awaits_verdict(incident):
        return "verdict_pending_after_recovery"
    if getattr(incident, "status", None) == "RESOLVED":
        return "closed"
    return str(getattr(incident, "status", "unknown")).lower()


def _incident_operational_state_dict(incident: dict[str, object]) -> str:
    status_value = incident.get("status")
    has_end_time = bool(incident.get("end_time"))
    if not has_end_time and status_value in {"OPEN", "MONITORING"}:
        return "active_operational_impact"
    if status_value == "AWAITING_VERDICT" or (has_end_time and status_value != "RESOLVED"):
        return "verdict_pending_after_recovery"
    if status_value == "RESOLVED":
        return "closed"
    return str(status_value or "unknown").lower()


def _timeline_smalltalk_answer(question: str, service_name: str) -> str | None:
    text = re.sub(r"\s+", " ", question.strip().lower())
    if not text:
        return None
    identity_terms = (
        "who are you",
        "introduce yourself",
        "introduce your self",
        "what are you",
        "your name",
        "who is this",
    )
    greeting_terms = ("hello", "hi", "hey", "good morning", "good afternoon", "good evening")
    thanks_terms = ("thanks", "thank you", "appreciate it")
    if any(term in text for term in identity_terms):
        return (
            "I'm Nexus Copilot, the SentinelOps assistant for service timelines and incident context. "
            f"For {service_name}, I can explain what happened, compare time windows, connect evidence across agent and Network Sentinel signals, "
            "and help identify the safest next operator move."
        )
    if text in greeting_terms or any(text.startswith(f"{term} ") for term in greeting_terms):
        return f"Hi. I'm here with the live Nexus timeline for {service_name}. Ask me what happened, when impact started or ended, or what evidence matters."
    if text in thanks_terms or any(text.startswith(f"{term} ") for term in thanks_terms):
        return "You're welcome. I'll keep the timeline grounded in Nexus evidence and call out uncertainty when the data is thin."
    return None


def _timeline_question_intent(question: str, history: list[dict[str, object]] | None = None) -> str:
    text = re.sub(r"\s+", " ", question.strip().lower())
    history_text = " ".join(
        str(turn.get("content") or "").lower()
        for turn in (history or [])[-4:]
        if turn.get("role") == "operator"
    )
    combined = f"{history_text} {text}".strip()
    if any(term in text for term in ("context", "detail", "details", "explain", "elaborate", "more on", "tell me more")):
        return "incident_context"
    if any(term in text for term in ("what happened", "last 24", "past 24", "yesterday", "today", "between", "after", "since", "from", "until", "till")):
        return "timeline_window"
    if any(term in text for term in ("evidence", "signal", "signals", "probe", "sentinel", "agent", "log", "runtime")):
        return "evidence_interpretation"
    if any(term in text for term in ("root", "cause", "culprit", "why")):
        return "root_cause_reasoning"
    if any(term in text for term in ("next", "move", "should", "check", "do now", "action", "verdict")):
        return "operator_next_move"
    if any(term in text for term in ("current", "now", "state", "status", "healthy", "running")):
        return "current_state"
    if "last 24" in combined or "past 24" in combined:
        return "timeline_window_followup"
    return "timeline_summary"


def _duration_minutes_for_incident(incident: object) -> int:
    start_time = _as_naive_utc(incident.start_time)
    end_time = _as_naive_utc(incident.end_time) if incident.end_time else datetime.utcnow()
    return max(0, int((end_time - start_time).total_seconds() // 60))


def _service_timeline_facts(service: object, incidents: list[object], timezone_name: str | None = None) -> dict[str, object]:
    active = [incident for incident in incidents if _incident_has_active_impact(incident)]
    awaiting_verdict = [incident for incident in incidents if _incident_awaits_verdict(incident)]
    closed = [incident for incident in incidents if incident.status == "RESOLVED"]
    latest = incidents[0] if incidents else None
    last_closed = next((incident for incident in incidents if incident.end_time), None)
    now = datetime.utcnow()
    zone_name = timezone_name or "UTC"

    def duration_minutes(incident: object | None) -> int | None:
        if incident is None:
            return None
        start_time = _as_naive_utc(incident.start_time)
        end_time = _as_naive_utc(incident.end_time) if incident.end_time else now
        return max(0, int((end_time - start_time).total_seconds() // 60))

    failure_domains = Counter(str(getattr(incident, "failure_domain", "unknown") or "unknown") for incident in incidents)
    data_sources = Counter(
        source
        for incident in incidents
        for source in (getattr(incident, "data_sources", []) or [])
    )
    verdict_states = Counter(_incident_operational_state(incident) or "unknown" for incident in incidents)
    incident_context = []
    for incident in incidents[:8]:
        evidence_items = list(getattr(incident, "evidence_timeline", []) or [])
        evidence_sources = Counter(str(item.source or "unknown") for item in evidence_items)
        evidence_domains = Counter(str(item.failure_domain_hint or "unknown") for item in evidence_items)
        incident_context.append(
            {
                "incident_id": incident.incident_id,
                "short_id": incident.incident_id[:8],
                "title": incident.title,
                "status": incident.status,
                "operational_state": _incident_operational_state(incident),
                "risk_level": incident.risk_level,
                "failure_domain": incident.failure_domain,
                "start_local": _iso_in_zone(incident.start_time, zone_name),
                "end_local": _iso_in_zone(incident.end_time, zone_name) if incident.end_time else None,
                "duration_minutes": duration_minutes(incident),
                "suspected_root_service_name": incident.suspected_root_service_name,
                "predicted_confidence": incident.predicted_confidence,
                "data_sources": list(getattr(incident, "data_sources", []) or []),
                "evidence_count": len(evidence_items),
                "evidence_source_counts": dict(evidence_sources),
                "evidence_failure_domain_counts": dict(evidence_domains),
                "top_evidence": [
                    {
                        "timestamp_local": _iso_in_zone(item.timestamp, zone_name),
                        "source": item.source,
                        "class": item.evidence_class,
                        "severity": item.severity,
                        "summary": item.summary,
                        "failure_domain_hint": item.failure_domain_hint,
                    }
                    for item in evidence_items[:5]
                ],
            }
        )

    return {
        "service_id": service.service_id,
        "service_name": service.service_name,
        "service_type": service.service_type,
        "environment": service.environment,
        "timezone": zone_name,
        "current_state": "active_operational_impact" if active else "awaiting_operator_verdict" if awaiting_verdict else "quiet",
        "state_explanation": (
            "One or more incidents have no end_time and are still OPEN/MONITORING."
            if active
            else "Operational impact has ended, but operator verdict is still pending."
            if awaiting_verdict
            else "No active or verdict-pending incident is retained for this service."
        ),
        "active_operational_incidents": len(active),
        "awaiting_verdict_incidents": len(awaiting_verdict),
        "closed_incidents": len(closed),
        "total_retained_incidents": len(incidents),
        "latest_incident_id": latest.incident_id if latest else None,
        "latest_incident_title": latest.title if latest else None,
        "latest_incident_status": latest.status if latest else None,
        "latest_incident_started_at": latest.start_time.isoformat() if latest else None,
        "latest_incident_started_at_local": _iso_in_zone(latest.start_time, zone_name) if latest else None,
        "latest_incident_ended_at": latest.end_time.isoformat() if latest and latest.end_time else None,
        "latest_incident_ended_at_local": _iso_in_zone(latest.end_time, zone_name) if latest and latest.end_time else None,
        "latest_incident_operational_state": _incident_operational_state(latest) if latest else None,
        "latest_incident_duration_minutes": duration_minutes(latest),
        "last_closed_incident_id": last_closed.incident_id if last_closed else None,
        "last_closed_incident_title": last_closed.title if last_closed else None,
        "last_closed_duration_minutes": duration_minutes(last_closed),
        "operational_state_counts": dict(verdict_states),
        "failure_domain_counts": dict(failure_domains),
        "data_source_counts": dict(data_sources),
        "recent_incident_context": incident_context,
    }


def _timeline_operator_context_brief(
    *,
    service: object,
    incidents: list[object],
    facts: dict[str, object],
    question: str,
    timezone_name: str,
) -> dict[str, object]:
    period_analysis = facts.get("period_analysis") if isinstance(facts.get("period_analysis"), dict) else {}
    focused_incidents = incidents[:6]
    if period_analysis.get("window_detected") and isinstance(period_analysis.get("overlapping_incidents"), list):
        overlap_ids = {
            str(item.get("incident_id"))
            for item in period_analysis.get("overlapping_incidents", [])
            if isinstance(item, dict) and item.get("incident_id")
        }
        if overlap_ids:
            focused_incidents = [incident for incident in incidents if incident.incident_id in overlap_ids][:8]

    source_counts: Counter[str] = Counter()
    evidence_domain_counts: Counter[str] = Counter()
    incident_domain_counts: Counter[str] = Counter()
    operational_counts: Counter[str] = Counter()
    for incident in focused_incidents:
        incident_domain_counts[str(getattr(incident, "failure_domain", "unknown") or "unknown")] += 1
        operational_counts[_incident_operational_state(incident) or "unknown"] += 1
        for evidence in getattr(incident, "evidence_timeline", []) or []:
            source_counts[str(getattr(evidence, "source", None) or "unknown")] += 1
            evidence_domain_counts[str(getattr(evidence, "failure_domain_hint", None) or "unknown")] += 1

    narrative: list[str] = []
    service_name = getattr(service, "service_name", None) or getattr(service, "service_id", None) or "this service"
    if not focused_incidents:
        if period_analysis.get("window_detected"):
            narrative.append(
                f"For {period_analysis.get('window_start_local')} to {period_analysis.get('window_end_local')} ({timezone_name}), Nexus has no retained incident overlap for {service_name}."
            )
        else:
            narrative.append(f"Nexus has no retained incident context for {service_name} yet.")
        return {
            "intent": facts.get("question_intent") or _timeline_question_intent(question),
            "narrative": narrative,
            "incident_stories": [],
            "source_mix": {},
            "failure_domain_mix": {},
            "operational_state_mix": {},
        }

    start_values = [_as_aware_in_zone(incident.start_time, timezone_name) for incident in focused_incidents]
    end_values = [
        _as_aware_in_zone(incident.end_time, timezone_name) if incident.end_time else datetime.now(_resolve_zone(timezone_name))
        for incident in focused_incidents
    ]
    first_start = min(start_values).isoformat()
    last_end = max(end_values).isoformat()
    total_evidence = sum(len(getattr(incident, "evidence_timeline", []) or []) for incident in focused_incidents)

    if period_analysis.get("window_detected"):
        narrative.append(
            f"For the requested window {period_analysis.get('window_start_local')} to {period_analysis.get('window_end_local')} ({timezone_name}), Nexus found {len(focused_incidents)} incident overlap(s) for {service_name}."
        )
    else:
        narrative.append(
            f"Nexus is focused on {len(focused_incidents)} retained incident(s) for {service_name}, spanning {first_start} to {last_end} in {timezone_name}."
        )
    narrative.append(
        f"Focused evidence volume: {total_evidence} item(s). Incident domains: {_counter_preview(incident_domain_counts)}. Signal sources: {_counter_preview(source_counts)}."
    )
    narrative.append(
        "Operational interpretation: "
        + _timeline_interpretation(incident_domain_counts, source_counts, evidence_domain_counts)
    )
    if int(facts.get("awaiting_verdict_incidents") or 0):
        narrative.append(
            f"Learning state: {facts.get('awaiting_verdict_incidents')} recovered incident(s) still need operator verdict, so Nexus should treat the root-cause model as unconfirmed until the operator closes the loop."
        )

    incident_stories = []
    for incident in focused_incidents[:6]:
        evidence_readout = _incident_evidence_readout(incident, timezone_name)
        incident_stories.append(
            {
                "incident_id": incident.incident_id,
                "short_id": incident.incident_id[:8],
                "title": incident.title,
                "state": _incident_operational_state(incident),
                "status": incident.status,
                "risk_level": incident.risk_level,
                "failure_domain": incident.failure_domain,
                "period": _incident_period_label(incident, timezone_name),
                "duration": _duration_label(_duration_minutes_for_incident(incident)),
                "root_candidate": _root_candidate_readout(incident),
                "evidence_readout": evidence_readout,
                "summary": incident.summary,
            }
        )

    return {
        "intent": facts.get("question_intent") or _timeline_question_intent(question),
        "narrative": narrative,
        "incident_stories": incident_stories,
        "source_mix": dict(source_counts),
        "failure_domain_mix": dict(incident_domain_counts),
        "evidence_failure_domain_mix": dict(evidence_domain_counts),
        "operational_state_mix": dict(operational_counts),
    }


def _counter_preview(counter: Counter[str], limit: int = 4) -> str:
    if not counter:
        return "none"
    return ", ".join(f"{key}: {value}" for key, value in counter.most_common(limit))


def _duration_label(minutes: int | None) -> str:
    if minutes is None:
        return "unknown duration"
    if minutes < 60:
        return f"{minutes} min"
    hours, mins = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {mins}m"
    days, rem_hours = divmod(hours, 24)
    return f"{days}d {rem_hours}h {mins}m"


def _incident_period_label(incident: object, timezone_name: str) -> str:
    start = _iso_in_zone(getattr(incident, "start_time", None), timezone_name) or "unknown start"
    end_time = getattr(incident, "end_time", None)
    end = _iso_in_zone(end_time, timezone_name) if end_time else "open"
    return f"{start} to {end}"


def _root_candidate_readout(incident: object) -> str:
    candidates = list(getattr(incident, "root_cause_candidates", []) or [])
    if not candidates:
        root = getattr(incident, "suspected_root_service_name", None) or getattr(incident, "suspected_root_service", None)
        return f"{root} is suspected, but no ranked candidate explanation is attached." if root else "No root candidate is attached."
    top = candidates[0]
    confidence = getattr(top, "confidence", None)
    confidence_text = f"{int(round(confidence * 100))}% confidence" if isinstance(confidence, (int, float)) else "confidence not scored"
    explanation = getattr(top, "explanation", None) or "No candidate explanation supplied."
    return f"{getattr(top, 'service_name', None) or getattr(top, 'service_id', 'unknown service')} at {confidence_text}: {explanation}"


def _incident_evidence_readout(incident: object, timezone_name: str) -> dict[str, object]:
    evidence_items = sorted(
        list(getattr(incident, "evidence_timeline", []) or []),
        key=lambda item: _as_naive_utc(getattr(item, "timestamp", None) or datetime.utcnow()),
    )
    if not evidence_items:
        return {
            "source_mix": {},
            "domain_mix": {},
            "first_signal": None,
            "latest_signal": None,
            "examples": [],
            "interpretation": "No evidence items are attached to this incident yet.",
        }

    source_counts = Counter(str(getattr(item, "source", None) or "unknown") for item in evidence_items)
    domain_counts = Counter(str(getattr(item, "failure_domain_hint", None) or "unknown") for item in evidence_items)
    examples: list[str] = []
    seen: set[str] = set()
    for item in evidence_items:
        summary = str(getattr(item, "summary", "") or "").strip()
        if summary and summary not in seen:
            examples.append(summary)
            seen.add(summary)
        if len(examples) >= 3:
            break

    def signal(item: object) -> dict[str, object]:
        return {
            "timestamp_local": _iso_in_zone(getattr(item, "timestamp", None), timezone_name),
            "source": getattr(item, "source", None),
            "severity": getattr(item, "severity", None),
            "summary": getattr(item, "summary", None),
            "failure_domain_hint": getattr(item, "failure_domain_hint", None),
        }

    return {
        "source_mix": dict(source_counts),
        "domain_mix": dict(domain_counts),
        "first_signal": signal(evidence_items[0]),
        "latest_signal": signal(evidence_items[-1]),
        "examples": examples,
        "interpretation": _timeline_interpretation(
            Counter({str(getattr(incident, "failure_domain", "unknown") or "unknown"): 1}),
            source_counts,
            domain_counts,
        ),
    }


def _timeline_interpretation(
    incident_domains: Counter[str],
    source_counts: Counter[str],
    evidence_domain_counts: Counter[str] | None = None,
) -> str:
    domain_names = {key for key in incident_domains if key and key != "unknown"}
    evidence_domain_names = {key for key in (evidence_domain_counts or Counter()) if key and key != "unknown"}
    source_names = {key for key in source_counts if key and key != "unknown"}
    all_domains = domain_names | evidence_domain_names
    if "service_runtime" in all_domains and "network_path" in all_domains:
        return (
            "local runtime and external network symptoms are part of the same operational story. "
            "The agent-side runtime signal can explain why Network Sentinel sees degraded or down reachability, so the signals should confirm one incident instead of creating duplicates."
        )
    if "service_runtime" in all_domains:
        return (
            "the strongest reading is service-side runtime impact: process, log, or host-local checks are more explanatory than external reachability alone."
        )
    if "network_path" in all_domains:
        return (
            "the strongest reading is network reachability impact. Network Sentinel evidence should be validated against local agent state before restart is considered."
        )
    if "database" in all_domains or "db" in all_domains:
        return "the focused evidence leans toward database or pool pressure and should be separated from pure service runtime failure."
    if "nexus_light_agent" in source_names and "network_sentinel" in source_names:
        return "Nexus has both local agent and external sentinel vantage points, but the retained failure-domain hints are not decisive yet."
    return "Nexus has enough timeline data to summarize the case, but the failure domain still needs operator confirmation."


def _service_timeline_period_analysis(
    incidents: list[object],
    question: str,
    timezone_name: str,
    history: list[dict[str, object]],
) -> dict[str, object]:
    window = _period_window_from_question(question, timezone_name, history)
    if window is None:
        return {"window_detected": False}

    window_start, window_end, basis = window
    overlapping = []
    for incident in incidents:
        incident_start = _as_aware_in_zone(incident.start_time, timezone_name)
        incident_end = _as_aware_in_zone(incident.end_time, timezone_name) if incident.end_time else datetime.now(_resolve_zone(timezone_name))
        if incident_start < window_end and incident_end > window_start:
            overlapping.append(
                {
                    "incident_id": incident.incident_id,
                    "incident_short_id": incident.incident_id[:8],
                    "title": incident.title,
                    "status": incident.status,
                    "operational_state": _incident_operational_state(incident),
                    "start_time_local": incident_start.isoformat(),
                    "end_time_local": incident_end.isoformat() if incident.end_time else None,
                    "duration_minutes": _duration_minutes_for_incident(incident),
                    "summary": incident.summary,
                }
            )

    return {
        "window_detected": True,
        "basis": basis,
        "timezone": timezone_name,
        "window_start_local": window_start.isoformat(),
        "window_end_local": window_end.isoformat(),
        "overlap_count": len(overlapping),
        "overlapping_incidents": overlapping[:12],
    }


def _period_window_from_question(
    question: str,
    timezone_name: str,
    history: list[dict[str, object]],
) -> tuple[datetime, datetime, str] | None:
    zone = _resolve_zone(timezone_name)
    now_local = datetime.now(zone)
    question_text = question.lower()
    history_text = " ".join(
        str(turn.get("content") or "").lower()
        for turn in history[-4:]
        if turn.get("role") == "operator"
    )
    followup_context = any(
        marker in question_text
        for marker in ("context", "detail", "details", "explain", "more", "those incident", "these incident", "that incident", "the incident")
    )
    uses_yesterday = "yesterday" in question_text or (
        "yesterday" in history_text and "today" not in question_text and "tomorrow" not in question_text
    )
    uses_today = "today" in question_text

    if "last 24" in question_text or "past 24" in question_text or (
        followup_context and ("last 24" in history_text or "past 24" in history_text)
    ):
        return now_local - timedelta(hours=24), now_local, "last_24_hours"

    base_date = now_local.date()
    basis = "today"
    if uses_yesterday:
        base_date = base_date - timedelta(days=1)
        basis = "yesterday"
    elif uses_today:
        basis = "today"

    time_matches = re.findall(r"\b([01]?\d|2[0-3])[:.]([0-5]\d)\b", question_text)
    mentions_period = any(marker in question_text for marker in ("between", "from", "after", "since", "until", "till", "period", "midnight"))
    if not time_matches and not uses_yesterday and not uses_today and not mentions_period:
        return None

    def at_time(match: tuple[str, str]) -> datetime:
        return datetime.combine(base_date, datetime.min.time(), tzinfo=zone).replace(
            hour=int(match[0]),
            minute=int(match[1]),
        )

    if time_matches:
        window_start = at_time(time_matches[0])
        if len(time_matches) >= 2:
            window_end = at_time(time_matches[1])
            if window_end <= window_start:
                window_end += timedelta(days=1)
            return window_start, window_end, f"{basis}_explicit_time_range"
        if "midnight" in question_text:
            return window_start, datetime.combine(base_date + timedelta(days=1), datetime.min.time(), tzinfo=zone), f"{basis}_until_midnight"
        if any(marker in question_text for marker in ("after", "from", "since")):
            if uses_yesterday or uses_today:
                return window_start, datetime.combine(base_date + timedelta(days=1), datetime.min.time(), tzinfo=zone), f"{basis}_after_time"
            return window_start, now_local, "from_time_to_now"
        return window_start, window_start + timedelta(hours=1), f"{basis}_time_focus"

    if uses_yesterday:
        return (
            datetime.combine(base_date, datetime.min.time(), tzinfo=zone),
            datetime.combine(base_date + timedelta(days=1), datetime.min.time(), tzinfo=zone),
            "yesterday_full_day",
        )
    if uses_today:
        return datetime.combine(base_date, datetime.min.time(), tzinfo=zone), now_local, "today_to_now"
    return None


def _build_service_timeline_prompt(
    *,
    service: dict[str, object],
    incidents: list[dict[str, object]],
    facts: dict[str, object],
    question: str,
    history: list[dict[str, object]],
    username: str,
    timezone: str,
) -> str:
    compact_incidents = []
    for incident in incidents:
        compact_incidents.append(
            {
                "incident_id": incident.get("incident_id"),
                "title": incident.get("title"),
                "status": incident.get("status"),
                "risk_level": incident.get("risk_level"),
                "start_time": incident.get("start_time"),
                "end_time": incident.get("end_time"),
                "local_start_time": _iso_in_zone(_parse_datetime(incident.get("start_time")), timezone),
                "local_end_time": _iso_in_zone(_parse_datetime(incident.get("end_time")), timezone) if incident.get("end_time") else None,
                "operational_state": _incident_operational_state_dict(incident),
                "summary": incident.get("summary"),
                "failure_domain": incident.get("failure_domain"),
                "suspected_root_service_name": incident.get("suspected_root_service_name"),
                "predicted_confidence": incident.get("predicted_confidence"),
                "affected_services": incident.get("affected_services"),
                "blast_radius": incident.get("blast_radius"),
                "business_flow": incident.get("primary_business_flow_name") or incident.get("primary_business_flow_id"),
                "data_sources": incident.get("data_sources"),
                "vantage_points": incident.get("vantage_points"),
                "evidence_count": len(incident.get("evidence_timeline") or []),
                "root_candidates": [
                    {
                        "service_id": candidate.get("service_id"),
                        "service_name": candidate.get("service_name"),
                        "confidence": candidate.get("confidence"),
                        "score": candidate.get("score"),
                        "explanation": candidate.get("explanation"),
                    }
                    for candidate in (incident.get("root_cause_candidates") or [])[:3]
                ],
                "recommendations": [
                    {
                        "action_type": recommendation.get("action_type"),
                        "status": recommendation.get("status"),
                        "eligible": recommendation.get("eligible"),
                        "justification": recommendation.get("justification"),
                        "blocked_reasons": recommendation.get("blocked_reasons"),
                    }
                    for recommendation in (incident.get("recommendations") or [])[:4]
                ],
                "log_signatures": [
                    {
                        "signature_family": signature.get("signature_family"),
                        "severity": signature.get("severity"),
                        "failure_domain": signature.get("failure_domain"),
                        "count": signature.get("count"),
                    }
                    for signature in (incident.get("log_signatures") or [])[:5]
                ],
                "evidence": [
                    {
                        "timestamp": evidence.get("timestamp"),
                        "local_timestamp": _iso_in_zone(_parse_datetime(evidence.get("timestamp")), timezone),
                        "severity": evidence.get("severity"),
                        "source": evidence.get("source"),
                        "evidence_class": evidence.get("evidence_class"),
                        "summary": evidence.get("summary"),
                        "failure_domain_hint": evidence.get("failure_domain_hint"),
                    }
                    for evidence in (incident.get("evidence_timeline") or [])[:8]
                ],
            }
        )

    return (
        f"Operator: {username}\n"
        f"Application timezone: {timezone}\n"
        f"Question: {question}\n\n"
        f"Conversation history:\n{history}\n\n"
        f"Service contract:\n{service}\n\n"
        f"Computed service facts:\n{facts}\n\n"
        f"Retained service incidents:\n{compact_incidents}\n\n"
        "Answer requirements:\n"
        "- If asked current state, answer from current_state, active_operational_incidents, and awaiting_verdict_incidents.\n"
        "- Never call an incident active operational impact if it has an end_time or operational_state says verdict_pending_after_recovery.\n"
        "- Explain the difference between active impact, recovered-but-awaiting-verdict, and fully resolved when relevant.\n"
        "- Use local_start_time/local_end_time when discussing operator-facing time; do not label raw Z timestamps as local time.\n"
        "- If asked last incident, use the latest retained incident and include duration when available.\n"
        "- If facts.period_analysis.window_detected is true, treat that computed window as authoritative for period questions.\n"
        "- If asked about a period, answer using facts.period_analysis.overlapping_incidents before drawing broader conclusions.\n"
        "- If asked for more context/details, do not repeat only headline times. Explain the incident pattern, evidence sources, failure domains, root-candidate reasoning, what recovered, and what still needs verdict.\n"
        "- Use facts.operator_context_brief as the canonical narrative spine for incident questions. It exists to prevent shallow headline-only answers.\n"
        "- Use facts.recent_incident_context and retained incident evidence to make the answer specific.\n"
        "- For 'what happened' questions, include operational meaning, what Nexus knows from signals, what Nexus infers, remaining uncertainty, and the safest next move when warranted.\n"
        "- Never change the year in the supplied timestamps; the context dates are authoritative.\n"
        "- If the data is missing, say exactly what Nexus does not have yet.\n"
        "- Keep memory of prior turns, but do not invent facts from memory.\n"
        "- Write a natural operator-facing answer, not a report template.\n"
        "- Prefer one short opening explanation, then compact bullets for exact incident/time facts.\n"
        "- Do not use markdown tables or decorative headings.\n"
        "- If the operator asks a follow-up, resolve references like 'that', 'it', 'yesterday', or 'the last incident' from chat history and computed facts.\n"
        "- End with the safest next operator move only if an action is actually warranted.\n"
    )


def _fallback_service_timeline_answer(service: dict[str, object], incidents: list[object], facts: dict[str, object], question: str) -> str:
    service_name = str(service.get("service_name") or service.get("service_id") or "this service")
    active_count = int(facts.get("active_operational_incidents") or 0)
    awaiting_count = int(facts.get("awaiting_verdict_incidents") or 0)
    latest = incidents[0] if incidents else None
    question_text = question.lower()
    active_incidents = [incident for incident in incidents if _incident_has_active_impact(incident)]
    awaiting_incidents = [incident for incident in incidents if _incident_awaits_verdict(incident)]
    lines: list[str] = []
    period_analysis = facts.get("period_analysis") if isinstance(facts.get("period_analysis"), dict) else {}
    rich_context_requested = period_analysis.get("window_detected") or any(
        term in question_text
        for term in ("what happened", "last 24", "past 24", "context", "detail", "details", "explain", "why", "incident", "incidents", "evidence")
    )

    if rich_context_requested:
        context_lines = _operator_context_brief_lines(facts)
        if context_lines:
            lines.extend(context_lines)

    if any(term in question_text for term in ("current", "now", "state", "status")):
        if active_count:
            lines.append(f"Current state: {service_name} has {active_count} active operational incident(s).")
        elif awaiting_count:
            lines.append(
                f"Current state: {service_name} has no active operational impact in Nexus, but {awaiting_count} recovered incident(s) still need operator verdict."
            )
        else:
            lines.append(f"Current state: {service_name} is quiet in the retained Nexus incident timeline.")
        if active_incidents:
            for incident in active_incidents[:3]:
                duration = max(0, int((datetime.utcnow() - _as_naive_utc(incident.start_time)).total_seconds() // 60))
                lines.append(f"- Active: {incident.title} | {incident.status} | running about {duration} minute(s).")
        if awaiting_incidents:
            for incident in awaiting_incidents[:3]:
                duration = _duration_minutes_for_incident(incident)
                lines.append(f"- Awaiting verdict: {incident.title} | impact ended {incident.end_time.isoformat() if incident.end_time else 'without an end timestamp'} | lasted about {duration} minute(s).")
        lines.append(f"Retained incidents linked to this service: {facts.get('total_retained_incidents', 0)}.")

    if any(term in question_text for term in ("last", "latest", "previous", "duration", "how long")):
        if latest:
            end_label = latest.end_time.isoformat() if latest.end_time else "still active or awaiting verdict"
            duration = facts.get("latest_incident_duration_minutes")
            lines.append(
                f"Latest incident: {latest.title}. It started {latest.start_time.isoformat()}, ended {end_label}, and lasted about {duration} minute(s)."
            )
            lines.append(f"Latest incident state: {_incident_operational_state(latest)}. Status: {latest.status}. Summary: {latest.summary}")
        else:
            lines.append(f"No retained incident is attached to {service_name} yet, so Nexus cannot identify a last incident.")

    if any(term in question_text for term in ("context", "detail", "details", "explain", "why", "more")) and not lines:
        lines.extend(_fallback_context_lines(facts, incidents))

    if period_analysis.get("window_detected") and not rich_context_requested:
        lines.extend(_period_analysis_lines(period_analysis))
    elif "between" in question_text or "period" in question_text or "from" in question_text:
        period_lines = _fallback_period_summary(incidents, question_text)
        lines.extend(period_lines)

    if not lines:
        lines.extend(
            [
                f"{service_name} is currently {'under active Nexus incident review' if active_count else 'quiet in the retained Nexus incident timeline'}.",
                f"Active operational incidents: {active_count}. Awaiting verdict: {awaiting_count}. Retained incidents: {facts.get('total_retained_incidents', 0)}.",
            ]
        )
    if latest and not rich_context_requested and not any(line.startswith("Latest incident:") for line in lines):
        end_label = latest.end_time.isoformat() if latest.end_time else "still active or awaiting verdict"
        duration = facts.get("latest_incident_duration_minutes")
        lines.append(
            f"Latest incident: {latest.title}, status {latest.status}, started {latest.start_time.isoformat()}, ended {end_label}, duration about {duration} minute(s)."
        )
        lines.append(f"Summary: {latest.summary}")
    elif not latest:
        lines.append("No retained incident is attached to this service yet.")
    return "\n".join(lines)


def _operator_context_brief_lines(facts: dict[str, object]) -> list[str]:
    brief = facts.get("operator_context_brief")
    if not isinstance(brief, dict):
        return []
    lines: list[str] = []
    narrative = brief.get("narrative")
    if isinstance(narrative, list):
        lines.extend(str(item) for item in narrative if item)
    stories = brief.get("incident_stories")
    if isinstance(stories, list) and stories:
        lines.append("Incident context:")
        for story in stories[:5]:
            if not isinstance(story, dict):
                continue
            evidence_readout = story.get("evidence_readout") if isinstance(story.get("evidence_readout"), dict) else {}
            source_mix = evidence_readout.get("source_mix") or {}
            domain_mix = evidence_readout.get("domain_mix") or {}
            examples = evidence_readout.get("examples") if isinstance(evidence_readout.get("examples"), list) else []
            lines.append(
                "- "
                f"{story.get('short_id')}: {story.get('failure_domain')} | {story.get('state')} | "
                f"{story.get('period')} | {story.get('duration')} | sources {source_mix or 'unknown'} | domains {domain_mix or 'unknown'}."
            )
            lines.append(f"  Root read: {story.get('root_candidate')}")
            if examples:
                lines.append("  Evidence examples: " + "; ".join(str(example) for example in examples[:3]))
            interpretation = evidence_readout.get("interpretation")
            if interpretation:
                lines.append(f"  Interpretation: {interpretation}")
    return lines


def _timeline_answer_too_thin(answer: str | None, facts: dict[str, object]) -> bool:
    if not answer:
        return False
    intent = str(facts.get("question_intent") or "")
    period_analysis = facts.get("period_analysis") if isinstance(facts.get("period_analysis"), dict) else {}
    rich_intents = {
        "incident_context",
        "timeline_window",
        "timeline_window_followup",
        "evidence_interpretation",
        "root_cause_reasoning",
    }
    if intent not in rich_intents and not period_analysis.get("window_detected"):
        return False
    words = re.findall(r"\w+", answer)
    if len(words) < 110:
        return True
    lower = answer.lower()
    evidence_markers = ("evidence", "signal", "network sentinel", "agent", "runtime", "icmp", "probe", "log")
    if facts.get("recent_incident_context") and not any(marker in lower for marker in evidence_markers):
        return True
    return False


def _fallback_context_lines(facts: dict[str, object], incidents: list[object]) -> list[str]:
    context = facts.get("recent_incident_context")
    lines: list[str] = []
    if isinstance(context, list) and context:
        lines.append("Context from the retained Nexus evidence:")
        for item in context[:4]:
            if not isinstance(item, dict):
                continue
            sources = item.get("evidence_source_counts") if isinstance(item.get("evidence_source_counts"), dict) else {}
            domains = item.get("evidence_failure_domain_counts") if isinstance(item.get("evidence_failure_domain_counts"), dict) else {}
            lines.append(
                "- "
                f"{item.get('short_id')}: {item.get('failure_domain')} incident, {item.get('operational_state')}, "
                f"{item.get('start_local')} to {item.get('end_local') or 'open'}, "
                f"{item.get('evidence_count')} evidence item(s), sources {sources or 'unknown'}, domains {domains or 'unknown'}."
            )
            top_evidence = item.get("top_evidence")
            if isinstance(top_evidence, list) and top_evidence:
                sample = next((evidence for evidence in top_evidence if isinstance(evidence, dict)), None)
                if sample:
                    lines.append(
                        f"  Evidence example: {sample.get('source')} at {sample.get('timestamp_local')} reported {sample.get('summary')}."
                    )
        domain_counts = facts.get("failure_domain_counts")
        source_counts = facts.get("data_source_counts")
        if domain_counts:
            lines.append(f"Overall retained failure-domain mix: {domain_counts}.")
        if source_counts:
            lines.append(f"Overall retained signal-source mix: {source_counts}.")
        lines.append("Uncertainty: Nexus still needs operator verdicts to confirm whether the suspected root cause was correct.")
        return lines

    if incidents:
        lines.append("Nexus has retained incidents, but the compact context cache is empty. The latest summaries are:")
        for incident in incidents[:4]:
            lines.append(f"- {incident.incident_id[:8]}: {incident.summary}")
        return lines
    return ["Nexus has no retained incident context for this service yet."]


def _fallback_period_summary(incidents: list[object], question_text: str) -> list[str]:
    time_matches = re.findall(r"\b([01]?\d|2[0-3]):([0-5]\d)\b", question_text)
    if len(time_matches) < 2:
        return [
            "For exact period analysis, include two times such as 'between 08:00 and 12:00'. Nexus will compare that window against incident start/end times and evidence timestamps."
        ]

    anchor = _as_naive_utc(incidents[0].start_time) if incidents else datetime.utcnow()
    start_hour, start_minute = (int(part) for part in time_matches[0])
    end_hour, end_minute = (int(part) for part in time_matches[1])
    window_start = anchor.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
    window_end = anchor.replace(hour=end_hour, minute=end_minute, second=0, microsecond=0)
    if window_end < window_start:
        window_end += timedelta(days=1)

    overlapping = []
    for incident in incidents:
        incident_start = _as_naive_utc(incident.start_time)
        incident_end = _as_naive_utc(incident.end_time) if incident.end_time else datetime.utcnow()
        if incident_start <= window_end and incident_end >= window_start:
            overlapping.append(incident)

    if not overlapping:
        return [
            f"Between {window_start.isoformat()} and {window_end.isoformat()}, Nexus has no retained incident overlap for this service."
        ]

    lines = [
        f"Between {window_start.isoformat()} and {window_end.isoformat()}, Nexus found {len(overlapping)} retained incident overlap(s):"
    ]
    for incident in overlapping[:5]:
        lines.append(f"- {incident.title} | {incident.status} | {incident.start_time.isoformat()} to {incident.end_time.isoformat() if incident.end_time else 'open'} | {incident.summary}")
    return lines


def _period_analysis_lines(period_analysis: dict[str, object]) -> list[str]:
    start = period_analysis.get("window_start_local")
    end = period_analysis.get("window_end_local")
    overlapping = period_analysis.get("overlapping_incidents")
    lines = [
        f"Requested period: {start} to {end} ({period_analysis.get('timezone')}).",
        f"Overlap count: {period_analysis.get('overlap_count', 0)} incident(s).",
    ]
    if not isinstance(overlapping, list) or not overlapping:
        lines.append("No retained service incident overlapped the requested period.")
        return lines
    for item in overlapping[:8]:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"- {item.get('incident_short_id')}: {item.get('title')} | {item.get('operational_state')} | {item.get('start_time_local')} to {item.get('end_time_local') or 'open'} | {item.get('duration_minutes')} minute(s)."
        )
    return lines


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    text = str(value)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _resolve_zone(timezone_name: str | None) -> ZoneInfo | timezone:
    if not timezone_name:
        return timezone.utc
    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        return timezone.utc


def _iso_in_zone(value: datetime | None, timezone_name: str | None) -> str | None:
    if value is None:
        return None
    return _as_aware_in_zone(value, timezone_name).isoformat()


def _as_aware_in_zone(value: datetime, timezone_name: str | None) -> datetime:
    source = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return source.astimezone(_resolve_zone(timezone_name))


def _as_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)
