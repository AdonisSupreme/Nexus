"""Sentinel Nexus API endpoints."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app.nexus.models import (
    AgentDiagnosticResult,
    AgentHeartbeat,
    AgentProbeReport,
    BusinessFlowUpsertRequest,
    ChangeEventRequest,
    DependencyClusterUpsertRequest,
    DependencyEdgeUpsertRequest,
    DiagnosticsRequest,
    IncidentVerdictRequest,
    ManagedSopUpsertRequest,
    ManagedSopValidationRequest,
    RestartActionRequest,
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


@router.get("/nexus/incidents")
async def list_incidents(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    incidents = [incident.model_dump(mode="json") for incident in services.nexus.list_incidents()]
    return {"incidents": incidents}


@router.get("/nexus/fabric-summary")
async def get_fabric_summary(request: Request, _: dict = Depends(require_nexus_access)) -> dict[str, object]:
    services = request.app.state.services
    return services.nexus.get_fabric_summary().model_dump(mode="json")


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

    incidents = [
        incident
        for incident in services.nexus.list_incidents()
        if service_id in incident.affected_services
        or incident.suspected_root_service == service_id
        or any(candidate.service_id == service_id for candidate in incident.root_cause_candidates)
    ]
    incidents.sort(key=lambda item: _as_naive_utc(item.start_time), reverse=True)
    facts = _service_timeline_facts(service, incidents)
    prompt = _build_service_timeline_prompt(
        service=service.model_dump(mode="json"),
        incidents=[incident.model_dump(mode="json") for incident in incidents[:20]],
        facts=facts,
        question=request_body.question,
        history=[turn.model_dump(mode="json") for turn in request_body.history[-10:]],
        username=user.get("username") or user.get("email") or "operator",
        timezone=request_body.timezone or "application timezone",
    )

    llm_answer = None
    if services.mistral_client.available:
        llm_answer = await services.mistral_client.chat_complete(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are Sentinel Nexus Service Timeline Intelligence. Answer as an operational analyst. "
                        "Use only the supplied service timeline context, call out uncertainty, remember prior turns, "
                        "and avoid generic SOP advice unless the question asks for procedure. Keep answers concise, "
                        "structured, and action-oriented."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=900,
        )

    fallback = _fallback_service_timeline_answer(service.model_dump(mode="json"), incidents, facts, request_body.question)
    answer = llm_answer or fallback
    return ServiceTimelineChatResponse(
        answer=answer,
        confidence=0.82 if llm_answer else 0.58,
        trace_id=str(uuid4()),
        llm_used=bool(llm_answer),
        suggestions=[
            "What is the current state?",
            "When was the last incident and how long did it last?",
            "What happened during the last 24 hours?",
            "Which evidence changed before recovery?",
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
        bundle = services.nexus.request_diagnostics(incident_id, request_body)
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
        action = services.nexus.handle_restart_action(incident_id, request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
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
    heartbeat = services.nexus.record_heartbeat(request_body)
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
        signals = services.nexus.record_probe_report(request_body)
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
        bundle = services.nexus.record_diagnostic_result(request_body)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return bundle.model_dump(mode="json")


def _service_timeline_facts(service: object, incidents: list[object]) -> dict[str, object]:
    active = [incident for incident in incidents if incident.status != "RESOLVED"]
    latest = incidents[0] if incidents else None
    last_closed = next((incident for incident in incidents if incident.end_time), None)
    now = datetime.utcnow()

    def duration_minutes(incident: object | None) -> int | None:
        if incident is None:
            return None
        start_time = _as_naive_utc(incident.start_time)
        end_time = _as_naive_utc(incident.end_time) if incident.end_time else now
        return max(0, int((end_time - start_time).total_seconds() // 60))

    return {
        "service_id": service.service_id,
        "service_name": service.service_name,
        "service_type": service.service_type,
        "environment": service.environment,
        "current_state": "active_incident" if active else "quiet",
        "active_incidents": len(active),
        "total_retained_incidents": len(incidents),
        "latest_incident_id": latest.incident_id if latest else None,
        "latest_incident_title": latest.title if latest else None,
        "latest_incident_status": latest.status if latest else None,
        "latest_incident_started_at": latest.start_time.isoformat() if latest else None,
        "latest_incident_duration_minutes": duration_minutes(latest),
        "last_closed_incident_id": last_closed.incident_id if last_closed else None,
        "last_closed_incident_title": last_closed.title if last_closed else None,
        "last_closed_duration_minutes": duration_minutes(last_closed),
    }


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
                "summary": incident.get("summary"),
                "failure_domain": incident.get("failure_domain"),
                "suspected_root_service_name": incident.get("suspected_root_service_name"),
                "affected_services": incident.get("affected_services"),
                "evidence": [
                    {
                        "timestamp": evidence.get("timestamp"),
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
        "- If asked current state, answer from active_incidents/current_state and latest evidence.\n"
        "- If asked last incident, use the latest retained incident and include duration when available.\n"
        "- If asked about a period, inspect incident start/end/evidence timestamps and explain what is inside or outside that window.\n"
        "- If the data is missing, say exactly what Nexus does not have yet.\n"
        "- Keep memory of prior turns, but do not invent facts from memory.\n"
    )


def _fallback_service_timeline_answer(service: dict[str, object], incidents: list[object], facts: dict[str, object], question: str) -> str:
    service_name = str(service.get("service_name") or service.get("service_id") or "this service")
    active_count = int(facts.get("active_incidents") or 0)
    latest = incidents[0] if incidents else None
    question_text = question.lower()
    active_incidents = [incident for incident in incidents if incident.status != "RESOLVED"]
    lines: list[str] = []

    if any(term in question_text for term in ("current", "now", "state", "status")):
        lines.append(
            f"Current state: {service_name} is {'under active Nexus incident review' if active_count else 'quiet in the retained Nexus incident timeline'}."
        )
        if active_incidents:
            for incident in active_incidents[:3]:
                duration = max(0, int((datetime.utcnow() - _as_naive_utc(incident.start_time)).total_seconds() // 60))
                lines.append(f"- Active: {incident.title} | {incident.status} | running about {duration} minute(s).")
        lines.append(f"Retained incidents linked to this service: {facts.get('total_retained_incidents', 0)}.")

    if any(term in question_text for term in ("last", "latest", "previous", "duration", "how long")):
        if latest:
            end_label = latest.end_time.isoformat() if latest.end_time else "still active or awaiting verdict"
            duration = facts.get("latest_incident_duration_minutes")
            lines.append(
                f"Latest incident: {latest.title}. It started {latest.start_time.isoformat()}, ended {end_label}, and lasted about {duration} minute(s)."
            )
            lines.append(f"Latest incident status: {latest.status}. Summary: {latest.summary}")
        else:
            lines.append(f"No retained incident is attached to {service_name} yet, so Nexus cannot identify a last incident.")

    if "between" in question_text or "period" in question_text or "from" in question_text:
        period_lines = _fallback_period_summary(incidents, question_text)
        lines.extend(period_lines)

    if not lines:
        lines.extend(
            [
                f"{service_name} is currently {'under active Nexus incident review' if active_count else 'quiet in the retained Nexus incident timeline'}.",
                f"Active incidents: {active_count}. Retained incidents: {facts.get('total_retained_incidents', 0)}.",
            ]
        )
    if latest and not any(line.startswith("Latest incident:") for line in lines):
        end_label = latest.end_time.isoformat() if latest.end_time else "still active or awaiting verdict"
        duration = facts.get("latest_incident_duration_minutes")
        lines.append(
            f"Latest incident: {latest.title}, status {latest.status}, started {latest.start_time.isoformat()}, ended {end_label}, duration about {duration} minute(s)."
        )
        lines.append(f"Summary: {latest.summary}")
    else:
        lines.append("No retained incident is attached to this service yet.")
    return "\n".join(lines)


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


def _as_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)
