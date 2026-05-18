"""Sentinel Nexus API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

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
    RestartActionRequest,
    ServiceUpsertRequest,
    SyncRequest,
    TaskHandoffRequest,
)
from app.utils.nexus_agent_auth import validate_nexus_agent_request
from app.utils.sentinelops_auth import require_nexus_access, require_nexus_admin, require_nexus_operator


router = APIRouter()


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
