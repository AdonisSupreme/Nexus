"""Sentinel Nexus runtime service."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import hashlib
import re
from typing import Iterable
from uuid import uuid4

import httpx

from app.config.settings import settings
from app.nexus.models import (
    ActionExecution,
    ActionRecommendation,
    AgentChangeContext,
    AgentDiagnosticResult,
    AgentHeartbeat,
    AgentLogRecord,
    AgentProbeReport,
    AgentTraceSummary,
    BusinessFlow,
    BusinessFlowStep,
    BusinessFlowUpsertRequest,
    CatalogService,
    ChangeEvent,
    ChangeEventRequest,
    DatabaseDependencyProfile,
    DatabaseProfile,
    DependencyCluster,
    DependencyClusterUpsertRequest,
    DependencyEdge,
    DependencyEdgeUpsertRequest,
    DiagnosticBundle,
    DiagnosticCommand,
    DiagnosticsRequest,
    FabricSummary,
    GraphEdge,
    GraphNode,
    IncidentVerdictRequest,
    LogSignature,
    ManagedSop,
    ManagedSopUpsertRequest,
    ManagedSopValidation,
    ManagedSopValidationRequest,
    NexusEvidence,
    NexusIncident,
    NexusState,
    OperatorFeedback,
    RestartActionRequest,
    RootCauseCandidate,
    ServiceGraphContext,
    ServiceUpsertRequest,
    SignalEvent,
    SyncRequest,
    TaskHandoff,
    TaskHandoffRequest,
)
from app.nexus.repository import NexusRepository
from app.utils.audit import audit_logger
from app.utils.logging import get_logger


logger = get_logger(__name__)


class NexusService:
    """Stateful graph-aware incident intelligence engine."""

    ACTIVE_WINDOW = timedelta(hours=6)
    INCIDENT_WINDOW = timedelta(minutes=10)
    MONITORING_WINDOW = timedelta(minutes=10)
    NETWORK_SYNC_INTERVAL = timedelta(seconds=10)
    MAX_SIGNALS = 1500
    MAX_CHANGES = 500

    def __init__(self, repository: NexusRepository | None = None) -> None:
        self.repository = repository or NexusRepository()
        self.state = NexusState()
        self._last_network_sync_at: datetime | None = None

    def startup(self) -> None:
        self.state = self.repository.load_state()
        self._normalize_state_datetimes()
        self._reconcile_catalog()
        if self.state.services:
            self.sync_network_sentinel(SyncRequest(force=True))
        else:
            self._update_fabric_summary(
                sync_health="idle",
                sync_message="No cataloged services yet. Configure services and clusters to activate live Nexus intelligence.",
            )
            self._rebuild_incidents()
            self.repository.persist_state(self.state)

    def list_incidents(self) -> list[NexusIncident]:
        self._ensure_live_state()
        return self.state.incidents

    def get_incident(self, incident_id: str) -> NexusIncident | None:
        self._ensure_live_state()
        return next((incident for incident in self.state.incidents if incident.incident_id == incident_id), None)

    def list_services(self) -> list[CatalogService]:
        self._ensure_live_state()
        return sorted(self.state.services, key=lambda item: (item.environment, item.service_name.lower()))

    def list_clusters(self) -> list[DependencyCluster]:
        self._ensure_live_state()
        return sorted(self.state.clusters, key=lambda item: (item.environment, item.cluster_name.lower()))

    def list_business_flows(self) -> list[BusinessFlow]:
        self._ensure_live_state()
        return sorted(
            self.state.business_flows,
            key=lambda item: (item.environment, item.flow_name.lower()),
        )

    def list_edges(self) -> list[DependencyEdge]:
        self._ensure_live_state()
        return sorted(
            self.state.dependency_edges,
            key=lambda item: ((item.cluster_id or ""), item.from_service_id, item.to_service_id, item.dependency_type),
        )

    def list_managed_sops(self, *, include_deprecated: bool = True) -> list[ManagedSop]:
        return self.repository.list_managed_sops(include_deprecated=include_deprecated)

    def upsert_managed_sop(self, request: ManagedSopUpsertRequest) -> ManagedSop:
        existing = self.repository.get_managed_sop(request.sop_id)
        now = datetime.utcnow()
        validation = self._validate_managed_sop_payload(request, requested_by=request.updated_by or "nexus")
        status = request.status
        if status == "approved" and not validation.valid:
            status = "needs_review"
        sop = ManagedSop(
            sop_id=request.sop_id.strip(),
            title=request.title.strip(),
            class_code=request.class_code.strip().upper(),
            severity=request.severity.strip().lower(),
            status=status,
            version=request.version,
            owner_team=request.owner_team,
            services=sorted({item.strip() for item in request.services if item.strip()}),
            environments=sorted({item.strip() for item in request.environments if item.strip()}),
            aliases=sorted({item.strip() for item in request.aliases if item.strip()}),
            tags=sorted({item.strip() for item in request.tags if item.strip()}),
            content={key: [str(line).strip() for line in value if str(line).strip()] for key, value in request.content.items()},
            validation=validation,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            updated_by=request.updated_by,
            metadata=request.metadata,
        )
        saved = self.repository.upsert_managed_sop(sop)
        audit_logger.log(
            event_type="nexus_sop_upserted",
            user=request.updated_by or "nexus_sop_registry",
            details={"sop_id": saved.sop_id, "status": saved.status, "valid": saved.validation.valid},
        )
        return saved

    def validate_managed_sop(self, sop_id: str, request: ManagedSopValidationRequest) -> ManagedSop:
        sop = self.repository.get_managed_sop(sop_id)
        if sop is None:
            raise KeyError(f"Unknown Nexus SOP {sop_id}")
        validation = self._validate_managed_sop_payload(
            ManagedSopUpsertRequest(**sop.model_dump(mode="json")),
            requested_by=request.requested_by,
        )
        status = sop.status
        if request.approve_if_valid and validation.valid:
            status = "approved"
        elif not validation.valid and status == "approved":
            status = "needs_review"
        updated = sop.model_copy(
            update={
                "status": status,
                "validation": validation,
                "updated_at": datetime.utcnow(),
                "updated_by": request.requested_by,
            }
        )
        saved = self.repository.upsert_managed_sop(updated)
        audit_logger.log(
            event_type="nexus_sop_validated",
            user=request.requested_by,
            details={"sop_id": sop_id, "status": saved.status, "valid": saved.validation.valid},
        )
        return saved

    def delete_managed_sop(self, sop_id: str, deleted_by: str) -> None:
        self.repository.delete_managed_sop(sop_id, deleted_by)
        audit_logger.log(
            event_type="nexus_sop_deleted",
            user=deleted_by,
            details={"sop_id": sop_id},
        )

    def get_agent_config(self, agent_id: str, service_id: str | None = None) -> dict[str, object]:
        """Return the DB-backed monitoring contract a light agent should execute."""
        self._ensure_live_state()
        services = self._service_map()
        service = services.get(service_id) if service_id else None
        if service is None:
            matches = [
                item
                for item in services.values()
                if item.observation_config.agent_id == agent_id
            ]
            if len(matches) != 1:
                raise KeyError(f"Unable to resolve a unique Nexus service for agent '{agent_id}'.")
            service = matches[0]
        if service.observation_config.agent_id and service.observation_config.agent_id != agent_id:
            raise PermissionError(f"Agent '{agent_id}' is not assigned to service '{service.service_id}'.")

        service_clusters = [
            cluster
            for cluster in self.state.clusters
            if service.service_id in cluster.service_ids or cluster.cluster_id in service.cluster_ids
        ]
        service_edges = [
            edge
            for edge in self.state.dependency_edges
            if edge.from_service_id == service.service_id or edge.to_service_id == service.service_id
        ]
        flow_ids = {flow_id for edge in service_edges for flow_id in edge.business_flow_ids}
        service_flows = [
            flow
            for flow in self.state.business_flows
            if flow.flow_id in flow_ids
            or service.service_id in flow.entry_service_ids
            or any(step.service_id == service.service_id for step in flow.steps)
        ]
        return {
            "agent_id": agent_id,
            "service_id": service.service_id,
            "environment": service.environment,
            "service": service.model_dump(mode="json"),
            "clusters": [cluster.model_dump(mode="json") for cluster in service_clusters],
            "dependencies": {
                "outgoing": [
                    edge.model_dump(mode="json")
                    for edge in service_edges
                    if edge.from_service_id == service.service_id
                ],
                "incoming": [
                    edge.model_dump(mode="json")
                    for edge in service_edges
                    if edge.to_service_id == service.service_id
                ],
            },
            "business_flows": [flow.model_dump(mode="json") for flow in service_flows],
            "diagnostic_commands": [
                command.model_dump(mode="json")
                for command in self._diagnostic_commands_for_service(service.service_id)
            ],
            "ingestion_contract": {
                "heartbeat_endpoint": "/api/v1/nexus/agents/heartbeat",
                "probe_report_endpoint": "/api/v1/nexus/agents/probe-report",
                "diagnostic_results_endpoint": f"/api/v1/nexus/agents/{agent_id}/diagnostic-results",
                "auth_headers": ["x-nexus-agent-id", "x-nexus-agent-token"],
                "canonical_fields": [
                    "agent_id",
                    "service_id",
                    "service_name",
                    "environment",
                    "timestamp",
                    "severity",
                    "source",
                    "vantage_point",
                    "observation_layer",
                    "failure_domain_hint",
                ],
                "log_signature_fields": [
                    "signature_family",
                    "error_class",
                    "exception_name",
                    "timeout_type",
                    "oom_flag",
                    "db_error_code",
                ],
            },
        }

    def get_fabric_summary(self) -> FabricSummary:
        self._ensure_live_state()
        return self.state.fabric_summary

    def upsert_service(self, request: ServiceUpsertRequest) -> CatalogService:
        existing = self._service_map().get(request.service_id)
        service = CatalogService(
            service_uuid=existing.service_uuid if existing else str(uuid4()),
            service_id=request.service_id,
            service_name=request.service_name,
            service_type=request.service_type,
            environment=request.environment,
            owner_team=request.owner_team,
            criticality=request.criticality,
            description=request.description,
            is_stateless=request.is_stateless,
            allow_diagnostics=request.allow_diagnostics,
            runbook_slug=request.runbook_slug,
            tags=request.tags,
            cluster=request.cluster,
            cluster_ids=request.cluster_ids,
            restart_policy=request.restart_policy,
            database_profile=self._normalized_database_profile(
                request.database_profile,
                service_type=request.service_type,
            ),
            endpoint_config=request.endpoint_config,
            observation_config=request.observation_config,
            certification=request.certification,
            metadata=request.metadata,
        )
        self.state.services = [item for item in self.state.services if item.service_id != service.service_id]
        self.state.services.append(service)
        self._reconcile_catalog()
        audit_logger.log(
            event_type="nexus_service_upserted",
            user="nexus_catalog",
            details=service.model_dump(mode="json"),
        )
        self._persist_and_refresh()
        return service

    def delete_service(self, service_id: str) -> None:
        if service_id not in self._service_map():
            raise KeyError(f"Unknown service {service_id}")
        self.state.services = [item for item in self.state.services if item.service_id != service_id]
        self.state.dependency_edges = [
            edge
            for edge in self.state.dependency_edges
            if edge.from_service_id != service_id and edge.to_service_id != service_id
        ]
        self.state.clusters = [
            cluster.model_copy(
                update={
                    "service_ids": [item for item in cluster.service_ids if item != service_id],
                    "entry_services": [item for item in cluster.entry_services if item != service_id],
                }
            )
            for cluster in self.state.clusters
        ]
        self.state.business_flows = [
            flow.model_copy(
                update={
                    "entry_service_ids": [item for item in flow.entry_service_ids if item != service_id],
                    "steps": [step for step in flow.steps if step.service_id != service_id],
                }
            )
            for flow in self.state.business_flows
        ]
        self._reconcile_catalog()
        audit_logger.log(
            event_type="nexus_service_deleted",
            user="nexus_catalog",
            details={"service_id": service_id},
        )
        self._persist_and_refresh()

    def upsert_cluster(self, request: DependencyClusterUpsertRequest) -> DependencyCluster:
        missing = [service_id for service_id in request.service_ids if service_id not in self._service_map()]
        if missing:
            raise KeyError(f"Unknown services referenced by cluster {request.cluster_id}: {', '.join(sorted(missing))}")
        cluster = DependencyCluster(
            cluster_id=request.cluster_id,
            cluster_name=request.cluster_name,
            environment=request.environment,
            owner_team=request.owner_team,
            criticality=request.criticality,
            description=request.description,
            service_ids=request.service_ids,
            entry_services=request.entry_services,
            routing_config=request.routing_config,
            tags=request.tags,
            metadata=request.metadata,
        )
        self.state.clusters = [item for item in self.state.clusters if item.cluster_id != cluster.cluster_id]
        self.state.clusters.append(cluster)
        self._reconcile_catalog()
        audit_logger.log(
            event_type="nexus_cluster_upserted",
            user="nexus_catalog",
            details=cluster.model_dump(mode="json"),
        )
        self._persist_and_refresh()
        return cluster

    def upsert_business_flow(self, request: BusinessFlowUpsertRequest) -> BusinessFlow:
        services = self._service_map()
        referenced_services = set(request.entry_service_ids)
        referenced_services.update(step.service_id for step in request.steps)
        missing = [service_id for service_id in referenced_services if service_id not in services]
        if missing:
            raise KeyError(f"Unknown services referenced by business flow {request.flow_id}: {', '.join(sorted(missing))}")

        steps = [
            step.model_copy(update={"step_id": step.step_id or f"{request.flow_id}:{step.step_order}:{step.service_id}"})
            for step in sorted(request.steps, key=lambda item: (item.step_order, item.service_id))
        ]
        flow = BusinessFlow(
            flow_id=request.flow_id,
            flow_name=request.flow_name,
            environment=request.environment,
            owner_team=request.owner_team,
            criticality=request.criticality,
            description=request.description,
            entry_service_ids=request.entry_service_ids,
            steps=steps,
            success_indicators=request.success_indicators,
            failure_indicators=request.failure_indicators,
            tags=request.tags,
            enabled=request.enabled,
            correlation_window_minutes=request.correlation_window_minutes,
            metadata=request.metadata,
        )
        self.state.business_flows = [item for item in self.state.business_flows if item.flow_id != flow.flow_id]
        self.state.business_flows.append(flow)
        self._reconcile_catalog()
        audit_logger.log(
            event_type="nexus_business_flow_upserted",
            user="nexus_catalog",
            details=flow.model_dump(mode="json"),
        )
        self._persist_and_refresh()
        return flow

    def delete_business_flow(self, flow_id: str) -> None:
        if not any(item.flow_id == flow_id for item in self.state.business_flows):
            raise KeyError(f"Unknown business flow {flow_id}")
        self.state.business_flows = [item for item in self.state.business_flows if item.flow_id != flow_id]
        for edge in self.state.dependency_edges:
            if flow_id in edge.business_flow_ids:
                edge.business_flow_ids = [item for item in edge.business_flow_ids if item != flow_id]
            metadata_flow_ids = edge.metadata.get("flow_ids")
            if isinstance(metadata_flow_ids, list) and flow_id in metadata_flow_ids:
                edge.metadata["flow_ids"] = [item for item in metadata_flow_ids if item != flow_id]
        for signal in self.state.signals:
            if signal.business_flow_id == flow_id:
                signal.business_flow_id = None
            if signal.attributes.get("business_flow_id") == flow_id:
                signal.attributes.pop("business_flow_id", None)
        audit_logger.log(
            event_type="nexus_business_flow_deleted",
            user="nexus_catalog",
            details={"flow_id": flow_id},
        )
        self._persist_and_refresh()

    def delete_cluster(self, cluster_id: str) -> None:
        if not any(item.cluster_id == cluster_id for item in self.state.clusters):
            raise KeyError(f"Unknown cluster {cluster_id}")
        self.state.clusters = [item for item in self.state.clusters if item.cluster_id != cluster_id]
        self.state.dependency_edges = [edge for edge in self.state.dependency_edges if edge.cluster_id != cluster_id]
        self._reconcile_catalog()
        audit_logger.log(
            event_type="nexus_cluster_deleted",
            user="nexus_catalog",
            details={"cluster_id": cluster_id},
        )
        self._persist_and_refresh()

    def upsert_edge(self, request: DependencyEdgeUpsertRequest) -> DependencyEdge:
        services = self._service_map()
        if request.from_service_id not in services or request.to_service_id not in services:
            raise KeyError("Both dependency endpoints must exist in the service catalog.")
        if request.cluster_id and not any(item.cluster_id == request.cluster_id for item in self.state.clusters):
            raise KeyError(f"Unknown cluster {request.cluster_id}")
        known_flow_ids = {flow.flow_id for flow in self.state.business_flows}
        missing_flow_ids = [flow_id for flow_id in request.business_flow_ids if flow_id not in known_flow_ids]
        if missing_flow_ids:
            raise KeyError(f"Unknown business flows referenced by dependency edge: {', '.join(sorted(missing_flow_ids))}")
        edge_id = request.edge_id or self._edge_id_for_request(request)
        valid_failure_domains = request.valid_failure_domains
        expected_evidence = request.expected_evidence
        if request.dependency_type == "db":
            valid_failure_domains = valid_failure_domains or ["database", "dependency", "service_runtime"]
            expected_evidence = expected_evidence or [
                "db_error_code",
                "connection_pool_usage",
                "active_sessions",
                "lock_waits",
                "slow_queries",
                "replication_lag",
                "tablespace_pressure",
            ]
        edge = DependencyEdge(
            edge_id=edge_id,
            cluster_id=request.cluster_id,
            from_service_id=request.from_service_id,
            to_service_id=request.to_service_id,
            dependency_type=request.dependency_type,
            dependency_purpose=request.dependency_purpose,
            dependency_scope=request.dependency_scope,
            business_flow_ids=request.business_flow_ids,
            valid_failure_domains=valid_failure_domains,
            expected_evidence=expected_evidence,
            criticality_weight=request.criticality_weight,
            timeout_budget_ms=request.timeout_budget_ms,
            is_hard_dependency=request.is_hard_dependency,
            database_access=self._normalized_database_access(request),
            metadata=request.metadata,
        )
        self.state.dependency_edges = [item for item in self.state.dependency_edges if (item.edge_id or "") != edge_id]
        self.state.dependency_edges.append(edge)
        self._reconcile_catalog()
        audit_logger.log(
            event_type="nexus_dependency_upserted",
            user="nexus_catalog",
            details=edge.model_dump(mode="json"),
        )
        self._persist_and_refresh()
        return edge

    def delete_edge(self, edge_id: str) -> None:
        if not any((item.edge_id or "") == edge_id for item in self.state.dependency_edges):
            raise KeyError(f"Unknown dependency edge {edge_id}")
        self.state.dependency_edges = [item for item in self.state.dependency_edges if (item.edge_id or "") != edge_id]
        audit_logger.log(
            event_type="nexus_dependency_deleted",
            user="nexus_catalog",
            details={"edge_id": edge_id},
        )
        self._persist_and_refresh()

    def get_graph_context(self, service_id: str) -> ServiceGraphContext:
        self._ensure_live_state()
        services = self._service_map()
        service = services.get(service_id)
        if service is None:
            raise KeyError(f"Unknown service {service_id}")

        active_incidents = {incident.incident_id: incident for incident in self.state.incidents}
        affected_services = {
            affected
            for incident in active_incidents.values()
            for affected in incident.affected_services
        }
        suspected_roots = {
            incident.suspected_root_service
            for incident in active_incidents.values()
            if incident.suspected_root_service
        }
        nodes = [
            GraphNode(
                service_id=item.service_id,
                service_name=item.service_name,
                service_type=item.service_type,
                criticality=item.criticality,
                environment=item.environment,
                affected=item.service_id in affected_services,
                suspected_root=item.service_id in suspected_roots,
            )
            for item in self.state.services
        ]
        highlighted_edges = {
            (edge.from_service_id, edge.to_service_id)
            for incident in active_incidents.values()
            for edge in self.state.dependency_edges
            if edge.from_service_id in incident.affected_services and edge.to_service_id in incident.affected_services
        }
        edges = [
            GraphEdge(
                edge_id=edge.edge_id,
                cluster_id=edge.cluster_id,
                from_service_id=edge.from_service_id,
                to_service_id=edge.to_service_id,
                dependency_type=edge.dependency_type,
                highlighted=(edge.from_service_id, edge.to_service_id) in highlighted_edges,
            )
            for edge in self.state.dependency_edges
        ]
        dependencies = [edge.to_service_id for edge in self.state.dependency_edges if edge.from_service_id == service_id]
        dependents = [edge.from_service_id for edge in self.state.dependency_edges if edge.to_service_id == service_id]
        return ServiceGraphContext(
            focus_service_id=service.service_id,
            focus_service_name=service.service_name,
            nodes=nodes,
            edges=edges,
            dependencies=dependencies,
            dependents=dependents,
            cluster_ids=self._cluster_ids_for_service(service_id),
        )

    def sync_network_sentinel(self, request: SyncRequest | None = None) -> FabricSummary:
        force = bool(request.force) if request else False
        now = datetime.utcnow()
        if (
            not force
            and self._last_network_sync_at is not None
            and (now - self._last_network_sync_at) < self.NETWORK_SYNC_INTERVAL
        ):
            return self.state.fabric_summary

        mapped_services = {
            service.service_id: service.observation_config.network_service_id
            for service in self.state.services
            if service.observation_config.network_service_id
        }
        if not mapped_services:
            self._update_fabric_summary(
                last_sync_at=now,
                sync_health="warning",
                sync_message="No Network Sentinel mappings configured yet. Add network_service_id values to start live sync.",
            )
            self._persist_and_refresh()
            self._last_network_sync_at = now
            return self.state.fabric_summary

        try:
            evidence = self.repository.fetch_network_sentinel_evidence(mapped_services)
        except Exception as exc:
            logger.exception("Network Sentinel sync failed")
            self._update_fabric_summary(
                last_sync_at=now,
                sync_health="error",
                sync_message=f"Network Sentinel sync failed: {exc}",
            )
            self.repository.persist_state(self.state)
            self._last_network_sync_at = now
            return self.state.fabric_summary

        signals = self._signals_from_network_sentinel(evidence)
        changes = self._changes_from_network_sentinel(evidence)
        for signal in signals:
            self._normalize_signal_datetime(signal)
        for change in changes:
            change.timestamp = self._to_naive_utc(change.timestamp) or change.timestamp
        self._merge_signals(signals)
        self._merge_change_events(changes)
        latest_by_service: dict[str, datetime] = {}
        for signal in signals:
            latest_by_service[signal.service_id] = max(latest_by_service.get(signal.service_id, signal.timestamp), signal.timestamp)
        for service_id, observed_at in latest_by_service.items():
            self._refresh_restart_monitoring(service_id, observed_at)

        self._update_fabric_summary(
            last_sync_at=now,
            sync_health="success",
            sync_message=f"Synchronized {len(signals)} live evidence records for {len(mapped_services)} mapped services.",
        )
        self._persist_and_refresh()
        self._last_network_sync_at = now
        return self.state.fabric_summary

    def record_change_event(self, request: ChangeEventRequest) -> ChangeEvent:
        service = self._service_map().get(request.service_id)
        if service is None:
            raise KeyError(f"Unknown service {request.service_id}")
        event = ChangeEvent(
            change_id=f"chg-{uuid4()}",
            service_id=request.service_id,
            change_type=request.change_type,
            timestamp=request.timestamp or datetime.utcnow(),
            source=request.source,
            summary=request.summary,
            metadata=request.metadata,
        )
        self._merge_change_events([event])
        audit_logger.log(
            event_type="nexus_change_event",
            user=request.source,
            details=event.model_dump(mode="json"),
        )
        self._persist_and_refresh()
        return event

    def request_diagnostics(self, incident_id: str, request: DiagnosticsRequest) -> DiagnosticBundle:
        incident = self._require_incident(incident_id)
        target_service_id = incident.suspected_root_service or incident.affected_services[0]
        target_service = self._service_map()[target_service_id]
        diagnostics_url = target_service.endpoint_config.diagnostics_url or self._cluster_diagnostics_url(target_service_id)
        commands = self._diagnostic_commands_for_service(target_service_id)
        bundle = DiagnosticBundle(
            bundle_id=f"diag-{uuid4()}",
            incident_id=incident_id,
            service_id=target_service_id,
            requested_at=datetime.utcnow(),
            requested_by=request.requested_by,
            status="READY",
            commands=commands,
            evidence_snapshot=incident.evidence_timeline[:6],
            notes=request.notes,
            diagnostics_url=diagnostics_url,
        )

        if diagnostics_url and target_service.certification.lifecycle_stage in {"diagnostics_ready", "restart_ready"}:
            try:
                response = httpx.post(
                    diagnostics_url,
                    headers=self._agent_command_headers(target_service),
                    json={
                        "bundle_id": bundle.bundle_id,
                        "incident_id": incident_id,
                        "service_id": target_service_id,
                        "requested_by": request.requested_by,
                        "commands": [item.model_dump(mode="json") for item in commands],
                    },
                    timeout=8.0,
                )
                response.raise_for_status()
                bundle.status = "IN_PROGRESS"
                bundle.dispatch_status = "sent"
            except Exception as exc:
                bundle.dispatch_status = f"dispatch_failed: {exc}"
        elif diagnostics_url:
            bundle.dispatch_status = "blocked: service is not certified for diagnostics"
        else:
            bundle.dispatch_status = "pending: no diagnostics endpoint configured"

        self.state.diagnostics = [item for item in self.state.diagnostics if item.bundle_id != bundle.bundle_id]
        self.state.diagnostics.insert(0, bundle)
        audit_logger.log(
            event_type="nexus_diagnostics_requested",
            user=request.requested_by,
            details={"incident_id": incident_id, "bundle_id": bundle.bundle_id, "service_id": target_service_id},
        )
        self._persist_and_refresh()
        return bundle

    def create_task_handoff(self, incident_id: str, request: TaskHandoffRequest) -> TaskHandoff:
        incident = self._require_incident(incident_id)
        handoff = self.repository.create_task_record(
            incident=incident,
            requested_by=request.requested_by,
            assignee=request.assignee,
            due_at=request.due_at,
            notes=request.notes,
        )
        self.state.task_handoffs = [item for item in self.state.task_handoffs if item.task_id != handoff.task_id]
        self.state.task_handoffs.insert(0, handoff)
        audit_logger.log(
            event_type="nexus_task_handoff_created",
            user=request.requested_by,
            details={"incident_id": incident_id, "task_id": handoff.task_id},
        )
        self._persist_and_refresh()
        return handoff

    def handle_restart_action(self, incident_id: str, request: RestartActionRequest) -> ActionExecution:
        incident = self._require_incident(incident_id)
        target_service_id = incident.suspected_root_service or incident.affected_services[0]
        target_service = self._service_map()[target_service_id]
        recommendation = next((item for item in incident.recommendations if item.action_type == "safe_restart"), None)
        blocked_reasons = recommendation.blocked_reasons[:] if recommendation and not recommendation.eligible else []
        restart_url = target_service.endpoint_config.restart_url or self._cluster_restart_url(target_service_id)

        if not request.approve:
            execution = ActionExecution(
                action_execution_id=f"act-{uuid4()}",
                incident_id=incident_id,
                service_id=target_service_id,
                action_type="safe_restart",
                requested_at=datetime.utcnow(),
                requested_by=request.requested_by,
                status="REJECTED",
                justification=request.notes or "Operator rejected safe restart recommendation.",
                precheck_evidence=incident.evidence_timeline[:4],
                blocked_reasons=["Operator rejected restart approval."],
                completed_at=datetime.utcnow(),
                executor_url=restart_url,
            )
            self.state.action_executions.insert(0, execution)
            self._persist_and_refresh()
            return execution

        if not restart_url:
            blocked_reasons.append("No restart execution URL is configured for this service or its dependency cluster.")

        if blocked_reasons:
            execution = ActionExecution(
                action_execution_id=f"act-{uuid4()}",
                incident_id=incident_id,
                service_id=target_service_id,
                action_type="safe_restart",
                requested_at=datetime.utcnow(),
                requested_by=request.requested_by,
                approved_by=request.requested_by,
                status="BLOCKED",
                justification=request.notes or "Safe restart blocked by policy.",
                precheck_evidence=incident.evidence_timeline[:4],
                blocked_reasons=blocked_reasons,
                completed_at=datetime.utcnow(),
                executor_url=restart_url,
            )
            self.state.action_executions.insert(0, execution)
            audit_logger.log(
                event_type="nexus_restart_blocked",
                user=request.requested_by,
                details={"incident_id": incident_id, "service_id": target_service_id, "reasons": blocked_reasons},
                success=False,
            )
            self._persist_and_refresh()
            return execution

        execution = ActionExecution(
            action_execution_id=f"act-{uuid4()}",
            incident_id=incident_id,
            service_id=target_service_id,
            action_type="safe_restart",
            requested_at=datetime.utcnow(),
            requested_by=request.requested_by,
            approved_by=request.requested_by,
            status="MONITORING",
            justification=request.notes or f"Approved safe restart for {target_service.service_name}.",
            precheck_evidence=incident.evidence_timeline[:4],
            monitoring_until=datetime.utcnow() + self.MONITORING_WINDOW,
            executor_url=restart_url,
        )
        try:
            response = httpx.post(
                restart_url,
                headers=self._agent_command_headers(target_service),
                json={
                    "action_execution_id": execution.action_execution_id,
                    "incident_id": incident_id,
                    "service_id": target_service_id,
                    "approved_by": request.requested_by,
                    "requested_by": request.requested_by,
                },
                timeout=8.0,
            )
            response.raise_for_status()
            payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            execution.remote_execution_id = str(payload.get("execution_id") or payload.get("request_id") or "")
        except Exception as exc:
            execution.status = "BLOCKED"
            execution.blocked_reasons = [f"Restart executor request failed: {exc}"]
            execution.completed_at = datetime.utcnow()
            execution.result_summary = "Restart request could not be dispatched to the configured service executor."
            self.state.action_executions.insert(0, execution)
            audit_logger.log(
                event_type="nexus_restart_blocked",
                user=request.requested_by,
                details={"incident_id": incident_id, "service_id": target_service_id, "reasons": execution.blocked_reasons},
                success=False,
            )
            self._persist_and_refresh()
            return execution

        self.state.action_executions.insert(0, execution)
        self._merge_change_events(
            [
                ChangeEvent(
                    change_id=f"chg-{uuid4()}",
                    service_id=target_service_id,
                    change_type="manual_restart",
                    timestamp=datetime.utcnow(),
                    source="nexus_restart",
                    summary=f"Human-approved safe restart initiated for {target_service.service_name}.",
                    metadata={"incident_id": incident_id, "requested_by": request.requested_by},
                )
            ]
        )
        audit_logger.log(
            event_type="nexus_restart_approved",
            user=request.requested_by,
            details={"incident_id": incident_id, "service_id": target_service_id, "action_execution_id": execution.action_execution_id},
        )
        self._persist_and_refresh()
        return execution

    def record_verdict(self, incident_id: str, request: IncidentVerdictRequest) -> OperatorFeedback:
        feedback = OperatorFeedback(
            feedback_id=f"fb-{uuid4()}",
            incident_id=incident_id,
            feedback_type="verdict",
            created_at=datetime.utcnow(),
            created_by=request.requested_by,
            details={
                "verdict": request.verdict,
                "actual_root_service_id": request.actual_root_service_id,
                "notes": request.notes,
            },
        )
        self.state.operator_feedback.insert(0, feedback)
        audit_logger.log(
            event_type="nexus_verdict_recorded",
            user=request.requested_by,
            details=feedback.model_dump(mode="json"),
        )
        self._persist_and_refresh()
        return feedback

    def record_heartbeat(self, heartbeat: AgentHeartbeat) -> AgentHeartbeat:
        self.state.agent_heartbeats = [item for item in self.state.agent_heartbeats if item.agent_id != heartbeat.agent_id]
        self.state.agent_heartbeats.insert(0, heartbeat)
        self.state.agent_heartbeats = self.state.agent_heartbeats[:200]
        self.repository.persist_state(self.state)
        return heartbeat

    def record_probe_report(self, report: AgentProbeReport) -> list[SignalEvent]:
        service = self._service_map().get(report.service_id)
        if service is None:
            raise KeyError(f"Unknown service {report.service_id}")

        signals: list[SignalEvent] = []
        change_events: list[ChangeEvent] = []
        instance_id = report.instance_id or report.agent_id
        cluster = report.cluster or service.cluster or (service.cluster_ids[0] if service.cluster_ids else None)
        change_context = [item.model_dump(mode="json") for item in report.change_context]
        signal_context = self._agent_report_signal_context(report)
        metric_attributes = {
            "metrics": report.metrics,
            "status": report.status,
            "host_id": report.host_id,
            "instance_id": instance_id,
            "cluster": cluster,
            "zone": report.zone,
            "service_version": report.service_version,
            "probe_family": report.probe_family,
            "metadata": report.metadata,
            "change_context": change_context,
            **signal_context,
        }
        if report.database or service.database_profile.enabled:
            metric_attributes.update(self._database_signal_attributes(service, report))
        signals.append(
            SignalEvent(
                signal_id=f"probe-{uuid4()}",
                signal_type="synthetic",
                service_id=service.service_id,
                service_name=service.service_name,
                instance_id=instance_id,
                severity=report.severity,
                timestamp=report.timestamp,
                source=report.source,
                environment=service.environment,
                cluster=cluster,
                vantage_point=signal_context["vantage_point"],
                observation_layer=signal_context["observation_layer"],
                failure_domain_hint=signal_context["failure_domain_hint"],
                business_flow_id=signal_context.get("business_flow_id"),
                message=report.message or f"Probe report received for {service.service_name}.",
                fingerprint=f"{service.service_id}:{report.source}:{report.timestamp.isoformat()}",
                attributes=metric_attributes,
            )
        )

        if report.database and self._database_snapshot_indicates_pressure(report.database):
            database_attributes = {
                **metric_attributes,
                "database_signal": True,
                "database_status": report.database.status,
                "database_connectivity": report.database.connectivity,
                "database_error_codes": report.database.error_codes,
            }
            signals.append(
                SignalEvent(
                    signal_id=f"db-{uuid4()}",
                    signal_type="metric",
                    service_id=service.service_id,
                    service_name=service.service_name,
                    instance_id=instance_id,
                    severity=report.severity,
                    timestamp=report.timestamp,
                    source=report.source,
                    environment=service.environment,
                    cluster=cluster,
                    vantage_point="database_probe",
                    observation_layer="database",
                    failure_domain_hint="database",
                    business_flow_id=signal_context.get("business_flow_id"),
                    message=self._database_snapshot_message(service, report),
                    fingerprint=f"{service.service_id}:database:{report.timestamp.isoformat()}:{report.database.status or 'unknown'}",
                    attributes=database_attributes,
                )
            )

        log_records = report.log_records or [
            AgentLogRecord(
                timestamp=report.timestamp,
                severity=report.severity,
                message=raw_line,
            )
            for raw_line in report.logs
        ]
        for log_record in log_records:
            log_timestamp = log_record.timestamp or report.timestamp
            log_severity = log_record.severity or report.severity
            signature = self._signature_from_log_record(service, log_record, log_timestamp)
            signature_failure_domain = self._failure_domain_from_signature(signature)
            log_failure_domain = signal_context["failure_domain_hint"]
            if signature_failure_domain != "service_runtime" or not log_failure_domain:
                log_failure_domain = signature_failure_domain
            signals.append(
                SignalEvent(
                    signal_id=f"log-{uuid4()}",
                    signal_type="log",
                    service_id=service.service_id,
                    service_name=service.service_name,
                    instance_id=instance_id,
                    severity=log_severity,
                    timestamp=log_timestamp,
                    source="loki",
                    environment=service.environment,
                    cluster=cluster,
                    message=log_record.message,
                    raw_excerpt=log_record.message,
                    fingerprint=f"{service.service_id}:log:{signature.signature_id}:{log_timestamp.isoformat()}",
                    attributes={
                        "label_set": {
                            "service": service.service_name,
                            "environment": service.environment,
                            "cluster": cluster,
                            "severity": log_severity.lower(),
                        },
                        "log_attributes": log_record.attributes,
                        "host_id": report.host_id,
                        "instance_id": instance_id,
                        "service_version": report.service_version,
                        "change_context": change_context,
                        **{**signal_context, "failure_domain_hint": log_failure_domain},
                    },
                    signature=signature,
                    vantage_point="application_log",
                    observation_layer="logs",
                    failure_domain_hint=log_failure_domain,
                    business_flow_id=signal_context.get("business_flow_id"),
                )
            )

        trace_summaries = report.trace_summaries or [
            self._trace_summary_from_legacy_payload(trace)
            for trace in report.traces
        ]
        for trace in trace_summaries:
            trace_timestamp = trace.timestamp or report.timestamp
            signals.append(
                SignalEvent(
                    signal_id=f"trace-{uuid4()}",
                    signal_type="trace",
                    service_id=service.service_id,
                    service_name=service.service_name,
                    instance_id=instance_id,
                    severity=report.severity,
                    timestamp=trace_timestamp,
                    source="otel",
                    environment=service.environment,
                    cluster=cluster,
                    vantage_point="distributed_trace",
                    observation_layer="traces",
                    failure_domain_hint=signal_context["failure_domain_hint"],
                    business_flow_id=signal_context.get("business_flow_id"),
                    message=trace.summary or f"Trace anomaly reported for {service.service_name}.",
                    fingerprint=f"{service.service_id}:trace:{trace_timestamp.isoformat()}:{'-'.join(trace.path)}",
                    attributes=self._trace_attributes(trace, report, instance_id, cluster, change_context),
                )
            )

        for item in report.change_context:
            change_events.append(
                self._change_event_from_agent_context(service.service_id, item, report.timestamp)
            )

        self._merge_signals(signals)
        self._merge_change_events(change_events)
        self._refresh_restart_monitoring(report.service_id, report.timestamp)
        self._persist_and_refresh()
        return signals

    def record_diagnostic_result(self, result: AgentDiagnosticResult) -> DiagnosticBundle:
        bundle = next((item for item in self.state.diagnostics if item.bundle_id == result.bundle_id), None)
        if bundle is None:
            raise KeyError(f"Unknown diagnostic bundle {result.bundle_id}")
        bundle.status = "COMPLETED"
        bundle.dispatch_status = "completed"
        bundle.notes = result.notes or bundle.notes
        audit_logger.log(
            event_type="nexus_diagnostics_completed",
            user=result.agent_id,
            details={"bundle_id": result.bundle_id, "incident_id": result.incident_id, "service_id": result.service_id},
        )
        self.repository.persist_state(self.state)
        return bundle

    def _ensure_live_state(self, force_sync: bool = False) -> None:
        if not self.state.services:
            self._rebuild_incidents()
            return
        self.sync_network_sentinel(SyncRequest(force=force_sync))

    def _persist_and_refresh(self) -> None:
        self._normalize_state_datetimes()
        self._rebuild_incidents()
        self._update_fabric_summary()
        self._normalize_state_datetimes()
        self.repository.persist_state(self.state)

    @staticmethod
    def _to_naive_utc(value: datetime | str | None) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        if value.tzinfo is None:
            return value
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def _normalize_state_datetimes(self) -> None:
        for signal in self.state.signals:
            self._normalize_signal_datetime(signal)
        for change in self.state.change_events:
            change.timestamp = self._to_naive_utc(change.timestamp) or change.timestamp
        for incident in self.state.incidents:
            incident.start_time = self._to_naive_utc(incident.start_time) or incident.start_time
            incident.end_time = self._to_naive_utc(incident.end_time)
            for evidence in incident.evidence_timeline:
                evidence.timestamp = self._to_naive_utc(evidence.timestamp) or evidence.timestamp
            for signature in incident.log_signatures:
                self._normalize_signature_datetime(signature)
            for task in incident.linked_tasks:
                task.created_at = self._to_naive_utc(task.created_at) or task.created_at
            for bundle in incident.diagnostics:
                self._normalize_diagnostic_datetime(bundle)
            for execution in incident.action_executions:
                self._normalize_action_datetime(execution)
            if incident.verdict:
                incident.verdict.created_at = self._to_naive_utc(incident.verdict.created_at) or incident.verdict.created_at
        for bundle in self.state.diagnostics:
            self._normalize_diagnostic_datetime(bundle)
        for execution in self.state.action_executions:
            self._normalize_action_datetime(execution)
        for feedback in self.state.operator_feedback:
            feedback.created_at = self._to_naive_utc(feedback.created_at) or feedback.created_at
        for task in self.state.task_handoffs:
            task.created_at = self._to_naive_utc(task.created_at) or task.created_at
        for heartbeat in self.state.agent_heartbeats:
            heartbeat.timestamp = self._to_naive_utc(heartbeat.timestamp) or heartbeat.timestamp
        self.state.fabric_summary.last_sync_at = self._to_naive_utc(self.state.fabric_summary.last_sync_at)

    def _normalize_signature_datetime(self, signature: LogSignature) -> None:
        signature.first_seen_at = self._to_naive_utc(signature.first_seen_at) or signature.first_seen_at
        signature.last_seen_at = self._to_naive_utc(signature.last_seen_at) or signature.last_seen_at

    def _normalize_signal_datetime(self, signal: SignalEvent) -> None:
        signal.timestamp = self._to_naive_utc(signal.timestamp) or signal.timestamp
        if not signal.vantage_point or not signal.observation_layer or not signal.failure_domain_hint:
            context = self._signal_context(signal)
            signal.vantage_point = signal.vantage_point or context["vantage_point"]
            signal.observation_layer = signal.observation_layer or context["observation_layer"]
            signal.failure_domain_hint = signal.failure_domain_hint or context["failure_domain_hint"]
            signal.business_flow_id = signal.business_flow_id or context.get("business_flow_id")
            signal.attributes = {**context, **signal.attributes}
        if signal.signature:
            self._normalize_signature_datetime(signal.signature)

    def _normalize_diagnostic_datetime(self, bundle: DiagnosticBundle) -> None:
        bundle.requested_at = self._to_naive_utc(bundle.requested_at) or bundle.requested_at
        for evidence in bundle.evidence_snapshot:
            evidence.timestamp = self._to_naive_utc(evidence.timestamp) or evidence.timestamp

    def _normalize_action_datetime(self, execution: ActionExecution) -> None:
        execution.requested_at = self._to_naive_utc(execution.requested_at) or execution.requested_at
        execution.monitoring_until = self._to_naive_utc(execution.monitoring_until)
        execution.completed_at = self._to_naive_utc(execution.completed_at)
        for evidence in execution.precheck_evidence:
            evidence.timestamp = self._to_naive_utc(evidence.timestamp) or evidence.timestamp

    def _reconcile_catalog(self) -> None:
        services = {service.service_id: service for service in self.state.services}
        cluster_membership: dict[str, set[str]] = defaultdict(set)
        for cluster in self.state.clusters:
            cluster.service_ids = [service_id for service_id in cluster.service_ids if service_id in services]
            cluster.entry_services = [service_id for service_id in cluster.entry_services if service_id in services]
            for service_id in cluster.service_ids:
                cluster_membership[service_id].add(cluster.cluster_id)
        for service in self.state.services:
            declared = set(service.cluster_ids)
            derived = cluster_membership.get(service.service_id, set())
            service.cluster_ids = sorted(declared.union(derived))
            if service.cluster and service.cluster not in service.cluster_ids:
                service.cluster_ids.insert(0, service.cluster)
            if not service.cluster and service.cluster_ids:
                service.cluster = service.cluster_ids[0]
        for flow in self.state.business_flows:
            flow.entry_service_ids = [service_id for service_id in flow.entry_service_ids if service_id in services]
            flow.steps = [
                step.model_copy(update={"step_id": step.step_id or f"{flow.flow_id}:{step.step_order}:{step.service_id}"})
                for step in flow.steps
                if step.service_id in services
            ]
        known_flow_ids = {flow.flow_id for flow in self.state.business_flows}
        for edge in self.state.dependency_edges:
            edge.edge_id = edge.edge_id or self._edge_id(edge)
            edge.business_flow_ids = [flow_id for flow_id in edge.business_flow_ids if flow_id in known_flow_ids]
        self._update_fabric_summary(sync_message=self.state.fabric_summary.sync_message)

    def _signals_from_network_sentinel(self, evidence: dict[str, object]) -> list[SignalEvent]:
        services = self._service_map()
        signals: list[SignalEvent] = []
        for snapshot in evidence.get("snapshots", []):
            service_id = snapshot.get("service_id")
            if not service_id or service_id not in services:
                continue
            service = services[service_id]
            cluster = service.cluster or (service.cluster_ids[0] if service.cluster_ids else None)
            status = str(snapshot.get("overall_status") or "UNKNOWN").upper()
            checked_at = self._to_naive_utc(snapshot.get("last_checked_at")) or datetime.utcnow()
            outage_started_at = self._to_naive_utc(snapshot.get("outage_started_at"))
            outage_id = str(snapshot.get("outage_id") or "").strip() or None
            severity = "CRITICAL" if status == "DOWN" else "WARN" if status == "DEGRADED" else "INFO"
            status_attributes = {
                "network_service_id": snapshot.get("network_service_id"),
                "address": snapshot.get("address"),
                "port": snapshot.get("port"),
                "status": status,
                "icmp_latency_ms": snapshot.get("icmp_latency_ms"),
                "tcp_latency_ms": snapshot.get("tcp_latency_ms"),
                "consecutive_failures": snapshot.get("consecutive_failures"),
                "outage_id": outage_id,
                "active_outage_id": outage_id,
                "outage_started_at": outage_started_at.isoformat() if outage_started_at else None,
                "outage_duration_seconds": snapshot.get("outage_duration_seconds"),
                "outage_active": bool(outage_id),
                "vantage_point": "external_network",
                "observation_layer": "network",
                "failure_domain_hint": "network_path",
            }
            signals.append(
                SignalEvent(
                    signal_id=f"ns-status-{snapshot['network_service_id']}-{status}-{checked_at.isoformat()}",
                    signal_type="synthetic",
                    service_id=service_id,
                    service_name=service.service_name,
                    severity=severity,
                    timestamp=checked_at,
                    source="network_sentinel",
                    environment=service.environment,
                    cluster=cluster,
                    vantage_point="external_network",
                    observation_layer="network",
                    failure_domain_hint="network_path",
                    message=snapshot.get("reason")
                    or f"Network Sentinel reports {service.service_name} as {status}.",
                    fingerprint=f"{service_id}:network_sentinel:status:{status}:{checked_at.isoformat()}",
                    attributes=status_attributes,
                )
            )
            if snapshot.get("outage_id"):
                signals.append(
                    SignalEvent(
                        signal_id=f"ns-outage-{snapshot['outage_id']}",
                        signal_type="alert",
                        service_id=service_id,
                        service_name=service.service_name,
                        severity="CRITICAL",
                        timestamp=outage_started_at or checked_at,
                        source="network_sentinel",
                        environment=service.environment,
                        cluster=cluster,
                        vantage_point="external_network",
                        observation_layer="network",
                        failure_domain_hint="network_path",
                        message=f"Active outage detected for {service.service_name}: {snapshot.get('outage_cause') or 'UNKNOWN'}.",
                        fingerprint=f"{service_id}:network_sentinel:outage:{snapshot['outage_id']}",
                        attributes={
                            "network_service_id": snapshot.get("network_service_id"),
                            "outage_id": snapshot.get("outage_id"),
                            "active_outage_id": outage_id,
                            "outage_started_at": outage_started_at.isoformat() if outage_started_at else None,
                            "outage_active": True,
                            "outage_duration_seconds": snapshot.get("outage_duration_seconds"),
                            "cause": snapshot.get("outage_cause"),
                            "details": snapshot.get("outage_details"),
                            "vantage_point": "external_network",
                            "observation_layer": "network",
                            "failure_domain_hint": "network_path",
                        },
                    )
                )
        for event in evidence.get("events", []):
            service_id = event.get("service_id")
            if not service_id or service_id not in services:
                continue
            service = services[service_id]
            cluster = service.cluster or (service.cluster_ids[0] if service.cluster_ids else None)
            severity = str(event.get("severity") or "INFO").upper()
            if severity not in {"INFO", "WARN", "CRITICAL"}:
                severity = "INFO"
            if self._network_event_is_change(event):
                continue
            message = event.get("summary") or event.get("title") or "Network Sentinel event recorded."
            signals.append(
                SignalEvent(
                    signal_id=f"ns-event-{event['event_id']}",
                    signal_type="alert",
                    service_id=service_id,
                    service_name=service.service_name,
                    severity=severity,
                    timestamp=event.get("created_at") or datetime.utcnow(),
                    source="network_sentinel",
                    environment=service.environment,
                    cluster=cluster,
                    vantage_point="external_network",
                    observation_layer="network",
                    failure_domain_hint="network_path",
                    message=message,
                    fingerprint=f"{service_id}:network_sentinel:event:{event['event_id']}",
                    attributes={
                        "network_service_id": event.get("network_service_id"),
                        "category": event.get("category"),
                        "event_type": event.get("event_type"),
                        "title": event.get("title"),
                        "details": event.get("details"),
                        "vantage_point": "external_network",
                        "observation_layer": "network",
                        "failure_domain_hint": "network_path",
                    },
                )
            )
        return signals

    def _changes_from_network_sentinel(self, evidence: dict[str, object]) -> list[ChangeEvent]:
        services = self._service_map()
        changes: list[ChangeEvent] = []
        for event in evidence.get("events", []):
            service_id = event.get("service_id")
            if not service_id or service_id not in services:
                continue
            if not self._network_event_is_change(event):
                continue
            change_type = self._network_change_type(event)
            changes.append(
                ChangeEvent(
                    change_id=f"ns-change-{event['event_id']}",
                    service_id=service_id,
                    change_type=change_type,
                    timestamp=event.get("created_at") or datetime.utcnow(),
                    source="network_sentinel",
                    summary=event.get("summary") or event.get("title") or change_type.replace("_", " ").title(),
                    metadata={
                        "category": event.get("category"),
                        "event_type": event.get("event_type"),
                        "details": event.get("details"),
                    },
                )
            )
        return changes

    def _merge_signals(self, signals: list[SignalEvent]) -> None:
        for signal in self.state.signals:
            self._normalize_signal_datetime(signal)
        for signal in signals:
            self._normalize_signal_datetime(signal)
        merged = {item.signal_id: item for item in self.state.signals}
        for signal in signals:
            merged[signal.signal_id] = signal
        self.state.signals = sorted(merged.values(), key=lambda item: item.timestamp)[-self.MAX_SIGNALS :]

    def _merge_change_events(self, events: list[ChangeEvent]) -> None:
        for event in self.state.change_events:
            event.timestamp = self._to_naive_utc(event.timestamp) or event.timestamp
        for event in events:
            event.timestamp = self._to_naive_utc(event.timestamp) or event.timestamp
        merged = {item.change_id: item for item in self.state.change_events}
        for event in events:
            merged[event.change_id] = event
        self.state.change_events = sorted(merged.values(), key=lambda item: item.timestamp)[-self.MAX_CHANGES :]

    def _update_fabric_summary(
        self,
        *,
        last_sync_at: datetime | None = None,
        sync_health=None,
        sync_message: str | None = None,
    ) -> None:
        summary = self.state.fabric_summary
        diagnostics_ready = len(
            [
                service
                for service in self.state.services
                if service.certification.lifecycle_stage in {"diagnostics_ready", "restart_ready"}
            ]
        )
        restart_ready = len(
            [service for service in self.state.services if service.certification.lifecycle_stage == "restart_ready"]
        )
        mapped_network = len(
            [service for service in self.state.services if service.observation_config.network_service_id]
        )
        self.state.fabric_summary = FabricSummary(
            total_services=len(self.state.services),
            total_clusters=len(self.state.clusters),
            total_edges=len(self.state.dependency_edges),
            mapped_network_services=mapped_network,
            diagnostics_ready_services=diagnostics_ready,
            restart_ready_services=restart_ready,
            active_incidents=len([incident for incident in self.state.incidents if incident.status in {"OPEN", "MONITORING"}]),
            last_sync_at=last_sync_at or summary.last_sync_at,
            sync_health=sync_health or summary.sync_health,
            sync_message=sync_message if sync_message is not None else summary.sync_message,
        )

    def _rebuild_incidents(self) -> None:
        services = self._service_map()
        if not services:
            self.state.incidents = []
            self._update_fabric_summary()
            return

        now = datetime.utcnow()
        service_signals = [signal for signal in self.state.signals if signal.service_id in services]
        healthy_cutoffs = self._latest_network_healthy_cutoffs(service_signals)
        active_outage_starts = self._active_network_outage_starts(service_signals, now)
        recent_signals = [
            signal
            for signal in service_signals
            if self._signal_is_current_for_correlation(signal, now, healthy_cutoffs, active_outage_starts)
        ]
        grouped = defaultdict(list)
        for signal in recent_signals:
            grouped[signal.service_id].append(signal)

        candidate_services = {
            service_id
            for service_id, items in grouped.items()
            if any(self._severity_value(item.severity) >= 0.55 for item in items)
        }
        components = self._build_components(candidate_services, grouped)
        existing_tasks = defaultdict(list)
        for task in self.state.task_handoffs:
            existing_tasks[task.incident_id].append(task)
        existing_diagnostics = defaultdict(list)
        for bundle in self.state.diagnostics:
            existing_diagnostics[bundle.incident_id].append(bundle)
        existing_actions = defaultdict(list)
        for execution in self.state.action_executions:
            existing_actions[execution.incident_id].append(execution)
        latest_feedback = {}
        for feedback in self.state.operator_feedback:
            latest_feedback.setdefault(feedback.incident_id, feedback)
        previous_incidents = list(self.state.incidents)
        existing_by_key = {incident.incident_key: incident for incident in self.state.incidents}

        incidents: list[NexusIncident] = []
        active_incident_ids: set[str] = set()
        for component in components:
            if not component:
                continue
            incident_signals = sorted(
                [signal for service_id in component for signal in grouped[service_id]],
                key=lambda item: item.timestamp,
            )
            affected_services = sorted(component, key=lambda service_id: services[service_id].service_name)
            flow_ids = self._flow_ids_for_context(affected_services, incident_signals)
            primary_flow = self._primary_business_flow(flow_ids)
            failure_domain = self._failure_domain_for_signals(incident_signals)
            incident_start = self._incident_start_for_signals(incident_signals)
            incident_scope = self._incident_scope_for_signals(incident_signals, incident_start)
            incident_key = self._incident_key_for_services(
                affected_services,
                flow_ids=flow_ids,
                failure_domain=failure_domain,
                incident_scope=incident_scope,
            )
            previous = existing_by_key.get(incident_key)
            vantage_points = sorted(
                {
                    signal.vantage_point or self._signal_context(signal)["vantage_point"] or "unknown"
                    for signal in incident_signals
                }
            )
            root_candidates = self._rank_root_causes(
                affected_services,
                incident_signals,
                flow_ids=flow_ids,
                failure_domain=failure_domain,
            )
            primary_candidate = root_candidates[0] if root_candidates else None
            risk_score = self._compute_risk_score(
                affected_services,
                incident_signals,
                primary_candidate,
                flow_ids=flow_ids,
            )
            risk_level = self._risk_level_for_score(risk_score)
            evidence = [self._evidence_from_signal(signal) for signal in incident_signals[-18:]]
            signatures = self._aggregate_log_signatures(incident_signals)
            recommendations = self._build_recommendations(
                affected_services=affected_services,
                primary_candidate=primary_candidate,
                risk_level=risk_level,
            )
            title = self._build_incident_title(affected_services, services, primary_candidate, primary_flow)
            summary = self._build_summary(
                affected_services,
                services,
                primary_candidate,
                signatures,
                incident_signals,
                primary_flow,
                failure_domain,
            )
            start_time = (
                previous.start_time
                if previous and previous.status in {"OPEN", "MONITORING"} and previous.end_time is None
                else incident_start
            )
            incident_id = previous.incident_id if previous else str(uuid4())
            cluster_ids = self._cluster_ids_for_services(affected_services)
            linked_actions = existing_actions.get(incident_id, [])
            verdict_feedback = latest_feedback.get(incident_id) or (previous.verdict if previous else None)
            if verdict_feedback:
                incident_status = "RESOLVED"
            elif any(action.status == "MONITORING" for action in linked_actions):
                incident_status = "MONITORING"
            else:
                incident_status = "OPEN"
            incident = NexusIncident(
                incident_id=incident_id,
                incident_key=incident_key,
                title=title,
                status=incident_status,
                start_time=start_time,
                end_time=(previous.end_time if previous and previous.end_time else now) if incident_status == "RESOLVED" else None,
                summary=summary,
                risk_level=risk_level,
                risk_score=risk_score,
                business_impact_score=self._business_impact_score(affected_services),
                affected_services=affected_services,
                suspected_root_service=primary_candidate.service_id if primary_candidate else None,
                suspected_root_service_name=primary_candidate.service_name if primary_candidate else None,
                predicted_confidence=primary_candidate.confidence if primary_candidate else 0.0,
                blast_radius=self._blast_radius_for(primary_candidate.service_id, flow_ids=flow_ids, failure_domain=failure_domain) if primary_candidate else affected_services,
                cluster_ids=cluster_ids,
                business_flow_ids=flow_ids,
                primary_business_flow_id=primary_flow.flow_id if primary_flow else None,
                primary_business_flow_name=primary_flow.flow_name if primary_flow else None,
                failure_domain=failure_domain,
                vantage_points=vantage_points,
                data_sources=sorted({signal.source for signal in incident_signals}),
                correlation_version="nexus-v3-flow-aware",
                root_cause_candidates=root_candidates,
                recommendations=recommendations,
                evidence_timeline=evidence,
                log_signatures=signatures,
                linked_tasks=existing_tasks.get(incident_id, []),
                diagnostics=existing_diagnostics.get(incident_id, []),
                action_executions=linked_actions,
                verdict=verdict_feedback,
            )
            incidents.append(incident)
            active_incident_ids.add(incident.incident_id)

        active_service_sets = [
            set(incident.affected_services)
            for incident in incidents
            if incident.status in {"OPEN", "MONITORING"}
        ]
        for previous in previous_incidents:
            if previous.incident_id in active_incident_ids:
                continue
            verdict_feedback = latest_feedback.get(previous.incident_id) or previous.verdict
            previous_services = set(previous.affected_services)
            superseded_by_current_component = (
                previous.status in {"OPEN", "MONITORING"}
                and not verdict_feedback
                and not previous.linked_tasks
                and not previous.diagnostics
                and not previous.action_executions
                and any(
                    previous_services < active_services
                    for active_services in active_service_sets
                )
            )
            if superseded_by_current_component:
                continue
            if verdict_feedback:
                incidents.append(
                    previous.model_copy(
                        update={
                            "status": "RESOLVED",
                            "end_time": previous.end_time
                            or self._latest_recovery_time_for_incident(previous, healthy_cutoffs)
                            or now,
                            "verdict": verdict_feedback,
                        }
                    )
                )
                continue
            if previous.status == "RESOLVED":
                incidents.append(previous)
                continue
            recovery_time = self._latest_recovery_time_for_incident(previous, healthy_cutoffs)
            if recovery_time:
                incidents.append(self._move_to_operator_verdict(previous, previous.end_time or recovery_time))
            else:
                latest_signal_time = self._latest_signal_time_for_incident(previous)
                stale_cutoff = now - self.ACTIVE_WINDOW
                if previous.status in {"OPEN", "MONITORING"} and previous.start_time < stale_cutoff and (
                    not latest_signal_time or latest_signal_time < stale_cutoff
                ):
                    incidents.append(self._move_to_operator_verdict(previous, previous.end_time or latest_signal_time or now))
                elif previous.status == "AWAITING_VERDICT" and previous.risk_level != "LOW":
                    incidents.append(self._move_to_operator_verdict(previous, previous.end_time or latest_signal_time or now))
                else:
                    incidents.append(previous)

        self.state.incidents = sorted(
            incidents,
            key=lambda item: (item.status != "RESOLVED", self._risk_rank(item.risk_level), item.start_time),
            reverse=True,
        )[:250]
        self._update_fabric_summary()

    def _latest_network_healthy_cutoffs(self, signals: list[SignalEvent]) -> dict[str, datetime]:
        cutoffs: dict[str, datetime] = {}
        for signal in signals:
            if signal.source != "network_sentinel":
                continue
            status = str(signal.attributes.get("status") or "").upper()
            if status not in {"UP", "HEALTHY", "OK"}:
                continue
            if signal.timestamp > cutoffs.get(signal.service_id, datetime.min):
                cutoffs[signal.service_id] = signal.timestamp
        return cutoffs

    def _active_network_outage_starts(self, signals: list[SignalEvent], now: datetime) -> dict[str, datetime]:
        starts: dict[str, datetime] = {}
        for signal in signals:
            if signal.source != "network_sentinel":
                continue
            if not (signal.attributes.get("active_outage_id") or signal.attributes.get("outage_active")):
                continue
            if signal.timestamp < now - self.ACTIVE_WINDOW:
                continue
            outage_started_at = self._to_naive_utc(signal.attributes.get("outage_started_at")) or signal.timestamp
            if outage_started_at > starts.get(signal.service_id, datetime.min):
                starts[signal.service_id] = outage_started_at
        return starts

    def _signal_is_current_for_correlation(
        self,
        signal: SignalEvent,
        now: datetime,
        healthy_cutoffs: dict[str, datetime],
        active_outage_starts: dict[str, datetime],
    ) -> bool:
        active_outage_start = active_outage_starts.get(signal.service_id)
        if active_outage_start and signal.source == "network_sentinel" and signal.timestamp < active_outage_start:
            return False
        active_outage = bool(signal.attributes.get("active_outage_id") or signal.attributes.get("outage_active"))
        if signal.timestamp < now - self.ACTIVE_WINDOW and not active_outage:
            return False
        if signal.source == "network_sentinel" and active_outage and signal.timestamp < now - self.ACTIVE_WINDOW:
            return False
        healthy_cutoff = healthy_cutoffs.get(signal.service_id)
        if (
            healthy_cutoff
            and signal.source == "network_sentinel"
            and self._severity_value(signal.severity) >= 0.55
            and signal.timestamp <= healthy_cutoff
        ):
            return False
        return True

    def _incident_start_for_signals(self, signals: list[SignalEvent]) -> datetime:
        active_outage_candidates: list[datetime] = []
        candidates: list[datetime] = []
        for signal in signals:
            outage_started_at = self._to_naive_utc(signal.attributes.get("outage_started_at"))
            if outage_started_at and (signal.attributes.get("active_outage_id") or signal.attributes.get("outage_id")):
                if signal.attributes.get("active_outage_id") or signal.attributes.get("outage_active"):
                    active_outage_candidates.append(outage_started_at)
                candidates.append(outage_started_at)
            else:
                candidates.append(signal.timestamp)
        if active_outage_candidates:
            return min(active_outage_candidates)
        return min(candidates) if candidates else datetime.utcnow()

    def _incident_scope_for_signals(self, signals: list[SignalEvent], incident_start: datetime) -> str | None:
        outage_ids = sorted(
            {
                str(signal.attributes.get("active_outage_id") or signal.attributes.get("outage_id")).strip()
                for signal in signals
                if str(signal.attributes.get("active_outage_id") or signal.attributes.get("outage_id") or "").strip()
            }
        )
        if outage_ids:
            return "network-outage:" + "|".join(outage_ids)
        if any(signal.source == "network_sentinel" and self._severity_value(signal.severity) >= 0.55 for signal in signals):
            return f"network-window:{incident_start.isoformat(timespec='seconds')}"
        return None

    def _latest_recovery_time_for_incident(
        self,
        incident: NexusIncident,
        healthy_cutoffs: dict[str, datetime],
    ) -> datetime | None:
        recovery_times = [
            healthy_cutoffs[service_id]
            for service_id in incident.affected_services
            if service_id in healthy_cutoffs and healthy_cutoffs[service_id] >= incident.start_time
        ]
        if not recovery_times:
            return None
        return max(recovery_times)

    def _latest_signal_time_for_incident(self, incident: NexusIncident) -> datetime | None:
        timestamps = [
            self._to_naive_utc(evidence.timestamp) or evidence.timestamp
            for evidence in incident.evidence_timeline
            if evidence.timestamp
        ]
        if not timestamps:
            return None
        return max(timestamps)

    def _move_to_operator_verdict(self, incident: NexusIncident, end_time: datetime) -> NexusIncident:
        """Recovered incidents stay visible for closure, but no longer represent active operational risk."""
        return incident.model_copy(
            update={
                "status": "AWAITING_VERDICT",
                "end_time": end_time,
                "risk_level": "LOW",
                "risk_score": min(incident.risk_score, 0.2),
            }
        )

    def _build_components(self, candidate_services: set[str], grouped: dict[str, list[SignalEvent]]) -> list[set[str]]:
        if not candidate_services:
            return []
        adjacency: dict[str, set[str]] = {service_id: {service_id} for service_id in candidate_services}
        for left in candidate_services:
            for right in candidate_services:
                if left == right:
                    continue
                score = self._incident_affinity(grouped[left], grouped[right], left, right)
                if score >= 0.68:
                    adjacency[left].add(right)
                    adjacency[right].add(left)

        visited: set[str] = set()
        components: list[set[str]] = []
        for service_id in sorted(candidate_services):
            if service_id in visited:
                continue
            component: set[str] = set()
            queue = deque([service_id])
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)
                queue.extend(adjacency.get(current, set()) - visited)
            components.append(component)
        return components

    def _incident_affinity(
        self,
        left_signals: list[SignalEvent],
        right_signals: list[SignalEvent],
        left_service: str,
        right_service: str,
    ) -> float:
        latest_left = max(left_signals, key=lambda item: item.timestamp)
        latest_right = max(right_signals, key=lambda item: item.timestamp)
        delta_seconds = abs((latest_left.timestamp - latest_right.timestamp).total_seconds())
        time_score = max(0.0, 1 - (delta_seconds / self.INCIDENT_WINDOW.total_seconds()))
        context_signals = [*left_signals, *right_signals]
        flow_ids = self._flow_ids_for_context([left_service, right_service], context_signals)
        failure_domain = self._failure_domain_for_signals(context_signals)
        graph_score = self._graph_proximity(left_service, right_service, flow_ids=flow_ids, failure_domain=failure_domain)
        signature_score = self._signature_compatibility(left_signals, right_signals)
        business_score = (
            self._criticality_weight(self._service_map()[left_service].criticality)
            + self._criticality_weight(self._service_map()[right_service].criticality)
        ) / 2
        business_score = max(business_score, self._business_flow_criticality_score(flow_ids))
        return min(1.0, (0.35 * time_score) + (0.30 * graph_score) + (0.20 * signature_score) + (0.15 * business_score))

    def _rank_root_causes(
        self,
        affected_services: list[str],
        signals: list[SignalEvent],
        *,
        flow_ids: list[str] | None = None,
        failure_domain: str = "unknown",
    ) -> list[RootCauseCandidate]:
        if not affected_services:
            return []
        flow_ids = flow_ids or []
        services = self._service_map()
        earliest_by_service = {
            service_id: min(
                (signal.timestamp for signal in signals if signal.service_id == service_id),
                default=datetime.utcnow(),
            )
            for service_id in affected_services
        }
        earliest_start = min(earliest_by_service.values())
        scores: list[tuple[str, float, float, float, float]] = []
        for service_id in affected_services:
            service_signals = [signal for signal in signals if signal.service_id == service_id]
            evidence_diversity = min(
                1.0,
                len({signal.signal_type for signal in service_signals}) / 4
                + len({signal.signature.signature_family for signal in service_signals if signal.signature}) / 4,
            )
            upstream_explanation = self._upstream_explanation_score(
                service_id,
                affected_services,
                flow_ids=flow_ids,
                failure_domain=failure_domain,
            )
            delta = (earliest_by_service[service_id] - earliest_start).total_seconds()
            earliest_symptom = max(0.0, 1 - (delta / self.INCIDENT_WINDOW.total_seconds()))
            blast_radius_fit = len(
                [
                    item
                    for item in affected_services
                    if item == service_id or self._path_exists(item, service_id, flow_ids=flow_ids, failure_domain=failure_domain)
                ]
            ) / max(len(affected_services), 1)
            change_proximity = self._change_proximity_score(service_id, earliest_start)
            historical_similarity = self._historical_similarity_score(service_id)
            flow_fit = self._flow_fit_score(service_id, flow_ids, affected_services)
            vantage_consistency = self._vantage_consistency_score(service_id, service_signals, signals, failure_domain)
            database_fit = self._database_root_fit_score(
                service_id,
                affected_services,
                signals,
                flow_ids=flow_ids,
                failure_domain=failure_domain,
            )
            base_score = min(
                1.0,
                (0.25 * upstream_explanation)
                + (0.20 * earliest_symptom)
                + (0.20 * evidence_diversity)
                + (0.15 * blast_radius_fit)
                + (0.10 * change_proximity)
                + (0.10 * historical_similarity),
            )
            score = min(
                1.0,
                (base_score * (0.72 + (0.23 * vantage_consistency)))
                + (0.07 * flow_fit)
                + (0.12 * database_fit),
            )
            scores.append(
                (
                    service_id,
                    score,
                    evidence_diversity,
                    upstream_explanation,
                    change_proximity,
                    flow_fit,
                    vantage_consistency,
                    database_fit,
                )
            )

        total = sum(item[1] for item in scores) or 1.0
        ranked = sorted(scores, key=lambda item: item[1], reverse=True)
        return [
            RootCauseCandidate(
                service_id=service_id,
                service_name=services[service_id].service_name,
                score=round(score, 4),
                confidence=round(score / total, 4),
                explanation=self._root_cause_explanation(
                    service_id,
                    evidence_diversity,
                    upstream_explanation,
                    change_proximity,
                    flow_fit,
                    vantage_consistency,
                    database_fit,
                    failure_domain,
                ),
                evidence_diversity=round(evidence_diversity, 4),
                upstream_explanation=round(upstream_explanation, 4),
                change_proximity=round(change_proximity, 4),
                flow_fit=round(flow_fit, 4),
                vantage_consistency=round(vantage_consistency, 4),
                database_fit=round(database_fit, 4),
                failure_domain=failure_domain,
            )
            for service_id, score, evidence_diversity, upstream_explanation, change_proximity, flow_fit, vantage_consistency, database_fit in ranked
        ]

    def _compute_risk_score(
        self,
        affected_services: list[str],
        signals: list[SignalEvent],
        primary_candidate: RootCauseCandidate | None,
        *,
        flow_ids: list[str] | None = None,
    ) -> float:
        if not signals:
            return 0.0
        symptom_severity = sum(self._severity_value(signal.severity) for signal in signals) / len(signals)
        blast_radius = (
            min(1.0, len(self._blast_radius_for(primary_candidate.service_id, flow_ids=flow_ids or [])) / max(len(self.state.services), 1))
            if primary_candidate
            else 0.2
        )
        business_criticality = self._business_impact_score(affected_services)
        if flow_ids:
            business_criticality = max(business_criticality, self._business_flow_criticality_score(flow_ids))
        persistence_seconds = (max(signal.timestamp for signal in signals) - min(signal.timestamp for signal in signals)).total_seconds()
        persistence = min(1.0, persistence_seconds / 3600)
        change_proximity = (
            self._change_proximity_score(primary_candidate.service_id, min(signal.timestamp for signal in signals))
            if primary_candidate
            else 0.1
        )
        return round(
            min(
                1.0,
                (0.30 * symptom_severity)
                + (0.25 * blast_radius)
                + (0.20 * business_criticality)
                + (0.15 * persistence)
                + (0.10 * change_proximity),
            ),
            4,
        )

    def _build_recommendations(
        self,
        affected_services: list[str],
        primary_candidate: RootCauseCandidate | None,
        risk_level: str,
    ) -> list[ActionRecommendation]:
        services = self._service_map()
        target_service_id = primary_candidate.service_id if primary_candidate else affected_services[0]
        target_service = services[target_service_id]
        diagnostics_blockers: list[str] = []
        restart_blocked_reasons: list[str] = []

        if not target_service.allow_diagnostics:
            diagnostics_blockers.append("Diagnostics are disabled for this service.")
        if target_service.certification.lifecycle_stage not in {"diagnostics_ready", "restart_ready"}:
            diagnostics_blockers.append("Service is not yet certified for diagnostics collection.")
        if not (target_service.endpoint_config.diagnostics_url or self._cluster_diagnostics_url(target_service_id)):
            diagnostics_blockers.append("No diagnostics dispatch URL is configured yet.")

        restart_blocked_types = {"db", "database", "cache", "queue", "auth", "infra"}
        restart_capable_types = {"app", "worker", "gateway", "channel", "channel_adapter", "integration"}
        service_type = target_service.service_type.lower()
        policy_allowed_types = {item.lower() for item in target_service.restart_policy.allowed_service_types} or restart_capable_types
        if service_type in restart_blocked_types:
            restart_blocked_reasons.append(f"Safe restart is blocked for {service_type} services.")
        if service_type not in restart_capable_types:
            restart_blocked_reasons.append("Service type is not restart-capable under the Nexus v1 guarded restart policy.")
        if service_type not in policy_allowed_types:
            restart_blocked_reasons.append("Restart policy does not include this service type in allowed_service_types.")
        if target_service.database_profile.shared_dependency:
            restart_blocked_reasons.append("Safe restart is blocked for shared database/dependency services.")
        if not target_service.restart_policy.allow_restart:
            restart_blocked_reasons.append("Restart policy does not allow safe restart for this service.")
        if not target_service.is_stateless:
            restart_blocked_reasons.append("Safe restart requires a stateless service.")
        if target_service.certification.lifecycle_stage != "restart_ready":
            restart_blocked_reasons.append("Service is not certified at restart_ready stage.")
        if self._has_active_maintenance(target_service_id):
            restart_blocked_reasons.append("An active maintenance window is recorded for this service.")
        if self._recent_restart_exists(target_service_id):
            restart_blocked_reasons.append("A restart was already executed inside the cooldown window.")
        if primary_candidate and primary_candidate.confidence < 0.75:
            restart_blocked_reasons.append("Safe restart requires root-cause confidence of at least 0.75.")
        if not (target_service.endpoint_config.restart_url or self._cluster_restart_url(target_service_id)):
            restart_blocked_reasons.append("No restart execution URL is configured for this service.")

        return [
            ActionRecommendation(
                recommendation_id=f"rec-diag-{target_service_id}",
                action_type="request_diagnostics",
                target_service_id=target_service_id,
                target_service_name=target_service.service_name,
                confidence=primary_candidate.confidence if primary_candidate else 0.6,
                risk=risk_level,
                justification=f"Capture pre-check evidence for {target_service.service_name} before taking manual action.",
                requires_human_approval=False,
                eligible=not diagnostics_blockers,
                blocked_reasons=diagnostics_blockers,
            ),
            ActionRecommendation(
                recommendation_id=f"rec-task-{target_service_id}",
                action_type="create_response_task",
                target_service_id=target_service_id,
                target_service_name=target_service.service_name,
                confidence=primary_candidate.confidence if primary_candidate else 0.6,
                risk=risk_level,
                justification=f"Open a Task Center response thread covering {', '.join(affected_services)}.",
                requires_human_approval=False,
                eligible=True,
                blocked_reasons=[],
            ),
            ActionRecommendation(
                recommendation_id=f"rec-restart-{target_service_id}",
                action_type="safe_restart",
                target_service_id=target_service_id,
                target_service_name=target_service.service_name,
                confidence=primary_candidate.confidence if primary_candidate else 0.0,
                risk=risk_level,
                justification=f"Human-approved safe restart can be used for {target_service.service_name} if policy, certification, endpoint, cooldown, and confidence thresholds are satisfied.",
                requires_human_approval=True,
                eligible=not restart_blocked_reasons,
                blocked_reasons=restart_blocked_reasons,
            ),
        ]

    def _refresh_restart_monitoring(self, service_id: str, observed_at: datetime) -> None:
        observed_at = self._to_naive_utc(observed_at) or observed_at
        relevant_actions = [
            action
            for action in self.state.action_executions
            if action.service_id == service_id and action.action_type == "safe_restart" and action.status == "MONITORING"
        ]
        latest_severity = self._latest_severity_for_service(service_id)
        for action in relevant_actions:
            self._normalize_action_datetime(action)
            if action.monitoring_until and observed_at >= action.monitoring_until:
                if latest_severity in {"INFO", "WARN"}:
                    action.status = "EFFECTIVE"
                    action.result_summary = "Post-restart evidence shows the service stabilizing."
                else:
                    action.status = "INEFFECTIVE"
                    action.result_summary = "Post-restart evidence still indicates critical service degradation."
                action.completed_at = observed_at

    def _aggregate_log_signatures(self, signals: Iterable[SignalEvent]) -> list[LogSignature]:
        grouped: dict[tuple[str, str], LogSignature] = {}
        for signal in signals:
            if not signal.signature:
                continue
            key = (signal.service_id, signal.signature.signature_family)
            if key not in grouped:
                grouped[key] = signal.signature.model_copy(deep=True)
                continue
            current = grouped[key]
            current.count += signal.signature.count
            current.last_seen_at = max(current.last_seen_at, signal.signature.last_seen_at)
            current.first_seen_at = min(current.first_seen_at, signal.signature.first_seen_at)
            current.samples = list(dict.fromkeys([*current.samples, *signal.signature.samples]))[:3]
        return sorted(grouped.values(), key=lambda item: (item.count, item.last_seen_at), reverse=True)

    def _diagnostic_commands_for_service(self, service_id: str) -> list[DiagnosticCommand]:
        service = self._service_map()[service_id]
        runtime_scope = ["app", "worker", "gateway", "channel", "channel_adapter", "integration", "auth"]
        host_scope = [*runtime_scope, "db", "database", "cache", "queue", "infra"]
        commands = [
            DiagnosticCommand(
                command_id="systemd_status",
                label="systemctl status",
                service_type_scope=runtime_scope,
                execution_hint="systemctl status <service> --no-pager",
            ),
            DiagnosticCommand(
                command_id="recent_journal",
                label="Recent journal",
                service_type_scope=runtime_scope,
                execution_hint="journalctl -u <service> -n 200 --no-pager",
            ),
            DiagnosticCommand(
                command_id="health_check",
                label="Health check",
                service_type_scope=runtime_scope,
                execution_hint="curl -fsS http://127.0.0.1:<port>/health",
            ),
            DiagnosticCommand(
                command_id="memory_summary",
                label="Memory summary",
                service_type_scope=host_scope,
                execution_hint="free -m",
            ),
            DiagnosticCommand(
                command_id="disk_summary",
                label="Disk summary",
                service_type_scope=host_scope,
                execution_hint="df -h",
            ),
            DiagnosticCommand(
                command_id="socket_summary",
                label="Socket summary",
                service_type_scope=host_scope,
                execution_hint="ss -lntp",
            ),
        ]
        service_type = service.service_type.lower()
        return [command for command in commands if service_type in command.service_type_scope]

    def _signature_from_log_record(
        self,
        service: CatalogService,
        log_record: AgentLogRecord,
        timestamp: datetime,
    ) -> LogSignature:
        if (
            log_record.signature_family
            or log_record.error_class
            or log_record.exception_name
            or log_record.timeout_type
            or log_record.oom_flag
            or log_record.db_error_code
        ):
            signature_family = log_record.signature_family or "generic_error"
            error_class = log_record.error_class or "generic"
            digest = hashlib.sha1(
                f"{service.service_id}|{signature_family}|{log_record.message}".encode("utf-8")
            ).hexdigest()[:12]
            return LogSignature(
                signature_id=f"sig-{service.service_id}-{digest}",
                service_id=service.service_id,
                signature_family=signature_family,
                error_class=error_class,
                exception_name=log_record.exception_name,
                timeout_type=log_record.timeout_type,
                oom_flag=log_record.oom_flag,
                db_error_code=log_record.db_error_code,
                first_seen_at=timestamp,
                last_seen_at=timestamp,
                count=1,
                samples=[log_record.message],
            )
        return self._extract_log_signature(service, log_record.message, timestamp)

    def _trace_summary_from_legacy_payload(self, payload: dict[str, object]) -> AgentTraceSummary:
        reserved_keys = {"summary", "path", "failed_trace_share", "span_count", "timestamp"}
        return AgentTraceSummary(
            timestamp=payload.get("timestamp"),
            summary=str(payload.get("summary") or "Trace anomaly reported."),
            path=[str(item) for item in payload.get("path", [])] if isinstance(payload.get("path"), list) else [],
            failed_trace_share=payload.get("failed_trace_share"),
            span_count=payload.get("span_count"),
            attributes={key: value for key, value in payload.items() if key not in reserved_keys},
        )

    def _trace_attributes(
        self,
        trace: AgentTraceSummary,
        report: AgentProbeReport,
        instance_id: str,
        cluster: str | None,
        change_context: list[dict[str, object]],
    ) -> dict[str, object]:
        return {
            "path": trace.path,
            "failed_trace_share": trace.failed_trace_share,
            "span_count": trace.span_count,
            "host_id": report.host_id,
            "instance_id": instance_id,
            "cluster": cluster,
            "service_version": report.service_version,
            "metadata": report.metadata,
            "change_context": change_context,
            **trace.attributes,
        }

    def _database_signal_attributes(self, service: CatalogService, report: AgentProbeReport) -> dict[str, object]:
        snapshot = report.database
        return {
            "database_profile": service.database_profile.model_dump(mode="json")
            if service.database_profile.enabled
            else None,
            "database": snapshot.model_dump(mode="json") if snapshot else None,
            "database_name": snapshot.database_name if snapshot else service.database_profile.database_name,
            "database_platform": snapshot.platform if snapshot else service.database_profile.platform,
            "database_role": snapshot.role if snapshot else service.database_profile.role,
            "db_error_codes": snapshot.error_codes if snapshot else [],
        }

    def _database_snapshot_indicates_pressure(self, snapshot) -> bool:
        status = (snapshot.status or "").lower()
        connectivity = (snapshot.connectivity or "").lower()
        if status in {"down", "degraded", "critical", "unhealthy", "failed"}:
            return True
        if connectivity in {"failed", "timeout", "refused", "unreachable", "degraded"}:
            return True
        if snapshot.error_codes:
            return True
        if snapshot.connection_pool_used is not None and snapshot.connection_pool_max:
            if snapshot.connection_pool_used / max(snapshot.connection_pool_max, 1) >= 0.85:
                return True
        if snapshot.active_sessions is not None and snapshot.max_sessions:
            if snapshot.active_sessions / max(snapshot.max_sessions, 1) >= 0.85:
                return True
        if (snapshot.lock_wait_count or 0) > 0 or (snapshot.deadlock_count or 0) > 0 or (snapshot.blocking_sessions or 0) > 0:
            return True
        if snapshot.replication_lag_seconds is not None and snapshot.replication_lag_seconds >= 60:
            return True
        if snapshot.tablespace_used_percent is not None and snapshot.tablespace_used_percent >= 85:
            return True
        if (snapshot.slow_query_count or 0) > 0:
            return True
        return False

    def _database_snapshot_message(self, service: CatalogService, report: AgentProbeReport) -> str:
        snapshot = report.database
        if not snapshot:
            return f"Database evidence reported for {service.service_name}."
        database_name = snapshot.database_name or snapshot.service_name or service.database_profile.database_name or service.service_name
        facts = []
        if snapshot.status:
            facts.append(f"status={snapshot.status}")
        if snapshot.connectivity:
            facts.append(f"connectivity={snapshot.connectivity}")
        if snapshot.error_codes:
            facts.append(f"errors={', '.join(snapshot.error_codes[:4])}")
        if snapshot.connection_pool_used is not None and snapshot.connection_pool_max:
            facts.append(f"pool={snapshot.connection_pool_used}/{snapshot.connection_pool_max}")
        if snapshot.active_sessions is not None and snapshot.max_sessions:
            facts.append(f"sessions={snapshot.active_sessions}/{snapshot.max_sessions}")
        if snapshot.lock_wait_count:
            facts.append(f"lock_waits={snapshot.lock_wait_count}")
        suffix = "; ".join(facts) if facts else "database pressure detected"
        return f"Database evidence for {database_name} affecting {service.service_name}: {suffix}."

    def _line_contains_database_error(self, lowered: str) -> bool:
        database_tokens = (
            "postgres",
            "postgresql",
            "sqlstate",
            "ora-",
            "tns-",
            "oracle",
            "jdbc",
            "datasource",
            "data source",
            "connection pool",
            "connection leak",
            "apparent connection leak",
            "proxyleaktask",
            "hikari",
            "hikaripool",
            "hikaridatasource",
            "pgconnection",
            "ucp",
            "database",
            "deadlock",
            "lock wait",
            "tablespace",
            "too many clients",
            "could not serialize access",
        )
        return any(token in lowered for token in database_tokens)

    def _database_signature_from_line(self, lowered: str, raw_line: str) -> tuple[str, str, str | None]:
        db_error_code = None
        oracle_match = re.search(r"\b(ORA-\d{5}|TNS-\d{5})\b", raw_line, flags=re.IGNORECASE)
        sqlstate_match = re.search(r"\bSQLSTATE\s*[:=]?\s*([A-Z0-9]{5})\b", raw_line, flags=re.IGNORECASE)
        if oracle_match:
            db_error_code = oracle_match.group(1).upper()
        elif sqlstate_match:
            db_error_code = sqlstate_match.group(1).upper()
        elif "57p01" in lowered:
            db_error_code = "57P01"

        if any(
            token in lowered
            for token in (
                "connection leak detection triggered",
                "apparent connection leak detected",
                "proxyleaktask",
            )
        ):
            return "database_connection_leak", "db_connection_leak", db_error_code or "HIKARI_CONNECTION_LEAK"
        if any(token in lowered for token in ("deadlock", "lock wait", "blocking session", "ora-00060")):
            return "database_locking", "db_lock_contention", db_error_code
        if any(token in lowered for token in ("too many clients", "maximum connections", "pool exhausted", "connection pool", "hikaripool")):
            return "database_capacity", "db_connection_pressure", db_error_code
        if any(token in lowered for token in ("listener", "tns-", "connection refused", "could not connect", "jdbc")):
            return "database_connectivity", "db_connectivity", db_error_code
        if any(token in lowered for token in ("tablespace", "disk full", "no space left")):
            return "database_storage", "db_storage_pressure", db_error_code
        return "database_error", "db_failure", db_error_code

    def _extract_log_signature(self, service: CatalogService, raw_line: str, timestamp: datetime) -> LogSignature:
        lowered = raw_line.lower()
        signature_family = "generic_error"
        error_class = "generic"
        exception_name = None
        timeout_type = None
        oom_flag = False
        db_error_code = None

        if "out of memory" in lowered or "oom" in lowered:
            signature_family = "memory_pressure"
            error_class = "oom_kill"
            exception_name = "OutOfMemory"
            oom_flag = True
        elif self._line_contains_database_error(lowered):
            signature_family, error_class, db_error_code = self._database_signature_from_line(lowered, raw_line)
            timeout_type = "database_dependency" if "timeout" in lowered else None
        elif "timeout" in lowered:
            signature_family = "dependency_timeout"
            error_class = "timeout"
            timeout_type = "generic_dependency"
        elif "connection refused" in lowered or "could not connect" in lowered:
            signature_family = "dependency_connectivity"
            error_class = "connection_refused"

        digest = hashlib.sha1(f"{service.service_id}|{signature_family}|{raw_line}".encode("utf-8")).hexdigest()[:12]
        return LogSignature(
            signature_id=f"sig-{service.service_id}-{digest}",
            service_id=service.service_id,
            signature_family=signature_family,
            error_class=error_class,
            exception_name=exception_name,
            timeout_type=timeout_type,
            oom_flag=oom_flag,
            db_error_code=db_error_code,
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            count=1,
            samples=[raw_line],
        )

    def _severity_value(self, severity: str) -> float:
        return {"INFO": 0.2, "WARN": 0.6, "CRITICAL": 1.0}.get(severity, 0.2)

    def _risk_level_for_score(self, score: float) -> str:
        if score >= 0.75:
            return "CRITICAL"
        if score >= 0.55:
            return "HIGH"
        if score >= 0.35:
            return "MEDIUM"
        return "LOW"

    def _risk_rank(self, risk_level: str) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(risk_level, 0)

    def _graph_proximity(
        self,
        left_service: str,
        right_service: str,
        *,
        flow_ids: list[str] | None = None,
        failure_domain: str | None = None,
    ) -> float:
        if left_service == right_service:
            return 1.0
        distance = self._shortest_path_distance(left_service, right_service, flow_ids=flow_ids or [], failure_domain=failure_domain)
        if distance == 1:
            return 0.85
        if distance == 2:
            return 0.55
        if distance == 3:
            return 0.3
        return 0.1

    def _signature_compatibility(self, left_signals: list[SignalEvent], right_signals: list[SignalEvent]) -> float:
        left_families = {signal.signature.signature_family for signal in left_signals if signal.signature}
        right_families = {signal.signature.signature_family for signal in right_signals if signal.signature}
        if left_families and right_families and left_families.intersection(right_families):
            return 1.0
        left_database = any(self._signal_has_database_evidence(signal) for signal in left_signals)
        right_database = any(self._signal_has_database_evidence(signal) for signal in right_signals)
        if left_database and right_database:
            return 0.95
        if left_database or right_database:
            other_signals = right_signals if left_database else left_signals
            if any(
                "timeout" in signal.message.lower()
                or "connection" in signal.message.lower()
                or (signal.signature and signal.signature.signature_family in {"dependency_timeout", "dependency_connectivity"})
                for signal in other_signals
            ):
                return 0.82
        left_timeout = any("timeout" in signal.message.lower() for signal in left_signals)
        right_timeout = any("timeout" in signal.message.lower() for signal in right_signals)
        return 0.65 if left_timeout and right_timeout else 0.2

    def _criticality_weight(self, criticality: str) -> float:
        return {"critical": 1.0, "high": 0.82, "medium": 0.64, "low": 0.4}.get(criticality.lower(), 0.4)

    def _business_impact_score(self, affected_services: list[str]) -> float:
        if not affected_services:
            return 0.0
        services = self._service_map()
        return round(
            sum(self._criticality_weight(services[service_id].criticality) for service_id in affected_services)
            / len(affected_services),
            4,
        )

    def _business_flow_criticality_score(self, flow_ids: list[str] | None) -> float:
        if not flow_ids:
            return 0.0
        flow_map = self._business_flow_map()
        weights = [self._criticality_weight(flow_map[flow_id].criticality) for flow_id in flow_ids if flow_id in flow_map]
        return max(weights) if weights else 0.0

    def _upstream_explanation_score(
        self,
        candidate_service_id: str,
        affected_services: list[str],
        *,
        flow_ids: list[str] | None = None,
        failure_domain: str | None = None,
    ) -> float:
        if len(affected_services) == 1:
            return 1.0
        explained = sum(
            1
            for service_id in affected_services
            if service_id == candidate_service_id
            or self._path_exists(service_id, candidate_service_id, flow_ids=flow_ids or [], failure_domain=failure_domain)
        )
        return min(1.0, explained / len(affected_services))

    def _blast_radius_for(
        self,
        service_id: str | None,
        *,
        flow_ids: list[str] | None = None,
        failure_domain: str | None = None,
    ) -> list[str]:
        if not service_id:
            return []
        dependents = [
            edge.from_service_id
            for edge in self.state.dependency_edges
            if edge.to_service_id == service_id and self._edge_applies(edge, flow_ids=flow_ids or [], failure_domain=failure_domain)
        ]
        return sorted(dict.fromkeys([service_id, *dependents]))

    def _path_exists(
        self,
        start_service: str,
        target_service: str,
        *,
        flow_ids: list[str] | None = None,
        failure_domain: str | None = None,
    ) -> bool:
        if start_service == target_service:
            return True
        visited: set[str] = set()
        queue = deque([start_service])
        adjacency = defaultdict(list)
        for edge in self.state.dependency_edges:
            if self._edge_applies(edge, flow_ids=flow_ids or [], failure_domain=failure_domain):
                adjacency[edge.from_service_id].append(edge.to_service_id)
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            for neighbor in adjacency.get(current, []):
                if neighbor == target_service:
                    return True
                queue.append(neighbor)
        return False

    def _shortest_path_distance(
        self,
        left_service: str,
        right_service: str,
        *,
        flow_ids: list[str] | None = None,
        failure_domain: str | None = None,
    ) -> int:
        adjacency = defaultdict(set)
        for edge in self.state.dependency_edges:
            if not self._edge_applies(edge, flow_ids=flow_ids or [], failure_domain=failure_domain):
                continue
            adjacency[edge.from_service_id].add(edge.to_service_id)
            adjacency[edge.to_service_id].add(edge.from_service_id)
        queue = deque([(left_service, 0)])
        visited = {left_service}
        while queue:
            current, distance = queue.popleft()
            if current == right_service:
                return distance
            for neighbor in adjacency.get(current, set()):
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                queue.append((neighbor, distance + 1))
        return 99

    def _edge_applies(
        self,
        edge: DependencyEdge,
        *,
        flow_ids: list[str] | None = None,
        failure_domain: str | None = None,
    ) -> bool:
        flow_ids = flow_ids or []
        edge_flow_ids = self._edge_flow_ids(edge)
        valid_failure_domains = set(edge.valid_failure_domains)
        metadata_domains = edge.metadata.get("valid_failure_domains")
        if isinstance(metadata_domains, list):
            valid_failure_domains.update(str(item) for item in metadata_domains)
        if failure_domain and valid_failure_domains and failure_domain not in valid_failure_domains:
            return False

        scope = edge.dependency_scope or str(edge.metadata.get("dependency_scope") or "")
        if not scope:
            scope = "flow_scoped" if edge_flow_ids else "global"
        if scope == "flow_scoped":
            return bool(edge_flow_ids and set(edge_flow_ids).intersection(flow_ids))
        if scope == "observed" and edge_flow_ids and flow_ids:
            return bool(set(edge_flow_ids).intersection(flow_ids))
        return True

    def _edge_flow_ids(self, edge: DependencyEdge) -> list[str]:
        flow_ids = list(edge.business_flow_ids)
        metadata_flow_ids = edge.metadata.get("flow_ids")
        if isinstance(metadata_flow_ids, list):
            flow_ids.extend(str(item) for item in metadata_flow_ids if str(item).strip())
        metadata_flow_id = edge.metadata.get("flow_id")
        if metadata_flow_id:
            flow_ids.append(str(metadata_flow_id))
        return sorted(dict.fromkeys(flow_ids))

    def _business_flow_map(self) -> dict[str, BusinessFlow]:
        return {flow.flow_id: flow for flow in self.state.business_flows if flow.enabled}

    def _flow_ids_for_context(self, service_ids: list[str], signals: list[SignalEvent]) -> list[str]:
        flow_map = self._business_flow_map()
        explicit = {
            flow_id
            for signal in signals
            for flow_id in [signal.business_flow_id or self._attribute_str(signal, "business_flow_id")]
            if flow_id and flow_id in flow_map
        }
        if explicit:
            return sorted(explicit)

        service_set = set(service_ids)
        matched: list[tuple[str, int, int]] = []
        for flow in flow_map.values():
            flow_services = {step.service_id for step in flow.steps}
            flow_services.update(flow.entry_service_ids)
            overlap = service_set.intersection(flow_services)
            if not overlap:
                continue
            required_overlap = {
                step.service_id
                for step in flow.steps
                if step.required and step.service_id in service_set
            }
            score = (len(required_overlap) * 2) + len(overlap)
            matched.append((flow.flow_id, score, len(flow_services)))
        if not matched:
            return []
        matched.sort(key=lambda item: (item[1], -item[2], item[0]), reverse=True)
        strongest_score = matched[0][1]
        return sorted(flow_id for flow_id, score, _ in matched if score == strongest_score or score >= 3)

    def _primary_business_flow(self, flow_ids: list[str]) -> BusinessFlow | None:
        flow_map = self._business_flow_map()
        flows = [flow_map[flow_id] for flow_id in flow_ids if flow_id in flow_map]
        if not flows:
            return None
        return sorted(flows, key=lambda item: (self._criticality_weight(item.criticality), item.flow_name), reverse=True)[0]

    def _failure_domain_for_signals(self, signals: list[SignalEvent]) -> str:
        if not signals:
            return "unknown"
        scores: dict[str, float] = defaultdict(float)
        for signal in signals:
            context = self._signal_context(signal)
            domain = signal.failure_domain_hint or context["failure_domain_hint"] or "unknown"
            scores[domain] += self._severity_value(signal.severity)
            if signal.source != "network_sentinel" and domain != "network_path":
                scores[domain] += 0.25
        if not scores:
            return "unknown"
        return max(scores.items(), key=lambda item: item[1])[0]

    def _flow_fit_score(self, service_id: str, flow_ids: list[str], affected_services: list[str]) -> float:
        if not flow_ids:
            return 0.35
        flow_map = self._business_flow_map()
        best = 0.0
        for flow_id in flow_ids:
            flow = flow_map.get(flow_id)
            if not flow:
                continue
            steps = [step for step in flow.steps if step.service_id == service_id]
            if not steps:
                best = max(best, 0.1)
                continue
            step = steps[0]
            role = step.service_role.lower()
            role_score = 0.7
            if any(token in role for token in ("core", "root", "system_of_record", "orchestrator", "database", "data_store", "ledger")):
                role_score = 1.0
            elif any(token in role for token in ("auth", "gateway", "entry")):
                role_score = 0.9
            elif any(token in role for token in ("adapter", "channel", "consumer")):
                role_score = 0.72
            required_bonus = 0.08 if step.required else 0.0
            flow_service_ids = {item.service_id for item in flow.steps}
            overlap_ratio = len(set(affected_services).intersection(flow_service_ids)) / max(len(flow_service_ids), 1)
            best = max(best, min(1.0, role_score + required_bonus + (0.15 * overlap_ratio)))
        return best

    def _vantage_consistency_score(
        self,
        service_id: str,
        service_signals: list[SignalEvent],
        all_signals: list[SignalEvent],
        failure_domain: str,
    ) -> float:
        if not service_signals:
            return 0.55
        vantages = {signal.vantage_point or self._signal_context(signal)["vantage_point"] for signal in service_signals}
        has_local_evidence = bool(vantages.intersection({"local_agent", "application_log", "distributed_trace", "database_probe"}))
        if failure_domain == "database":
            if "database_probe" in vantages:
                return 1.0
            return 0.88 if has_local_evidence else 0.42
        if failure_domain == "network_path":
            if has_local_evidence:
                return 0.75
            return 0.35
        if has_local_evidence:
            return 1.0
        if vantages == {"external_network"}:
            peer_local = any(
                signal.service_id != service_id
                and (signal.vantage_point or self._signal_context(signal)["vantage_point"])
                in {"local_agent", "application_log", "distributed_trace"}
                for signal in all_signals
            )
            return 0.45 if peer_local else 0.6
        return 0.7

    def _change_proximity_score(self, service_id: str, baseline_time: datetime) -> float:
        changes = [event for event in self.state.change_events if event.service_id == service_id]
        if not changes:
            return 0.15
        closest = min(changes, key=lambda item: abs((item.timestamp - baseline_time).total_seconds()))
        delta_minutes = abs((closest.timestamp - baseline_time).total_seconds()) / 60
        if delta_minutes <= 30:
            return 1.0
        if delta_minutes <= 60:
            return 0.7
        return 0.25

    def _historical_similarity_score(self, service_id: str) -> float:
        for feedback in self.state.operator_feedback:
            actual = feedback.details.get("actual_root_service_id")
            if actual == service_id:
                return 0.9
        return 0.4

    def _root_cause_explanation(
        self,
        service_id: str,
        evidence_diversity: float,
        upstream_explanation: float,
        change_proximity: float,
        flow_fit: float,
        vantage_consistency: float,
        database_fit: float,
        failure_domain: str,
    ) -> str:
        service = self._service_map()[service_id]
        database_clause = (
            f", database fit of {database_fit:.2f}"
            if database_fit >= 0.35 or failure_domain == "database"
            else ""
        )
        return (
            f"{service.service_name} ranks highly for the {failure_domain} failure domain because it fits the scoped dependency path, "
            f"shows evidence diversity of {evidence_diversity:.2f}, flow fit of {flow_fit:.2f}, "
            f"vantage consistency of {vantage_consistency:.2f}{database_clause}, and change proximity score {change_proximity:.2f}."
        )

    def _build_incident_title(
        self,
        affected_services: list[str],
        services: dict[str, CatalogService],
        primary_candidate: RootCauseCandidate | None,
        primary_flow: BusinessFlow | None = None,
    ) -> str:
        flow_prefix = f"{primary_flow.flow_name}: " if primary_flow else ""
        if primary_candidate:
            return f"{flow_prefix}{services[primary_candidate.service_id].service_name} degradation impacting {len(affected_services)} services"
        return f"{flow_prefix}Sentinel Nexus incident impacting {len(affected_services)} services"

    def _build_summary(
        self,
        affected_services: list[str],
        services: dict[str, CatalogService],
        primary_candidate: RootCauseCandidate | None,
        signatures: list[LogSignature],
        signals: list[SignalEvent],
        primary_flow: BusinessFlow | None = None,
        failure_domain: str = "unknown",
    ) -> str:
        signature_summary = signatures[0].signature_family.replace("_", " ") if signatures else "multi-signal degradation"
        primary_name = services[primary_candidate.service_id].service_name if primary_candidate else "unknown dependency"
        flow_clause = f" in the {primary_flow.flow_name} business flow" if primary_flow else ""
        return (
            f"{primary_name} is the most likely root cause for the current {failure_domain} incident{flow_clause}. "
            f"The incident spans {', '.join(services[service_id].service_name for service_id in affected_services)} "
            f"with {signature_summary} as the dominant evidence pattern across the last {len(signals)} signals."
        )

    def _latest_severity_for_service(self, service_id: str) -> str:
        service_signals = [signal for signal in self.state.signals if signal.service_id == service_id]
        if not service_signals:
            return "INFO"
        return max(service_signals, key=lambda item: item.timestamp).severity

    def _has_active_maintenance(self, service_id: str) -> bool:
        window_start = datetime.utcnow() - timedelta(hours=2)
        return any(
            event.service_id == service_id
            and event.change_type == "maintenance_window"
            and event.timestamp >= window_start
            for event in self.state.change_events
        )

    def _recent_restart_exists(self, service_id: str) -> bool:
        cutoff = datetime.utcnow() - timedelta(minutes=15)
        return any(
            action.service_id == service_id
            and action.action_type == "safe_restart"
            and action.requested_at >= cutoff
            and action.status in {"APPROVED", "MONITORING", "EFFECTIVE"}
            for action in self.state.action_executions
        )

    def _evidence_from_signal(self, signal: SignalEvent) -> NexusEvidence:
        provenance_url = None
        if signal.source == "network_sentinel":
            provenance_url = f"/network-sentinel?service={signal.service_id}&tab=evidence"
        return NexusEvidence(
            evidence_id=f"ev-{signal.signal_id}",
            signal_id=signal.signal_id,
            service_id=signal.service_id,
            service_name=signal.service_name,
            timestamp=signal.timestamp,
            evidence_class=signal.signal_type,
            severity=signal.severity,
            source=signal.source,
            summary=signal.message,
            raw_excerpt=signal.raw_excerpt,
            signature_family=signal.signature.signature_family if signal.signature else None,
            vantage_point=signal.vantage_point,
            observation_layer=signal.observation_layer,
            failure_domain_hint=signal.failure_domain_hint,
            business_flow_id=signal.business_flow_id,
            provenance_url=provenance_url,
        )

    def _incident_key_for_services(
        self,
        service_ids: list[str],
        *,
        flow_ids: list[str] | None = None,
        failure_domain: str | None = None,
        incident_scope: str | None = None,
    ) -> str:
        parts = ["incident-key", "services:" + "|".join(sorted(service_ids))]
        if flow_ids:
            parts.append("flows:" + "|".join(sorted(flow_ids)))
        if failure_domain:
            parts.append(f"domain:{failure_domain}")
        if incident_scope:
            parts.append(f"scope:{incident_scope}")
        return "::".join(parts)

    def _validate_managed_sop_payload(
        self,
        sop: ManagedSopUpsertRequest,
        *,
        requested_by: str,
    ) -> ManagedSopValidation:
        errors: list[str] = []
        warnings: list[str] = []
        class_code = sop.class_code.strip().upper()
        severity = sop.severity.strip().lower()
        content = {key: [str(line).strip() for line in value if str(line).strip()] for key, value in sop.content.items()}
        known_services = set(self._service_map())

        if not sop.sop_id.strip():
            errors.append("SOP ID is required.")
        if not sop.title.strip():
            errors.append("Title is required.")
        if class_code not in {"A", "B", "C", "D", "E", "F"}:
            errors.append("Class code must be one of A, B, C, D, E, or F.")
        if severity not in {"critical", "high", "medium", "low", "info"}:
            errors.append("Severity must be critical, high, medium, low, or info.")
        if not any(content.get(section) for section in ("checks", "actions", "verification_steps", "escalation")):
            errors.append("At least one operational section is required: checks, actions, verification steps, or escalation.")

        unknown_services = sorted({service_id for service_id in sop.services if service_id and service_id not in known_services})
        if unknown_services:
            warnings.append(f"These service IDs are not currently in the Nexus catalog: {', '.join(unknown_services)}.")
        if content.get("actions") and not content.get("preconditions"):
            warnings.append("Action-bearing SOPs should define preconditions before operators execute changes.")
        if content.get("actions") and not content.get("verification_steps"):
            warnings.append("Action-bearing SOPs should define recovery verification steps.")
        restart_actions = [line for line in content.get("actions", []) if "restart" in line.lower()]
        if restart_actions and not any("approval" in line.lower() or "authorize" in line.lower() for line in content.get("preconditions", [])):
            warnings.append("Restart SOPs should explicitly mention approval or authorization preconditions.")
        if sop.status == "approved" and warnings:
            warnings.append("Approved SOP has warnings; keep this intentional and reviewed.")

        return ManagedSopValidation(
            valid=not errors,
            errors=errors,
            warnings=warnings,
            checked_at=datetime.utcnow(),
            checked_by=requested_by,
        )

    def _require_incident(self, incident_id: str) -> NexusIncident:
        incident = self.get_incident(incident_id)
        if incident is None:
            raise KeyError(f"Unknown incident {incident_id}")
        return incident

    def _service_map(self) -> dict[str, CatalogService]:
        return {service.service_id: service for service in self.state.services}

    def _normalized_database_profile(self, profile: DatabaseProfile, *, service_type: str) -> DatabaseProfile:
        should_enable = profile.enabled or service_type.lower() in {"db", "database", "oracle", "postgres", "postgresql"}
        if not should_enable:
            return profile
        expected_evidence = profile.expected_evidence or [
            "connection_state",
            "active_sessions",
            "connection_pool_usage",
            "lock_waits",
            "slow_queries",
            "replication_lag",
            "tablespace_or_disk_pressure",
            "database_error_codes",
        ]
        safe_diagnostics = profile.safe_diagnostics or [
            "connectivity_check",
            "session_summary",
            "lock_summary",
            "tablespace_summary",
            "replication_summary",
            "recent_database_errors",
        ]
        return profile.model_copy(
            update={
                "enabled": True,
                "expected_evidence": expected_evidence,
                "safe_diagnostics": safe_diagnostics,
                "shared_dependency": profile.shared_dependency or service_type.lower() in {"db", "database", "oracle", "postgres", "postgresql"},
            }
        )

    def _normalized_database_access(self, request: DependencyEdgeUpsertRequest) -> DatabaseDependencyProfile:
        access = request.database_access
        if request.dependency_type != "db":
            return access
        expected_error_codes = access.expected_error_codes or ["SQLSTATE", "ORA-", "TNS-", "JDBC", "connection_pool_timeout"]
        operation_types = access.operation_types or ["connect", "read", "write"]
        return access.model_copy(
            update={
                "access_mode": access.access_mode or "read_write",
                "operation_types": operation_types,
                "expected_error_codes": expected_error_codes,
                "transactional": True if access.transactional is None else access.transactional,
            }
        )

    def _cluster_map(self) -> dict[str, DependencyCluster]:
        return {cluster.cluster_id: cluster for cluster in self.state.clusters}

    def _cluster_ids_for_service(self, service_id: str) -> list[str]:
        service = self._service_map().get(service_id)
        if not service:
            return []
        cluster_ids = set(service.cluster_ids)
        if service.cluster:
            cluster_ids.add(service.cluster)
        return sorted(cluster_ids)

    def _cluster_ids_for_services(self, service_ids: list[str]) -> list[str]:
        cluster_ids: set[str] = set()
        for service_id in service_ids:
            cluster_ids.update(self._cluster_ids_for_service(service_id))
        return sorted(cluster_ids)

    def _cluster_restart_url(self, service_id: str) -> str | None:
        cluster_map = self._cluster_map()
        for cluster_id in self._cluster_ids_for_service(service_id):
            cluster = cluster_map.get(cluster_id)
            if cluster and cluster.routing_config.restart_url:
                return cluster.routing_config.restart_url
        return None

    def _cluster_diagnostics_url(self, service_id: str) -> str | None:
        cluster_map = self._cluster_map()
        for cluster_id in self._cluster_ids_for_service(service_id):
            cluster = cluster_map.get(cluster_id)
            if cluster and cluster.routing_config.diagnostics_url:
                return cluster.routing_config.diagnostics_url
        return None

    def _agent_command_headers(self, service: CatalogService) -> dict[str, str]:
        headers: dict[str, str] = {}
        if service.observation_config.agent_id:
            headers["X-Nexus-Agent-Id"] = service.observation_config.agent_id
        if settings.NEXUS_AGENT_API_TOKEN:
            headers["X-Nexus-Agent-Token"] = settings.NEXUS_AGENT_API_TOKEN.get_secret_value()
        return headers

    def _network_event_is_change(self, event: dict[str, object]) -> bool:
        event_type = str(event.get("event_type") or "").lower()
        category = str(event.get("category") or "").lower()
        return category == "audit" or any(
            token in event_type for token in ("created", "updated", "enabled", "disabled", "restart", "maintenance", "deploy")
        )

    def _network_change_type(self, event: dict[str, object]) -> str:
        event_type = str(event.get("event_type") or "").lower()
        if "restart" in event_type:
            return "manual_restart"
        if "maintenance" in event_type:
            return "maintenance_window"
        if "deploy" in event_type:
            return "deployment"
        if "config" in event_type or "update" in event_type:
            return "config_change"
        return "operator_ack"

    def _change_event_from_agent_context(
        self,
        service_id: str,
        item: AgentChangeContext,
        fallback_timestamp: datetime,
    ) -> ChangeEvent:
        digest = hashlib.sha1(
            f"{service_id}|{item.change_type}|{item.source}|{item.summary}|{(item.timestamp or fallback_timestamp).isoformat()}".encode("utf-8")
        ).hexdigest()[:16]
        return ChangeEvent(
            change_id=f"agent-change-{digest}",
            service_id=service_id,
            change_type=item.change_type,
            timestamp=item.timestamp or fallback_timestamp,
            source=item.source,
            summary=item.summary,
            metadata=item.metadata,
        )

    def _report_has_database_evidence(self, report: AgentProbeReport) -> bool:
        if report.database is not None:
            return True
        probe_family = (report.probe_family or "").lower()
        if any(token in probe_family for token in ("database", "postgres", "postgresql", "oracle", "jdbc", "sql")):
            return True
        metadata = report.metadata or {}
        if any(str(metadata.get(key) or "").lower() for key in ("database_name", "database_platform", "db_error_code")):
            return True
        for raw_line in [*report.logs, *(record.message for record in report.log_records)]:
            if self._line_contains_database_error(raw_line.lower()):
                return True
        metric_keys = {str(key).lower() for key in report.metrics.keys()}
        return any(
            token in key
            for key in metric_keys
            for token in ("db_", "database", "sql", "jdbc", "connection_pool", "active_sessions", "lock_wait", "replication_lag", "tablespace")
        )

    def _signal_has_database_evidence(self, signal: SignalEvent) -> bool:
        if signal.failure_domain_hint == "database":
            return True
        if signal.signature and (signal.signature.signature_family.startswith("database") or signal.signature.db_error_code):
            return True
        if self._attribute_str(signal, "database_signal") == "True" or self._attribute_str(signal, "database_signal") == "true":
            return True
        database_snapshot = signal.attributes.get("database")
        if isinstance(database_snapshot, dict) and any(value not in (None, "", [], {}) for value in database_snapshot.values()):
            return True
        database_profile = signal.attributes.get("database_profile")
        if (
            isinstance(database_profile, dict)
            and database_profile.get("enabled")
            and (signal.observation_layer == "database" or self._attribute_str(signal, "observation_layer") == "database")
        ):
            return True
        if self._attribute_str(signal, "database_name") or self._attribute_str(signal, "database_platform"):
            return True
        service = self._service_map().get(signal.service_id)
        if service and service.service_type.lower() in {"db", "database"}:
            return True
        message = signal.message.lower()
        return any(
            token in message
            for token in (
                "sqlstate",
                "ora-",
                "tns-",
                "jdbc",
                "connection pool",
                "connection leak",
                "proxyleaktask",
                "hikari",
                "pgconnection",
                "database",
                "postgres",
                "oracle",
                "lock wait",
                "tablespace",
            )
        )

    def _database_root_fit_score(
        self,
        candidate_service_id: str,
        affected_services: list[str],
        signals: list[SignalEvent],
        *,
        flow_ids: list[str],
        failure_domain: str,
    ) -> float:
        services = self._service_map()
        candidate = services.get(candidate_service_id)
        if not candidate:
            return 0.0
        is_database_service = candidate.service_type.lower() in {"db", "database"} or candidate.database_profile.enabled
        database_evidence_present = failure_domain == "database" or any(self._signal_has_database_evidence(signal) for signal in signals)
        if not is_database_service and not database_evidence_present:
            return 0.0

        candidate_signals = [signal for signal in signals if signal.service_id == candidate_service_id]
        direct_database_evidence = any(self._signal_has_database_evidence(signal) for signal in candidate_signals)
        explained_dependents = [
            service_id
            for service_id in affected_services
            if service_id == candidate_service_id
            or self._path_exists(service_id, candidate_service_id, flow_ids=flow_ids, failure_domain="database")
            or self._path_exists(service_id, candidate_service_id, flow_ids=flow_ids, failure_domain=failure_domain)
        ]
        dependent_ratio = len(set(explained_dependents)) / max(len(affected_services), 1)
        profile_score = 0.18 if candidate.database_profile.enabled else 0.0
        shared_score = 0.1 if candidate.database_profile.shared_dependency else 0.0
        direct_score = 0.45 if direct_database_evidence else 0.0
        domain_score = 0.22 if failure_domain == "database" else 0.0
        return min(1.0, (0.45 * dependent_ratio) + direct_score + profile_score + shared_score + domain_score)

    def _agent_report_signal_context(self, report: AgentProbeReport) -> dict[str, str | None]:
        metadata = report.metadata or {}
        probe_family = (report.probe_family or metadata.get("probe_family") or "").lower()
        observation_layer = report.observation_layer or str(metadata.get("observation_layer") or "")
        if not observation_layer:
            if self._report_has_database_evidence(report):
                observation_layer = "database"
            elif "host" in probe_family or "system" in probe_family or "systemd" in probe_family:
                observation_layer = "host"
            elif "dependency" in probe_family or "downstream" in probe_family:
                observation_layer = "dependency_probe"
            elif "business" in probe_family or "transaction" in probe_family:
                observation_layer = "business_probe"
            else:
                observation_layer = "runtime"

        failure_domain_hint = report.failure_domain_hint or str(metadata.get("failure_domain_hint") or "")
        if not failure_domain_hint:
            if "auth" in probe_family:
                failure_domain_hint = "authentication"
            elif self._report_has_database_evidence(report):
                failure_domain_hint = "database"
            elif "dependency" in probe_family or "downstream" in probe_family:
                failure_domain_hint = "dependency"
            elif "host" in probe_family or "system" in probe_family or "systemd" in probe_family:
                failure_domain_hint = "host"
            elif "business" in probe_family or "transaction" in probe_family:
                failure_domain_hint = "business_process"
            else:
                failure_domain_hint = "service_runtime"

        business_flow_id = report.business_flow_id or metadata.get("business_flow_id") or metadata.get("flow_id")
        return {
            "vantage_point": report.vantage_point
            or str(metadata.get("vantage_point") or ("database_probe" if self._report_has_database_evidence(report) else "local_agent")),
            "observation_layer": observation_layer,
            "failure_domain_hint": failure_domain_hint,
            "business_flow_id": str(business_flow_id) if business_flow_id else None,
        }

    def _signal_context(self, signal: SignalEvent) -> dict[str, str | None]:
        if signal.source == "network_sentinel":
            return {
                "vantage_point": "external_network",
                "observation_layer": "network",
                "failure_domain_hint": "network_path",
                "business_flow_id": self._attribute_str(signal, "business_flow_id"),
            }
        if signal.source == "loki" or signal.signal_type == "log":
            return {
                "vantage_point": "application_log",
                "observation_layer": "logs",
                "failure_domain_hint": self._failure_domain_from_signature(signal.signature),
                "business_flow_id": self._attribute_str(signal, "business_flow_id"),
            }
        if signal.source == "otel" or signal.signal_type == "trace":
            return {
                "vantage_point": "distributed_trace",
                "observation_layer": "traces",
                "failure_domain_hint": "dependency",
                "business_flow_id": self._attribute_str(signal, "business_flow_id"),
            }
        if signal.signal_type == "change":
            return {
                "vantage_point": "operator",
                "observation_layer": "change",
                "failure_domain_hint": "operator_change",
                "business_flow_id": self._attribute_str(signal, "business_flow_id"),
            }
        if self._signal_has_database_evidence(signal):
            return {
                "vantage_point": self._attribute_str(signal, "vantage_point") or "database_probe",
                "observation_layer": self._attribute_str(signal, "observation_layer") or "database",
                "failure_domain_hint": "database",
                "business_flow_id": self._attribute_str(signal, "business_flow_id"),
            }
        return {
            "vantage_point": self._attribute_str(signal, "vantage_point") or "local_agent",
            "observation_layer": self._attribute_str(signal, "observation_layer") or "runtime",
            "failure_domain_hint": self._attribute_str(signal, "failure_domain_hint") or "service_runtime",
            "business_flow_id": self._attribute_str(signal, "business_flow_id"),
        }

    def _failure_domain_from_signature(self, signature: LogSignature | None) -> str:
        if not signature:
            return "service_runtime"
        if signature.signature_family.startswith("database") or signature.db_error_code:
            return "database"
        if signature.signature_family in {"dependency_timeout", "dependency_connectivity"}:
            return "dependency"
        if signature.signature_family in {"ussd_session_expiry_burst", "ussd_session_path_degradation"}:
            return "channel_tunnel"
        if signature.signature_family == "memory_pressure" or signature.oom_flag:
            return "host"
        if "auth" in (signature.timeout_type or "").lower() or "auth" in signature.error_class.lower():
            return "authentication"
        return "service_runtime"

    @staticmethod
    def _attribute_str(signal: SignalEvent, key: str) -> str | None:
        value = signal.attributes.get(key)
        return str(value) if value not in (None, "") else None

    def _edge_id(self, edge: DependencyEdge) -> str:
        cluster_id = edge.cluster_id or "global"
        return f"{cluster_id}:{edge.from_service_id}->{edge.to_service_id}:{edge.dependency_type}"

    def _edge_id_for_request(self, request: DependencyEdgeUpsertRequest) -> str:
        cluster_id = request.cluster_id or "global"
        return f"{cluster_id}:{request.from_service_id}->{request.to_service_id}:{request.dependency_type}"
