"""Pydantic models for Sentinel Nexus."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["INFO", "WARN", "CRITICAL"]
SignalType = Literal["metric", "log", "trace", "alert", "change", "synthetic", "operator"]
IncidentStatus = Literal["OPEN", "MONITORING", "RESOLVED"]
RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RecommendationType = Literal["request_diagnostics", "create_response_task", "safe_restart"]
RecommendationStatus = Literal["recommended", "requested", "approved", "rejected", "blocked", "completed"]
ActionExecutionStatus = Literal[
    "READY",
    "REQUESTED",
    "APPROVED",
    "REJECTED",
    "BLOCKED",
    "MONITORING",
    "EFFECTIVE",
    "INEFFECTIVE",
    "ROLLED_BACK_NOT_SUPPORTED",
]
DiagnosticStatus = Literal["READY", "IN_PROGRESS", "COMPLETED"]
FeedbackType = Literal["acknowledged", "verdict", "suppression", "root_cause_override"]
CertificationStage = Literal["catalog_only", "observe_only", "correlate_ready", "diagnostics_ready", "restart_ready"]
SyncHealth = Literal["idle", "success", "warning", "error"]


class BusinessFlowStep(BaseModel):
    step_id: str | None = None
    step_order: int
    service_id: str
    service_role: str
    required: bool = True
    expected_signal_sources: list[str] = Field(default_factory=list)
    failure_domains: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BusinessFlow(BaseModel):
    flow_id: str
    flow_name: str
    environment: str
    owner_team: str
    criticality: str = "high"
    description: str | None = None
    entry_service_ids: list[str] = Field(default_factory=list)
    steps: list[BusinessFlowStep] = Field(default_factory=list)
    success_indicators: list[str] = Field(default_factory=list)
    failure_indicators: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    correlation_window_minutes: int = 10
    metadata: dict[str, Any] = Field(default_factory=dict)


class RestartPolicy(BaseModel):
    allow_restart: bool = False
    requires_human_approval: bool = True
    cooldown_minutes: int = 15
    allowed_service_types: list[str] = Field(default_factory=lambda: ["app", "worker"])


class DatabaseProfile(BaseModel):
    enabled: bool = False
    platform: str | None = None
    database_name: str | None = None
    instance_name: str | None = None
    service_name: str | None = None
    role: str | None = None
    host_group: str | None = None
    port: int | None = None
    schemas: list[str] = Field(default_factory=list)
    connection_pool: str | None = None
    max_pool_size: int | None = None
    replication_group: str | None = None
    failover_group: str | None = None
    read_only: bool = False
    shared_dependency: bool = False
    data_classification: str | None = None
    expected_evidence: list[str] = Field(default_factory=list)
    safe_diagnostics: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DatabaseDependencyProfile(BaseModel):
    access_mode: str | None = None
    schema_names: list[str] = Field(default_factory=list)
    operation_types: list[str] = Field(default_factory=list)
    connection_pool: str | None = None
    max_connections: int | None = None
    statement_timeout_ms: int | None = None
    expected_error_codes: list[str] = Field(default_factory=list)
    query_fingerprint_scope: str | None = None
    transactional: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ServiceEndpointConfig(BaseModel):
    collector_url: str | None = None
    healthcheck_url: str | None = None
    metrics_url: str | None = None
    logs_url: str | None = None
    traces_url: str | None = None
    diagnostics_url: str | None = None
    restart_url: str | None = None
    extraction_url: str | None = None
    formatting_url: str | None = None
    shipping_url: str | None = None
    dashboard_url: str | None = None


class ServiceObservationConfig(BaseModel):
    network_service_id: str | None = None
    agent_id: str | None = None
    systemd_unit: str | None = None
    host_group: str | None = None
    log_selector: str | None = None
    metrics_namespace: str | None = None
    trace_service_name: str | None = None
    preferred_signal_source: str | None = None
    analysis_profile: str | None = None
    analysis_config: dict[str, Any] = Field(default_factory=dict)


class ServiceCertification(BaseModel):
    lifecycle_stage: CertificationStage = "catalog_only"
    certified_by: str | None = None
    certified_at: datetime | None = None
    notes: str | None = None


class ClusterRoutingConfig(BaseModel):
    topology_doc_url: str | None = None
    dashboard_url: str | None = None
    collector_url: str | None = None
    extraction_url: str | None = None
    formatting_url: str | None = None
    shipping_url: str | None = None
    diagnostics_url: str | None = None
    restart_url: str | None = None
    query_url: str | None = None
    notes_url: str | None = None


class CatalogService(BaseModel):
    service_uuid: str | None = None
    service_id: str
    service_name: str
    service_type: str
    environment: str
    owner_team: str
    criticality: str
    description: str | None = None
    is_stateless: bool = False
    allow_diagnostics: bool = True
    runbook_slug: str | None = None
    tags: list[str] = Field(default_factory=list)
    cluster: str | None = None
    cluster_ids: list[str] = Field(default_factory=list)
    restart_policy: RestartPolicy = Field(default_factory=RestartPolicy)
    database_profile: DatabaseProfile = Field(default_factory=DatabaseProfile)
    endpoint_config: ServiceEndpointConfig = Field(default_factory=ServiceEndpointConfig)
    observation_config: ServiceObservationConfig = Field(default_factory=ServiceObservationConfig)
    certification: ServiceCertification = Field(default_factory=ServiceCertification)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DependencyCluster(BaseModel):
    cluster_id: str
    cluster_name: str
    environment: str
    owner_team: str
    criticality: str = "high"
    description: str | None = None
    service_ids: list[str] = Field(default_factory=list)
    entry_services: list[str] = Field(default_factory=list)
    routing_config: ClusterRoutingConfig = Field(default_factory=ClusterRoutingConfig)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DependencyEdge(BaseModel):
    edge_id: str | None = None
    cluster_id: str | None = None
    from_service_id: str
    to_service_id: str
    dependency_type: str
    dependency_purpose: str | None = None
    dependency_scope: str = "global"
    business_flow_ids: list[str] = Field(default_factory=list)
    valid_failure_domains: list[str] = Field(default_factory=list)
    expected_evidence: list[str] = Field(default_factory=list)
    criticality_weight: float = 0.6
    timeout_budget_ms: int | None = None
    is_hard_dependency: bool = True
    database_access: DatabaseDependencyProfile = Field(default_factory=DatabaseDependencyProfile)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LogSignature(BaseModel):
    signature_id: str
    service_id: str
    signature_family: str
    error_class: str
    exception_name: str | None = None
    timeout_type: str | None = None
    oom_flag: bool = False
    db_error_code: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    count: int = 1
    samples: list[str] = Field(default_factory=list)


class SignalEvent(BaseModel):
    signal_id: str
    signal_type: SignalType
    service_id: str
    service_name: str
    instance_id: str | None = None
    severity: Severity
    timestamp: datetime
    source: str
    environment: str
    cluster: str | None = None
    vantage_point: str | None = None
    observation_layer: str | None = None
    failure_domain_hint: str | None = None
    business_flow_id: str | None = None
    message: str
    fingerprint: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_excerpt: str | None = None
    signature: LogSignature | None = None


class ChangeEvent(BaseModel):
    change_id: str
    service_id: str
    change_type: str
    timestamp: datetime
    source: str
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class NexusEvidence(BaseModel):
    evidence_id: str
    signal_id: str
    service_id: str
    service_name: str
    timestamp: datetime
    evidence_class: str
    severity: Severity
    source: str
    summary: str
    raw_excerpt: str | None = None
    signature_family: str | None = None
    vantage_point: str | None = None
    observation_layer: str | None = None
    failure_domain_hint: str | None = None
    business_flow_id: str | None = None
    provenance_url: str | None = None


class RootCauseCandidate(BaseModel):
    service_id: str
    service_name: str
    score: float
    confidence: float
    explanation: str
    evidence_diversity: float
    upstream_explanation: float
    change_proximity: float
    flow_fit: float = 0.0
    vantage_consistency: float = 0.0
    database_fit: float = 0.0
    failure_domain: str | None = None


class ActionRecommendation(BaseModel):
    recommendation_id: str
    action_type: RecommendationType
    target_service_id: str
    target_service_name: str
    confidence: float
    risk: RiskLevel
    justification: str
    requires_human_approval: bool
    eligible: bool = True
    blocked_reasons: list[str] = Field(default_factory=list)
    status: RecommendationStatus = "recommended"


class TaskHandoff(BaseModel):
    task_id: str
    incident_id: str
    title: str
    description: str
    created_at: datetime
    created_by: str
    route_hint: str
    status: str = "created"
    tags: list[str] = Field(default_factory=list)
    external_task_id: str | None = None
    assigned_to: str | None = None
    task_status: str | None = None


class DiagnosticCommand(BaseModel):
    command_id: str
    label: str
    service_type_scope: list[str]
    requires_root: bool = False
    execution_hint: str


class DiagnosticBundle(BaseModel):
    bundle_id: str
    incident_id: str
    service_id: str
    requested_at: datetime
    requested_by: str
    status: DiagnosticStatus = "READY"
    commands: list[DiagnosticCommand] = Field(default_factory=list)
    evidence_snapshot: list[NexusEvidence] = Field(default_factory=list)
    notes: str | None = None
    diagnostics_url: str | None = None
    dispatch_status: str | None = None


class ActionExecution(BaseModel):
    action_execution_id: str
    incident_id: str
    service_id: str
    action_type: str
    requested_at: datetime
    requested_by: str
    approved_by: str | None = None
    status: ActionExecutionStatus
    justification: str
    precheck_evidence: list[NexusEvidence] = Field(default_factory=list)
    blocked_reasons: list[str] = Field(default_factory=list)
    result_summary: str | None = None
    monitoring_until: datetime | None = None
    completed_at: datetime | None = None
    executor_url: str | None = None
    remote_execution_id: str | None = None


class OperatorFeedback(BaseModel):
    feedback_id: str
    incident_id: str
    feedback_type: FeedbackType
    created_at: datetime
    created_by: str
    details: dict[str, Any] = Field(default_factory=dict)


class NexusIncident(BaseModel):
    incident_id: str
    incident_key: str
    title: str
    status: IncidentStatus
    start_time: datetime
    end_time: datetime | None = None
    summary: str
    risk_level: RiskLevel
    risk_score: float
    business_impact_score: float
    affected_services: list[str]
    suspected_root_service: str | None = None
    suspected_root_service_name: str | None = None
    predicted_confidence: float
    blast_radius: list[str] = Field(default_factory=list)
    cluster_ids: list[str] = Field(default_factory=list)
    business_flow_ids: list[str] = Field(default_factory=list)
    primary_business_flow_id: str | None = None
    primary_business_flow_name: str | None = None
    failure_domain: str = "unknown"
    vantage_points: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    correlation_version: str = "nexus-v2"
    root_cause_candidates: list[RootCauseCandidate] = Field(default_factory=list)
    recommendations: list[ActionRecommendation] = Field(default_factory=list)
    evidence_timeline: list[NexusEvidence] = Field(default_factory=list)
    log_signatures: list[LogSignature] = Field(default_factory=list)
    linked_tasks: list[TaskHandoff] = Field(default_factory=list)
    diagnostics: list[DiagnosticBundle] = Field(default_factory=list)
    action_executions: list[ActionExecution] = Field(default_factory=list)
    verdict: OperatorFeedback | None = None


class GraphNode(BaseModel):
    service_id: str
    service_name: str
    service_type: str
    criticality: str
    environment: str
    affected: bool = False
    suspected_root: bool = False


class GraphEdge(BaseModel):
    edge_id: str | None = None
    cluster_id: str | None = None
    from_service_id: str
    to_service_id: str
    dependency_type: str
    highlighted: bool = False


class ServiceGraphContext(BaseModel):
    focus_service_id: str
    focus_service_name: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    dependents: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    cluster_ids: list[str] = Field(default_factory=list)


class FabricSummary(BaseModel):
    total_services: int = 0
    total_clusters: int = 0
    total_edges: int = 0
    mapped_network_services: int = 0
    diagnostics_ready_services: int = 0
    restart_ready_services: int = 0
    active_incidents: int = 0
    last_sync_at: datetime | None = None
    sync_health: SyncHealth = "idle"
    sync_message: str | None = None


class AgentLogRecord(BaseModel):
    timestamp: datetime | None = None
    severity: Severity | None = None
    message: str
    signature_family: str | None = None
    error_class: str | None = None
    exception_name: str | None = None
    timeout_type: str | None = None
    oom_flag: bool = False
    db_error_code: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class AgentTraceSummary(BaseModel):
    timestamp: datetime | None = None
    summary: str
    path: list[str] = Field(default_factory=list)
    failed_trace_share: float | None = None
    span_count: int | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class AgentChangeContext(BaseModel):
    change_type: str
    source: str
    summary: str
    timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentDatabaseSnapshot(BaseModel):
    platform: str | None = None
    database_name: str | None = None
    instance_name: str | None = None
    service_name: str | None = None
    role: str | None = None
    status: str | None = None
    connectivity: str | None = None
    active_sessions: int | None = None
    max_sessions: int | None = None
    connection_pool_used: int | None = None
    connection_pool_max: int | None = None
    lock_wait_count: int | None = None
    deadlock_count: int | None = None
    blocking_sessions: int | None = None
    replication_lag_seconds: float | None = None
    tablespace_used_percent: float | None = None
    slow_query_count: int | None = None
    error_codes: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)


class AgentHeartbeat(BaseModel):
    agent_id: str
    service_id: str
    environment: str
    timestamp: datetime
    platform: str
    version: str | None = None
    instance_id: str | None = None
    host_id: str | None = None
    cluster: str | None = None
    zone: str | None = None
    service_version: str | None = None
    capabilities: list[str] = Field(default_factory=list)


class AgentProbeReport(BaseModel):
    agent_id: str
    service_id: str
    service_name: str
    environment: str
    timestamp: datetime
    source: str = "agent"
    severity: Severity
    instance_id: str | None = None
    host_id: str | None = None
    cluster: str | None = None
    zone: str | None = None
    service_version: str | None = None
    probe_family: str | None = None
    vantage_point: str | None = None
    observation_layer: str | None = None
    failure_domain_hint: str | None = None
    business_flow_id: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    database: AgentDatabaseSnapshot | None = None
    logs: list[str] = Field(default_factory=list)
    log_records: list[AgentLogRecord] = Field(default_factory=list)
    traces: list[dict[str, Any]] = Field(default_factory=list)
    trace_summaries: list[AgentTraceSummary] = Field(default_factory=list)
    change_context: list[AgentChangeContext] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: str | None = None
    message: str = ""


class AgentDiagnosticResult(BaseModel):
    agent_id: str
    bundle_id: str
    incident_id: str
    service_id: str
    timestamp: datetime
    instance_id: str | None = None
    host_id: str | None = None
    command_results: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    notes: str | None = None


class ServiceUpsertRequest(BaseModel):
    service_id: str
    service_name: str
    service_type: str
    environment: str
    owner_team: str
    criticality: str
    description: str | None = None
    is_stateless: bool = False
    allow_diagnostics: bool = True
    runbook_slug: str | None = None
    tags: list[str] = Field(default_factory=list)
    cluster: str | None = None
    cluster_ids: list[str] = Field(default_factory=list)
    restart_policy: RestartPolicy = Field(default_factory=RestartPolicy)
    database_profile: DatabaseProfile = Field(default_factory=DatabaseProfile)
    endpoint_config: ServiceEndpointConfig = Field(default_factory=ServiceEndpointConfig)
    observation_config: ServiceObservationConfig = Field(default_factory=ServiceObservationConfig)
    certification: ServiceCertification = Field(default_factory=ServiceCertification)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DependencyClusterUpsertRequest(BaseModel):
    cluster_id: str
    cluster_name: str
    environment: str
    owner_team: str
    criticality: str = "high"
    description: str | None = None
    service_ids: list[str] = Field(default_factory=list)
    entry_services: list[str] = Field(default_factory=list)
    routing_config: ClusterRoutingConfig = Field(default_factory=ClusterRoutingConfig)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DependencyEdgeUpsertRequest(BaseModel):
    edge_id: str | None = None
    cluster_id: str | None = None
    from_service_id: str
    to_service_id: str
    dependency_type: str
    dependency_purpose: str | None = None
    dependency_scope: str = "global"
    business_flow_ids: list[str] = Field(default_factory=list)
    valid_failure_domains: list[str] = Field(default_factory=list)
    expected_evidence: list[str] = Field(default_factory=list)
    criticality_weight: float = 0.6
    timeout_budget_ms: int | None = None
    is_hard_dependency: bool = True
    database_access: DatabaseDependencyProfile = Field(default_factory=DatabaseDependencyProfile)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BusinessFlowUpsertRequest(BaseModel):
    flow_id: str
    flow_name: str
    environment: str
    owner_team: str
    criticality: str = "high"
    description: str | None = None
    entry_service_ids: list[str] = Field(default_factory=list)
    steps: list[BusinessFlowStep] = Field(default_factory=list)
    success_indicators: list[str] = Field(default_factory=list)
    failure_indicators: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    correlation_window_minutes: int = 10
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChangeEventRequest(BaseModel):
    service_id: str
    change_type: str
    source: str
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None


class DiagnosticsRequest(BaseModel):
    requested_by: str
    notes: str | None = None


class RestartActionRequest(BaseModel):
    requested_by: str
    approve: bool = True
    notes: str | None = None


class TaskHandoffRequest(BaseModel):
    requested_by: str
    assignee: str | None = None
    due_at: datetime | None = None
    notes: str | None = None


class IncidentVerdictRequest(BaseModel):
    requested_by: str
    verdict: str
    actual_root_service_id: str | None = None
    notes: str | None = None


class SyncRequest(BaseModel):
    force: bool = False


class NexusState(BaseModel):
    services: list[CatalogService] = Field(default_factory=list)
    clusters: list[DependencyCluster] = Field(default_factory=list)
    business_flows: list[BusinessFlow] = Field(default_factory=list)
    dependency_edges: list[DependencyEdge] = Field(default_factory=list)
    signals: list[SignalEvent] = Field(default_factory=list)
    change_events: list[ChangeEvent] = Field(default_factory=list)
    incidents: list[NexusIncident] = Field(default_factory=list)
    diagnostics: list[DiagnosticBundle] = Field(default_factory=list)
    action_executions: list[ActionExecution] = Field(default_factory=list)
    operator_feedback: list[OperatorFeedback] = Field(default_factory=list)
    task_handoffs: list[TaskHandoff] = Field(default_factory=list)
    agent_heartbeats: list[AgentHeartbeat] = Field(default_factory=list)
    fabric_summary: FabricSummary = Field(default_factory=FabricSummary)
