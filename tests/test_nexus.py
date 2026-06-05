from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api import nexus
from app.config.settings import settings
from app.nexus.models import (
    ActionExecution,
    AgentControlResult,
    AgentHeartbeat,
    AgentProbeReport,
    BusinessFlowStep,
    BusinessFlowUpsertRequest,
    DatabaseConnectionTestRequest,
    DatabaseDependencyProfile,
    DatabaseProfile,
    DependencyClusterUpsertRequest,
    DependencyEdgeUpsertRequest,
    NexusState,
    RestartPolicy,
    RolloverAssessment,
    RolloverAssessmentRequest,
    RolloverChallengeRequest,
    RolloverEnvironment,
    RolloverEnvironmentUpsertRequest,
    RolloverExecuteRequest,
    RolloverExecution,
    RolloverReminderRequest,
    RolloverReplacementRule,
    RolloverRuleAssessment,
    ServiceCertification,
    ServiceEndpointConfig,
    ServiceObservationConfig,
    ServiceUpsertRequest,
    SignalEvent,
    SyncRequest,
)
from app.nexus.repository import NexusRepository
from app.nexus.database_connections import postgres_dsn_from_datagrip
from app.nexus.rollover import RolloverOracleGateway
from app.nexus.service import NexusService
from app.utils.sentinelops_auth import require_nexus_access, require_nexus_admin, require_nexus_operator


class InMemoryNexusRepository:
    def __init__(self) -> None:
        self.state = NexusState()
        self.rollover_environments: dict[str, RolloverEnvironment] = {}
        self.rollover_passwords: dict[str, str] = {}
        self.rollover_executions = []
        self.rollover_reminders = []
        self.rollover_challenges = []

    def load_state(self):
        return self.state.model_copy(deep=True)

    def persist_state(self, state):
        self.state = state.model_copy(deep=True)

    def fetch_network_sentinel_evidence(self, service_map):
        return {"snapshots": [], "events": []}

    def list_rollover_environments(self):
        return list(self.rollover_environments.values())

    def get_rollover_environment(self, environment_id):
        return self.rollover_environments.get(environment_id)

    def get_rollover_environment_with_secret(self, environment_id):
        environment = self.rollover_environments.get(environment_id)
        return environment, self.rollover_passwords.get(environment_id)

    def upsert_rollover_environment(self, environment, *, credential_password=None):
        if credential_password:
            environment.connection.password_set = True
            self.rollover_passwords[environment.environment_id] = credential_password
        self.rollover_environments[environment.environment_id] = environment.model_copy(deep=True)
        return self.rollover_environments[environment.environment_id].model_copy(deep=True)

    def delete_rollover_environment(self, environment_id, deleted_by):
        if environment_id not in self.rollover_environments:
            raise KeyError(f"Unknown Nexus rollover environment {environment_id}")
        self.rollover_environments.pop(environment_id)
        self.rollover_passwords.pop(environment_id, None)

    def list_rollover_executions(self, environment_id=None):
        rows = self.rollover_executions
        if environment_id:
            rows = [item for item in rows if item.environment_id == environment_id]
        return rows

    def persist_rollover_execution(self, execution):
        self.rollover_executions = [item for item in self.rollover_executions if item.execution_id != execution.execution_id]
        self.rollover_executions.insert(0, execution)
        return execution

    def list_rollover_reminders(self, environment_id=None):
        rows = self.rollover_reminders
        if environment_id:
            rows = [item for item in rows if item.environment_id == environment_id]
        return rows

    def upsert_rollover_reminder(self, reminder):
        self.rollover_reminders = [item for item in self.rollover_reminders if item.reminder_id != reminder.reminder_id]
        self.rollover_reminders.append(reminder)
        return reminder

    def cancel_rollover_reminder(self, reminder_id, cancelled_by):
        for reminder in self.rollover_reminders:
            if reminder.reminder_id == reminder_id:
                reminder.status = "cancelled"
                return
        raise KeyError(f"Unknown Nexus rollover reminder {reminder_id}")

    def load_rollover_challenges(self):
        return list(self.rollover_challenges)

    def persist_rollover_challenges(self, challenges):
        self.rollover_challenges = list(challenges)


class MutableNetworkEvidenceRepository(InMemoryNexusRepository):
    def __init__(self) -> None:
        super().__init__()
        self.evidence = {"snapshots": [], "events": []}

    def fetch_network_sentinel_evidence(self, service_map):
        return self.evidence


def make_service() -> NexusService:
    repository = InMemoryNexusRepository()
    service = NexusService(repository=repository)
    service.startup()
    return service


def seed_catalog(service: NexusService) -> None:
    service.upsert_service(
        ServiceUpsertRequest(
            service_id="idc-gateway",
            service_name="IDC Gateway",
            service_type="gateway",
            environment="production",
            owner_team="channels",
            criticality="critical",
            is_stateless=True,
            endpoint_config=ServiceEndpointConfig(collector_url="http://gateway-agent:9100", healthcheck_url="http://gateway/health"),
            observation_config=ServiceObservationConfig(network_service_id="11111111-1111-1111-1111-111111111111"),
            certification=ServiceCertification(lifecycle_stage="correlate_ready"),
        )
    )
    service.upsert_service(
        ServiceUpsertRequest(
            service_id="auth-api",
            service_name="Auth API",
            service_type="app",
            environment="production",
            owner_team="identity",
            criticality="critical",
            is_stateless=True,
            restart_policy=RestartPolicy(allow_restart=True, requires_human_approval=True, cooldown_minutes=15),
            endpoint_config=ServiceEndpointConfig(
                collector_url="http://auth-api-agent:9100",
                healthcheck_url="http://auth-api/health",
                diagnostics_url="http://auth-api-agent:9100/diagnostics",
                restart_url="http://auth-api-agent:9100/restart",
            ),
            observation_config=ServiceObservationConfig(
                network_service_id="22222222-2222-2222-2222-222222222222",
                agent_id="agent-auth-api-01",
                systemd_unit="auth-api.service",
                log_selector="{service=\"auth-api\"}",
                metrics_namespace="auth_api",
                trace_service_name="auth-api",
            ),
            certification=ServiceCertification(lifecycle_stage="restart_ready"),
        )
    )
    service.upsert_service(
        ServiceUpsertRequest(
            service_id="auth-cache",
            service_name="Auth Cache",
            service_type="cache",
            environment="production",
            owner_team="identity",
            criticality="high",
            is_stateless=False,
            restart_policy=RestartPolicy(allow_restart=False, requires_human_approval=True, cooldown_minutes=15),
            endpoint_config=ServiceEndpointConfig(
                collector_url="http://auth-cache-agent:9100",
                healthcheck_url="http://auth-cache/health",
                diagnostics_url="http://auth-cache-agent:9100/diagnostics",
            ),
            observation_config=ServiceObservationConfig(
                network_service_id="33333333-3333-3333-3333-333333333333",
                agent_id="agent-auth-cache-01",
                systemd_unit="auth-cache.service",
                log_selector="{service=\"auth-cache\"}",
                metrics_namespace="auth_cache",
                trace_service_name="auth-cache",
            ),
            certification=ServiceCertification(lifecycle_stage="diagnostics_ready"),
        )
    )
    service.upsert_service(
        ServiceUpsertRequest(
            service_id="postgres-primary",
            service_name="Postgres Primary",
            service_type="db",
            environment="production",
            owner_team="platform",
            criticality="critical",
            is_stateless=False,
            restart_policy=RestartPolicy(allow_restart=False, requires_human_approval=True, cooldown_minutes=15),
            endpoint_config=ServiceEndpointConfig(
                collector_url="http://postgres-agent:9100",
                healthcheck_url="http://postgres-primary/health",
                diagnostics_url="http://postgres-agent:9100/diagnostics",
            ),
            database_profile=DatabaseProfile(
                enabled=True,
                platform="postgres",
                database_name="authdb",
                role="primary",
                schemas=["auth"],
                shared_dependency=True,
                expected_evidence=["active_sessions", "connection_pool_usage", "sqlstate"],
            ),
            observation_config=ServiceObservationConfig(
                network_service_id="44444444-4444-4444-4444-444444444444",
                agent_id="agent-postgres-01",
                systemd_unit="postgresql.service",
                log_selector="{service=\"postgres-primary\"}",
                metrics_namespace="postgres",
                trace_service_name="postgres-primary",
            ),
            certification=ServiceCertification(lifecycle_stage="diagnostics_ready"),
        )
    )
    service.upsert_cluster(
        DependencyClusterUpsertRequest(
            cluster_id="idc-auth",
            cluster_name="IDC Authentication Path",
            environment="production",
            owner_team="identity",
            criticality="critical",
            description="IDC entry path from gateway to cache and database.",
            service_ids=["idc-gateway", "auth-api", "auth-cache", "postgres-primary"],
            entry_services=["idc-gateway"],
        )
    )
    service.upsert_edge(
        DependencyEdgeUpsertRequest(
            cluster_id="idc-auth",
            from_service_id="idc-gateway",
            to_service_id="auth-api",
            dependency_type="sync_api",
            criticality_weight=0.9,
        )
    )
    service.upsert_edge(
        DependencyEdgeUpsertRequest(
            cluster_id="idc-auth",
            from_service_id="auth-api",
            to_service_id="auth-cache",
            dependency_type="cache",
            criticality_weight=0.95,
        )
    )
    service.upsert_edge(
        DependencyEdgeUpsertRequest(
            cluster_id="idc-auth",
            from_service_id="auth-api",
            to_service_id="postgres-primary",
            dependency_type="db",
            database_access=DatabaseDependencyProfile(
                access_mode="read_write",
                schema_names=["auth"],
                operation_types=["connect", "read", "write"],
                connection_pool="auth-main",
                expected_error_codes=["SQLSTATE", "57P01"],
            ),
            criticality_weight=0.9,
        )
    )


def seed_idc_production_flows(service: NexusService) -> None:
    for service_id, service_name, service_type in [
        ("arx", "ARX", "gateway"),
        ("idc-core", "IDC Core", "app"),
        ("idc-microservices", "IDC Microservices", "app"),
    ]:
        service.upsert_service(
            ServiceUpsertRequest(
                service_id=service_id,
                service_name=service_name,
                service_type=service_type,
                environment="production",
                owner_team="Intellect",
                criticality="critical",
                is_stateless=False,
                observation_config=ServiceObservationConfig(agent_id=f"agent-{service_id}-01"),
                certification=ServiceCertification(lifecycle_stage="correlate_ready"),
            )
        )
    service.upsert_cluster(
        DependencyClusterUpsertRequest(
            cluster_id="intellect-idc",
            cluster_name="Intellect IDC",
            environment="production",
            owner_team="Intellect",
            criticality="critical",
            service_ids=["arx", "idc-core", "idc-microservices"],
            entry_services=["arx", "idc-core"],
        )
    )
    service.upsert_business_flow(
        BusinessFlowUpsertRequest(
            flow_id="idc-user-access",
            flow_name="IDC User Access",
            environment="production",
            owner_team="Intellect",
            criticality="critical",
            entry_service_ids=["arx"],
            steps=[
                BusinessFlowStep(step_order=1, service_id="arx", service_role="authentication_gateway", failure_domains=["authentication"]),
                BusinessFlowStep(step_order=2, service_id="idc-core", service_role="access_target", failure_domains=["authentication"]),
            ],
        )
    )
    service.upsert_business_flow(
        BusinessFlowUpsertRequest(
            flow_id="idc-transaction-processing",
            flow_name="IDC Transaction Processing",
            environment="production",
            owner_team="Intellect",
            criticality="critical",
            entry_service_ids=["idc-core"],
            steps=[
                BusinessFlowStep(step_order=1, service_id="idc-core", service_role="core_banking_orchestrator", failure_domains=["business_process"]),
                BusinessFlowStep(step_order=2, service_id="idc-microservices", service_role="transaction_support", failure_domains=["business_process"]),
            ],
        )
    )
    service.upsert_edge(
        DependencyEdgeUpsertRequest(
            cluster_id="intellect-idc",
            from_service_id="idc-core",
            to_service_id="arx",
            dependency_type="sync_api",
            dependency_purpose="authentication_access",
            dependency_scope="flow_scoped",
            business_flow_ids=["idc-user-access"],
            valid_failure_domains=["authentication", "network_path", "service_runtime"],
            criticality_weight=1.0,
        )
    )
    service.upsert_edge(
        DependencyEdgeUpsertRequest(
            cluster_id="intellect-idc",
            from_service_id="idc-core",
            to_service_id="idc-microservices",
            dependency_type="sync_api",
            dependency_purpose="transaction_processing",
            dependency_scope="flow_scoped",
            business_flow_ids=["idc-transaction-processing"],
            valid_failure_domains=["business_process", "dependency", "service_runtime"],
            criticality_weight=0.98,
        )
    )


def seed_mobile_banking_flow(service: NexusService) -> None:
    for service_id, service_name, service_type, criticality in [
        ("txn-mobile-ussd", "Mobile Banking USSD", "channel", "critical"),
        ("txn-transaction-service", "Transaction Service", "app", "critical"),
        ("txn-integration-idc", "IDC Integration", "integration", "critical"),
        ("idc-core", "IDC Core", "app", "critical"),
    ]:
        service.upsert_service(
            ServiceUpsertRequest(
                service_id=service_id,
                service_name=service_name,
                service_type=service_type,
                environment="ate",
                owner_team="Digital Banking",
                criticality=criticality,
                is_stateless=service_type in {"app", "channel", "integration"},
                observation_config=ServiceObservationConfig(agent_id=f"agent-{service_id}-ate-01"),
                certification=ServiceCertification(lifecycle_stage="correlate_ready"),
            )
        )
    service.upsert_service(
        ServiceUpsertRequest(
            service_id="txn-mobile-postgres",
            service_name="Mobile Banking PostgreSQL",
            service_type="db",
            environment="ate",
            owner_team="Digital Banking",
            criticality="critical",
            is_stateless=False,
            database_profile=DatabaseProfile(
                enabled=True,
                platform="postgres",
                database_name="mobile-banking",
                role="primary",
                connection_pool="Hikari",
                shared_dependency=True,
                expected_evidence=["Hikari", "org.postgresql.jdbc.PgConnection", "SQLSTATE"],
            ),
            observation_config=ServiceObservationConfig(agent_id="agent-txn-mobile-postgres-ate-01"),
            certification=ServiceCertification(lifecycle_stage="correlate_ready"),
        )
    )
    service.upsert_cluster(
        DependencyClusterUpsertRequest(
            cluster_id="mobile-banking-ate",
            cluster_name="Mobile Banking ATE",
            environment="ate",
            owner_team="Digital Banking",
            criticality="critical",
            service_ids=[
                "txn-mobile-ussd",
                "txn-mobile-postgres",
                "txn-transaction-service",
                "txn-integration-idc",
                "idc-core",
            ],
            entry_services=["txn-mobile-ussd"],
        )
    )
    service.upsert_business_flow(
        BusinessFlowUpsertRequest(
            flow_id="mobile-ussd-balance-enquiry",
            flow_name="Mobile USSD Balance Enquiry",
            environment="ate",
            owner_team="Digital Banking",
            criticality="critical",
            entry_service_ids=["txn-mobile-ussd"],
            steps=[
                BusinessFlowStep(step_order=1, service_id="txn-mobile-ussd", service_role="ussd_session_processor", failure_domains=["service_runtime", "database"]),
                BusinessFlowStep(step_order=2, service_id="txn-mobile-postgres", service_role="session_settings_database", failure_domains=["database"]),
                BusinessFlowStep(step_order=3, service_id="txn-transaction-service", service_role="transaction_orchestrator", failure_domains=["dependency", "business_process"]),
                BusinessFlowStep(step_order=4, service_id="txn-integration-idc", service_role="core_banking_bridge", failure_domains=["dependency", "business_process"]),
                BusinessFlowStep(step_order=5, service_id="idc-core", service_role="core_banking_validator", failure_domains=["dependency", "business_process"]),
            ],
        )
    )
    service.upsert_edge(
        DependencyEdgeUpsertRequest(
            cluster_id="mobile-banking-ate",
            from_service_id="txn-mobile-ussd",
            to_service_id="txn-mobile-postgres",
            dependency_type="db",
            dependency_purpose="session_settings_and_menu_data",
            dependency_scope="flow_scoped",
            business_flow_ids=["mobile-ussd-balance-enquiry"],
            valid_failure_domains=["database", "service_runtime"],
            database_access=DatabaseDependencyProfile(
                access_mode="read_write",
                operation_types=["connect", "read", "write", "settings_lookup"],
                connection_pool="Hikari",
                expected_error_codes=["HIKARI_CONNECTION_LEAK", "SQLSTATE"],
            ),
            criticality_weight=0.96,
        )
    )
    service.upsert_edge(
        DependencyEdgeUpsertRequest(
            cluster_id="mobile-banking-ate",
            from_service_id="txn-mobile-ussd",
            to_service_id="txn-transaction-service",
            dependency_type="sync_api",
            dependency_scope="flow_scoped",
            business_flow_ids=["mobile-ussd-balance-enquiry"],
            valid_failure_domains=["dependency", "business_process", "service_runtime"],
            criticality_weight=0.95,
        )
    )
    service.upsert_edge(
        DependencyEdgeUpsertRequest(
            cluster_id="mobile-banking-ate",
            from_service_id="txn-transaction-service",
            to_service_id="txn-integration-idc",
            dependency_type="sync_api",
            dependency_purpose="core_banking_validation",
            dependency_scope="flow_scoped",
            business_flow_ids=["mobile-ussd-balance-enquiry"],
            valid_failure_domains=["dependency", "business_process", "network_path", "service_runtime"],
            criticality_weight=1.0,
        )
    )
    service.upsert_edge(
        DependencyEdgeUpsertRequest(
            cluster_id="mobile-banking-ate",
            from_service_id="txn-integration-idc",
            to_service_id="idc-core",
            dependency_type="sync_api",
            dependency_purpose="core_banking_authorization",
            dependency_scope="flow_scoped",
            business_flow_ids=["mobile-ussd-balance-enquiry"],
            valid_failure_domains=["dependency", "business_process", "database", "service_runtime", "network_path"],
            criticality_weight=1.0,
        )
    )


def test_nexus_starts_empty_without_seed_state():
    service = make_service()

    assert service.list_services() == []
    assert service.list_incidents() == []
    assert service.get_fabric_summary().total_services == 0


def test_mobile_banking_seed_is_catalog_only_and_model_valid():
    seed_path = Path(__file__).resolve().parents[1] / "data" / "nexus_seed_mobile_banking_ate.json"
    state = NexusState.model_validate(json.loads(seed_path.read_text(encoding="utf-8")))

    assert len(state.services) == 27
    assert len(state.clusters) == 4
    assert len(state.business_flows) == 4
    assert len(state.dependency_edges) == 17
    assert state.signals == []
    assert state.incidents == []
    assert any(service.service_id == "txn-integration-idc" for service in state.services)
    assert any(edge.from_service_id == "txn-integration-idc" and edge.to_service_id == "idc-core" for edge in state.dependency_edges)
    assert any(service.service_id == "txn-mobile-postgres" and service.database_profile.enabled for service in state.services)


def test_repository_normalizes_legacy_incident_payloads():
    repository = NexusRepository()
    legacy_payload = {
        "services": [],
        "dependency_edges": [],
        "signals": [],
        "change_events": [],
        "incidents": [
            {
                "incident_id": "incident-auth-api-auth-cache-idc-gateway",
                "title": "Legacy incident",
                "status": "OPEN",
                "start_time": "2026-04-19T15:07:16.755563",
                "summary": "Legacy payload without incident key.",
                "risk_level": "HIGH",
                "risk_score": 0.61,
                "business_impact_score": 0.94,
                "affected_services": ["auth-api", "auth-cache", "idc-gateway"],
                "predicted_confidence": 0.49,
            }
        ],
        "task_handoffs": [
            {
                "task_id": "task-1",
                "incident_id": "incident-auth-api-auth-cache-idc-gateway",
                "title": "Legacy task",
                "description": "Legacy task description",
                "created_at": "2026-04-19T17:58:59.331096",
                "created_by": "ashumba",
                "route_hint": "/tasks?task=legacy",
            }
        ],
    }

    state = repository._state_from_payload(legacy_payload, persist_on_migrate=False)

    assert len(state.incidents) == 1
    assert state.incidents[0].incident_key == "incident-key:auth-api|auth-cache|idc-gateway"
    assert state.incidents[0].incident_id != "incident-auth-api-auth-cache-idc-gateway"
    assert state.task_handoffs[0].incident_id == state.incidents[0].incident_id


def test_probe_report_extracts_timeout_signature_and_persists_signal():
    service = make_service()
    seed_catalog(service)

    report = AgentProbeReport(
        agent_id="agent-auth-api-01",
        service_id="auth-api",
        service_name="Auth API",
        environment="production",
        timestamp=datetime.utcnow(),
        severity="CRITICAL",
        metrics={"p95_latency_ms": 2200},
        logs=["auth-api: timeout waiting for auth-cache response after 250ms"],
        message="Probe detected critical timeout burst.",
    )

    signals = service.record_probe_report(report)

    log_signals = [signal for signal in signals if signal.signal_type == "log"]
    assert log_signals
    assert log_signals[0].signature is not None
    assert log_signals[0].signature.signature_family == "dependency_timeout"


def test_probe_report_accepts_structured_logs_traces_and_change_context():
    service = make_service()
    seed_catalog(service)

    report = AgentProbeReport(
        agent_id="agent-auth-api-01",
        service_id="auth-api",
        service_name="Auth API",
        environment="production",
        timestamp=datetime.utcnow(),
        severity="CRITICAL",
        instance_id="auth-api-01",
        host_id="srv-auth-01",
        cluster="idc-auth",
        service_version="2026.04.21-rc1",
        metrics={"p95_latency_ms": 1950, "error_ratio": 0.18},
        log_records=[
            {
                "message": "auth-api: timeout waiting for auth-cache response after 250ms",
                "signature_family": "dependency_timeout",
                "error_class": "timeout",
                "timeout_type": "cache_dependency",
                "attributes": {"logger": "auth.request"},
            }
        ],
        trace_summaries=[
            {
                "summary": "Failed traces concentrated on auth-api -> auth-cache",
                "path": ["auth-api", "auth-cache"],
                "failed_trace_share": 0.71,
                "span_count": 18,
                "attributes": {"trace_root": "idc-gateway"},
            }
        ],
        change_context=[
            {
                "change_type": "deployment",
                "source": "cicd",
                "summary": "Auth API release candidate deployed",
            }
        ],
        metadata={"collector": "light-agent"},
        message="Structured probe detected correlated auth degradation.",
    )

    signals = service.record_probe_report(report)

    log_signal = next(signal for signal in signals if signal.signal_type == "log")
    trace_signal = next(signal for signal in signals if signal.signal_type == "trace")
    assert log_signal.signature is not None
    assert log_signal.signature.signature_family == "dependency_timeout"
    assert log_signal.attributes["host_id"] == "srv-auth-01"
    assert trace_signal.attributes["path"] == ["auth-api", "auth-cache"]
    assert any(change.change_type == "deployment" for change in service.state.change_events)


def test_graph_correlation_groups_dependency_chain_and_ranks_root_cause():
    service = make_service()
    seed_catalog(service)
    base_time = datetime.utcnow()

    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-auth-cache-01",
            service_id="auth-cache",
            service_name="Auth Cache",
            environment="production",
            timestamp=base_time - timedelta(minutes=2),
            severity="CRITICAL",
            metrics={"memory_usage_percent": 98},
            logs=["auth-cache: out of memory while serving session keys"],
            message="Auth cache memory pressure is critical.",
        )
    )
    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-auth-api-01",
            service_id="auth-api",
            service_name="Auth API",
            environment="production",
            timestamp=base_time - timedelta(minutes=1),
            severity="CRITICAL",
            metrics={"p95_latency_ms": 2100, "error_ratio": 0.22},
            logs=["auth-api: timeout waiting for auth-cache response after 250ms"],
            message="Auth API timeout burst detected.",
        )
    )
    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-idc-gateway-01",
            service_id="idc-gateway",
            service_name="IDC Gateway",
            environment="production",
            timestamp=base_time,
            severity="WARN",
            metrics={"p95_latency_ms": 1600},
            logs=["idc-gateway: login timeout returned from auth-api"],
            message="IDC gateway latency is rising because auth is degraded.",
        )
    )

    incidents = service.list_incidents()

    assert len(incidents) == 1
    incident = incidents[0]
    assert {"idc-gateway", "auth-api", "auth-cache"}.issubset(set(incident.affected_services))
    assert incident.suspected_root_service == "auth-cache"
    assert incident.cluster_ids == ["idc-auth"]
    assert any(signature.signature_family == "memory_pressure" for signature in incident.log_signatures)


def test_database_dependency_evidence_promotes_database_root_cause():
    service = make_service()
    seed_catalog(service)
    base_time = datetime.utcnow()

    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-postgres-01",
            service_id="postgres-primary",
            service_name="Postgres Primary",
            environment="production",
            timestamp=base_time - timedelta(minutes=2),
            severity="CRITICAL",
            probe_family="database",
            database={
                "platform": "postgres",
                "database_name": "authdb",
                "role": "primary",
                "status": "degraded",
                "connectivity": "degraded",
                "active_sessions": 94,
                "max_sessions": 100,
                "connection_pool_used": 88,
                "connection_pool_max": 100,
                "lock_wait_count": 7,
                "error_codes": ["SQLSTATE 53300"],
            },
            metrics={"active_sessions": 94, "max_sessions": 100, "db_connection_pool_used": 88},
            logs=["postgres: SQLSTATE 53300 too many clients already; connection pool exhausted"],
            message="Postgres primary database is under session and pool pressure.",
        )
    )
    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-auth-api-01",
            service_id="auth-api",
            service_name="Auth API",
            environment="production",
            timestamp=base_time - timedelta(minutes=1),
            severity="CRITICAL",
            failure_domain_hint="database",
            metrics={"p95_latency_ms": 2300, "db_pool_wait_ms": 1400},
            logs=["auth-api: JDBC connection pool timeout while querying auth database"],
            message="Auth API cannot obtain database connections.",
        )
    )

    incident = next(item for item in service.list_incidents() if "postgres-primary" in item.affected_services)

    assert incident.failure_domain == "database"
    assert incident.suspected_root_service == "postgres-primary"
    assert incident.root_cause_candidates[0].database_fit > 0.8
    assert any(signature.signature_family.startswith("database") for signature in incident.log_signatures)


def test_mobile_banking_hikari_leak_log_is_database_evidence():
    service = make_service()
    seed_mobile_banking_flow(service)

    signals = service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-txn-mobile-ussd-ate-01",
            service_id="txn-mobile-ussd",
            service_name="Mobile Banking USSD",
            environment="ate",
            timestamp=datetime.utcnow(),
            severity="CRITICAL",
            business_flow_id="mobile-ussd-balance-enquiry",
            metrics={"http_server_errors": 4},
            logs=[
                "[2026-05-12 17:37:38.289] WARN [l-1 housekeeper] "
                "c.z.h.pool.ProxyLeakTask ATE-Trace-ID=[] - Connection leak detection triggered "
                "for org.postgresql.jdbc.PgConnection@43d1646c on thread http-nio-8091-exec-148; "
                "java.lang.Exception: Apparent connection leak detected at "
                "com.zaxxer.hikari.HikariDataSource.getConnection"
            ],
            message="USSD probe detected Hikari/PostgreSQL connection leak evidence.",
        )
    )

    log_signal = next(signal for signal in signals if signal.signal_type == "log")
    assert log_signal.signature is not None
    assert log_signal.signature.signature_family == "database_connection_leak"
    assert log_signal.signature.db_error_code == "HIKARI_CONNECTION_LEAK"
    assert log_signal.failure_domain_hint == "database"
    assert log_signal.business_flow_id == "mobile-ussd-balance-enquiry"

    incident = service.list_incidents()[0]
    assert incident.failure_domain == "database"
    assert incident.primary_business_flow_id == "mobile-ussd-balance-enquiry"
    assert "txn-mobile-ussd" in incident.affected_services
    assert any(signature.signature_family == "database_connection_leak" for signature in incident.log_signatures)


def test_agent_config_exposes_db_backed_mobile_banking_contract():
    service = make_service()
    seed_mobile_banking_flow(service)

    config = service.get_agent_config("agent-txn-mobile-ussd-ate-01")

    assert config["service_id"] == "txn-mobile-ussd"
    assert config["environment"] == "ate"
    assert config["ingestion_contract"]["probe_report_endpoint"] == "/api/v1/nexus/agents/probe-report"
    assert any(edge["to_service_id"] == "txn-mobile-postgres" for edge in config["dependencies"]["outgoing"])
    assert any(flow["flow_id"] == "mobile-ussd-balance-enquiry" for flow in config["business_flows"])


def test_flow_scoped_arx_dependency_does_not_explain_idc_transaction_failures():
    service = make_service()
    seed_idc_production_flows(service)
    base_time = datetime.utcnow()

    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-idc-microservices-01",
            service_id="idc-microservices",
            service_name="IDC Microservices",
            environment="production",
            timestamp=base_time - timedelta(minutes=2),
            severity="CRITICAL",
            business_flow_id="idc-transaction-processing",
            failure_domain_hint="business_process",
            metrics={"error_ratio": 0.31},
            logs=["idc-microservices: transaction timeout while resolving processing dependency"],
            message="IDC transaction support is degraded.",
        )
    )
    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-idc-core-01",
            service_id="idc-core",
            service_name="IDC Core",
            environment="production",
            timestamp=base_time - timedelta(minutes=1),
            severity="CRITICAL",
            business_flow_id="idc-transaction-processing",
            failure_domain_hint="business_process",
            metrics={"transaction_failures": 44},
            logs=["idc-core: transaction processing timeout from idc-microservices"],
            message="IDC Core transaction failures are rising.",
        )
    )
    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-arx-01",
            service_id="arx",
            service_name="ARX",
            environment="production",
            timestamp=base_time,
            source="network_sentinel",
            severity="CRITICAL",
            vantage_point="external_network",
            observation_layer="network",
            failure_domain_hint="network_path",
            message="Network Sentinel cannot reach ARX externally.",
        )
    )

    incidents = service.list_incidents()
    transaction_incident = next(incident for incident in incidents if "idc-microservices" in incident.affected_services)

    assert transaction_incident.primary_business_flow_id == "idc-transaction-processing"
    assert transaction_incident.suspected_root_service == "idc-microservices"
    assert "arx" not in transaction_incident.affected_services


def test_flow_scoped_arx_dependency_explains_idc_access_failures():
    service = make_service()
    seed_idc_production_flows(service)
    base_time = datetime.utcnow()

    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-arx-01",
            service_id="arx",
            service_name="ARX",
            environment="production",
            timestamp=base_time - timedelta(minutes=2),
            severity="CRITICAL",
            business_flow_id="idc-user-access",
            failure_domain_hint="authentication",
            metrics={"login_gateway_failures": 12},
            logs=["arx: authentication gateway unavailable for IDC super admin access"],
            message="ARX authentication gateway is unavailable.",
        )
    )
    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-idc-core-01",
            service_id="idc-core",
            service_name="IDC Core",
            environment="production",
            timestamp=base_time,
            severity="WARN",
            business_flow_id="idc-user-access",
            failure_domain_hint="authentication",
            metrics={"login_failures": 12},
            logs=["idc-core: login access unavailable through ARX"],
            message="IDC access is blocked during authentication.",
        )
    )

    incident = service.list_incidents()[0]

    assert incident.primary_business_flow_id == "idc-user-access"
    assert set(incident.affected_services) == {"arx", "idc-core"}
    assert incident.suspected_root_service == "arx"


def test_graph_correlation_accepts_timezone_aware_database_timestamps():
    service = make_service()
    seed_catalog(service)

    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-auth-api-01",
            service_id="auth-api",
            service_name="Auth API",
            environment="production",
            timestamp=datetime.now(timezone.utc),
            severity="CRITICAL",
            metrics={"p95_latency_ms": 2200},
            logs=["auth-api: timeout waiting for auth-cache response after 250ms"],
            message="Timezone-aware probe report from database-like source.",
        )
    )

    assert service.list_incidents()
    assert service.state.signals[0].timestamp.tzinfo is None


def test_network_sentinel_outage_lifecycle_waits_for_operator_verdict():
    repository = MutableNetworkEvidenceRepository()
    service = NexusService(repository=repository)
    service.startup()
    seed_catalog(service)

    outage_started_at = datetime.utcnow() - timedelta(minutes=26)
    checked_at = outage_started_at + timedelta(minutes=26)
    repository.evidence = {
        "snapshots": [
            {
                "service_id": "idc-gateway",
                "network_service_id": "11111111-1111-1111-1111-111111111111",
                "address": "idc-gateway.local",
                "port": 8443,
                "overall_status": "DOWN",
                "last_checked_at": checked_at,
                "reason": "TCP connection failed from Network Sentinel vantage point.",
                "consecutive_failures": 12,
                "outage_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "outage_started_at": outage_started_at,
                "outage_duration_seconds": 1560,
                "outage_cause": "TCP_UNREACHABLE",
                "outage_details": {"source": "network_sentinel"},
            }
        ],
        "events": [
            {
                "service_id": "idc-gateway",
                "network_service_id": "11111111-1111-1111-1111-111111111111",
                "event_id": "legacy-network-event",
                "severity": "CRITICAL",
                "category": "availability",
                "event_type": "network_check",
                "title": "Older Network Sentinel noise",
                "summary": "Old evidence must not become the current outage start.",
                "details": {},
                "created_at": outage_started_at - timedelta(hours=5),
            }
        ],
    }

    service.sync_network_sentinel(SyncRequest(force=True))
    incident = next(item for item in service.list_incidents() if "idc-gateway" in item.affected_services)

    assert incident.status == "OPEN"
    assert incident.start_time == outage_started_at
    assert "scope:network-outage:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in incident.incident_key

    recovered_at = checked_at + timedelta(seconds=10)
    repository.evidence = {
        "snapshots": [
            {
                "service_id": "idc-gateway",
                "network_service_id": "11111111-1111-1111-1111-111111111111",
                "address": "idc-gateway.local",
                "port": 8443,
                "overall_status": "UP",
                "last_checked_at": recovered_at,
                "reason": "Network Sentinel check recovered.",
                "consecutive_failures": 0,
                "icmp_latency_ms": 2,
                "tcp_latency_ms": 7,
            }
        ],
        "events": [],
    }

    service.sync_network_sentinel(SyncRequest(force=True))
    awaiting = next(item for item in service.list_incidents() if item.incident_id == incident.incident_id)

    assert awaiting.status == "AWAITING_VERDICT"
    assert awaiting.end_time == recovered_at

    service.record_verdict(
        incident.incident_id,
        SimpleNamespace(
            requested_by="ops-manager",
            verdict="confirmed",
            actual_root_service_id="idc-gateway",
            notes="Recovered after network path restoration.",
        ),
    )
    resolved = next(item for item in service.list_incidents() if item.incident_id == incident.incident_id)

    assert resolved.status == "RESOLVED"
    assert resolved.verdict is not None


def test_network_sentinel_transient_outage_under_grace_does_not_create_incident():
    repository = MutableNetworkEvidenceRepository()
    service = NexusService(repository=repository)
    service.startup()
    seed_catalog(service)

    outage_started_at = datetime.utcnow() - timedelta(seconds=35)
    checked_at = outage_started_at + timedelta(seconds=35)
    repository.evidence = {
        "snapshots": [
            {
                "service_id": "idc-gateway",
                "network_service_id": "11111111-1111-1111-1111-111111111111",
                "address": "idc-gateway.local",
                "port": 8443,
                "overall_status": "DEGRADED",
                "last_checked_at": checked_at,
                "reason": "Short-lived ICMP timeout from Network Sentinel vantage point.",
                "consecutive_failures": 1,
                "outage_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "outage_started_at": outage_started_at,
                "outage_duration_seconds": 35,
                "outage_cause": "ICMP_TIMEOUT",
                "outage_details": {"source": "network_sentinel"},
            }
        ],
        "events": [
            {
                "service_id": "idc-gateway",
                "network_service_id": "11111111-1111-1111-1111-111111111111",
                "event_id": "transient-network-event",
                "severity": "CRITICAL",
                "category": "availability",
                "event_type": "network_check",
                "title": "Transient ICMP timeout",
                "summary": "ICMP timed out briefly.",
                "details": {},
                "created_at": checked_at,
            }
        ],
    }

    service.sync_network_sentinel(SyncRequest(force=True))

    assert service.list_incidents() == []
    assert service.state.signals
    assert all(
        signal.attributes.get("network_incident_eligible") is not True
        for signal in service.state.signals
        if signal.source == "network_sentinel"
    )


def test_network_sentinel_degraded_persistence_without_outage_creates_incident():
    repository = MutableNetworkEvidenceRepository()
    service = NexusService(repository=repository)
    service.startup()
    seed_catalog(service)

    degraded_started_at = datetime.utcnow() - timedelta(seconds=70)
    checked_at = degraded_started_at + timedelta(seconds=70)
    repository.evidence = {
        "snapshots": [
            {
                "service_id": "idc-gateway",
                "network_service_id": "11111111-1111-1111-1111-111111111111",
                "address": "idc-gateway.local",
                "port": 8443,
                "overall_status": "DEGRADED",
                "last_checked_at": checked_at,
                "last_state_change_at": degraded_started_at,
                "reason": "Host reachable but service port is unavailable.",
                "consecutive_failures": 0,
                "icmp_latency_ms": 2,
                "tcp_latency_ms": None,
            }
        ],
        "events": [],
    }

    service.sync_network_sentinel(SyncRequest(force=True))
    incident = next(item for item in service.list_incidents() if "idc-gateway" in item.affected_services)

    assert incident.status == "OPEN"
    assert incident.failure_domain == "network_path"
    assert incident.start_time == degraded_started_at
    assert "scope:network-problem:" in incident.incident_key
    assert any(
        signal.source == "network_sentinel"
        and signal.severity == "WARN"
        and signal.attributes.get("network_incident_eligible") is True
        for signal in service.state.signals
    )


def test_network_sentinel_degraded_tcp_message_names_host_not_service():
    repository = MutableNetworkEvidenceRepository()
    service = NexusService(repository=repository)
    service.startup()
    seed_catalog(service)

    checked_at = datetime.utcnow()
    repository.evidence = {
        "snapshots": [
            {
                "service_id": "idc-gateway",
                "network_service_id": "11111111-1111-1111-1111-111111111111",
                "address": "idc-gateway.local",
                "port": 8443,
                "overall_status": "DEGRADED",
                "last_checked_at": checked_at,
                "last_state_change_at": checked_at - timedelta(seconds=70),
                "reason": "TCP failed while the service remained reachable",
                "icmp_latency_ms": 2,
                "tcp_latency_ms": None,
            }
        ],
        "events": [],
    }

    service.sync_network_sentinel(SyncRequest(force=True))
    signal = next(item for item in service.state.signals if item.source == "network_sentinel" and item.signal_type == "synthetic")

    assert signal.message == "TCP failed while the host remained reachable; the service port is not accepting connections."


def test_service_control_cooldown_applies_only_to_restart():
    service = make_service()
    seed_catalog(service)
    now = datetime.utcnow()
    service.state.action_executions.append(
        ActionExecution(
            action_execution_id="planned-stop-1",
            service_id="auth-api",
            action_type="planned_stop",
            requested_at=now,
            requested_by="operator",
            status="EFFECTIVE",
            justification="test stop",
        )
    )
    auth_api = next(item for item in service.list_services() if item.service_id == "auth-api")
    auth_api.endpoint_config.restart_url = "http://auth-api-agent:9100/control"
    auth_api.certification.lifecycle_stage = "restart_ready"
    auth_api.restart_policy.allowed_service_types = ["app", "worker", "gateway"]

    start_readiness = service._service_control_readiness(auth_api, "start")
    restart_readiness = service._service_control_readiness(auth_api, "restart")

    assert "cooldown" not in " ".join(start_readiness["blocked_reasons"]).lower()
    assert "cooldown" not in " ".join(restart_readiness["blocked_reasons"]).lower()

    service.state.action_executions.append(
        ActionExecution(
            action_execution_id="planned-restart-1",
            service_id="auth-api",
            action_type="planned_restart",
            requested_at=now,
            requested_by="operator",
            status="EFFECTIVE",
            justification="test restart",
        )
    )

    start_after_restart = service._service_control_readiness(auth_api, "start")
    restart_after_restart = service._service_control_readiness(auth_api, "restart")

    assert "cooldown" not in " ".join(start_after_restart["blocked_reasons"]).lower()
    assert "cooldown" in " ".join(restart_after_restart["blocked_reasons"]).lower()


def test_control_result_immediately_updates_service_live_runtime_state():
    service = make_service()
    seed_catalog(service)
    now = datetime.utcnow()
    service.state.action_executions.insert(
        0,
        ActionExecution(
            action_execution_id="act-control-stop-1",
            service_id="auth-api",
            action_type="planned_stop",
            requested_at=now,
            requested_by="operator",
            approved_by="operator",
            status="MONITORING",
            justification="test stop",
            remote_execution_id="stop-exec-1",
        ),
    )

    action = service.record_control_result(
        AgentControlResult(
            agent_id="agent-auth-api-01",
            execution_id="stop-exec-1",
            action_execution_id="act-control-stop-1",
            service_id="auth-api",
            operation="stop",
            timestamp=datetime.now(timezone.utc),
            successful=True,
            status="verified",
            return_code=0,
            postcheck={
                "success": True,
                "status": "verified",
                "message": "Post-stop verification passed: no matching service process is visible.",
                "expected_state": "stopped",
                "process_count": 0,
                "processes": [],
            },
        )
    )
    live = service.get_service_live_state("auth-api")

    assert action.status == "EFFECTIVE"
    assert live["agent"]["runtime_state"] == "stopped"
    assert live["agent"]["process_count"] == 0
    assert live["agent"]["latest_signal"]["message"].startswith("Post-stop verification passed")


def test_newer_start_control_verification_beats_stale_network_degraded_live_status():
    service = make_service()
    seed_catalog(service)
    stale_network_time = datetime.utcnow() - timedelta(seconds=30)
    service.state.signals.append(
        SignalEvent(
            signal_id="stale-network-degraded",
            signal_type="synthetic",
            service_id="auth-api",
            service_name="Auth API",
            severity="WARN",
            timestamp=stale_network_time,
            source="network_sentinel",
            environment="production",
            vantage_point="external_network",
            observation_layer="network",
            failure_domain_hint="network_path",
            message="TCP failed while the host remained reachable; the service port is not accepting connections.",
            attributes={"status": "DEGRADED", "network_incident_eligible": True},
        )
    )
    service.state.action_executions.insert(
        0,
        ActionExecution(
            action_execution_id="act-control-start-1",
            service_id="auth-api",
            action_type="planned_start",
            requested_at=datetime.utcnow(),
            requested_by="operator",
            approved_by="operator",
            status="MONITORING",
            justification="test start",
            remote_execution_id="start-exec-1",
        ),
    )

    service.record_control_result(
        AgentControlResult(
            agent_id="agent-auth-api-01",
            execution_id="start-exec-1",
            action_execution_id="act-control-start-1",
            service_id="auth-api",
            operation="start",
            timestamp=datetime.now(timezone.utc),
            successful=True,
            status="verified",
            return_code=0,
            postcheck={
                "success": True,
                "status": "verified",
                "message": "Post-start verification passed: matching service process is running.",
                "expected_state": "running",
                "process_count": 1,
                "processes": [{"pid": 1234, "cmdline": "java -jar auth-api.jar"}],
            },
        )
    )
    live = service.get_service_live_state("auth-api")

    assert live["status"]["label"] == "Live"
    assert live["agent"]["runtime_state"] == "running"
    assert live["network"]["status"] == "DEGRADED"


def test_start_control_tcp_pending_stays_monitoring_and_surfaces_starting_state():
    service = make_service()
    seed_catalog(service)
    service.state.action_executions.insert(
        0,
        ActionExecution(
            action_execution_id="act-control-start-pending",
            service_id="auth-api",
            action_type="planned_start",
            requested_at=datetime.utcnow(),
            requested_by="operator",
            approved_by="operator",
            status="MONITORING",
            justification="test start",
            remote_execution_id="start-exec-pending",
        ),
    )

    action = service.record_control_result(
        AgentControlResult(
            agent_id="agent-auth-api-01",
            execution_id="start-exec-pending",
            action_execution_id="act-control-start-pending",
            service_id="auth-api",
            operation="start",
            timestamp=datetime.now(timezone.utc),
            successful=False,
            status="starting",
            return_code=0,
            postcheck={
                "success": False,
                "status": "tcp_not_ready",
                "message": "Post-start verification waiting: matching service process is running, but TCP readiness is not open yet.",
                "expected_state": "running",
                "process_count": 1,
                "processes": [{"pid": 1234, "cmdline": "java -jar auth-api.jar"}],
                "readiness": {"required": True, "ready": False, "host": "127.0.0.1", "port": 8091},
            },
        )
    )
    live = service.get_service_live_state("auth-api")

    assert action.status == "MONITORING"
    assert action.completed_at is None
    assert live["status"]["label"] == "Starting"
    assert live["agent"]["runtime_state"] == "running"
    assert live["agent"]["status"] == "starting"


def make_rollover_request() -> RolloverEnvironmentUpsertRequest:
    return RolloverEnvironmentUpsertRequest(
        environment_id="idcuatapp02",
        environment_name="IDC UAT2",
        environment_type="uat",
        service_environment="production",
        owner_team="Intellect",
        connection={
            "username": "IDC_UAT",
            "host": "idcuatapp02-db",
            "port": 1521,
            "service_name": "IDCZWG",
            "schema_name": "IDC_UAT",
        },
        credential_password="secret",
        rules=[
            RolloverReplacementRule(
                rule_id="eftendptm-interface-host",
                table_name="EFTENDPTM",
                column_name="EFTEP_ENDPT_URL",
                source_value="intellectinterfacelv01",
                target_value="idcuatapp02",
                sequence=10,
            ),
            RolloverReplacementRule(
                rule_id="procctlopenapi-core-ip",
                table_name="PROCCTLOPENAPI",
                column_name="OPENAPI_URL",
                source_value="192.168.1.108",
                target_value="192.168.4.24",
                sequence=20,
            ),
        ],
    )


def make_rollover_environment() -> RolloverEnvironment:
    request = make_rollover_request()
    return RolloverEnvironment.model_validate(request.model_dump(exclude={"credential_password"}))


class FakeRolloverGateway:
    def __init__(self) -> None:
        self.passwords: list[str | None] = []

    def assess_environment(self, environment, *, password, assessed_by=None):
        self.passwords.append(password)
        return RolloverAssessment(
            assessment_id="assessment-1",
            environment_id=environment.environment_id,
            environment_name=environment.environment_name,
            status="requires_rollover",
            assessed_by=assessed_by,
            connected=True,
            rules_checked=1,
            rules_requiring_change=1,
            rule_results=[
                RolloverRuleAssessment(
                    rule_id=environment.rules[0].rule_id,
                    table_name=environment.rules[0].table_name,
                    column_name=environment.rules[0].column_name,
                    source_value=environment.rules[0].source_value,
                    target_value=environment.rules[0].target_value,
                    status="requires_change",
                    source_matches=2,
                    target_matches=0,
                    generated_sql="UPDATE EFTENDPTM SET EFTEP_ENDPT_URL = REPLACE(...)",
                )
            ],
        )

    def execute_environment(self, environment, *, password, requested_by, approved_by, reason):
        self.passwords.append(password)
        assessment = self.assess_environment(environment, password=password, assessed_by=requested_by)
        result = assessment.rule_results[0].model_copy(update={"rows_affected": 2})
        return RolloverExecution(
            execution_id="execution-1",
            environment_id=environment.environment_id,
            environment_name=environment.environment_name,
            status="COMPLETED",
            requested_by=requested_by,
            approved_by=approved_by,
            reason=reason,
            pre_assessment=assessment,
            post_assessment=assessment.model_copy(update={"status": "aligned", "rules_requiring_change": 0}),
            rule_results=[result],
            committed=True,
            completed_at=datetime.utcnow(),
            result_summary="Rollover committed for IDC UAT2; 2 row(s) updated.",
        )


def test_rollover_oracle_gateway_prefers_host_service_easy_connect_over_tns_alias():
    environment = make_rollover_environment()
    environment.connection.dsn = "IDCZWG"

    dsn = RolloverOracleGateway()._dsn(environment)

    assert dsn == "idcuatapp02-db:1521/IDCZWG"


def test_rollover_oracle_gateway_uses_datagrip_sid_without_service_name():
    environment = make_rollover_environment()
    environment.connection.service_name = ""
    environment.connection.instance_name = "IDCZWG"

    dsn = RolloverOracleGateway()._dsn(environment)

    assert "(HOST=idcuatapp02-db)" in dsn
    assert "(PORT=1521)" in dsn
    assert "(SID=IDCZWG)" in dsn


def test_rollover_oracle_gateway_supports_tns_config_dir(monkeypatch):
    environment = make_rollover_environment()
    environment.connection.host = ""
    environment.connection.service_name = ""
    environment.connection.dsn = "IDCZWG"
    environment.connection.config_dir = r"C:\oracle\network\admin"
    captured = {}

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setitem(sys.modules, "oracledb", SimpleNamespace(connect=fake_connect))

    connection = RolloverOracleGateway()._connect(environment, password="secret")

    assert isinstance(connection, SimpleNamespace)
    assert captured["dsn"] == "IDCZWG"
    assert captured["config_dir"] == r"C:\oracle\network\admin"


def test_database_connection_helper_supports_datagrip_postgres_fields():
    profile = SimpleNamespace(
        host="postgres-primary.local",
        port=5432,
        database_name="authdb",
        username="auth_user",
        metadata={},
    )

    dsn = postgres_dsn_from_datagrip(profile)

    assert dsn == "host=postgres-primary.local port=5432 dbname=authdb user=auth_user"


def test_rollover_connection_test_uses_stored_oracle_credentials(monkeypatch):
    service = make_service()
    environment = service.upsert_rollover_environment(make_rollover_request(), user="admin")
    captured = {}

    class FakeCursor:
        def execute(self, *args, **kwargs):
            captured["query"] = args[0]

        def fetchone(self):
            return (1,)

        def close(self):
            return None

    class FakeConnection:
        def cursor(self):
            return FakeCursor()

        def close(self):
            return None

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return FakeConnection()

    monkeypatch.setitem(sys.modules, "oracledb", SimpleNamespace(connect=fake_connect))

    result = service.test_rollover_connection(
        environment.environment_id,
        DatabaseConnectionTestRequest(requested_by="operator"),
        user="operator",
    )

    assert result.connected is True
    assert result.scope == "rollover"
    assert result.driver == "python-oracledb"
    assert captured["user"] == "IDC_UAT"
    assert captured["password"] == "secret"
    assert captured["dsn"] == "idcuatapp02-db:1521/IDCZWG"
    assert captured["query"] == "SELECT 1 FROM DUAL"


def test_database_fabric_connection_test_supports_postgres_profile(monkeypatch):
    service = make_service()
    service.upsert_service(
        ServiceUpsertRequest(
            service_id="sentinel-postgres",
            service_name="SentinelOps Postgres",
            service_type="db",
            environment="production",
            owner_team="platform",
            criticality="critical",
            database_profile=DatabaseProfile(
                enabled=True,
                platform="postgres",
                host="postgres-primary.local",
                port=5432,
                database_name="sentinelops",
                username="sentinel_user",
            ),
        )
    )
    captured = {}

    class FakeCursor:
        def execute(self, *args, **kwargs):
            captured["query"] = args[0]

        def fetchone(self):
            return (1,)

        def close(self):
            return None

    class FakeConnection:
        def cursor(self):
            return FakeCursor()

        def close(self):
            return None

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return FakeConnection()

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=fake_connect))

    result = service.test_database_fabric_connection(
        "sentinel-postgres",
        DatabaseConnectionTestRequest(requested_by="operator", credential_password="pg-secret"),
        user="operator",
    )

    assert result.connected is True
    assert result.scope == "database_fabric"
    assert result.driver == "psycopg"
    assert captured["conninfo"] == "host=postgres-primary.local port=5432 dbname=sentinelops user=sentinel_user"
    assert captured["password"] == "pg-secret"
    assert captured["query"] == "SELECT 1"


def test_rollover_environment_can_inherit_oracle_database_fabric_profile():
    service = make_service()
    seed_catalog(service)
    service.upsert_service(
        ServiceUpsertRequest(
            service_id="idc-oracle-uat2",
            service_name="IDC Oracle UAT2",
            service_type="db",
            environment="production",
            owner_team="Intellect",
            criticality="critical",
            database_profile=DatabaseProfile(
                enabled=True,
                platform="oracle",
                host="idcuatapp02-db",
                port=1521,
                database_name="IDCZWG",
                instance_name="IDCZWG",
                username="IDC_UAT",
                schemas=["IDC_UAT"],
            ),
        ),
    )
    request = make_rollover_request()
    request.connection.host = ""
    request.connection.service_name = ""
    request.connection.instance_name = ""
    request.connection.database_name = ""
    request.connection.schema_name = ""
    request.connection.username = ""
    request.connection.source_service_id = "idc-oracle-uat2"

    environment = service.upsert_rollover_environment(request, user="admin")

    assert environment.connection.host == "idcuatapp02-db"
    assert environment.connection.sid == "IDCZWG"
    assert environment.connection.username == "IDC_UAT"
    assert environment.connection.schema_name == "IDC_UAT"
    assert environment.connection.metadata["database_fabric_inherited"] is True


def test_rollover_environment_profiles_are_configurable_and_link_services():
    service = make_service()
    seed_catalog(service)
    service.rollover_gateway = FakeRolloverGateway()

    environment = service.upsert_rollover_environment(make_rollover_request(), user="admin")
    linked_services = service.get_rollover_environment_services(environment.environment_id)
    assessment = service.assess_rollover_environment(
        environment.environment_id,
        RolloverAssessmentRequest(requested_by="operator"),
        user="operator",
    )

    assert environment.connection.password_set is True
    assert [rule.rule_id for rule in environment.rules] == ["eftendptm-interface-host", "procctlopenapi-core-ip"]
    assert {item.service_id for item in linked_services}.issuperset({"idc-gateway", "auth-api"})
    assert assessment.status == "requires_rollover"
    assert assessment.rule_results[0].source_matches == 2
    assert service.rollover_gateway.passwords[-1] == "secret"


def test_rollover_execution_requires_otp_and_records_change(monkeypatch):
    service = make_service()
    seed_catalog(service)
    service.rollover_gateway = FakeRolloverGateway()
    environment = service.upsert_rollover_environment(make_rollover_request(), user="admin")
    captured: dict[str, str] = {}

    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.internal")
    monkeypatch.setattr(settings, "SMTP_FROM", "nexus@sentinelops.local")

    def capture_otp(**kwargs):
        captured["code"] = kwargs["code"]

    monkeypatch.setattr("app.nexus.service.send_nexus_control_otp", capture_otp)

    challenge = service.request_rollover_challenge(
        environment.environment_id,
        RolloverChallengeRequest(reason="UAT2 rollover validation", requested_by="operator"),
        user={"username": "operator", "email": "operator@sentinelops.local"},
    )
    execution = service.execute_rollover(
        environment.environment_id,
        RolloverExecuteRequest(
            challenge_id=challenge.challenge_id,
            otp_code=captured["code"],
            reason="UAT2 rollover validation",
            requested_by="operator",
        ),
        user={"username": "operator", "email": "operator@sentinelops.local"},
    )

    assert execution.status == "COMPLETED"
    assert execution.committed is True
    assert service.repository.list_rollover_executions(environment.environment_id)[0].execution_id == "execution-1"
    assert any(event.change_type == "environment_rollover" for event in service.state.change_events)


def test_rollover_schedule_is_reminder_only():
    service = make_service()
    service.upsert_rollover_environment(make_rollover_request(), user="admin")

    reminder = service.schedule_rollover_reminder(
        "idcuatapp02",
        RolloverReminderRequest(
            scheduled_for=datetime.utcnow() + timedelta(hours=4),
            timezone="Africa/Johannesburg",
            notify_recipients=["operator@sentinelops.local"],
            notes="Prepare UAT rollover window",
        ),
        user="operator",
    )

    assert reminder.status == "scheduled"
    assert reminder.metadata["autonomous_rollover"] is False
    assert service.repository.list_rollover_reminders("idcuatapp02")[0].reminder_id == reminder.reminder_id


def test_local_agent_runtime_signal_supersedes_matching_network_only_incident():
    repository = MutableNetworkEvidenceRepository()
    service = NexusService(repository=repository)
    service.startup()
    seed_catalog(service)

    degraded_started_at = datetime.utcnow() - timedelta(seconds=80)
    checked_at = degraded_started_at + timedelta(seconds=80)
    repository.evidence = {
        "snapshots": [
            {
                "service_id": "idc-gateway",
                "network_service_id": "11111111-1111-1111-1111-111111111111",
                "address": "idc-gateway.local",
                "port": 8443,
                "overall_status": "DEGRADED",
                "last_checked_at": checked_at,
                "last_state_change_at": degraded_started_at,
                "reason": "TCP handshake failed while host is reachable.",
                "consecutive_failures": 0,
            }
        ],
        "events": [],
    }

    service.sync_network_sentinel(SyncRequest(force=True))
    network_incident = next(item for item in service.list_incidents() if "idc-gateway" in item.affected_services)
    assert network_incident.failure_domain == "network_path"

    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-idc-gateway-01",
            service_id="idc-gateway",
            service_name="IDC Gateway",
            environment="production",
            timestamp=checked_at + timedelta(seconds=5),
            source="nexus_light_agent",
            severity="CRITICAL",
            status="down",
            vantage_point="local_agent",
            observation_layer="service_runtime",
            failure_domain_hint="service_runtime",
            metrics={"process_count": 0, "processes": []},
            message="IDC Gateway process is not running on the local host.",
        )
    )

    current = [item for item in service.list_incidents() if "idc-gateway" in item.affected_services and item.status == "OPEN"]
    assert len(current) == 1
    assert current[0].failure_domain == "service_runtime"
    assert {"network_sentinel", "nexus_light_agent"}.issubset(set(current[0].data_sources))


def test_safe_restart_is_blocked_for_stateful_database_incident():
    service = make_service()
    seed_catalog(service)

    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-postgres-01",
            service_id="postgres-primary",
            service_name="Postgres Primary",
            environment="production",
            timestamp=datetime.utcnow(),
            severity="CRITICAL",
            metrics={"connection_failures": 42},
            logs=["postgres: could not connect to startup process"],
            message="Critical database startup failures detected.",
        )
    )
    postgres_incident = next(
        incident for incident in service.list_incidents() if incident.suspected_root_service == "postgres-primary"
    )

    execution = service.handle_restart_action(
        postgres_incident.incident_id,
        SimpleNamespace(requested_by="ops-manager", approve=True, notes="Attempt guarded restart."),
    )

    assert execution.status == "BLOCKED"
    assert any("Service Control" in reason or "control gate" in reason for reason in execution.blocked_reasons)


def test_nexus_router_lists_catalog_and_incidents():
    service = make_service()
    seed_catalog(service)
    service.record_probe_report(
        AgentProbeReport(
            agent_id="agent-auth-api-01",
            service_id="auth-api",
            service_name="Auth API",
            environment="production",
            timestamp=datetime.utcnow(),
            severity="CRITICAL",
            metrics={"p95_latency_ms": 2200},
            logs=["auth-api: timeout waiting for auth-cache response after 250ms"],
            message="Probe detected critical timeout burst.",
        )
    )

    app = FastAPI()
    app.state.services = SimpleNamespace(nexus=service)
    app.dependency_overrides[require_nexus_access] = lambda: {"username": "ashumba", "role": "admin", "section_id": "7bd4144d-68d8-4ac3-897d-245941612daf"}
    app.dependency_overrides[require_nexus_operator] = lambda: {"username": "ashumba", "role": "admin"}
    app.dependency_overrides[require_nexus_admin] = lambda: {"username": "ashumba", "role": "admin"}
    app.include_router(nexus.router, prefix="/api/v1")
    client = TestClient(app)

    incidents_response = client.get("/api/v1/nexus/incidents")
    services_response = client.get("/api/v1/nexus/catalog/services")
    summary_response = client.get("/api/v1/nexus/fabric-summary")

    assert incidents_response.status_code == 200
    assert incidents_response.json()["incidents"]
    assert services_response.status_code == 200
    assert len(services_response.json()["services"]) == 4
    assert summary_response.status_code == 200
    assert summary_response.json()["total_services"] == 4


def test_nexus_router_requires_sentinelops_session_for_human_apis():
    service = make_service()
    app = FastAPI()
    app.state.services = SimpleNamespace(nexus=service)
    app.include_router(nexus.router, prefix="/api/v1")
    client = TestClient(app)

    response = client.get("/api/v1/nexus/incidents")

    assert response.status_code == 401


def test_nexus_agent_ingestion_remains_separate_from_frontend_session_auth(monkeypatch):
    monkeypatch.setattr(settings, "NEXUS_REQUIRE_AGENT_AUTH", False)
    service = make_service()
    seed_catalog(service)
    app = FastAPI()
    app.state.services = SimpleNamespace(nexus=service)
    app.include_router(nexus.router, prefix="/api/v1")
    client = TestClient(app)

    response = client.post(
        "/api/v1/nexus/agents/heartbeat",
        json={
            "agent_id": "agent-auth-api-01",
            "service_id": "auth-api",
            "environment": "production",
            "timestamp": datetime.utcnow().isoformat(),
            "platform": "linux",
            "capabilities": ["health_check", "recent_journal"],
        },
    )

    assert response.status_code == 200
    assert response.json()["service_id"] == "auth-api"


def test_service_signal_feed_filters_sources_and_keeps_counts():
    service = make_service()
    seed_catalog(service)
    now = datetime.utcnow()
    service.state.signals = [
        SignalEvent(
            signal_id="sig-agent-runtime",
            signal_type="metric",
            service_id="auth-api",
            service_name="Auth API",
            severity="INFO",
            timestamp=now,
            source="nexus_light_agent",
            environment="production",
            vantage_point="local_agent",
            observation_layer="service_runtime",
            failure_domain_hint="service_runtime",
            message="Auth API runtime is healthy.",
            fingerprint="auth-api:agent",
        ),
        SignalEvent(
            signal_id="sig-network-down",
            signal_type="synthetic",
            service_id="auth-api",
            service_name="Auth API",
            severity="WARN",
            timestamp=now - timedelta(minutes=1),
            source="network_sentinel",
            environment="production",
            vantage_point="external_network",
            observation_layer="external_network",
            failure_domain_hint="network_path",
            message="TCP failed while the host remained reachable.",
            fingerprint="auth-api:network",
        ),
    ]

    feed = service.get_service_signal_feed("auth-api", source="network_sentinel", limit=20, since_hours=2)

    assert feed["total"] == 1
    assert feed["source_counts"] == {"nexus_light_agent": 1, "network_sentinel": 1}
    assert feed["signals"][0]["source"] == "network_sentinel"
    assert feed["signals"][0]["failure_domain_hint"] == "network_path"


def test_light_agent_fleet_groups_multi_service_heartbeats_by_agent_and_service():
    service = make_service()
    seed_catalog(service)
    service.upsert_service(
        ServiceUpsertRequest(
            service_id="auth-worker",
            service_name="Auth Worker",
            service_type="worker",
            environment="production",
            owner_team="identity",
            criticality="high",
            is_stateless=True,
            endpoint_config=ServiceEndpointConfig(diagnostics_url="http://auth-api-agent:9100/diagnostics"),
            observation_config=ServiceObservationConfig(agent_id="agent-auth-api-01"),
            certification=ServiceCertification(lifecycle_stage="diagnostics_ready"),
        )
    )
    heartbeat_base = {
        "agent_id": "agent-auth-api-01",
        "environment": "production",
        "timestamp": datetime.utcnow(),
        "platform": "linux",
        "version": "0.1.0",
        "host_id": "auth-host-01",
        "capabilities": ["runtime_probe", "bounded_live_log_tail"],
        "metadata": {
            "host": {"memory": {"used_percent": 42.5, "available_mb": 4096}},
            "resource_pressure": {"collector_mode": "normal"},
            "command_server": {"enabled": True, "public_base_url": "http://auth-host-01:8765"},
        },
    }

    service.record_heartbeat(AgentHeartbeat(service_id="auth-api", **heartbeat_base))
    service.record_heartbeat(AgentHeartbeat(service_id="auth-worker", **{**heartbeat_base, "timestamp": datetime.utcnow()}))

    agents = service.list_light_agents()
    agent = next(item for item in agents if item["agent_id"] == "agent-auth-api-01")

    assert len(service.state.agent_heartbeats) == 2
    assert agent["status"] == "online"
    assert agent["configured_service_count"] == 2
    assert agent["reporting_service_count"] == 2
    assert agent["missing_service_ids"] == []
    assert agent["host"]["memory"]["used_percent"] == 42.5


def test_light_agent_fleet_excludes_catalog_only_agent_mappings_without_heartbeat():
    service = make_service()
    seed_catalog(service)
    service.upsert_service(
        ServiceUpsertRequest(
            service_id="catalog-only",
            service_name="Catalog Only",
            service_type="app",
            environment="production",
            owner_team="identity",
            criticality="medium",
            observation_config=ServiceObservationConfig(agent_id="agent-catalog-only-01"),
            certification=ServiceCertification(lifecycle_stage="observe_only"),
        )
    )
    service.record_heartbeat(
        AgentHeartbeat(
            agent_id="agent-auth-api-01",
            service_id="auth-api",
            environment="production",
            timestamp=datetime.utcnow(),
            platform="linux",
            version="0.1.0",
            host_id="auth-host-01",
            capabilities=["runtime_probe"],
            metadata={
                "host": {"memory": {"used_percent": 41.0}},
                "watched_services": [
                    {"service_id": "auth-api", "service_name": "Auth API", "environment": "production"}
                ],
            },
        )
    )

    agents = service.list_light_agents()

    assert [agent["agent_id"] for agent in agents] == ["agent-auth-api-01"]
    assert agents[0]["configured_service_count"] == 1
    assert agents[0]["services"][0]["service_id"] == "auth-api"


def test_nexus_agent_ingestion_requires_agent_token_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "NEXUS_REQUIRE_AGENT_AUTH", True)
    monkeypatch.setattr(settings, "NEXUS_AGENT_API_TOKEN", SecretStr("agent-secret"))
    service = make_service()
    seed_catalog(service)
    app = FastAPI()
    app.state.services = SimpleNamespace(nexus=service)
    app.include_router(nexus.router, prefix="/api/v1")
    client = TestClient(app)

    blocked = client.post(
        "/api/v1/nexus/agents/heartbeat",
        json={
            "agent_id": "agent-auth-api-01",
            "service_id": "auth-api",
            "environment": "production",
            "timestamp": datetime.utcnow().isoformat(),
            "platform": "linux",
            "capabilities": ["health_check"],
        },
    )
    allowed = client.post(
        "/api/v1/nexus/agents/heartbeat",
        headers={"X-Nexus-Agent-Token": "agent-secret", "X-Nexus-Agent-Id": "agent-auth-api-01"},
        json={
            "agent_id": "agent-auth-api-01",
            "service_id": "auth-api",
            "environment": "production",
            "timestamp": datetime.utcnow().isoformat(),
            "platform": "linux",
            "capabilities": ["health_check"],
        },
    )

    assert blocked.status_code == 401
    assert allowed.status_code == 200


def test_nexus_agent_config_requires_agent_token_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "NEXUS_REQUIRE_AGENT_AUTH", True)
    monkeypatch.setattr(settings, "NEXUS_AGENT_API_TOKEN", SecretStr("agent-secret"))
    service = make_service()
    seed_mobile_banking_flow(service)
    app = FastAPI()
    app.state.services = SimpleNamespace(nexus=service)
    app.include_router(nexus.router, prefix="/api/v1")
    client = TestClient(app)

    config_url = "/api/v1/nexus/agents/agent-txn-mobile-ussd-ate-01/config?service_id=txn-mobile-ussd"
    blocked = client.get(config_url)
    allowed = client.get(
        config_url,
        headers={"X-Nexus-Agent-Token": "agent-secret", "X-Nexus-Agent-Id": "agent-txn-mobile-ussd-ate-01"},
    )

    assert blocked.status_code == 401
    assert allowed.status_code == 200
    assert allowed.json()["service_id"] == "txn-mobile-ussd"


def test_timeline_smalltalk_is_short_and_human():
    answer = nexus._timeline_smalltalk_answer("By the way, who are you?", "Mobile Banking USSD")

    assert answer is not None
    assert answer.startswith("I'm Nexus Copilot")
    assert "persona" not in answer.lower()


def test_timeline_followup_reuses_last_24_hour_window():
    window = nexus._period_window_from_question(
        "Give more context on the incidents",
        "Africa/Harare",
        [{"role": "operator", "content": "What happened in the last 24 hours?"}],
    )

    assert window is not None
    start, end, basis = window
    assert basis == "last_24_hours"
    assert end - start == timedelta(hours=24)


def test_timeline_fallback_uses_evidence_rich_context():
    start = datetime(2026, 5, 25, 16, 6, tzinfo=timezone.utc)
    incident = SimpleNamespace(
        incident_id="abcdef12-1111-2222-3333-444444444444",
        incident_key="txn-mobile-ussd:network-path",
        title="Mobile USSD Balance Enquiry degradation impacting 1 services",
        status="AWAITING_VERDICT",
        start_time=start,
        end_time=start + timedelta(hours=14),
        summary="Mobile Banking USSD showed network path degradation during balance enquiry.",
        risk_level="LOW",
        risk_score=0.2,
        business_impact_score=1.0,
        affected_services=["txn-mobile-ussd"],
        suspected_root_service="txn-mobile-ussd",
        suspected_root_service_name="Mobile Banking USSD",
        predicted_confidence=1.0,
        blast_radius=["txn-mobile-ussd", "txn-ussd-adapter"],
        cluster_ids=["mobile-banking-ate"],
        business_flow_ids=["mobile-ussd-balance-enquiry"],
        primary_business_flow_id="mobile-ussd-balance-enquiry",
        primary_business_flow_name="Mobile USSD Balance Enquiry",
        failure_domain="network_path",
        vantage_points=["external_network"],
        data_sources=["network_sentinel"],
        root_cause_candidates=[
            SimpleNamespace(
                service_id="txn-mobile-ussd",
                service_name="Mobile Banking USSD",
                confidence=1.0,
                explanation="Fits the scoped dependency path and Network Sentinel evidence.",
            )
        ],
        recommendations=[],
        evidence_timeline=[
            SimpleNamespace(
                timestamp=start + timedelta(minutes=1),
                source="network_sentinel",
                evidence_class="synthetic",
                severity="HIGH",
                summary="ICMP timed out",
                failure_domain_hint="network_path",
            ),
            SimpleNamespace(
                timestamp=start + timedelta(minutes=5),
                source="network_sentinel",
                evidence_class="synthetic",
                severity="HIGH",
                summary="Network Sentinel reports Mobile Banking USSD as DOWN.",
                failure_domain_hint="network_path",
            ),
        ],
        log_signatures=[],
        diagnostics=[],
        action_executions=[],
        verdict=None,
    )
    service_stub = SimpleNamespace(
        service_id="txn-mobile-ussd",
        service_name="Mobile Banking USSD",
        service_type="channel",
        environment="ate",
    )
    facts = nexus._service_timeline_facts(service_stub, [incident], "Africa/Harare")
    facts["question_intent"] = "incident_context"
    facts["period_analysis"] = {"window_detected": False}
    facts["operator_context_brief"] = nexus._timeline_operator_context_brief(
        service=service_stub,
        incidents=[incident],
        facts=facts,
        question="Give more context on the incidents",
        timezone_name="Africa/Harare",
    )

    answer = nexus._fallback_service_timeline_answer(
        service_stub.__dict__,
        [incident],
        facts,
        "Give more context on the incidents",
    )

    assert "Operational interpretation" in answer
    assert "Incident context:" in answer
    assert "Evidence examples: ICMP timed out" in answer
    assert "2026-05-25" in answer
