from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api import nexus
from app.config.settings import settings
from app.nexus.models import (
    AgentProbeReport,
    BusinessFlowStep,
    BusinessFlowUpsertRequest,
    DatabaseDependencyProfile,
    DatabaseProfile,
    DependencyClusterUpsertRequest,
    DependencyEdgeUpsertRequest,
    NexusState,
    RestartPolicy,
    ServiceCertification,
    ServiceEndpointConfig,
    ServiceObservationConfig,
    ServiceUpsertRequest,
    SyncRequest,
)
from app.nexus.repository import NexusRepository
from app.nexus.service import NexusService
from app.utils.sentinelops_auth import require_nexus_access, require_nexus_admin, require_nexus_operator


class InMemoryNexusRepository:
    def __init__(self) -> None:
        self.state = NexusState()

    def load_state(self):
        return self.state.model_copy(deep=True)

    def persist_state(self, state):
        self.state = state.model_copy(deep=True)

    def fetch_network_sentinel_evidence(self, service_map):
        return {"snapshots": [], "events": []}


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
    assert any("Restart policy does not allow" in reason or "stateless" in reason for reason in execution.blocked_reasons)


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
