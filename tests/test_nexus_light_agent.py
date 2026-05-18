from __future__ import annotations

import json

from nexus_light_agent.agent import NexusLightAgent
from nexus_light_agent.command_server import _restart_allowed
from nexus_light_agent.config import AgentSettings, config_template
from nexus_light_agent.logs import BoundedLogTailer
from nexus_light_agent.signatures import classify_line, summarize_signatures
from app.nexus.models import AgentHeartbeat, AgentProbeReport


def test_agent_config_template_is_valid(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")

    settings = AgentSettings.from_dict(config_template())

    assert settings.agent_id == "agent-ate-mobile-banking-01"
    assert settings.resolve_agent_token() == "test-token"
    assert settings.enabled_services[0].service_id == "txn-mobile-ussd"
    assert settings.enabled_services[0].process_match == "txn-mobile-ussd-0.0.1-SNAPSHOT.jar"
    assert settings.enabled_services[0].analysis_profile == "mobile_ussd"
    assert settings.enabled_services[0].analysis_config["session_expiry_warn_threshold"] == 10


def test_log_signature_classifier_detects_hikari_database_leak():
    line = (
        "2026-05-13 10:00:00 ERROR [HikariPool-1 housekeeper] "
        "com.zaxxer.hikari.pool.ProxyLeakTask - Apparent connection leak detected"
    )

    signature = classify_line(line)

    assert signature is not None
    assert signature.signature_family == "database_connection_leak"
    assert signature.failure_domain == "database"
    assert signature.db_error_code == "HIKARI_CONNECTION_LEAK"
    assert signature.severity == "CRITICAL"


def test_bounded_log_tailer_reads_incrementally(tmp_path):
    log_path = tmp_path / "txn-mobile-ussd-human.log"
    log_path.write_text(
        "\n".join(
            [
                "2026-05-13 10:00:00 INFO startup complete",
                "2026-05-13 10:00:01 ERROR SQLSTATE 53300 too many connections",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    state: dict[str, object] = {}
    tailer = BoundedLogTailer(state)

    first_lines, first_meta = tailer.read_new_lines(
        str(log_path),
        max_bytes=4096,
        max_lines=50,
        initial_tail_bytes=4096,
    )
    log_path.write_text(
        log_path.read_text(encoding="utf-8")
        + "2026-05-13 10:00:02 WARN downstream timeout contacting txn-integration-idc\n",
        encoding="utf-8",
    )
    second_lines, second_meta = tailer.read_new_lines(
        str(log_path),
        max_bytes=4096,
        max_lines=50,
        initial_tail_bytes=4096,
    )

    assert len(first_lines) == 2
    assert first_meta["bytes_read"] > 0
    assert second_lines == ["2026-05-13 10:00:02 WARN downstream timeout contacting txn-integration-idc"]
    assert second_meta["lines_read"] == 1


def test_agent_collects_process_and_database_log_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    log_path = tmp_path / "txn-mobile-ussd-human.log"
    log_path.write_text(
        "2026-05-13 10:00:00 ERROR com.zaxxer.hikari.pool.ProxyLeakTask - "
        "Connection leak detection triggered for org.postgresql.jdbc.PgConnection\n",
        encoding="utf-8",
    )
    config = config_template()
    config["nexus_base_url"] = "http://nexus.local:8010"
    config["state_dir"] = str(tmp_path / "state")
    config["log_file"] = None
    config["services"][0]["log_path"] = str(log_path)

    sent_reports: list[dict[str, object]] = []
    sent_heartbeats: list[dict[str, object]] = []

    class FakeClient:
        def fetch_agent_config(self, service_id: str) -> dict[str, object]:
            return {"service": {"service_id": service_id, "service_type": "channel", "criticality": "HIGH"}}

        def heartbeat(self, payload: dict[str, object]) -> dict[str, object]:
            sent_heartbeats.append(payload)
            return {"ok": True}

        def probe_report(self, payload: dict[str, object]) -> dict[str, object]:
            sent_reports.append(payload)
            return {"ok": True}

    monkeypatch.setattr(
        "nexus_light_agent.agent.find_processes",
        lambda _match: [
            {
                "pid": 1234,
                "state": "S",
                "threads": 42,
                "rss_mb": 256.0,
                "vm_size_mb": 1024.0,
                "vm_rss_mb": 256.0,
                "cpu_seconds": 10.0,
                "cmdline": "java -jar txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
            }
        ],
    )
    monkeypatch.setattr(
        "nexus_light_agent.agent.host_snapshot",
        lambda _primary_log: {
            "hostname": "ate-live",
            "cpu_count": 16,
            "load_per_core": 0.25,
            "memory": {"available_mb": 49152},
            "disk": {"root": {"used_percent": 73}},
        },
    )

    agent = NexusLightAgent(AgentSettings.from_dict(config))
    agent.client = FakeClient()
    agent.state.load()

    reports = agent.run_once()

    assert len(reports) == 1
    assert reports[0]["service_id"] == "txn-mobile-ussd"
    assert reports[0]["status"] == "degraded"
    assert reports[0]["failure_domain_hint"] == "database"
    assert reports[0]["metadata"]["log_signatures"][0]["signature_family"] == "database_connection_leak"
    assert sent_reports[0]["severity"] == "CRITICAL"
    assert sent_reports[0]["log_records"][0]["signature_family"] == "database_connection_leak"
    assert sent_heartbeats[0]["agent_id"] == "agent-ate-mobile-banking-01"
    assert sent_heartbeats[0]["service_id"] == "txn-mobile-ussd"
    AgentProbeReport.model_validate(sent_reports[0])
    AgentHeartbeat.model_validate(sent_heartbeats[0])


def test_ussd_low_volume_session_expiry_is_observation_not_degradation(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    log_path = tmp_path / "txn-mobile-ussd-human.log"
    log_path.write_text(
        "\n".join(
            [
                "[2026-05-15 13:42:14.100] DEBUG [pool-2-thread-1]",
                "SessionStoreManager - Expiring session with key econet:263700000001:session-a",
                "[2026-05-15 13:42:15.100] DEBUG [pool-2-thread-2]",
                "SessionStoreManager - Expiring session with key econet:263700000002:session-b",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config = config_template()
    config["nexus_base_url"] = "http://nexus.local:8010"
    config["state_dir"] = str(tmp_path / "state")
    config["log_file"] = None
    config["services"][0]["log_path"] = str(log_path)

    class FakeClient:
        def fetch_agent_config(self, service_id: str) -> dict[str, object]:
            return {"service": {"service_id": service_id, "service_type": "channel", "criticality": "HIGH"}}

        def heartbeat(self, payload: dict[str, object]) -> dict[str, object]:
            return {"ok": True}

        def probe_report(self, payload: dict[str, object]) -> dict[str, object]:
            return {"ok": True}

    monkeypatch.setattr("nexus_light_agent.agent.find_processes", lambda _match: [{"pid": 1234, "cmdline": "java"}])
    monkeypatch.setattr(
        "nexus_light_agent.agent.host_snapshot",
        lambda _primary_log: {
            "hostname": "ate-live",
            "cpu_count": 16,
            "load_per_core": 0.25,
            "memory": {"available_mb": 49152},
            "disk": {"root": {"used_percent": 73}},
        },
    )

    agent = NexusLightAgent(AgentSettings.from_dict(config))
    agent.client = FakeClient()
    agent.state.load()

    report = agent.run_once()[0]

    assert report["status"] == "up"
    assert report["severity"] == "INFO"
    assert report["log_records"] == []
    assert report["metrics"]["service_profile"]["session_expiry_count"] == 2
    assert report["metadata"]["service_profile_observations"][0]["false_positive_note"].startswith("Low-volume")


def test_ussd_session_expiry_burst_becomes_channel_tunnel_evidence_without_pii(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    log_path = tmp_path / "txn-mobile-ussd-human.log"
    lines: list[str] = []
    carriers = ["econet", "netone"]
    for index in range(11):
        second = 14 + min(index // 3, 4)
        carrier = carriers[index % len(carriers)]
        lines.extend(
            [
                f"[2026-05-15 13:42:{second:02d}.100] DEBUG [pool-2-thread-{index}]",
                f"SessionStoreManager - Expiring session with key {carrier}:2637000000{index:02d}:session-{index}",
            ]
        )
    lines.extend(["[2026-05-15 13:42:18.100] DEBUG [o-8091-exec-1]", "SessionControllerImpl - SessionResponse"])
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    config = config_template()
    config["nexus_base_url"] = "http://nexus.local:8010"
    config["state_dir"] = str(tmp_path / "state")
    config["log_file"] = None
    config["services"][0]["log_path"] = str(log_path)

    sent_reports: list[dict[str, object]] = []

    class FakeClient:
        def fetch_agent_config(self, service_id: str) -> dict[str, object]:
            return {"service": {"service_id": service_id, "service_type": "channel", "criticality": "HIGH"}}

        def heartbeat(self, payload: dict[str, object]) -> dict[str, object]:
            return {"ok": True}

        def probe_report(self, payload: dict[str, object]) -> dict[str, object]:
            sent_reports.append(payload)
            return {"ok": True}

    monkeypatch.setattr("nexus_light_agent.agent.find_processes", lambda _match: [{"pid": 1234, "cmdline": "java"}])
    monkeypatch.setattr(
        "nexus_light_agent.agent.host_snapshot",
        lambda _primary_log: {
            "hostname": "ate-live",
            "cpu_count": 16,
            "load_per_core": 0.25,
            "memory": {"available_mb": 49152},
            "disk": {"root": {"used_percent": 73}},
        },
    )

    agent = NexusLightAgent(AgentSettings.from_dict(config))
    agent.client = FakeClient()
    agent.state.load()

    report = agent.run_once()[0]
    log_record = report["log_records"][0]

    assert report["status"] == "degraded"
    assert report["severity"] == "WARN"
    assert report["failure_domain_hint"] == "channel_tunnel"
    assert log_record["signature_family"] == "ussd_session_expiry_burst"
    assert log_record["attributes"]["pii_redacted"] is True
    assert "263700" not in log_record["message"]
    assert "session-0" not in log_record["message"]
    assert report["metrics"]["service_profile"]["session_expiry_carrier_count"] == 2
    AgentProbeReport.model_validate(sent_reports[0])


def test_signature_summary_groups_database_codes():
    signatures = [
        classify_line("2026-05-13 10:00:00 ERROR SQLSTATE 53300 too many connections"),
        classify_line("2026-05-13 10:00:01 ERROR SQLSTATE 53300 remaining connection slots reserved"),
    ]

    summary = summarize_signatures([item for item in signatures if item is not None])

    assert summary == [
        {
            "signature_family": "database_error",
            "db_error_code": "53300",
            "failure_domain": "database",
            "severity": "WARN",
            "count": 2,
            "first_seen": "2026-05-13T10:00:00Z",
            "last_seen": "2026-05-13T10:00:01Z",
        }
    ]


def test_restart_policy_requires_restart_ready_stateless_service_type_allowlist(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    settings = AgentSettings.from_dict(config_template())
    service = settings.enabled_services[0]
    contract = {
        "service": {
            "service_id": service.service_id,
            "service_type": "channel",
            "is_stateless": True,
            "database_profile": {"shared_dependency": False},
            "certification": {"lifecycle_stage": "restart_ready"},
            "restart_policy": {
                "allow_restart": True,
                "cooldown_minutes": 15,
                "allowed_service_types": ["channel"],
            },
        }
    }

    allowed, reasons = _restart_allowed(contract, service, {})

    assert allowed is True
    assert reasons == []


def test_restart_policy_blocks_databases_even_when_policy_is_wrong(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    settings = AgentSettings.from_dict(config_template())
    service = settings.enabled_services[0]
    contract = {
        "service": {
            "service_id": "postgres-primary",
            "service_type": "db",
            "is_stateless": True,
            "database_profile": {"shared_dependency": True},
            "certification": {"lifecycle_stage": "restart_ready"},
            "restart_policy": {
                "allow_restart": True,
                "cooldown_minutes": 15,
                "allowed_service_types": ["db"],
            },
        }
    }

    allowed, reasons = _restart_allowed(contract, service, {})

    assert allowed is False
    assert any("blocked" in reason.lower() for reason in reasons)
