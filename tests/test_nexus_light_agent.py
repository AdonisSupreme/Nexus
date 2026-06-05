from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from nexus_light_agent.agent import NexusLightAgent
from nexus_light_agent.command_server import (
    BUILTIN_SPRING_BOOT_CONTROL,
    _control_command,
    _control_command_timeout_seconds,
    _control_postcheck_timeout_seconds,
    _discover_spring_server_port,
    _execute_diagnostic_command,
    _post_control_check,
    _restart_allowed,
    _start_spring_boot_service,
    _tail_service_log,
    _wait_for_post_control_check,
)
from nexus_light_agent.config import AgentSettings, config_template
from nexus_light_agent.logs import BoundedLogTailer
from nexus_light_agent.signatures import classify_line, summarize_signatures
from app.nexus.models import AgentHeartbeat, AgentProbeReport


def test_agent_config_template_is_valid(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")

    settings = AgentSettings.from_dict(config_template())

    assert settings.agent_id == "agent-txn-mobile-ussd-ate-01"
    assert settings.resolve_agent_token() == "test-token"
    assert [service.service_id for service in settings.enabled_services] == ["txn-mobile-ussd", "txn-ussd-adapter"]
    assert settings.enabled_services[0].service_id == "txn-mobile-ussd"
    assert settings.enabled_services[0].process_match == "txn-mobile-ussd-0.0.1-SNAPSHOT.jar"
    assert settings.enabled_services[0].working_dir == "/srv"
    assert settings.enabled_services[0].readiness_host == "127.0.0.1"
    assert settings.enabled_services[0].readiness_port == 8091
    assert settings.enabled_services[0].start_command == ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/start.sh"]
    assert settings.enabled_services[0].restart_settle_seconds == 30
    assert settings.enabled_services[0].analysis_profile == "mobile_ussd"
    assert settings.enabled_services[0].analysis_config["session_expiry_warn_threshold"] == 10
    assert settings.enabled_services[1].service_id == "txn-ussd-adapter"
    assert settings.enabled_services[1].process_match == "txn-ussd-adapter-0.0.1-SNAPSHOT.jar"
    assert settings.enabled_services[1].log_path == "/srv/log/ate/txn-mobile/txn-ussd-adapter/txn-ussd-adapter-human.log"
    assert settings.enabled_services[1].start_command == ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/start.sh"]
    assert settings.enabled_services[1].readiness_port is None


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
    assert sent_heartbeats[0]["agent_id"] == "agent-txn-mobile-ussd-ate-01"
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


def test_live_log_tail_uses_cursor_and_returns_latest_first(tmp_path):
    log_path = tmp_path / "txn-mobile-ussd-human.log"
    log_path.write_text(
        "\n".join(
            [
                "2026-06-02 20:40:00 INFO first",
                "2026-06-02 20:40:01 WARN second",
                "2026-06-02 20:40:02 ERROR third",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    service = SimpleNamespace(service_id="txn-mobile-ussd", service_name="Mobile Banking USSD", log_path=str(log_path))

    snapshot = _tail_service_log(service, max_lines=2, max_bytes=4096)
    cursor = snapshot["cursor"]
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write("2026-06-02 20:40:03 INFO fourth\n")
        handle.write("2026-06-02 20:40:04 WARN fifth\n")

    delta = _tail_service_log(service, max_lines=10, max_bytes=4096, cursor=cursor)

    assert snapshot["lines"][0]["message"].endswith("third")
    assert delta["tail_mode"] == "delta"
    assert [line["message"] for line in delta["lines"]] == [
        "2026-06-02 20:40:04 WARN fifth",
        "2026-06-02 20:40:03 INFO fourth",
    ]
    assert delta["cursor"] > cursor


def test_live_log_tail_groups_ate_multiline_events(tmp_path):
    log_path = tmp_path / "txn-mobile-ussd-human.log"
    log_path.write_text(
        "\n".join(
            [
                "[2026-05-15 13:42:09.724] INFO  [o-8091-exec-582]",
                "                m.s.r.ProfileRemoteServiceImpl ATE-Trace-ID=[abc] - REMOTE SERVICE SUCCESS RESPONSE, HTTP STATUS=200",
                "[2026-05-15 13:42:09.729] DEBUG [o-8091-exec-582]",
                "                .t.e.m.c.SessionControllerImpl ATE-Trace-ID=[abc] - SessionResponse",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    service = SimpleNamespace(service_id="txn-mobile-ussd", service_name="Mobile Banking USSD", log_path=str(log_path))

    snapshot = _tail_service_log(service, max_lines=10, max_bytes=4096)

    assert snapshot["line_grouping"] == "timestamp_event"
    assert snapshot["physical_line_count"] == 4
    assert snapshot["event_count"] == 2
    assert len(snapshot["lines"]) == 2
    newest = snapshot["lines"][0]
    older = snapshot["lines"][1]
    assert newest["timestamp"] == "2026-05-15 13:42:09.729"
    assert newest["physical_line_count"] == 2
    assert "SessionResponse" in newest["message"]
    assert older["timestamp"] == "2026-05-15 13:42:09.724"
    assert older["continuation_count"] == 1
    assert "REMOTE SERVICE SUCCESS RESPONSE" in older["message"]


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


def test_control_postcheck_rejects_false_success_when_process_still_running(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    service = AgentSettings.from_dict(config_template()).enabled_services[0]

    monkeypatch.setattr(
        "nexus_light_agent.command_server.find_processes",
        lambda _match: [{"pid": 4162832, "cmdline": "java -jar txn-mobile-ussd-0.0.1-SNAPSHOT.jar"}],
    )

    postcheck = _post_control_check(service, "stop", {"return_code": 0, "stdout": "", "stderr": ""})

    assert postcheck["success"] is False
    assert postcheck["status"] == "process_still_running"
    assert postcheck["process_count"] == 1


def test_start_postcheck_requires_tcp_readiness_when_port_is_known(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    service = AgentSettings.from_dict(config_template()).enabled_services[0]
    service.readiness_port = 9090
    monkeypatch.setattr(
        "nexus_light_agent.command_server.find_processes",
        lambda _match: [{"pid": 4162832, "cmdline": "java -jar txn-mobile-ussd-0.0.1-SNAPSHOT.jar"}],
    )
    monkeypatch.setattr(
        "nexus_light_agent.command_server.socket.create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("connection refused")),
    )

    postcheck = _post_control_check(service, "start", {"return_code": 0, "stdout": "", "stderr": ""})

    assert postcheck["success"] is False
    assert postcheck["status"] == "tcp_not_ready"
    assert postcheck["process_count"] == 1
    assert postcheck["readiness"]["port"] == 9090


def test_start_postcheck_uses_contract_config_path_for_tcp_readiness(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    config = config_template()
    config["services"][0]["config_path"] = None
    config["services"][0]["readiness_port"] = None
    service = AgentSettings.from_dict(config).enabled_services[0]
    application_yml = tmp_path / "application.yml"
    application_yml.write_text("server:\n  port: 8091\n", encoding="utf-8")
    contract = {
        "service": {
            "metadata": {
                "config_path": str(application_yml),
                "process_match": "txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
            }
        }
    }
    calls: list[tuple[str, int]] = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_create_connection(address, timeout):
        calls.append(address)
        return FakeSocket()

    monkeypatch.setattr(
        "nexus_light_agent.command_server.find_processes",
        lambda _match: [{"pid": 4162832, "cmdline": "java -jar txn-mobile-ussd-0.0.1-SNAPSHOT.jar"}],
    )
    monkeypatch.setattr("nexus_light_agent.command_server.socket.create_connection", fake_create_connection)

    postcheck = _post_control_check(
        service,
        "start",
        {"return_code": 0, "stdout": "", "stderr": ""},
        contract=contract,
    )

    assert postcheck["success"] is True
    assert postcheck["status"] == "verified"
    assert postcheck["readiness"]["required"] is True
    assert postcheck["readiness"]["port"] == 8091
    assert calls[0] == ("127.0.0.1", 8091)


def test_start_postcheck_rejects_wrong_manual_launch_directory(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    config = config_template()
    config["services"][0]["working_dir"] = "/srv"
    config["services"][0]["jar_path"] = "/srv/afc/txn-mobile/txn-mobile-ussd/lib/txn-mobile-ussd-0.0.1-SNAPSHOT.jar"
    config["services"][0]["config_path"] = "/srv/afc/txn-mobile/txn-mobile-ussd/etc/application.yml"
    service = AgentSettings.from_dict(config).enabled_services[0]

    monkeypatch.setattr(
        "nexus_light_agent.command_server.find_processes",
        lambda _match: [
            {
                "pid": 15447,
                "cwd": "/srv/afc/txn-mobile/txn-mobile-ussd/lib",
                "cmdline": "java -jar /srv/afc/txn-mobile/txn-mobile-ussd/lib/txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
            }
        ],
    )
    monkeypatch.setattr(
        "nexus_light_agent.command_server._service_readiness_check",
        lambda _service, contract=None: {"required": True, "ready": False, "host": "127.0.0.1", "port": 8091},
    )

    postcheck = _post_control_check(service, "start", {"return_code": 0, "stdout": "", "stderr": ""})

    assert postcheck["success"] is False
    assert postcheck["status"] == "launch_context_mismatch"
    assert postcheck["launch_context"]["expected_cwd"] == "/srv"
    assert postcheck["launch_context"]["actual_cwds"] == ["/srv/afc/txn-mobile/txn-mobile-ussd/lib"]
    assert "manual ATE launch directory" in postcheck["message"]


def test_control_postcheck_explains_privilege_failure(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    service = AgentSettings.from_dict(config_template()).enabled_services[0]

    postcheck = _post_control_check(
        service,
        "stop",
        {
            "return_code": 1,
            "stdout": "",
            "stderr": "Permission denied killing pid 4162832: [Errno 1] Operation not permitted",
        },
    )

    assert postcheck["success"] is False
    assert postcheck["status"] == "command_failed"
    assert "sudo allowlist helper" in postcheck["message"]


def test_control_postcheck_returns_immediately_when_stop_is_verified(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    service = AgentSettings.from_dict(config_template()).enabled_services[0]
    service.restart_settle_seconds = 30
    monkeypatch.setattr("nexus_light_agent.command_server.find_processes", lambda _match: [])

    started = time.monotonic()
    postcheck = _wait_for_post_control_check(service, "stop", {"return_code": 0, "stdout": "", "stderr": ""})

    assert postcheck["success"] is True
    assert postcheck["status"] == "verified"
    assert postcheck["verification_timeout_seconds"] == 0
    assert time.monotonic() - started < 1


def test_start_postcheck_uses_configured_settle_window(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    service = AgentSettings.from_dict(config_template()).enabled_services[0]
    service.restart_settle_seconds = 30

    assert _control_postcheck_timeout_seconds(service, "start") == 30
    assert _control_postcheck_timeout_seconds(service, "restart") == 30
    assert _control_postcheck_timeout_seconds(service, "stop") == 8
    assert _control_command_timeout_seconds(service, "start") == 40
    assert _control_command_timeout_seconds(service, "restart") == 50


def test_diagnostics_runtime_status_includes_process_metrics(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    settings = AgentSettings.from_dict(config_template())
    service = settings.enabled_services[0]
    agent = SimpleNamespace(settings=settings, state=SimpleNamespace(data={}), get_cached_remote_contract=lambda _service_id: None)
    monkeypatch.setattr(
        "nexus_light_agent.command_server.find_processes",
        lambda _match: [{"pid": 4162832, "cmdline": "java -jar txn-mobile-ussd-0.0.1-SNAPSHOT.jar"}],
    )
    monkeypatch.setattr(
        "nexus_light_agent.command_server.host_snapshot",
        lambda _log_path: {"hostname": "ussd-ate-test", "memory": {"available_mb": 12000}},
    )
    monkeypatch.setattr(
        "nexus_light_agent.command_server.resource_pressure",
        lambda _host, _load, _memory: {"collector_mode": "normal"},
    )

    result = _execute_diagnostic_command(agent, service, {"command_id": "runtime_status"})

    assert result["status"] == "COMPLETED"
    assert result["output"]["runtime_state"] == "running"
    assert result["output"]["process_count"] == 1
    assert result["output"]["resource_pressure"]["collector_mode"] == "normal"


def test_spring_server_port_is_discovered_from_application_yml(tmp_path):
    config_path = tmp_path / "application.yml"
    config_path.write_text(
        """
spring:
  application:
    name: txn-mobile-ussd
server:
  port: 8091
""",
        encoding="utf-8",
    )

    assert _discover_spring_server_port(str(config_path)) == 8091


def test_builtin_spring_start_uses_manual_script_style_working_dir(tmp_path, monkeypatch):
    jar_path = tmp_path / "txn-mobile-ussd-0.0.1-SNAPSHOT.jar"
    config_path = tmp_path / "application.yml"
    working_dir = tmp_path / "srv"
    jar_path.write_text("jar", encoding="utf-8")
    config_path.write_text("server:\n  port: 8091\n", encoding="utf-8")
    working_dir.mkdir()
    captured: dict[str, object] = {}

    class FakeProcess:
        pid = 9876

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["cwd"] = kwargs.get("cwd")
        captured["stderr"] = kwargs.get("stderr")
        return FakeProcess()

    monkeypatch.setattr("nexus_light_agent.command_server.find_processes", lambda _match: [])
    monkeypatch.setattr("nexus_light_agent.command_server.subprocess.Popen", fake_popen)

    result = _start_spring_boot_service(
        {
            "java_bin": "java",
            "jar_path": str(jar_path),
            "config_path": str(config_path),
            "process_match": "txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
            "working_dir": str(working_dir),
        }
    )

    assert result["return_code"] == 0
    assert captured["command"][:3] == ["nohup", "java", "-jar"]
    assert captured["cwd"] == str(working_dir)


def test_builtin_spring_start_fails_if_manual_working_dir_is_missing(tmp_path, monkeypatch):
    jar_path = tmp_path / "txn-mobile-ussd-0.0.1-SNAPSHOT.jar"
    config_path = tmp_path / "application.yml"
    missing_working_dir = tmp_path / "srv"
    jar_path.write_text("jar", encoding="utf-8")
    config_path.write_text("server:\n  port: 8091\n", encoding="utf-8")
    monkeypatch.setattr("nexus_light_agent.command_server.find_processes", lambda _match: [])

    result = _start_spring_boot_service(
        {
            "java_bin": "java",
            "jar_path": str(jar_path),
            "config_path": str(config_path),
            "process_match": "txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
            "working_dir": str(missing_working_dir),
        }
    )

    assert result["return_code"] == 127
    assert "Working directory does not exist" in "\n".join(result["stderr"])


def test_txn_mobile_ussd_helper_mirrors_manual_start_contract():
    script = Path("nexus_light_agent/control_helpers/txn-mobile-ussd/start.sh").read_text(encoding="utf-8")

    assert 'WORKING_DIR="/srv"' in script
    assert 'READINESS_PORT="8091"' in script
    assert 'cd "$WORKING_DIR"' in script
    assert "systemd-run" in script
    assert "--unit=\"$SYSTEMD_UNIT\"" in script
    assert 'nohup "$JAVA_BIN" -jar "$JAR_PATH" --spring.config.location="$CONFIG_PATH"' in script
    assert "stop_existing_processes" in script
    assert "verify_launch_context" in script


def test_txn_mobile_ussd_stop_helper_cleans_transient_unit():
    script = Path("nexus_light_agent/control_helpers/txn-mobile-ussd/stop.sh").read_text(encoding="utf-8")

    assert 'SYSTEMD_UNIT="sentinel-nexus-${SERVICE_NAME}"' in script
    assert 'systemctl stop "${SYSTEMD_UNIT}.service"' in script
    assert 'systemctl reset-failed "${SYSTEMD_UNIT}.service"' in script


def test_txn_ussd_adapter_helper_mirrors_manual_start_contract():
    script = Path("nexus_light_agent/control_helpers/txn-ussd-adapter/start.sh").read_text(encoding="utf-8")
    stop_script = Path("nexus_light_agent/control_helpers/txn-ussd-adapter/stop.sh").read_text(encoding="utf-8")

    assert 'SERVICE_NAME="txn-ussd-adapter"' in script
    assert 'WORKING_DIR="/srv"' in script
    assert 'CONFIG_PATH="/srv/afc/txn-mobile/txn-ussd-adapter/etc/application.yml"' in script
    assert "discover_readiness_port" in script
    assert "systemd-run" in script
    assert "--unit=\"$SYSTEMD_UNIT\"" in script
    assert 'SYSTEMD_UNIT="sentinel-nexus-${SERVICE_NAME}"' in stop_script
    assert 'systemctl stop "${SYSTEMD_UNIT}.service"' in stop_script


def test_restart_policy_ignores_unverified_control_history_for_cooldown(monkeypatch):
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
    state = {
        "restart_history": {
            service.service_id: {
                "operation": "stop",
                "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "verified": False,
            }
        }
    }

    allowed, reasons = _restart_allowed(contract, service, state, operation="stop")

    assert allowed is True
    assert reasons == []


def test_restart_policy_does_not_cooldown_start_after_verified_stop(monkeypatch):
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
    state = {
        "restart_history": {
            service.service_id: {
                "operation": "stop",
                "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "verified": True,
            }
        }
    }

    allowed, reasons = _restart_allowed(contract, service, state, operation="start")

    assert allowed is True
    assert reasons == []


def test_restart_policy_cooldown_blocks_restart_only_after_verified_restart(monkeypatch):
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
    state = {
        "restart_history": {
            service.service_id: {
                "operation": "restart",
                "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "verified": True,
            }
        }
    }

    start_allowed, start_reasons = _restart_allowed(contract, service, state, operation="start")
    stop_allowed, stop_reasons = _restart_allowed(contract, service, state, operation="stop")
    restart_allowed, restart_reasons = _restart_allowed(contract, service, state, operation="restart")

    assert start_allowed is True
    assert start_reasons == []
    assert stop_allowed is True
    assert stop_reasons == []
    assert restart_allowed is False
    assert any("cooldown" in reason.lower() for reason in restart_reasons)


def test_agent_can_derive_builtin_spring_boot_control_from_contract_metadata(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_API_TOKEN", "test-token")
    config = config_template()
    config["services"][0]["jar_path"] = None
    config["services"][0]["config_path"] = None
    config["services"][0]["start_command"] = []
    config["services"][0]["stop_command"] = []
    config["services"][0]["restart_command"] = []
    settings = AgentSettings.from_dict(config)
    service = settings.enabled_services[0]
    contract = {
        "service": {
            "metadata": {
                "jar_path": "/srv/afc/txn-mobile/txn-mobile-ussd/lib/txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
                "config_path": "/srv/afc/txn-mobile/txn-mobile-ussd/etc/application.yml",
                "process_match": "txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
            }
        }
    }

    command = _control_command(service, "stop", contract)

    assert command == [BUILTIN_SPRING_BOOT_CONTROL, "stop"]
