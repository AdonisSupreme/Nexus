# Sentinel Nexus Light Agent Command Surface

This document is for implementers configuring the Nexus light agent on Linux service hosts. Operator-facing instructions belong in the SentinelOps UI guide; this file covers the backend and server-side mechanics.

## Design Contract

The agent has two separate responsibilities:

- Telemetry path: outbound heartbeat and probe reports to Nexus Core.
- Command path: optional inbound HTTP surface for Nexus-dispatched diagnostics and certified restart.

The command path is not a general remote shell. It accepts only token-authenticated Nexus requests and executes only local allowlisted actions configured on the host.

## Endpoints

```text
GET  /health
POST /diagnostics
POST /restart
```

Required headers:

```text
X-Nexus-Agent-Id: <agent_id>
X-Nexus-Agent-Token: <NEXUS_AGENT_API_TOKEN>
```

Nexus Core sends these headers automatically when `NEXUS_AGENT_API_TOKEN` is configured in `sentinelops-ai` and the service has `observation_config.agent_id`.

## Configuration Fields

Agent-level command configuration:

```json
{
  "command_server": {
    "enabled": true,
    "bind_host": "0.0.0.0",
    "port": 8765,
    "public_base_url": "http://ate-test-hostname:8765",
    "request_timeout_seconds": 8
  }
}
```

Service-level restart configuration:

```json
{
  "service_id": "txn-mobile-ussd",
  "systemd_unit": "txn-mobile-ussd.service",
  "restart_command": [],
  "restart_settle_seconds": 5
}
```

Use `systemd_unit` when possible. Use `restart_command` only for a preapproved fixed command array, never for request-provided input.

Service-level analysis profile configuration:

```json
{
  "service_id": "txn-mobile-ussd",
  "analysis_profile": "mobile_ussd",
  "analysis_config": {
    "session_expiry_burst_window_seconds": 60,
    "session_expiry_warn_threshold": 10,
    "session_expiry_min_carriers": 2
  }
}
```

Analysis profiles are service-specific. Do not copy the USSD profile to another service unless that service has the same session/tunnel semantics and its normal false-positive conditions have been reviewed.

## Nexus Service Requirements

For diagnostics:

- `endpoint_config.diagnostics_url` or cluster `routing_config.diagnostics_url` points to `http://<agent-host>:8765/diagnostics`.
- `observation_config.agent_id` matches the deployed agent ID.
- `allow_diagnostics=true`.
- `certification.lifecycle_stage` is `diagnostics_ready` or `restart_ready`.

For restart:

- `endpoint_config.restart_url` or cluster `routing_config.restart_url` points to `http://<agent-host>:8765/restart`.
- `observation_config.agent_id` matches the deployed agent ID.
- `certification.lifecycle_stage=restart_ready`.
- `restart_policy.allow_restart=true`.
- `restart_policy.allowed_service_types` includes the service type.
- `is_stateless=true`.
- The service is not `db`, `database`, `cache`, `queue`, `auth`, or `infra`.
- The service is not marked as a shared database/dependency service.
- The Nexus incident recommendation confidence and cooldown gates pass.

## Restart Execution Model

Nexus performs the policy decision first. The agent repeats the critical safety checks locally before accepting the command. The agent returns `202 Accepted` quickly, executes the local restart command in a background thread, records local restart history, and lets Nexus monitor recovery through subsequent probe reports.

This avoids long HTTP requests for Java services that may take longer than the Nexus dispatch timeout to settle.

## Permission Model

Run the agent as a dedicated service account. Grant only the exact privilege required for certified restart.

Acceptable patterns:

- A dedicated systemd/polkit permission to restart one named unit.
- A narrowly scoped sudoers rule for one exact command, used as a fixed `restart_command` array.

Forbidden patterns:

- General shell access.
- Broad `sudo systemctl *`.
- Root-equivalent agent permissions.
- Any command string supplied by a Nexus request payload.

## Rollback

Disable command execution without removing telemetry:

```json
{
  "command_server": {
    "enabled": false
  }
}
```

Then restart the agent. Nexus will continue receiving heartbeat/probe evidence, while diagnostics and restart dispatch become unavailable until URLs/certification are restored.
