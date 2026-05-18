# Sentinel Nexus Light Agent - Mobile Banking USSD

This is the first production-shaped Nexus light agent. It is designed for dense Linux application servers where many Java services share the same host, so the agent is one small host process that can watch multiple configured services. The first enabled service is `txn-mobile-ussd`.

## Why This Shape

- It reads service process state from `/proc`, not from expensive shell pipelines.
- It tails only bounded increments of configured logs and skips low-value noise.
- It sends heartbeats and probe reports to Nexus using the dedicated agent token path, not a frontend user session.
- It spools only a small bounded queue when Nexus is unreachable.
- It can expose a token-protected command surface for allowlisted diagnostics and certified guarded restart.
- It cannot execute arbitrary commands from Nexus, an operator note, a log line, or a request payload.
- It throttles log reads when host load or memory pressure is high.

## First Service Contract

`txn-mobile-ussd` is configured from the Mobile Banking inventory:

- JAR marker: `txn-mobile-ussd-0.0.1-SNAPSHOT.jar`
- Log path: `/srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log`
- Cluster: `mobile-banking-ate`
- Business flow: `mobile-ussd-balance-enquiry`
- Nexus instance: `ussd-ate-test:txn-mobile-ussd`

## What The Agent Sends

The agent sends one probe report per configured service:

- local process count, PID, CPU delta, RSS, JVM command marker, thread count
- host load, memory availability, swap usage, root/log filesystem usage
- bounded log signature evidence including Hikari leaks, SQLSTATE, Oracle errors, timeouts, connectivity failures, exceptions, and out-of-memory symptoms
- failure domain hints such as `database`, `dependency`, `network_or_dependency`, `host`, or `service_runtime`
- service status: `up`, `degraded`, or `down`

## USSD-Specific Session Intelligence

`txn-mobile-ussd` has an additional `mobile_ussd` analysis profile because USSD failure semantics are different from ordinary HTTP services. A service can be running locally and reachable on its local port while the external USSD tunnel/session path is failing from the customer side.

The profile watches for `Expiring session with key` patterns, but it does not treat every expiry as an outage. A single expiry, or a low number of expiries, can simply mean a customer did not respond before the USSD session timeout. Nexus should only treat expiry evidence as degradation when it looks like a burst.

Default burst gates:

- at least 10 expiries inside a 60 second window, or a compact burst of at least 5 expiries inside 10 seconds
- at least 2 carriers represented, for example `econet` and `netone`
- expiry-to-session-response ratio at or above 0.25 when session responses are visible in the same bounded log window

When the burst gate passes, the agent emits a redacted `ussd_session_expiry_burst` log signature with failure domain `channel_tunnel`. It includes counts, carrier names, burst window, and ratio evidence, but it does not ship subscriber numbers or raw session keys.

This signal means: local runtime may be healthy, but the USSD channel/session path may be impaired. Nexus should correlate it with Network Sentinel, customer-impact reports, local process state, DB evidence, and downstream integration evidence before recommending action.

Service profile configuration:

```json
{
  "service_id": "txn-mobile-ussd",
  "agent_id": "agent-txn-mobile-ussd-ate-01",
  "environment": "ate",
  "analysis_profile": "mobile_ussd",
  "analysis_config": {
    "session_expiry_burst_window_seconds": 60,
    "session_expiry_warn_threshold": 10,
    "session_expiry_critical_threshold": 30,
    "session_expiry_min_carriers": 2,
    "session_expiry_ratio_warn": 0.25,
    "session_expiry_compact_window_seconds": 10,
    "session_expiry_compact_threshold": 5
  }
}
```

## Command Surface

The command surface is disabled by default. Enable it only when the service has been reviewed and Nexus is ready to dispatch diagnostics or restart through a controlled URL.

Optional local endpoints:

```text
GET  /health
POST /diagnostics
POST /restart
```

All command requests must include:

```text
X-Nexus-Agent-Id: <agent_id>
X-Nexus-Agent-Token: <NEXUS_AGENT_API_TOKEN>
```

Diagnostics are accepted only when the service is certified as `diagnostics_ready` or `restart_ready` in Nexus. The agent executes only known diagnostic command IDs and returns results through the Nexus diagnostic-results API.

Restart is accepted only when all gates pass:

- The service exists in the local agent configuration.
- Nexus reports the service as `restart_ready`.
- `restart_policy.allow_restart=true`.
- `restart_policy.allowed_service_types` includes the service type.
- The service is stateless.
- The service is not `db`, `database`, `cache`, `queue`, `auth`, or `infra`.
- The service is not marked as a shared database/dependency service.
- The local cooldown window is clear.
- The local config has a `systemd_unit` or explicit `restart_command`.

The restart request payload cannot supply a command. The command must be preconfigured locally on the server.

## Install Layout

Recommended production layout:

```text
/opt/sentinel-nexus-agent/venv
/etc/sentinel-nexus-agent/txn-mobile-ussd.json
/etc/sentinel-nexus-agent/txn-mobile-ussd.env
/var/lib/sentinel-nexus-agent
/var/log/sentinel-nexus-agent
```

The env file must contain only the Nexus agent token:

```bash
NEXUS_AGENT_API_TOKEN=replace-with-the-token-configured-on-sentinelops-ai
```

## Start With One Service

Use the template at:

```text
sentinelops-ai/nexus_light_agent/examples/txn-mobile-ussd.agent.json
```

Before starting the service, replace:

- `nexus_base_url` with the reachable SentinelOps AI/Nexus Core URL from the ATE server.
- `log_path` if the ATE log root differs from `/srv/log/ate`.
- `process_match` if the deployed JAR marker differs.
- `agent_id` if this host has a different role or environment.
- `analysis_config` thresholds after a short ATE-test observation period if normal daytime expiry volume proves different.
- `command_server.enabled`, `bind_host`, and `public_base_url` only if Nexus will dispatch diagnostics or certified restart to this agent.
- `systemd_unit` or `restart_command` only after the service is approved for guarded restart.

## Validate Safely

Run validation:

```bash
python -m nexus_light_agent --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json --validate-config
```

Run one collection cycle without daemonizing:

```bash
python -m nexus_light_agent --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json --once
```

Then confirm in Nexus:

- agent heartbeat appears for `agent-ate-mobile-banking-01`
- `txn-mobile-ussd` receives local runtime evidence
- log signatures are attached to incidents only when real evidence exists
- no fake incidents or seeded signals are created by the agent

## Systemd

Use the unit template:

```text
sentinelops-ai/nexus_light_agent/systemd/sentinel-nexus-agent.service
```

The unit intentionally limits resource usage:

- `CPUQuota=2%`
- `MemoryMax=128M`
- `Nice=10`
- read-only access to `/proc`, `/srv/log`, and `/srv/afc`
- write access only to agent state and agent logs

If restart execution is enabled, grant the agent only the narrow permission needed to restart the exact certified service. Prefer a dedicated systemd unit permission or a tightly scoped sudoers rule for one command. Do not grant general shell, broad systemctl, or root-equivalent access.

## Operational Guardrails

- Do not run one agent process per service on ATE. Add services to the same host agent config.
- Do not point the agent at broad log folders. Use exact service log files.
- Do not lower the poll interval below 30 seconds on dense production hosts.
- Do not add request-driven shell diagnostics to this agent. Diagnostics and restart remain Nexus-controlled, audited, allowlisted, and policy-gated.
- Do not enable restart until the service is certified `restart_ready` in Nexus and the local command has been tested in ATE-test.
- Do not use this token in browser/frontend contexts. It is only for server-side agent ingestion.

## Next Services

After `txn-mobile-ussd` is stable, add one service at a time to the same `services` array. Start with adjacent Mobile Banking services whose logs and process markers are already known, then add `txn-integration-idc` because it is the exact banking-core integration path.
