# Sentinel Nexus Light Agent ATE Operations Runbook

This runbook is the source of truth for the current ATE Nexus light-agent rollout on `ussd-ate-test`.

Update this document every time a service is added, a control path changes, or a validation result proves a better operating pattern. The production runbook must be copied from known-good ATE evidence, not from memory.

## Current ATE Agent

One host should run one Nexus light agent for the ATE Mobile Banking services on that server.

```text
agent_id: agent-txn-mobile-ussd-ate-01
host_group: ussd-ate-test
command_server: http://192.168.4.13:8765
local_config: /etc/nexus-light/txn-mobile-ussd.json
systemd_unit: nexus-light-txn-mobile-ussd.service
state_dir: /var/lib/sentinel-nexus-agent
log_file: /var/log/sentinel-nexus-agent/agent.log
```

Do not deploy one agent per service on the same host. Add each new ATE service to the same `services` array.

## Control Script Rule

Yes, each service that Nexus can START, STOP, or RESTART needs its own narrow allowlisted control scripts.

That is intentional. The scripts are the security boundary:

- Nexus cannot send arbitrary shell commands.
- The light-agent user only receives `sudo -n` access to exact root-owned files.
- Each service has exact jar, config, log, working directory, process marker, and transient systemd unit names.
- A bad or stale process is replaced only when it does not match the manual-good launch context.

The shared pattern is:

```text
/opt/sentinel-nexus-control/<service-id>/start.sh
/opt/sentinel-nexus-control/<service-id>/stop.sh
/opt/sentinel-nexus-control/<service-id>/restart.sh
```

The sudoers line must name exact script paths. Do not allow wildcards, broad `systemctl`, shell interpreters, or directories.

## Why Nexus Uses systemd-run

The manual ATE script starts services from `/srv` with:

```bash
nohup java -jar <jar> --spring.config.location=<application.yml> &
```

When the light agent calls a helper, plain `nohup` can leave the Java child inside the light-agent systemd cgroup. The agent unit is deliberately constrained, so the application may appear as a running process but fail to open its port quickly or at all.

The fixed Nexus helper keeps the manual launch command shape but delegates the Java process to a transient unit:

```bash
systemd-run --unit="sentinel-nexus-<service-id>" --collect --quiet --property=Restart=no \
  /bin/bash -lc "cd /srv && exec java -jar <jar> --spring.config.location=<application.yml> >>/srv/nohup.out 2>&1"
```

Expected post-start checks:

```bash
pid="$(pgrep -f '<service-id>-0.0.1-SNAPSHOT.jar' | head -n 1)"
readlink -f "/proc/${pid}/cwd"
systemctl status "sentinel-nexus-<service-id>.service" --no-pager -l
```

The cwd must be `/srv`.

## Service 1: Mobile Banking USSD

Local agent service block:

```json
{
  "service_id": "txn-mobile-ussd",
  "service_name": "Mobile Banking USSD",
  "environment": "ate",
  "cluster_id": "mobile-banking-ate",
  "business_flow_id": "mobile-ussd-balance-enquiry",
  "instance_id": "ussd-ate-test:txn-mobile-ussd",
  "expected_running": true,
  "process_match": "txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
  "log_path": "/srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log",
  "healthcheck_url": null,
  "systemd_unit": null,
  "jar_path": "/srv/afc/txn-mobile/txn-mobile-ussd/lib/txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
  "config_path": "/srv/afc/txn-mobile/txn-mobile-ussd/etc/application.yml",
  "java_bin": "java",
  "working_dir": "/srv",
  "readiness_host": "127.0.0.1",
  "readiness_port": 8091,
  "start_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/start.sh"],
  "stop_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/stop.sh"],
  "restart_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/restart.sh"],
  "restart_settle_seconds": 30,
  "tags": ["mobile-banking", "ussd", "channel"],
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

Validated control result:

```text
STOP: verified, no matching process visible.
START: verified, matching process running and TCP readiness open on 127.0.0.1:8091.
```

## Service 2: USSD Adapter

Manual ATE source from `/srv/main.sh`:

```text
USSD_ADAPTER_SERVICE_NAME=txn-ussd-adapter
USSD_ADAPTER_JAR=/srv/afc/txn-mobile/txn-ussd-adapter/lib/txn-ussd-adapter-0.0.1-SNAPSHOT.jar
USSD_ADAPTER_JAR_PROP=/srv/afc/txn-mobile/txn-ussd-adapter/etc/application.yml
USSD_ADAPTER_LOG=/srv/log/ate/txn-mobile/txn-ussd-adapter/txn-ussd-adapter-human.log
```

Local agent service block to add under `services[]`:

```json
{
  "service_id": "txn-ussd-adapter",
  "service_name": "USSD Adapter",
  "environment": "ate",
  "cluster_id": "mobile-banking-ate",
  "business_flow_id": "mobile-ussd-balance-enquiry",
  "instance_id": "ussd-ate-test:txn-ussd-adapter",
  "expected_running": true,
  "process_match": "txn-ussd-adapter-0.0.1-SNAPSHOT.jar",
  "log_path": "/srv/log/ate/txn-mobile/txn-ussd-adapter/txn-ussd-adapter-human.log",
  "healthcheck_url": null,
  "systemd_unit": null,
  "jar_path": "/srv/afc/txn-mobile/txn-ussd-adapter/lib/txn-ussd-adapter-0.0.1-SNAPSHOT.jar",
  "config_path": "/srv/afc/txn-mobile/txn-ussd-adapter/etc/application.yml",
  "java_bin": "java",
  "working_dir": "/srv",
  "readiness_host": "127.0.0.1",
  "readiness_port": null,
  "start_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/start.sh"],
  "stop_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh"],
  "restart_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/restart.sh"],
  "restart_settle_seconds": 30,
  "tags": ["mobile-banking", "ussd", "adapter", "channel-adapter"],
  "analysis_profile": null,
  "analysis_config": {}
}
```

`readiness_port` is `null` until the actual adapter `server.port` is confirmed from the host. The light agent will attempt to discover it from `config_path`. If a concrete port exists, update both the local config and the Nexus service metadata.

Exact command to confirm the adapter port:

```bash
grep -nE '^[[:space:]]*server:|^[[:space:]]*port:' /srv/afc/txn-mobile/txn-ussd-adapter/etc/application.yml
```

Nexus service contract must use:

```text
observation_config.agent_id: agent-txn-mobile-ussd-ate-01
endpoint_config.collector_url: http://192.168.203.143:8010/api/v1/nexus/agents/probe-report
endpoint_config.logs_url: file:///srv/log/ate/txn-mobile/txn-ussd-adapter/txn-ussd-adapter-human.log
endpoint_config.diagnostics_url: http://192.168.4.13:8765/diagnostics
endpoint_config.restart_url: http://192.168.4.13:8765/control
restart_policy.allowed_service_types: app, worker, channel, channel_adapter
certification.lifecycle_stage: diagnostics_ready first, then restart_ready only after ATE control validation
```

Do not use `agent-txn-ussd-adapter-ate-01` for this host unless a second physical agent is actually deployed. The current ATE adapter is watched by `agent-txn-mobile-ussd-ate-01`.

## Adapter Remote Config 401

If the agent log shows this error:

```text
remote config unavailable for txn-ussd-adapter: Nexus returned HTTP 401
Agent 'agent-txn-mobile-ussd-ate-01' is not assigned to service 'txn-ussd-adapter'.
```

The local `/etc/nexus-light/txn-mobile-ussd.json` can still be correct. This error means the Nexus Core service contract stored in the Nexus database still assigns `txn-ussd-adapter` to a different agent ID.

Fix it in Nexus:

1. Open `Nexus -> Services -> USSD Adapter -> Contract Configuration`.
2. In `Observation Mapping`, set `Agent ID` to `agent-txn-mobile-ussd-ate-01`.
3. Set `Preferred Signal Source` to `agent`.
4. Set `Host Group` to `ussd-ate-test`.
5. Set `Log Selector` to `{service="txn-ussd-adapter", environment="ate"}`.
6. Set `Metrics Namespace` to `txn_ussd_adapter`.
7. Set `Trace Service Name` to `txn-ussd-adapter`.
8. In `Execution & Shipping URLs`, set `Collector URL` to `http://192.168.203.143:8010/api/v1/nexus/agents/probe-report`.
9. Set `Diagnostics URL` to `http://192.168.4.13:8765/diagnostics`.
10. Set `Restart URL` to `http://192.168.4.13:8765/control`.
11. Set `Logs URL` to `file:///srv/log/ate/txn-mobile/txn-ussd-adapter/txn-ussd-adapter-human.log`.
12. Save the service contract.

Verify from `ussd-ate-test`:

```bash
TOKEN="$(sudo awk -F= '/^NEXUS_AGENT_API_TOKEN=/{print $2}' /etc/nexus-light/txn-mobile-ussd.env)"
curl -fsS \
  -H "X-Nexus-Agent-Id: agent-txn-mobile-ussd-ate-01" \
  -H "X-Nexus-Agent-Token: $TOKEN" \
  "http://192.168.203.143:8010/api/v1/nexus/agents/agent-txn-mobile-ussd-ate-01/config?service_id=txn-ussd-adapter" | python3 -m json.tool
unset TOKEN
```

Expected result: HTTP 200 with `service_id` equal to `txn-ussd-adapter` and `observation_config.agent_id` equal to `agent-txn-mobile-ussd-ate-01`.

## Adapter Deployment Steps

Install helper scripts:

```bash
sudo install -d -o root -g root -m 0750 /opt/sentinel-nexus-control/txn-ussd-adapter
sudo install -o root -g root -m 0750 start.sh /opt/sentinel-nexus-control/txn-ussd-adapter/start.sh
sudo install -o root -g root -m 0750 stop.sh /opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh
sudo install -o root -g root -m 0750 restart.sh /opt/sentinel-nexus-control/txn-ussd-adapter/restart.sh
```

Validate helper syntax before enabling Nexus control:

```bash
sudo bash -n /opt/sentinel-nexus-control/txn-ussd-adapter/start.sh
sudo bash -n /opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh
sudo bash -n /opt/sentinel-nexus-control/txn-ussd-adapter/restart.sh
```

Sudoers must be narrow and command-specific. Create this exact allowlist:

```bash
sudo tee /etc/sudoers.d/sentinel-nexus-txn-ussd-adapter >/dev/null <<'SUDOERS'
ashumba ALL=(root) NOPASSWD: /opt/sentinel-nexus-control/txn-ussd-adapter/start.sh, /opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh, /opt/sentinel-nexus-control/txn-ussd-adapter/restart.sh
SUDOERS
sudo chmod 0440 /etc/sudoers.d/sentinel-nexus-txn-ussd-adapter
sudo visudo -cf /etc/sudoers.d/sentinel-nexus-txn-ussd-adapter
```

Validate:

```bash
sudo -n /opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh
sudo -n /opt/sentinel-nexus-control/txn-ussd-adapter/start.sh
pid="$(pgrep -f 'txn-ussd-adapter-0.0.1-SNAPSHOT.jar' | head -n 1)"
readlink -f "/proc/${pid}/cwd"
systemctl status sentinel-nexus-txn-ussd-adapter.service --no-pager -l
tail -n 80 /srv/log/ate/txn-mobile/txn-ussd-adapter/txn-ussd-adapter-human.log
```

Expected:

```text
/srv
Active: active
Adapter process visible through pgrep.
If server.port is declared, the port should listen and Nexus start verification should pass TCP readiness.
```

## Production Rule

Before production deployment, every service must have:

- exact jar path from the server startup script
- exact application config path
- exact log path
- exact process marker
- confirmed service owner expectation for `expected_running`
- confirmed readiness port or documented reason why no local port is expected
- exact root-owned helper scripts
- exact sudoers allowlist
- Nexus service contract pointing to the actual host agent ID
- diagnostics-ready validation before restart-ready certification
- one successful STOP and START in ATE using Nexus, not only manual shell

## Nexus Control UX Rule

Service START, STOP, and RESTART must run only through the service `Live Operations -> Service Control Gate`.

- The incident command view may link operators to Service Control, but it must not expose direct `Approve Restart` or `Reject Restart` execution buttons.
- The retired incident restart API path records a blocked audit action and tells callers to use the OTP-gated service control path.
- The control OTP modal auto-verifies once the operator enters six digits. The code is still single-use, email-bound, service-bound, and operation-bound.
- Restart cooldown applies to `restart` only. `start` and `stop` remain available according to runtime state and readiness gates.

## Nexus Log Tail Rule

ATE Java/Spring logs use timestamp headers followed by continuation payload lines:

```text
[2026-05-15 13:42:09.724] INFO  [o-8091-exec-582]
                m.s.r.ProfileRemoteServiceImpl ATE-Trace-ID=[...] - message payload
```

Nexus live log tail groups this as one timestamped log event, not two unrelated rows. The UI remains latest-first, but the bounded window counts grouped events instead of raw physical lines. Each grouped event may expose `physical_line_count` and `continuation_count` so operators can see when a readable row contains multiple file lines.
