# Sentinel Nexus Light Agent: ATE Test Launch Manual

This runbook launches the Sentinel Nexus light agent for `txn-mobile-ussd` on `ussd-ate-test` and explains exactly what belongs in the Nexus service contract. The goal is fast real evidence without guessing, fake data, arbitrary shell access, or unnecessary host load.

## 0. Non-negotiable launch rule

Do not invent URLs. If a URL is not verified, leave it blank in Nexus.

For v1 collection, the light agent does not need separate collector, extraction, formatting, or shipping URLs. It posts directly to Nexus Core using:

```text
http://192.168.203.53:8010/api/v1/nexus/agents/heartbeat
http://192.168.203.53:8010/api/v1/nexus/agents/probe-report
```

The local config only needs `nexus_base_url`. The agent derives the API paths internally.

## 1. Exact Nexus service contract for txn-mobile-ussd

Open `Nexus -> Services -> Mobile Banking USSD -> Edit`.

### Service identity

Use these values:

| Field | Value |
| --- | --- |
| Service ID | `txn-mobile-ussd` |
| Service Name | `Mobile Banking USSD` |
| Environment | `ate` |
| Service Type | `channel` |
| Criticality | `critical` or the approved production value |
| Owner Team | Mobile Banking / Digital Channels owner team |
| Cluster | `mobile-banking-ate` |
| Lifecycle Stage | `correlate_ready` for first launch; move to `diagnostics_ready` only after command server approval |
| Allow Diagnostics | `true` is acceptable, but diagnostics still stay blocked until lifecycle and URL gates pass |
| Stateless | keep the certified value only; do not mark stateless unless the service owner confirms it |

### Observation Mapping

Use these values:

| Field | Value | Why |
| --- | --- | --- |
| Network Service UUID | `67426a23-8c96-499c-9f03-dc644537b80e` | Bridges Network Sentinel external reachability to local runtime evidence |
| Agent ID | `agent-txn-mobile-ussd-ate-01` | Must exactly match the local agent config |
| Systemd Unit | blank for now | `main.sh` manages the Java service; do not invent a unit |
| Host Group | `ussd-ate-test` | Stable host/group identity for ATE |
| Log Selector | `{service="txn-mobile-ussd", environment="ate"}` | Loki-style selector for future log backend correlation |
| Metrics Namespace | `txn_mobile_ussd` | Stable metrics prefix if/when actuator/Prometheus metrics are exposed |
| Trace Service Name | `txn-mobile-ussd` | OTel trace service identity if tracing is later enabled |
| Preferred Signal Source | `agent` | Local runtime evidence should outrank external-only reachability for runtime diagnosis |

### Execution and Shipping URLs

Use these values now:

| Field | Value now | How to change later |
| --- | --- | --- |
| Collector URL | `http://192.168.203.53:8010/api/v1/nexus/agents/probe-report` | Informational. The agent itself only needs `nexus_base_url`. |
| Healthcheck URL | blank | Set only after verifying a real local health endpoint, for example `http://127.0.0.1:<port>/actuator/health`. |
| Metrics URL | blank | Set only after verifying a real metrics endpoint, for example `http://127.0.0.1:<port>/actuator/prometheus`. |
| Logs URL | `file:///srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log` | Exact local log file the agent tails. |
| Traces URL | blank | Set only when a trace backend or service trace query URL exists. |
| Diagnostics URL | blank for first launch | Later: `http://<approved-agent-host-or-ip>:8765/diagnostics` after command server is approved and reachable only from Nexus Core. |
| Restart URL | blank | Later: `http://<approved-agent-host-or-ip>:8765/restart` only after `restart_ready`, stateless certification, local restart command approval, and operator approval path testing. |
| Extraction URL | blank | Not used by v1 light agent. |
| Formatting URL | blank | Not used by v1 light agent. |
| Shipping URL | blank | Not used by v1 light agent. |
| Dashboard URL | optional | If desired, use the Network Sentinel deep link for this UUID or leave blank. |

### Metadata JSON

Use this as the initial metadata block:

```json
{
  "agent_launch_phase": "ate_test_runtime_evidence",
  "agent_host": "ussd-ate-test",
  "nexus_core_url": "http://192.168.203.53:8010",
  "agent_config_path": "/etc/sentinel-nexus-agent/txn-mobile-ussd.json",
  "agent_state_dir": "/var/lib/sentinel-nexus-agent",
  "agent_log_file": "/var/log/sentinel-nexus-agent/agent.log",
  "process_marker": "txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
  "runtime_log_path": "/srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log",
  "network_service_uuid": "67426a23-8c96-499c-9f03-dc644537b80e",
  "analysis_profile": "mobile_ussd",
  "command_server_status": "disabled_until_diagnostics_or_restart_approval",
  "evidence_contract": [
    "local_process_state",
    "bounded_log_signatures",
    "host_resource_pressure",
    "mobile_ussd_session_expiry_burst",
    "network_sentinel_external_reachability"
  ],
  "safety_notes": [
    "no arbitrary shell",
    "no autonomous restart",
    "diagnostics_url blank until command server approval",
    "restart_url blank until restart_ready certification"
  ]
}
```

## 2. Generate and protect the agent token

1. Open SentinelOps.
2. Go to `Nexus -> Onboarding`.
3. In `Agent Trust Gate`, click `Generate Token`.
4. If a token already exists:
   - choose `Cancel` to keep the deployed token,
   - choose `OK` only if you are rotating and will update every deployed agent immediately.
5. Copy the generated token immediately. Nexus stores only a salted hash.

Use the copied token only as the ATE host environment value:

```text
NEXUS_AGENT_API_TOKEN=<copied-token>
```

Do not paste the token into `agent_token_env`. `agent_token_env` must remain the variable name `NEXUS_AGENT_API_TOKEN`.

## 3. Verify the ATE host facts before writing config

Run these on `ussd-ate-test`.

### Confirm Nexus Core connectivity

```bash
nc -zv 192.168.203.53 8010
curl -fsS http://192.168.203.53:8010/health
```

Expected:

- TCP connection succeeds.
- `/health` returns Nexus healthy or degraded but with `database_connected=true` and `schema_ready=true`.
- If `agent_auth_configured=false`, generate the token in Nexus before continuing.

### Confirm the Java process marker

```bash
pgrep -af 'txn-mobile-ussd|txn-mobile-ussd-0.0.1-SNAPSHOT.jar'
```

Expected:

- At least one Java command includes `txn-mobile-ussd-0.0.1-SNAPSHOT.jar`.
- If not, do not launch yet. Capture the real command line and update `process_match`.

### Confirm the log file exists and is readable

```bash
test -r /srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log && echo readable
stat /srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log
tail -n 5 /srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log
```

Expected:

- `readable` is printed.
- The file is the active USSD human log.
- If the future systemd user cannot read it, grant read access to the exact log file/path, not broad filesystem access.

### Discover health and metrics only if they really exist

Do not set `healthcheck_url` or `metrics_url` until this is proven.

```bash
grep -nE 'server:|port:|management:|actuator|prometheus|context-path' /srv/afc/txn-mobile/txn-mobile-ussd/etc/application.yml
ss -lntp | grep -E 'java|txn-mobile-ussd' || true
```

If a port is found, test likely Spring Boot endpoints:

```bash
curl -fsS http://127.0.0.1:<port>/actuator/health
curl -fsS http://127.0.0.1:<port>/actuator/prometheus | head
```

Only after a successful `curl`, set:

- `services[0].healthcheck_url` in the local agent config.
- `Healthcheck URL` in Nexus.
- `Metrics URL` in Nexus if `/actuator/prometheus` works.

## 4. Create the local agent config

Create the config directory:

```bash
sudo install -d -m 0750 /etc/sentinel-nexus-agent
sudo install -d -m 0750 /var/lib/sentinel-nexus-agent
sudo install -d -m 0750 /var/log/sentinel-nexus-agent
```

Write `/etc/sentinel-nexus-agent/txn-mobile-ussd.json`:

```bash
sudo tee /etc/sentinel-nexus-agent/txn-mobile-ussd.json >/dev/null <<'JSON'
{
  "agent_id": "agent-txn-mobile-ussd-ate-01",
  "environment": "ate",
  "nexus_base_url": "http://192.168.203.53:8010",
  "agent_token_env": "NEXUS_AGENT_API_TOKEN",
  "poll_interval_seconds": 30,
  "heartbeat_interval_seconds": 60,
  "config_refresh_interval_seconds": 300,
  "http_timeout_seconds": 5,
  "state_dir": "/var/lib/sentinel-nexus-agent",
  "log_file": "/var/log/sentinel-nexus-agent/agent.log",
  "resource_guard": {
    "nice": 10,
    "max_log_bytes_per_cycle": 65536,
    "max_log_lines_per_cycle": 80,
    "initial_tail_bytes": 65536,
    "high_load_per_core": 0.85,
    "critical_load_per_core": 1.2,
    "min_available_memory_mb": 1024,
    "spool_max_records": 200
  },
  "command_server": {
    "enabled": false,
    "bind_host": "127.0.0.1",
    "port": 8765,
    "public_base_url": null,
    "request_timeout_seconds": 8
  },
  "services": [
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
      "restart_command": [],
      "restart_settle_seconds": 5,
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
  ]
}
JSON
sudo chmod 0640 /etc/sentinel-nexus-agent/txn-mobile-ussd.json
```

If a verified health endpoint exists, replace `"healthcheck_url": null` with the verified local URL.

## 5. Configure the token on ATE

For an immediate foreground test:

```bash
export NEXUS_AGENT_API_TOKEN='<paste-token-here>'
```

For systemd later:

```bash
sudo sh -c "printf 'NEXUS_AGENT_API_TOKEN=%s\n' '<paste-token-here>' > /etc/sentinel-nexus-agent/txn-mobile-ussd.env"
sudo chmod 0600 /etc/sentinel-nexus-agent/txn-mobile-ussd.env
```

## 6. Validate config without collecting

Because the current ATE folder is a direct package folder, use the file entrypoint:

```bash
cd /home/ashumba/Nexus-Light
python3 __main__.py --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json --validate-config
```

Expected output:

```json
{
  "valid": true,
  "agent_id": "agent-txn-mobile-ussd-ate-01",
  "nexus_base_url": "http://192.168.203.53:8010",
  "services": ["txn-mobile-ussd"]
}
```

If it fails with token missing, re-check `export NEXUS_AGENT_API_TOKEN=...`.

If it fails with import errors, use the fixed `__main__.py` from the current repository or run from the parent directory as a package after installation.

## 7. Run one evidence cycle

```bash
cd /home/ashumba/Nexus-Light
python3 __main__.py --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json --once
```

Expected output:

```json
{
  "reports": 1,
  "services": ["txn-mobile-ussd"]
}
```

Then check the agent log:

```bash
tail -n 80 /var/log/sentinel-nexus-agent/agent.log
```

No `401`, `404`, or `spooled` messages should appear.

## 8. Confirm in Nexus

In SentinelOps:

1. Open `Nexus -> Onboarding`.
2. Confirm `agent-txn-mobile-ussd-ate-01` shows recent use/heartbeat.
3. Open `Nexus -> Services -> Mobile Banking USSD`.
4. Confirm local-agent evidence is visible.
5. Open service timeline and confirm evidence source distinguishes:
   - `network_sentinel` for external reachability,
   - `nexus_light_agent` for local runtime/process/log evidence.

Good first result:

- process count is captured,
- host resource pressure is captured,
- log window metadata is captured,
- low-volume USSD expiries are observations, not incidents,
- burst USSD expiries become `channel_tunnel` evidence only when thresholds are crossed.

## 9. Only after one clean foreground cycle: daemonize

For a fast ATE daemon using the existing folder, create a temporary systemd unit:

```bash
sudo tee /etc/systemd/system/sentinel-nexus-agent-txn-mobile-ussd.service >/dev/null <<'UNIT'
[Unit]
Description=Sentinel Nexus Light Agent - txn-mobile-ussd ATE
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ashumba
Group=ashumba
EnvironmentFile=/etc/sentinel-nexus-agent/txn-mobile-ussd.env
WorkingDirectory=/home/ashumba/Nexus-Light
ExecStart=/usr/bin/python3 /home/ashumba/Nexus-Light/__main__.py --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json
Restart=always
RestartSec=15
Nice=10
CPUQuota=2%
MemoryMax=128M
IOSchedulingClass=best-effort
IOSchedulingPriority=7
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-nexus-agent-txn-mobile-ussd.service
sudo systemctl status sentinel-nexus-agent-txn-mobile-ussd.service --no-pager
```

Production hardening should later move the package to `/opt/sentinel-nexus-agent`, run as a dedicated `sentinelnexus` user, and use the hardened unit in `nexus_light_agent/systemd/sentinel-nexus-agent.service`.

## 10. Diagnostics and restart are separate phases

Keep this for first launch:

```json
"command_server": {
  "enabled": false
}
```

Do not set `Diagnostics URL` or `Restart URL` in Nexus until command server approval is complete.

When diagnostics are approved:

1. Determine the ATE host IP reachable from Nexus Core:

   ```bash
   hostname -I
   ```

2. Enable command server with a controlled bind address.
3. Firewall port `8765` so only Nexus Core `192.168.203.53` can reach it.
4. Set Nexus `Diagnostics URL` to:

   ```text
   http://<approved-agent-host-ip-or-dns>:8765/diagnostics
   ```

5. Move lifecycle stage to `diagnostics_ready`.

Restart comes after that and remains blocked until:

- `service_type` is restart-capable,
- `is_stateless=true` is certified,
- lifecycle is `restart_ready`,
- `restart_policy.allow_restart=true`,
- `allowed_service_types` includes `channel`,
- local `systemd_unit` or fixed `restart_command` is approved,
- Nexus operator approval path is tested,
- cooldown policy is accepted.

Only then set:

```text
Restart URL = http://<approved-agent-host-ip-or-dns>:8765/restart
```

## 11. Troubleshooting map

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `401 Invalid Nexus agent credentials` | Wrong token, token not generated, or env var not exported | Generate token, export `NEXUS_AGENT_API_TOKEN`, retry |
| `404 Unknown Nexus service` | `service_id` missing in Nexus catalog or typo | Confirm `txn-mobile-ussd` exists in Nexus services |
| Agent reports but no heartbeat | First run was too soon after heartbeat interval or heartbeat failed | Run `--once` again after 60 seconds, check log |
| `remote config unavailable` | Agent ID mismatch, token issue, or service not allowlisted | Confirm Nexus Agent ID equals `agent-txn-mobile-ussd-ate-01` |
| Process down but service is actually up | Wrong `process_match` | Use `pgrep -af` output and update marker |
| Log signatures missing | Log path unreadable, rotated, or wrong file | Verify `test -r`, `stat`, and `tail` as the agent user |
| Too much load | Poll interval too low or log bytes too high | Keep 30s poll, 64KB/80-line limit, nice 10, CPUQuota 2% |

## 12. What to send back after first run

Send these outputs for review:

```bash
python3 /home/ashumba/Nexus-Light/__main__.py --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json --validate-config
python3 /home/ashumba/Nexus-Light/__main__.py --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json --once
tail -n 80 /var/log/sentinel-nexus-agent/agent.log
pgrep -af 'txn-mobile-ussd|txn-mobile-ussd-0.0.1-SNAPSHOT.jar'
stat /srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log
```

Redact only the token. Do not redact service IDs, hostnames, paths, or error messages.
