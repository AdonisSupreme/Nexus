# Sentinel Nexus Light Agent ATE Runbook

This runbook is for launching the Nexus light agent on `ate-test` for the first monitored service, `txn-mobile-ussd`.

## Current Observation

The central Nexus Core is reachable from ATE:

```bash
nc -zv 192.168.203.53 8010
curl http://192.168.203.53:8010/health
```

The reported health shows:

- Nexus database is connected.
- Nexus schema is ready.
- Mistral inference is available.
- Agent authentication is required.
- Agent authentication is not yet configured on Nexus Core.

That last point matters. If `NEXUS_REQUIRE_AGENT_AUTH=true` and `NEXUS_AGENT_API_TOKEN` is not configured on the core, the light agent should not be considered ready for production ingestion yet.

## Why `python3 -m nexus_light_agent` Failed

The command failed with:

```text
/usr/bin/python3: No module named nexus_light_agent
```

This means Python cannot see a package named `nexus_light_agent` on its module path.

The files are currently inside:

```bash
~/Nexus-Light
```

but `python3 -m nexus_light_agent` only works if the parent directory contains a folder/package named:

```bash
nexus_light_agent/
```

The current folder appears to contain the package files directly, not inside a package folder with that exact name.

## Safe First Checks On ATE

Run these first and share the output before we certify the service:

```bash
cd ~/Nexus-Light
pwd
ls -la
python3 --version
python3 __main__.py --help
find . -maxdepth 2 -type f | sort
```

If `__main__.py` supports direct execution, validate the config with:

```bash
cd ~/Nexus-Light
python3 __main__.py --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json --validate-config
```

If it does not support direct execution, reshape the package layout:

```bash
cd ~
mv Nexus-Light nexus_light_agent
python3 -m nexus_light_agent --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json --validate-config
```

Only use the rename approach if `~/Nexus-Light` is not referenced by systemd or another deployment script yet.

## Nexus Core Agent Authentication

For test with authentication enabled, set the same token on both sides.

On Nexus Core:

```powershell
$env:NEXUS_REQUIRE_AGENT_AUTH="true"
$env:NEXUS_AGENT_API_TOKEN="<shared-agent-token>"
```

On ATE agent config:

```json
{
  "nexus_base_url": "http://192.168.203.53:8010",
  "agent_token": "<shared-agent-token>"
}
```

Never put the final token in chat or screenshots. Store it in a protected config file or environment file.

## Minimum `txn-mobile-ussd` Agent Contract

The service config must identify the exact service and what evidence it can safely collect:

```json
{
  "agent_id": "ate-test-txn-mobile-ussd-01",
  "service_id": "txn-mobile-ussd",
  "service_name": "TXN Mobile USSD",
  "environment": "ate-test",
  "nexus_base_url": "http://192.168.203.53:8010",
  "heartbeat_interval_seconds": 30,
  "probe_interval_seconds": 60,
  "process_markers": ["txn-mobile-ussd"],
  "log_files": ["/path/to/txn-mobile-ussd.log"],
  "service_profile": "txn_mobile_ussd",
  "diagnostics": {
    "enabled": true,
    "allowlisted_commands": [
      "process_summary",
      "recent_logs",
      "memory_summary",
      "disk_summary",
      "socket_summary",
      "health_check"
    ]
  },
  "restart": {
    "enabled": false,
    "requires_approval": true,
    "cooldown_minutes": 15,
    "command": ""
  }
}
```

Keep restart disabled until the service is certified as `restart_ready` in Nexus and the exact restart command is approved by the service owner.

## Running The Agent Manually

After config validation passes:

```bash
cd ~/Nexus-Light
python3 __main__.py --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json
```

If the package has been renamed to `~/nexus_light_agent`:

```bash
cd ~
python3 -m nexus_light_agent --config /etc/sentinel-nexus-agent/txn-mobile-ussd.json
```

Watch for:

- Heartbeat accepted by Nexus Core.
- Probe report accepted by Nexus Core.
- No repeated spool growth.
- No high CPU loop.
- No log-file permission errors.
- No authentication failures.

## Running The Command Server

If diagnostics or restart dispatch is enabled, the command server must run with a protected local token and a narrow allowlist.

Before enabling it, confirm:

- The configured bind host and port.
- Whether it binds to localhost only or a management interface.
- Whether firewall rules restrict access to Nexus Core.
- Whether TLS or token auth is enabled.
- Whether restart remains disabled until certification.

## Nexus Catalog Configuration

In Nexus, configure `txn-mobile-ussd` as a real service:

- `service_id`: `txn-mobile-ussd`
- `service_type`: `channel` or `app`, depending on ownership confirmation
- `environment`: `ate-test`
- `owner_team`: mobile banking or confirmed owner
- `criticality`: high or critical
- `observation_config.agent_id`: `ate-test-txn-mobile-ussd-01`
- `observation_config.analysis_profile`: `txn_mobile_ussd`
- `endpoint_config.collector_url`: Nexus Core ingestion URL
- `endpoint_config.diagnostics_url`: command server diagnostics URL, only after command server is secured
- `endpoint_config.restart_url`: empty until restart certification
- `certification.lifecycle_stage`: start at `observe_only`

Then place the service in the correct cluster and business flow. For example:

- Cluster: mobile banking ATE fabric
- Flow: Mobile USSD balance enquiry
- Edges: USSD service to integration service, integration service to IDC/core-banking path, plus any database dependency once DB access is confirmed

## Evidence To Verify In Nexus

After one controlled collection cycle, verify:

- Agent heartbeat appears for `txn-mobile-ussd`.
- Probe reports create normalized `signal_event` records.
- Log signatures are extracted when matching evidence exists.
- The service page shows recent runtime evidence.
- Network Sentinel evidence remains separate from runtime-agent evidence.
- USSD-specific session/tunnel interpretation appears only under the `txn_mobile_ussd` analysis profile.

## Information Still Needed

Provide these before we certify the ATE agent:

- Output of `python3 __main__.py --help`.
- Sanitized `/etc/sentinel-nexus-agent/txn-mobile-ussd.json`.
- Exact log file path and sample log line formats.
- Exact process marker or command line for `txn-mobile-ussd`.
- Whether the app is managed by systemd, shell script, supervisor, or another runner.
- Whether the service is stateless.
- The approved diagnostics bind port.
- The approved restart command, if restart will ever be certified.
- The MB database platform, host/port, database name, read-only user, and safe diagnostic queries.
