# Sentinel Nexus Service Rollout

## Production topology

- `SentinelOps-beta` remains the operational application backend on `:8000`.
- `sentinelops-ai` runs as Nexus Core on a dedicated internal port such as `:8010`.
- The frontend can keep `REACT_APP_API_BASE_URL=http://127.0.0.1:8000` for core SentinelOps features.
- Nexus calls should use `REACT_APP_NEXUS_API_BASE_URL=http://127.0.0.1:8010`.
- In production, place both services behind the same gateway and route `/api/v1/nexus/*` to Nexus Core.

## What every light-analysis service must send

Every service-specific agent can have a different local startup method, but the central contract must stay uniform.

Required identity fields:

- `agent_id`
- `service_id`
- `service_name`
- `environment`
- `timestamp`
- `severity`

Strongly recommended canonical fields:

- `instance_id`
- `host_id`
- `cluster`
- `zone`
- `service_version`
- `probe_family`

Required data classes:

- `metrics`: structured key/value symptom snapshot
- `log_records`: stable signature-bearing evidence records
- `trace_summaries`: dependency-path summaries
- `change_context`: recent deployments, restarts, config changes, maintenance markers
- `metadata`: collector-specific context that does not affect correlation rules directly

Bootstrap compatibility:

- `logs` and `traces` are still accepted for early rollout.
- Production onboarding should move each service to `log_records` and `trace_summaries`.

## Canonical probe payload

```json
{
  "agent_id": "agent-auth-api-01",
  "service_id": "auth-api",
  "service_name": "Auth API",
  "environment": "production",
  "timestamp": "2026-04-19T15:42:00Z",
  "severity": "CRITICAL",
  "instance_id": "auth-api-01",
  "host_id": "srv-auth-01",
  "cluster": "idc-prod-a",
  "zone": "zw-hre-1a",
  "service_version": "2026.04.19-rc2",
  "probe_family": "linux-systemd",
  "metrics": {
    "availability": 0.82,
    "p95_latency_ms": 1950,
    "error_ratio": 0.18,
    "rss_mb": 912,
    "restart_count_10m": 2
  },
  "log_records": [
    {
      "timestamp": "2026-04-19T15:41:33Z",
      "severity": "CRITICAL",
      "message": "auth-api: timeout waiting for auth-cache response after 250ms",
      "signature_family": "dependency_timeout",
      "error_class": "timeout",
      "timeout_type": "cache_dependency",
      "attributes": {
        "logger": "auth.request",
        "request_path": "/login"
      }
    }
  ],
  "trace_summaries": [
    {
      "timestamp": "2026-04-19T15:41:45Z",
      "summary": "Failed traces concentrated on auth-api -> auth-cache",
      "path": ["idc-gateway", "auth-api", "auth-cache"],
      "failed_trace_share": 0.71,
      "span_count": 18,
      "attributes": {
        "trace_root": "idc-gateway"
      }
    }
  ],
  "change_context": [
    {
      "change_type": "deployment",
      "source": "cicd",
      "summary": "Auth API release candidate deployed",
      "timestamp": "2026-04-19T15:18:00Z",
      "metadata": {
        "version": "2026.04.19-rc2"
      }
    }
  ],
  "metadata": {
    "collector": "sentinel-light-agent",
    "health_endpoint": "http://127.0.0.1:8080/health"
  },
  "status": "degraded",
  "message": "Correlated auth degradation detected."
}
```

## Minimum onboarding facts per service

Before onboarding a service into Nexus, collect the following facts:

- canonical `service_id`
- owner team and escalation path
- service type: `app | worker | gateway | db | cache | queue | infra`
- environment and cluster placement
- stateful or stateless
- restart policy and cooldown
- systemd unit or startup command
- health check command or endpoint
- local log source: journald unit, file path, or container stream
- minimum metrics to sample
- known dependency targets
- recent change sources: deployment pipeline, config store, manual ops actions
- safe diagnostics allowlist
- whether human-approved restart is permitted

If any of the above is unknown, the service is not ready for safe automation and should stay at advise-only mode.

## Linux-first diagnostics contract

The light-analysis service should only execute allowlisted diagnostics:

- `systemd_status`
- `recent_journal`
- `health_check`
- `memory_summary`
- `disk_summary`
- `socket_summary`

Each command result should return the same structure:

```json
{
  "command_id": "recent_journal",
  "status": "ok",
  "started_at": "2026-04-19T15:43:02Z",
  "completed_at": "2026-04-19T15:43:05Z",
  "exit_code": 0,
  "stdout_excerpt": "...",
  "stderr_excerpt": "",
  "truncated": true
}
```

## Dependency tree rollout order

Roll out one service at a time using this order:

1. Register the service in the curated catalog with restart policy and owner metadata.
2. Add its declared upstream dependencies and direct dependents.
3. Stand up the light-analysis service on the host or node group.
4. Validate heartbeat payloads.
5. Validate probe payloads with stable metric keys and stable log signatures.
6. Fire a synthetic degradation case and confirm incident grouping.
7. Confirm blast radius and root-cause ranking are directionally correct.
8. Only then enable diagnostics for that service.
9. Only after stable diagnostics should restart approval be enabled.

## Service implementation template

For every new service, produce a small onboarding record with:

- service name
- host class or node group
- runtime type: `systemd`, container, batch worker, appliance bridge
- health endpoint or health command
- log source selector
- metric extraction rules
- dependency declarations
- restart policy
- diagnostics allowlist
- sample payloads for heartbeat and probe report

This template is the bridge between heterogeneous infrastructure and a uniform Nexus intelligence model.

## Initial IDC rollout recommendation

Start with one critical but controllable path:

1. `auth-api`
2. `auth-cache`
3. `idc-gateway`
4. `user-session`

This order gives Nexus an immediately useful dependency chain for correlation:

- gateway symptom
- app symptom
- cache root-cause candidate
- session blast-radius validation

After that, onboard one stateful dependency such as `postgres-primary` in diagnostics-only mode before enabling any restart recommendation logic around adjacent services.
