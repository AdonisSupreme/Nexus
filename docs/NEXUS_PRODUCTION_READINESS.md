# Sentinel Nexus Production Readiness

Sentinel Nexus is database-backed operational intelligence. It must run from the shared SentinelOps Postgres database, use the SentinelOps frontend session model for human APIs, and accept light-agent evidence through a separate agent credential path.

This checklist is the production deployment guardrail before building or installing Mobile Banking and IDC light agents.

## Production Rules

- Do not run Nexus from local JSON state in production.
- Set `DATABASE_URL` to the shared SentinelOps database.
- Keep `NEXUS_REQUIRE_DATABASE=true`.
- Keep `NEXUS_ALLOW_LOCAL_STATE=false`.
- Keep `NEXUS_REQUIRE_AGENT_AUTH=true`.
- Configure a strong `NEXUS_AGENT_API_TOKEN` before any agent is deployed.
- Use the same `SECRET_KEY` and `ALGORITHM` as `SentinelOps-beta` so Nexus validates existing frontend sessions.
- Restart `sentinelops-ai` after applying schema migrations or importing catalog seeds because Nexus loads state into memory at startup.

## Required Database Migrations

Run these against the target SentinelOps database in this order:

```powershell
psql "$env:DATABASE_URL" -f "C:\Users\ashumba\Documents\Sentinel\SentinelOps-beta\app\db\migrations\2026_04_add_sentinel_nexus.sql"
psql "$env:DATABASE_URL" -f "C:\Users\ashumba\Documents\Sentinel\SentinelOps-beta\app\db\migrations\2026_05_add_nexus_business_flows.sql"
psql "$env:DATABASE_URL" -f "C:\Users\ashumba\Documents\Sentinel\SentinelOps-beta\app\db\migrations\2026_05_add_nexus_database_awareness.sql"
```

These migrations create the durable Nexus schema:

- `nexus_meta`
- `service_catalog`
- `dependency_cluster`
- `business_flow`
- `business_flow_step`
- `service_health_snapshot`
- `dependency_edge`
- `signal_event`
- `change_event`
- `incident`
- `incident_service`
- `task_handoff`
- `operator_feedback`
- `diagnostic_bundle`
- `action_execution`
- `agent_heartbeat`

## Optional Catalog Bootstrap

The seed files are real catalog/bootstrap contracts, not fake runtime telemetry. They contain zero fake signals and zero fake incidents.

Validate IDC/Postilion seed without writing:

```powershell
cd C:\Users\ashumba\Documents\Sentinel\sentinelops-ai
.\sentinelai\Scripts\python.exe .\scripts\migrate_nexus_state_to_postgres.py --source .\data\nexus_seed_idc_core.json --dry-run --merge
```

Apply IDC/Postilion seed:

```powershell
.\sentinelai\Scripts\python.exe .\scripts\migrate_nexus_state_to_postgres.py --source .\data\nexus_seed_idc_core.json --apply --merge --verify
```

Validate Mobile Banking ATE seed without writing:

```powershell
.\sentinelai\Scripts\python.exe .\scripts\migrate_nexus_state_to_postgres.py --source .\data\nexus_seed_mobile_banking_ate.json --dry-run --merge
```

Apply Mobile Banking ATE seed:

```powershell
.\sentinelai\Scripts\python.exe .\scripts\migrate_nexus_state_to_postgres.py --source .\data\nexus_seed_mobile_banking_ate.json --apply --merge --verify
```

Always use `--merge` when importing a seed into an existing database. Without `--merge`, the tool treats the source file as the complete Nexus state.

## Post-Migration Verification

Verify the database state:

```powershell
cd C:\Users\ashumba\Documents\Sentinel\sentinelops-ai
.\sentinelai\Scripts\python.exe .\scripts\migrate_nexus_state_to_postgres.py --verify
```

Verify tests:

```powershell
.\sentinelai\Scripts\python.exe -m pytest tests\test_nexus.py -q
.\sentinelai\Scripts\python.exe -m pytest tests\test_nexus_light_agent.py -q
```

Verify frontend production build:

```powershell
cd C:\Users\ashumba\Documents\Sentinel\SentinelOps
npm run build
```

## Light Agent Contract

Agents should not hardcode service topology. They should fetch their service contract from Nexus after install:

```http
GET /api/v1/nexus/agents/{agent_id}/config?service_id={service_id}
X-Nexus-Agent-Id: {agent_id}
X-Nexus-Agent-Token: {token}
```

The response includes:

- Service contract from `service_catalog`
- Cluster membership
- Incoming and outgoing dependency edges
- Business flow membership
- Safe diagnostic command hints
- Canonical heartbeat/probe/diagnostic result endpoints
- Required log signature fields
- Database dependency profile when applicable

For Mobile Banking, start with `txn-mobile-ussd`, `txn-transaction-service`, and `txn-integration-idc`, then expand outward to channel, switch, notification, and database dependencies.

The first production-shaped host agent is documented in:

```text
C:\Users\ashumba\Documents\Sentinel\sentinelops-ai\docs\NEXUS_LIGHT_AGENT_MB_USSD.md
```

It is a single low-resource host agent configured first for `txn-mobile-ussd`. Add more services to the same agent only after the first service is stable in Nexus.

The guarded diagnostics/restart command surface is documented in:

```text
C:\Users\ashumba\Documents\Sentinel\sentinelops-ai\docs\NEXUS_LIGHT_AGENT_COMMAND_SURFACE.md
```

Do not configure `diagnostics_url` or `restart_url` until the service has the correct `observation_config.agent_id`, certification stage, policy gates, and agent token configuration.

## Production Readiness Verdict

Nexus is ready for the next phase when:

- Migrations above are applied.
- `sentinelops-ai` starts with DB required and local state disabled.
- Human Nexus APIs reject anonymous requests.
- Agent APIs reject missing or invalid agent tokens.
- Catalog contains only real services, clusters, flows, and dependency edges.
- Runtime telemetry comes only from Network Sentinel, agent probe reports, logs, traces, changes, and operator actions.
- Restart remains disabled until a service is certified as stateless, restart-safe, and `restart_ready`.
- Restart dispatch uses only the token-protected light-agent command surface and never accepts arbitrary command payloads.
