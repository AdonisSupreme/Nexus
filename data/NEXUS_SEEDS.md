# Sentinel Nexus Production Bootstrap

`nexus_seed_idc_core.json` and `nexus_seed_mobile_banking_ate.json` are optional bootstrap catalog packages for the shared SentinelOps database. They are not runtime dummy telemetry and they are not loaded automatically by `sentinelops-ai`.

Normal Nexus operation must use the SentinelOps Postgres database through `DATABASE_URL`. Local JSON files are retained only as migration/import material and test fallback input when `NEXUS_ALLOW_LOCAL_STATE=true` is explicitly enabled.

IDC bootstrap contents:

- 12 service catalog contracts for the first IDC/Postilion dependency fabric.
- 3 dependency clusters: `intellect-idc`, `idc-core-processing`, and `postilion-card-transactions`.
- 3 business flows: IDC user access, IDC transaction processing, and Postilion card transaction processing.
- 11 dependency edges with flow-scoped semantics where required.
- 0 fake signals, 0 fake incidents, 0 fake diagnostics, and 0 fake actions.
- Restart disabled unless service owners validate statelessness, cooldown, approval, and restart safety.

Mobile Banking ATE bootstrap contents:

- 27 service catalog contracts from the real `/srv` Mobile Banking startup/status/log material.
- 4 dependency clusters: `mobile-banking-ate`, `mobile-channel-fabric-ate`, `mobile-core-transaction-fabric-ate`, and `mobile-database-fabric-ate`.
- 4 business flows for USSD balance enquiry, smartphone core transactions, card/switch transactions, and supporting services.
- 17 dependency edges, including the critical `txn-transaction-service -> txn-integration-idc -> idc-core` banking validation path.
- First-class PostgreSQL/Hikari database modeling through `txn-mobile-postgres`, based on the real USSD log evidence.
- 0 fake signals, 0 fake incidents, 0 fake diagnostics, and 0 fake actions.
- Restart disabled until light-agent URLs, service-owner approval, drain/idempotency rules, and expected stopped/running posture are validated.

Use this file only when you want to import a known starter topology into an empty SentinelOps database. For production onboarding, prefer adding verified services, clusters, business flows, and edges through the Nexus catalog UI/API one service at a time.

Use `--merge` when applying a seed to an existing SentinelOps database. Without `--merge`, the migration utility treats the source as the whole Nexus state and replaces the persisted catalog.

Validate without writing:

```powershell
cd C:\Users\ashumba\Documents\Sentinel\sentinelops-ai
.\sentinelai\Scripts\python.exe .\scripts\migrate_nexus_state_to_postgres.py --source .\data\nexus_seed_idc_core.json --dry-run
```

Import into SentinelOps Postgres:

```powershell
.\sentinelai\Scripts\python.exe .\scripts\migrate_nexus_state_to_postgres.py --source .\data\nexus_seed_idc_core.json --apply --merge --verify
```

Validate Mobile Banking without writing:

```powershell
.\sentinelai\Scripts\python.exe .\scripts\migrate_nexus_state_to_postgres.py --source .\data\nexus_seed_mobile_banking_ate.json --dry-run --merge
```

Merge Mobile Banking into the existing SentinelOps Postgres catalog:

```powershell
.\sentinelai\Scripts\python.exe .\scripts\migrate_nexus_state_to_postgres.py --source .\data\nexus_seed_mobile_banking_ate.json --apply --merge --verify
```

After import, open `/nexus`, run `Sync Network Sentinel`, then validate each service's real environment, Network Sentinel mapping, light-agent URL, log selectors, metrics namespace, diagnostics endpoint, ownership, dependency purpose, business-flow placement, and restart policy.
