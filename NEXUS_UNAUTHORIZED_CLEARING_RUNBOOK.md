# SentinelOps Funds Custody Runbook

## Purpose

SentinelOps Funds Custody is an independent operator workspace backed by the
Nexus clearing service. It replaces direct operational SQL with a
reconciled, approved, row-locked execution path. It imports the clearing source,
proves the current Oracle state, records an immutable preview, enforces
maker-checker separation, applies only approved row mutations, and retains
before/after evidence for audit and compensating rollback.

The implementation never accepts operator-authored SQL.

## Safety Contract

- Reconciliation uses the read-only Oracle identity.
- Execution and rollback use a separate, least-privilege Oracle identity.
- Oracle writes require `NEXUS_CLEARING_WRITES_ENABLED=true`.
- Production additionally requires
  `NEXUS_CLEARING_PRODUCTION_WRITES_ENABLED=true`.
- Both gates default to `false`, so production always requires two explicit
  decisions.
- An operator cannot approve their own batch. An administrator may make and
  approve under the explicit administrative exception, and that identity is
  retained in custody evidence.
- Checker approval is the mutation command. It atomically creates the execution
  ledger and runs the sealed payload; there is no routine third execute step.
- Administrators may always clear one exact queue record. A persisted policy
  controls whether other users may do so; when disabled, they may clear only
  the complete unauthorized debit for the selected currency row.
- The approved payload hash must match the payload used at execution.
- Every target Oracle row is locked and revalidated before mutation.
- Extra queue rows are preserved unless their complete identifying tuple is in
  the approved execution plan.
- Every database transaction is atomic. Ambiguous mappings, drift, or failed
  post-validation result in rollback and a recorded failure.
- A connection loss during commit is recorded as `COMMIT_UNCERTAIN`; operators
  must reconcile Oracle state before any retry.

## Migration Order

Apply migrations to the same Postgres database used by SentinelOps and Nexus:

1. `SentinelOps-beta/app/db/migrations/2026_04_add_sentinel_nexus.sql`
2. Any later Nexus migrations already deployed in the environment
3. `SentinelOps-beta/app/db/migrations/2026_07_add_nexus_unauthorized_clearing.sql`
4. `SentinelOps-beta/app/db/migrations/2026_08_refine_nexus_unauthorized_debit_clearing.sql`
5. `SentinelOps-beta/app/db/migrations/2026_09_add_nexus_clearing_rrn_lookup.sql`
6. `SentinelOps-beta/app/db/migrations/2026_10_refine_nexus_clearing_custody.sql`
7. `SentinelOps-beta/app/db/migrations/2026_11_refine_nexus_clearing_workflow.sql`
8. `SentinelOps-beta/app/db/migrations/2026_12_repair_nexus_clearing_source_contract.sql`

The clearing migration is additive. It does not modify core banking tables.

## Oracle Identities

Provision two distinct Oracle accounts:

### Read-only identity

Required access:

- `SELECT` on `ACNTS`
- `SELECT` on `ACNTBAL`
- `SELECT` on `ASIBGPQNP`
- permission to call `FACNO` if not available through public execution rights

### Guarded write identity

Required access:

- `SELECT` and `UPDATE` on `ACNTBAL`
- `SELECT`, `DELETE`, and `INSERT` on `ASIBGPQNP`
- `SELECT` on `USER_TAB_COLS`
- permission to call `FACNO`

Do not grant broad DDL, account-management, or unrelated application-table
privileges.

## Environment

Set the following in the Nexus runtime:

```dotenv
NEXUS_CLEARING_ORACLE_RO_DSN=
NEXUS_CLEARING_ORACLE_RO_USER=
NEXUS_CLEARING_ORACLE_RO_PASSWORD=
NEXUS_CLEARING_ORACLE_RW_DSN=
NEXUS_CLEARING_ORACLE_RW_USER=
NEXUS_CLEARING_ORACLE_RW_PASSWORD=
NEXUS_CLEARING_ORACLE_CONFIG_DIR=
NEXUS_CLEARING_ENTITY_NUMBER=1
NEXUS_CLEARING_MAX_BATCH_SIZE=500
NEXUS_CLEARING_MAX_SOURCE_BYTES=8388608
NEXUS_CLEARING_TIMEZONE=Africa/Harare

NEXUS_CLEARING_MAKER_ROLES=admin,manager,supervisor
NEXUS_CLEARING_APPROVER_ROLES=admin,manager
NEXUS_CLEARING_EXECUTOR_ROLES=admin,manager
NEXUS_CLEARING_ROLLBACK_ROLES=admin

NEXUS_CLEARING_WRITES_ENABLED=false
NEXUS_CLEARING_PRODUCTION_WRITES_ENABLED=false
```

Use either full DSNs or aliases resolved through
`NEXUS_CLEARING_ORACLE_CONFIG_DIR`.

## Source Contract

The importer accepts CSV and XLSX, up to the configured source-size limit. Its
canonical headings are:

- `Date`
- `From Account`
- `To Account` (optional destination context)
- `Currency` (optional; otherwise resolved from the exact queue row)
- `RRN`
- `STAN`
- `Amount`
- `Fee`
- `Narration`

Canonical CSV example:

```csv
Date,From Account,To Account,Currency,RRN,STAN,Amount,Fee,Narration
2026-07-29,100004167974,200000000001,ZWG,613506493636,493636,65.00,2.20,Approved Finance debit transaction
```

Common aliases such as `Entry Date`, `Debit Account`, `Credit Account`,
`Transaction Amount`, `Charge`, `Description`, `STAN Number`, `Trace Number`,
and `System Trace Audit Number` are normalized automatically. `Credit Account`
is accepted only as a destination-context alias; it never authorizes credit
clearing. Date, From Account, RRN, STAN, and amount are required. To Account,
Currency, Fee, and narration are optional; fee defaults to zero. STAN must come
from the Finance transaction source and
must not be fabricated because it is part of the exact ASIBGPQNP queue-row
identity. Source rows receive immutable SHA-256 fingerprints. Duplicate
authorization or queue identities are rejected before execution.
In Excel, format account, RRN, and STAN columns as text so leading zeroes are
preserved exactly.

## Account Explorer

Account Explorer has three evidence modes:

- Accounts in the selected Finance batch open their latest batch-bound
  reconciliation snapshot.
- Any external account can be inspected directly from Oracle when no batch is
  selected or the account is outside the selected batch.
- An RRN can be inspected when the operator does not have the external account
  number. The Nexus backend finds the RRN token in `ASIBGPQNP.BGPQ_TRN_NARR1`,
  resolves `BGPQ_INT_ACCT_1`, reads `ACNTBAL` directly by that internal account,
  then uses `FACNO(1, ACNTS_INTERNAL_ACNUM)` to surface the corresponding
  customer-facing account number when `ACNTS` proves one unique result.

Direct Oracle inspection resolves the external-to-internal mapping, reads every
physical `ACNTBAL` currency row for the mapped account, reads the current debit
queue rows, surfaces transaction and account currency separately, and writes an
append-only `live_account_inspected` audit event. Inspection itself is read-only.
An operator may then select one physical currency row and either one queue
transaction or the full unauthorized debit on that row. SentinelOps seals that
choice into a new `ACCOUNT_EXPLORER` batch; it still requires reconciliation,
submission, and guarded checker approval before Oracle can change. The
specific-record policy may restrict non-admin users to full-row clearing.

RRN inspection uses the queue-resolved internal account as its mutation
authority. The reverse `ACNTS` lookup is presentation evidence only: a missing
external account does not replace, weaken, or broaden that authority. The
matched queue records are shown as the lookup evidence. If one RRN resolves to
more than one internal account, the service returns the candidates but blocks
batch creation until the ambiguity is resolved. Every RRN inspection writes an
append-only `rrn_account_inspected` audit event with both internal and surfaced
external identities.

## Operating Window

Batch reconciliation and approval-triggered execution are blocked from 08:00
inclusive until 19:00 exclusive in `NEXUS_CLEARING_TIMEZONE` only when the batch
contains more than 20 records. Smaller batches remain available. The browser
reflects the lock, but the Nexus service enforces it server-side. Import,
account inspection, batch review, selection, submission, deletion of eligible
draft batches, and audit review remain available during the protected period.

## UAT Release Sequence

1. Apply all clearing Postgres migrations in the order listed above.
2. Start Nexus with both write gates disabled.
3. Import an anonymized or approved UAT source.
4. Reconcile all selected rows and inspect every account dossier.
5. Confirm physical `ACNTBAL` row handling for accounts with one and multiple
   rows.
6. Confirm queue matching on account, date, RRN, STAN, amount, and fee.
7. Confirm unrelated queue rows appear as preserved evidence.
8. Enable `NEXUS_CLEARING_WRITES_ENABLED=true` in UAT only.
9. Submit and approve using different users. Approval should create and complete
   the execution without a separate execute command.
10. Compare the sealed preview with Oracle before/after evidence.
11. Exercise compensating rollback against the UAT batch.
12. Review the audit trail and exported evidence with operations, database, and
    risk owners.
13. Only after formal approval, enable the production gate during an authorized
    change window.

## Production Operation

1. Import and verify the source batch.
2. Deselect any row that is blocked, ambiguous, or requires special review.
3. Outside the protected business-hours window, reconcile immediately before
   submission.
4. Submit with a precise change reference.
5. Have a second authorized operator inspect the immutable plan in Execution
   Desk. Administrators may self-approve only under the explicit admin exception.
6. Do not approve if any ROWID, amount, currency, before value, or queue match
   differs from the submitted source. Approval executes the mutation.
7. Confirm the execution result and post-validation evidence.
8. If status is `COMMIT_UNCERTAIN`, do not retry. Reconcile first and escalate to
   the database owner.

## Recovery

Rollback is a compensating transaction, not blind replay. It runs only when:

- the caller has a rollback role;
- the original execution completed;
- no prior rollback completed;
- every current target row still equals the recorded execution after-image.

If any row has changed since execution, rollback is blocked to avoid erasing
legitimate later activity.

## Verification

Backend:

```powershell
cd sentinelops-ai
.\sentinelai\Scripts\python.exe -m pytest tests\test_unauthorized_clearing.py -q
```

Frontend:

```powershell
cd SentinelOps
npm run build
```
