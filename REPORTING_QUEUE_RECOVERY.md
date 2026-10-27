# Reporting queue recovery deployment

## Changes

- Loan-ledger All statuses now sends an explicit empty status; omission still defaults to Pending for existing API clients.
- Failed queues support exact trimmed failure-description filtering. Blank and missing descriptions form one selectable category.
- Individual, selected and all-filtered failures enter a review before requeue. Personal loans also accept ID-only CSV/text imports.
- Each review is limited to 500 matching records. Narrow the filter for larger queues; the server rejects oversized matches rather than silently truncating them.
- Custody history is paginated and administrator-only at the API. Source records remain accessible according to their assigned module.
- Personal loans use a separate `reports.personal_loans` entitlement, assigned explicitly by administrators.

## Before enabling

1. Apply `app/db/migrations/2026_21_reporting_queue_recovery.sql` to the shared SentinelOps/Nexus PostgreSQL database.
2. Apply the core API migration `SentinelOps-beta/app/db/migrations/2026_21_personal_loan_module.sql` to the access-management database. These may be the same database in your installation.
3. Grant the Nexus application role access to the new custody table (substitute the actual runtime role if different):

   ```sql
   GRANT SELECT, INSERT, UPDATE ON TABLE public.nexus_queue_recovery TO sysops;
   ```

   No sequence grant is needed: action IDs are application-generated UUID strings. Do not grant DELETE for ordinary operation.

4. Install the Nexus requirements, including `PyMySQL==1.2.3`.
5. Set these **server-side** variables in Nexus's normal configuration; never place them in frontend environment files:

   ```text
   OD_DB_HOST=<MySQL host>
   OD_DB_PORT=3306
   OD_DB_DATABASE=flexi_doc
   OD_DB_USERNAME=<application identity>
   OD_DB_PASSWORD=<secret>
   ```

   Source table: `overdraft_applications`. It must use InnoDB for recovery. Grant SELECT and UPDATE of `status_id,is_processed` to the application identity. No source schema migration is performed by SentinelOps.

6. Existing `TXN_BOT_DATABASE_URL` and all bot schedules, credentials, date-repair rules and settings remain in use. The existing source identity needs UPDATE of `hovering.status` for the new recovery operation.
7. Deploy the frontend, core API access catalog/policy, and Nexus API together. Assign **Personal loans — 48 months** to the intended sections in Section & Module Access Management.

## Exact mutation contracts

Loan ledger: existing configured credit account and type, `status='FAILED'`. Changes only `status` to `PENDING`. Dates, description, amounts and external references are preserved.

Personal loans: only exact tenures `USD PERSONAL LOAN 48 MONTHS` and `ZWL PERSONAL LOAN 48 MONTHS`, with `status_id=18 AND is_processed='2'`. Changes only `status_id=31, is_processed='0'`. No successful, pending or other-stage application is eligible.

Every execution reselects and locks the reviewed IDs and compares their reviewed evidence. If any record changed or ceased to qualify, the entire source transaction is rejected. Reviews expire after ten minutes and are bound to the requesting operator and queue. Execution claims a review once under a PostgreSQL row lock.

## Custody and ambiguous outcomes

The source and custody databases are separate. A durable PREPARED record stores the exact IDs and before-evidence. APPLYING is committed before touching the source; COMPLETED records the count afterward. A known eligibility rejection is REJECTED. A connection or commit failure can be UNCERTAIN; a crash can leave APPLYING.

**Never blindly retry APPLYING or UNCERTAIN actions.** An administrator must inspect the action ID and reviewed IDs, source state and bot evidence to determine whether the update committed. These actions cannot be executed again using their original review. The application does not claim a distributed atomic transaction or automatically reconcile an ambiguous commit. Preserve the custody evidence during investigation.

Recovery returns records to bot processing; it does not fix the failure's underlying business cause. Resolve that cause before confirming. Imported IDs that are missing, out of scope or no longer failed are excluded and their excluded count is shown before confirmation.

## Verification limits

Unit/API/UI tests use synthetic records and mocked database connections. They verify filtering, access policy, mutation boundaries, changed-record rejection, one-shot execution and UI request behavior. Production source connectivity, DB privileges, query plans and real bot coexistence must be checked in a staging environment before rollout. No production records were changed during development.

USD, ZWL and Both currency views scope counts, records, failure reasons and recovery previews by the exact loan tenure. The personal-loan summary displays source counts and successful share, refreshed sequentially at five-second intervals after each read while visible (with immediate refresh on focus or reconnection). It does not label count changes as throughput or infer a completion ETA without evidence. For large source tables, inspect EXPLAIN for tenure/status/date queries before adding any index; the application does not create source indexes automatically.

## Credit reporting workflows

Personal Loans now supports customer/account/loan/application lookup, exact branch filtering, created versus processed date ranges, maturity boundaries, and next-pay-date boundaries. The optional legacy preset exposes (rather than silently enforcing) maturity after 2029-12-31 and next pay date from 2025-06-01. Only the two exact 48-month tenures remain in scope; historical 30/90-day overdraft statistics were not brought into this workspace.

Analyze scope runs on demand. It reports counts and approved amounts by tenure/currency and current status, observed minimum/maximum amounts, and the latest 62 date/currency activity groups. These are application amounts, not proof of disbursement or policy limits. Created/processed ranges use inclusive starts and exclusive ends; maturity-after is exclusive, other date boundaries inclusive. Date shortcuts use the operator's local calendar, transmitted with timezone offsets. Missing source dates do not match date predicates.

CSV exports include all matching pages, up to 10,000 records. Larger scopes are rejected explicitly. Files are built per request, use an explicit operational field allow-list (excluding national IDs), neutralize spreadsheet formulas, and are served with no-store headers. The existing personal-loan module permission protects report and export routes. Recovery remains capped at 500 failed records and uses the same applied boundaries. Imported IDs intentionally use the selected currency only, as documented in the import workflow.

Deploy frontend and Nexus API together. No new database migration or bot configuration change is needed. The source must expose full_name, branch_origin, amount_applied, maturity and next_pay_date, as used by the reference credit dashboard.
