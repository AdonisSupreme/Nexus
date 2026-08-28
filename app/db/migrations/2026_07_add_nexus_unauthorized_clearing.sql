-- Sentinel Nexus: governed unauthorized-clearing custody ledger.
-- Apply this baseline before the debit-only refinement migration.

CREATE TABLE IF NOT EXISTS nexus_clearing_batch (
    batch_id TEXT PRIMARY KEY,
    batch_name TEXT NOT NULL,
    finance_reference TEXT NOT NULL,
    source_filename TEXT NOT NULL,
    source_sha256 CHAR(64) NOT NULL,
    status TEXT NOT NULL DEFAULT 'IMPORTED'
        CHECK (status IN (
            'IMPORTED', 'RECONCILING', 'RECONCILED', 'HAS_EXCEPTIONS',
            'READY_FOR_APPROVAL', 'PENDING_APPROVAL', 'APPROVED',
            'EXECUTION_READY', 'EXECUTING', 'COMPLETED', 'ROLLED_BACK',
            'BLOCKED', 'FAILED', 'COMMIT_UNCERTAIN'
        )),
    transaction_count INTEGER NOT NULL CHECK (transaction_count > 0),
    debit_account_count INTEGER NOT NULL DEFAULT 0,
    credit_account_count INTEGER NOT NULL DEFAULT 0,
    total_amount NUMERIC(20, 2) NOT NULL DEFAULT 0,
    total_charge NUMERIC(20, 2) NOT NULL DEFAULT 0,
    total_debit NUMERIC(20, 2) NOT NULL DEFAULT 0,
    selected_count INTEGER NOT NULL DEFAULT 0,
    reconciliation_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    approved_payload JSONB NULL,
    payload_hash CHAR(64) NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    submitted_by TEXT NULL,
    submitted_at TIMESTAMPTZ NULL,
    approved_by TEXT NULL,
    approved_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_nexus_clearing_batch_source
    ON nexus_clearing_batch (source_sha256, finance_reference);
CREATE INDEX IF NOT EXISTS idx_nexus_clearing_batch_status
    ON nexus_clearing_batch (status, updated_at DESC);

CREATE TABLE IF NOT EXISTS nexus_clearing_transaction (
    fingerprint CHAR(64) PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES nexus_clearing_batch(batch_id) ON DELETE RESTRICT,
    source_row INTEGER NOT NULL CHECK (source_row > 0),
    entry_date DATE NOT NULL,
    from_account TEXT NOT NULL,
    to_account TEXT NOT NULL,
    rrn TEXT NOT NULL,
    stan TEXT NOT NULL,
    amount NUMERIC(20, 2) NOT NULL CHECK (amount > 0),
    charge NUMERIC(20, 2) NOT NULL DEFAULT 0 CHECK (charge >= 0),
    narration TEXT NOT NULL DEFAULT '',
    selected BOOLEAN NOT NULL DEFAULT TRUE,
    reconciliation_state TEXT NOT NULL DEFAULT 'NOT_RECONCILED'
        CHECK (reconciliation_state IN (
            'NOT_RECONCILED', 'STALE', 'EXCLUDED', 'READY',
            'READY_WITH_RESIDUAL', 'SAFE_EXTRA_QUEUE', 'SPECIAL_REVIEW',
            'NO_LONGER_OUTSTANDING', 'BLOCKED'
        )),
    reconciliation_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (batch_id, source_row),
    UNIQUE (batch_id, rrn, stan, from_account, entry_date, amount, charge)
);

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_transaction_batch
    ON nexus_clearing_transaction (batch_id, selected, reconciliation_state, source_row);
CREATE INDEX IF NOT EXISTS idx_nexus_clearing_transaction_accounts
    ON nexus_clearing_transaction (batch_id, from_account, to_account);

CREATE TABLE IF NOT EXISTS nexus_clearing_reconciliation_run (
    reconciliation_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES nexus_clearing_batch(batch_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('RUNNING', 'COMPLETED', 'HAS_EXCEPTIONS', 'FAILED')),
    requested_by TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ NULL,
    selected_count INTEGER NOT NULL DEFAULT 0,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_reconciliation_batch
    ON nexus_clearing_reconciliation_run (batch_id, started_at DESC);

CREATE TABLE IF NOT EXISTS nexus_clearing_account_snapshot (
    snapshot_id TEXT PRIMARY KEY,
    reconciliation_id TEXT NOT NULL
        REFERENCES nexus_clearing_reconciliation_run(reconciliation_id) ON DELETE RESTRICT,
    batch_id TEXT NOT NULL REFERENCES nexus_clearing_batch(batch_id) ON DELETE RESTRICT,
    external_account TEXT NOT NULL,
    internal_account TEXT NULL,
    account_role TEXT NOT NULL CHECK (account_role IN ('DEBIT', 'CREDIT', 'BOTH')),
    mapping_count INTEGER NOT NULL DEFAULT 0,
    balance_rows JSONB NOT NULL DEFAULT '[]'::jsonb,
    queue_rows JSONB NOT NULL DEFAULT '[]'::jsonb,
    resolution JSONB NOT NULL DEFAULT '{}'::jsonb,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_account_snapshot_lookup
    ON nexus_clearing_account_snapshot (batch_id, external_account, captured_at DESC);

CREATE TABLE IF NOT EXISTS nexus_clearing_approval (
    approval_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES nexus_clearing_batch(batch_id) ON DELETE RESTRICT,
    payload_hash CHAR(64) NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    submitted_by TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by TEXT NULL,
    reviewed_at TIMESTAMPTZ NULL,
    review_note TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_approval_batch
    ON nexus_clearing_approval (batch_id, submitted_at DESC);

CREATE TABLE IF NOT EXISTS nexus_clearing_execution_run (
    execution_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES nexus_clearing_batch(batch_id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_hash CHAR(64) NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'CREATED', 'PREPARING', 'LOCKING', 'REVALIDATING', 'EXECUTING',
        'POST_VALIDATING', 'COMMITTED', 'BLOCKED', 'ROLLED_BACK', 'FAILED',
        'COMMIT_UNCERTAIN', 'ROLLBACK_REQUIRED'
    )),
    requested_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    approved_payload JSONB NOT NULL,
    oracle_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    rollback_requested_by TEXT NULL,
    rollback_reason TEXT NULL,
    rolled_back_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_execution_batch
    ON nexus_clearing_execution_run (batch_id, created_at DESC);

CREATE TABLE IF NOT EXISTS nexus_clearing_execution_item (
    execution_item_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL
        REFERENCES nexus_clearing_execution_run(execution_id) ON DELETE RESTRICT,
    fingerprint CHAR(64) NOT NULL
        REFERENCES nexus_clearing_transaction(fingerprint) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'VALIDATED', 'COMMITTED', 'ROLLED_BACK', 'BLOCKED', 'FAILED')),
    before_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    after_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (execution_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS nexus_clearing_audit (
    audit_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    actor_role TEXT NULL,
    batch_id TEXT NULL,
    reconciliation_id TEXT NULL,
    execution_id TEXT NULL,
    fingerprint CHAR(64) NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_audit_timeline
    ON nexus_clearing_audit (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_nexus_clearing_audit_batch
    ON nexus_clearing_audit (batch_id, occurred_at DESC)
    WHERE batch_id IS NOT NULL;

COMMENT ON TABLE nexus_clearing_batch IS
    'Immutable authorization batches and their controlled clearing lifecycle.';
COMMENT ON TABLE nexus_clearing_transaction IS
    'Authorized source transactions. The fingerprint is the authorization identity.';
COMMENT ON TABLE nexus_clearing_account_snapshot IS
    'Read-only Oracle mapping, physical ACNTBAL rows, queue evidence, and deterministic resolution.';
COMMENT ON TABLE nexus_clearing_execution_run IS
    'Human-approved atomic Oracle execution and compensating reversal evidence.';
COMMENT ON TABLE nexus_clearing_audit IS
    'Append-only Sentinel Nexus clearing custody trail.';
