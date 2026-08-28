-- Sentinel Nexus: debit-only, currency-bound unauthorized clearing.
-- Apply after 2026_07_add_nexus_unauthorized_clearing.sql.

ALTER TABLE nexus_clearing_batch
    ADD COLUMN IF NOT EXISTS source_kind TEXT NOT NULL DEFAULT 'FINANCE_IMPORT',
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS deleted_by TEXT NULL;

ALTER TABLE nexus_clearing_batch
    DROP CONSTRAINT IF EXISTS nexus_clearing_batch_source_kind_check;

ALTER TABLE nexus_clearing_batch
    ADD CONSTRAINT nexus_clearing_batch_source_kind_check
    CHECK (source_kind IN ('FINANCE_IMPORT', 'ACCOUNT_EXPLORER'));

ALTER TABLE nexus_clearing_transaction
    ALTER COLUMN to_account DROP NOT NULL,
    ALTER COLUMN to_account SET DEFAULT '',
    ADD COLUMN IF NOT EXISTS currency VARCHAR(3) NULL,
    ADD COLUMN IF NOT EXISTS clear_amount NUMERIC(20, 2) NULL,
    ADD COLUMN IF NOT EXISTS operation_mode TEXT NOT NULL DEFAULT 'QUEUE_EXACT',
    ADD COLUMN IF NOT EXISTS queue_row_id TEXT NULL;

UPDATE nexus_clearing_transaction
SET to_account = ''
WHERE to_account IS NULL;

ALTER TABLE nexus_clearing_transaction
    DROP CONSTRAINT IF EXISTS nexus_clearing_transaction_operation_mode_check,
    DROP CONSTRAINT IF EXISTS nexus_clearing_transaction_clear_amount_check;

ALTER TABLE nexus_clearing_transaction
    ADD CONSTRAINT nexus_clearing_transaction_operation_mode_check
        CHECK (operation_mode IN ('QUEUE_EXACT', 'QUEUE_PARTIAL', 'BALANCE_ALL')),
    ADD CONSTRAINT nexus_clearing_transaction_clear_amount_check
        CHECK (clear_amount IS NULL OR clear_amount > 0);

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_batch_active
    ON nexus_clearing_batch (updated_at DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_transaction_currency
    ON nexus_clearing_transaction (batch_id, from_account, currency, operation_mode);

COMMENT ON COLUMN nexus_clearing_transaction.to_account IS
    'Optional destination context from the source; never a clearing mutation target.';
COMMENT ON COLUMN nexus_clearing_transaction.currency IS
    'Explicit ACNTBAL currency partition selected or resolved for the unauthorized debit.';
COMMENT ON COLUMN nexus_clearing_transaction.clear_amount IS
    'Authorized debit reduction. NULL means source amount plus source charge.';
COMMENT ON COLUMN nexus_clearing_transaction.operation_mode IS
    'Exact queue clear, partial queue-linked clear, or full selected ACNTBAL debit row clear.';
