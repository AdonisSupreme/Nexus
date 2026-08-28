-- Funds Custody: reusable staged imports and rolling execution tranches.
-- Apply after 2026_12_repair_nexus_clearing_source_contract.sql.

ALTER TABLE nexus_clearing_transaction
    ADD COLUMN IF NOT EXISTS custody_state TEXT NOT NULL DEFAULT 'PENDING',
    ADD COLUMN IF NOT EXISTS committed_execution_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS committed_at TIMESTAMPTZ NULL;

ALTER TABLE nexus_clearing_transaction
    DROP CONSTRAINT IF EXISTS nexus_clearing_transaction_custody_state_check;

ALTER TABLE nexus_clearing_transaction
    ADD CONSTRAINT nexus_clearing_transaction_custody_state_check
    CHECK (custody_state IN ('PENDING', 'SEALED', 'COMMITTED', 'ROLLED_BACK'));

DROP INDEX IF EXISTS ux_nexus_clearing_batch_source;

CREATE UNIQUE INDEX ux_nexus_clearing_batch_source
    ON nexus_clearing_batch (source_sha256, finance_reference)
    WHERE deleted_at IS NULL;

-- A deleted source that never entered approval or execution custody may be
-- corrected and re-imported. Preserve its batch, reconciliation snapshots,
-- and audit chronology while releasing the global transaction fingerprints.
DELETE FROM nexus_clearing_transaction transaction
USING nexus_clearing_batch batch
WHERE transaction.batch_id = batch.batch_id
  AND batch.deleted_at IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM nexus_clearing_approval approval
      WHERE approval.batch_id = batch.batch_id
  )
  AND NOT EXISTS (
      SELECT 1 FROM nexus_clearing_execution_run execution
      WHERE execution.batch_id = batch.batch_id
  );

-- Normalize open legacy batches to one 20-record command tranche. No source
-- row is removed; rows outside the tranche remain available for the next pass.
WITH ranked AS (
    SELECT
        transaction.fingerprint,
        transaction.batch_id,
        ROW_NUMBER() OVER (
            PARTITION BY transaction.batch_id
            ORDER BY transaction.source_row, transaction.fingerprint
        ) AS command_rank
    FROM nexus_clearing_transaction transaction
    JOIN nexus_clearing_batch batch ON batch.batch_id = transaction.batch_id
    WHERE batch.deleted_at IS NULL
      AND batch.status IN ('IMPORTED', 'RECONCILED', 'HAS_EXCEPTIONS', 'READY_FOR_APPROVAL', 'FAILED', 'BLOCKED')
      AND transaction.custody_state = 'PENDING'
)
UPDATE nexus_clearing_transaction transaction
SET selected = ranked.command_rank <= 20,
    reconciliation_state = CASE
        WHEN ranked.command_rank <= 20 THEN transaction.reconciliation_state
        ELSE 'EXCLUDED'
    END,
    updated_at = now()
FROM ranked
WHERE transaction.fingerprint = ranked.fingerprint;

UPDATE nexus_clearing_batch batch
SET selected_count = selection.selected_count,
    updated_at = now()
FROM (
    SELECT batch_id, COUNT(*) FILTER (WHERE selected) AS selected_count
    FROM nexus_clearing_transaction
    GROUP BY batch_id
) selection
WHERE batch.batch_id = selection.batch_id
  AND batch.deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_transaction_custody
    ON nexus_clearing_transaction (batch_id, custody_state, selected, source_row);

COMMENT ON COLUMN nexus_clearing_transaction.custody_state IS
    'Rolling source-row lifecycle. PENDING rows can enter a later command tranche; COMMITTED rows are immutable execution evidence.';
