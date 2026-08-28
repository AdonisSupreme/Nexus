-- Sentinel Nexus: preserve the direct internal-account authority resolved by RRN lookup.
-- Apply after 2026_08_refine_nexus_unauthorized_debit_clearing.sql.

ALTER TABLE nexus_clearing_transaction
    ADD COLUMN IF NOT EXISTS source_internal_account TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_nexus_clearing_transaction_internal_source
    ON nexus_clearing_transaction (batch_id, source_internal_account)
    WHERE source_internal_account IS NOT NULL;

COMMENT ON COLUMN nexus_clearing_transaction.source_internal_account IS
    'Internal debit account resolved directly from ASIBGPQNP narration RRN evidence; bypasses ACNTS mapping during reconciliation.';
