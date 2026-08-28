-- Repair Funds Custody source-kind drift on installations that applied the
-- workflow migrations without the identity-intake constraint expansion.

ALTER TABLE nexus_clearing_batch
    DROP CONSTRAINT IF EXISTS nexus_clearing_batch_source_kind_check;

ALTER TABLE nexus_clearing_batch
    ADD CONSTRAINT nexus_clearing_batch_source_kind_check
    CHECK (source_kind IN ('FINANCE_IMPORT', 'IDENTITY_IMPORT', 'ACCOUNT_EXPLORER'));

COMMENT ON COLUMN nexus_clearing_batch.source_kind IS
    'Custody source authority: Finance transaction file, one-column identity intake, or Account Explorer.';
