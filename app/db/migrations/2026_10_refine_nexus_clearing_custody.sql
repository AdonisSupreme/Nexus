-- Identity-only batch intake. Existing Finance and Account Explorer batches remain valid.

ALTER TABLE nexus_clearing_batch
    DROP CONSTRAINT IF EXISTS nexus_clearing_batch_source_kind_check;

ALTER TABLE nexus_clearing_batch
    ADD CONSTRAINT nexus_clearing_batch_source_kind_check
    CHECK (source_kind IN ('FINANCE_IMPORT', 'IDENTITY_IMPORT', 'ACCOUNT_EXPLORER'));
