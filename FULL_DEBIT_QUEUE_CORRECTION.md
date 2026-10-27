# Full-debit queue inclusion correction (2026-10-27)

Root cause: BALANCE_ALL reconciliation never attached queue rows to the sealed payload. QUEUE_EXACT already deleted its matched row atomically; QUEUE_PARTIAL intentionally retains its unresolved queue, and standalone queue cleanup remains available.

Full-debit clearing now seals the evidenced debit queue rows for the same account/currency. It rejects queue totals exceeding authority, unknown queue currencies and incomplete identities. Physical debit and queue removals execute in the same Oracle transaction, with locks, pre/post validation, insertable custody snapshots and rollback on failure. Other currencies and credit rows remain untouched. If new queue rows appear after approval, execution stops for a fresh reconciliation instead of deleting unreviewed rows.

Pending full-debit approvals created before this correction must be reconciled and approved again. Old balance-only approvals are explicitly rejected at execution. Completed historical batches are not rewritten; existing residue can still use the queue cleanup workflow.

Validation uses mocked Oracle transactions, including full clearing, exact clearing with unrelated residual queues, failed deletion rollback, and post-approval queue additions. No production data was modified during development. Deploy frontend and Nexus API together; no schema migration is required for this correction.
