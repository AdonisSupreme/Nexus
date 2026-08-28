-- SentinelOps Funds Custody: two-step execution, scoped-clearing policy, and tolerant identity intake.
-- Apply after 2026_10_refine_nexus_clearing_custody.sql.

CREATE TABLE IF NOT EXISTS nexus_clearing_policy (
    policy_key TEXT PRIMARY KEY
        CHECK (policy_key IN ('specific-record-clearing')),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by TEXT NOT NULL DEFAULT 'system',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO nexus_clearing_policy (policy_key, enabled, updated_by)
VALUES ('specific-record-clearing', FALSE, 'system')
ON CONFLICT (policy_key) DO NOTHING;

ALTER TABLE nexus_clearing_transaction
    DROP CONSTRAINT IF EXISTS nexus_clearing_transaction_amount_check,
    DROP CONSTRAINT IF EXISTS nexus_clearing_transaction_clear_amount_check;

ALTER TABLE nexus_clearing_transaction
    ADD CONSTRAINT nexus_clearing_transaction_amount_check
        CHECK (amount > 0 OR (operation_mode = 'BALANCE_ALL' AND amount = 0)),
    ADD CONSTRAINT nexus_clearing_transaction_clear_amount_check
        CHECK (
            clear_amount IS NULL
            OR clear_amount > 0
            OR (operation_mode = 'BALANCE_ALL' AND clear_amount = 0)
        );

COMMENT ON TABLE nexus_clearing_policy IS
    'Administrator-owned Funds Custody controls. Specific-record clearing remains disabled by default.';
COMMENT ON COLUMN nexus_clearing_transaction.amount IS
    'Zero is reserved for unresolved or already-clear BALANCE_ALL intake evidence; it is never executable.';
