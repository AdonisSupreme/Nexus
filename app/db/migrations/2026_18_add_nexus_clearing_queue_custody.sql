-- Funds Custody: explicit queue-only custody and terminal Account Explorer retirement.
-- Apply after 2026_17_refine_nexus_hovering_flow.sql.

ALTER TABLE nexus_clearing_transaction
    DROP CONSTRAINT IF EXISTS nexus_clearing_transaction_operation_mode_check,
    DROP CONSTRAINT IF EXISTS nexus_clearing_transaction_amount_check,
    DROP CONSTRAINT IF EXISTS nexus_clearing_transaction_clear_amount_check;

ALTER TABLE nexus_clearing_transaction
    ADD CONSTRAINT nexus_clearing_transaction_operation_mode_check
        CHECK (operation_mode IN (
            'QUEUE_EXACT',
            'QUEUE_PARTIAL',
            'BALANCE_ALL',
            'QUEUE_ROW_ONLY',
            'QUEUE_AMOUNT_RESET'
        )),
    ADD CONSTRAINT nexus_clearing_transaction_amount_check
        CHECK (
            amount > 0
            OR (operation_mode IN ('BALANCE_ALL', 'QUEUE_ROW_ONLY', 'QUEUE_AMOUNT_RESET') AND amount = 0)
        ),
    ADD CONSTRAINT nexus_clearing_transaction_clear_amount_check
        CHECK (
            clear_amount IS NULL
            OR clear_amount > 0
            OR (operation_mode IN ('BALANCE_ALL', 'QUEUE_ROW_ONLY', 'QUEUE_AMOUNT_RESET') AND clear_amount = 0)
        );

COMMENT ON COLUMN nexus_clearing_transaction.operation_mode IS
    'Governed debit clearing, exact queue-row removal without ACNTBAL debit mutation, or orphaned ACNTBAL debit-queue amount repair.';
