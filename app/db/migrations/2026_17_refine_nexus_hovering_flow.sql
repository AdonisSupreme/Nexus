-- SentinelOps Reporting Custody: separate queue arrivals from robot processing.
-- Apply after 2026_16_add_nexus_hovering_setting_audit.sql.

ALTER TABLE nexus_hovering_queue_sample
    ADD COLUMN IF NOT EXISTS created_count BIGINT NULL
        CHECK (created_count IS NULL OR created_count >= 0);

COMMENT ON COLUMN nexus_hovering_queue_sample.created_count IS
    'Cumulative txn-bot hovering rows observed at sample time; used with pending_count to derive arrivals, processed work, and net queue movement.';

