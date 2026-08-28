-- SentinelOps Reporting Custody: loan hovering queue monitoring and date remediation.
-- Apply after 2026_14_add_nexus_crb_reporting.sql.

CREATE TABLE IF NOT EXISTS nexus_hovering_policy (
    policy_key TEXT PRIMARY KEY
        CHECK (policy_key = 'midnight-installment-rollover'),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by TEXT NOT NULL DEFAULT 'system',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_day DATE NULL,
    last_run_at TIMESTAMPTZ NULL,
    last_updated_count INTEGER NOT NULL DEFAULT 0,
    last_run_status TEXT NOT NULL DEFAULT 'NEVER'
        CHECK (last_run_status IN ('NEVER', 'RUNNING', 'COMPLETED', 'FAILED')),
    last_error TEXT NULL
);

INSERT INTO nexus_hovering_policy (policy_key)
VALUES ('midnight-installment-rollover')
ON CONFLICT (policy_key) DO NOTHING;

CREATE TABLE IF NOT EXISTS nexus_hovering_policy_audit (
    audit_id TEXT PRIMARY KEY,
    policy_key TEXT NOT NULL REFERENCES nexus_hovering_policy(policy_key) ON DELETE RESTRICT,
    previous_enabled BOOLEAN NOT NULL,
    enabled BOOLEAN NOT NULL,
    changed_by TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_nexus_hovering_policy_audit_time
    ON nexus_hovering_policy_audit (changed_at DESC);

CREATE TABLE IF NOT EXISTS nexus_hovering_queue_sample (
    sample_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL,
    pending_count BIGINT NOT NULL CHECK (pending_count >= 0),
    overdue_count BIGINT NOT NULL CHECK (overdue_count >= 0),
    due_today_count BIGINT NOT NULL CHECK (due_today_count >= 0),
    future_count BIGINT NOT NULL CHECK (future_count >= 0),
    latest_queue_update TIMESTAMP NULL
);

CREATE INDEX IF NOT EXISTS idx_nexus_hovering_queue_sample_time
    ON nexus_hovering_queue_sample (observed_at DESC);

CREATE TABLE IF NOT EXISTS nexus_hovering_date_action (
    action_id TEXT PRIMARY KEY,
    trigger TEXT NOT NULL CHECK (trigger IN ('MANUAL', 'SCHEDULED')),
    actor TEXT NOT NULL,
    requested_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_count INTEGER NOT NULL DEFAULT 0 CHECK (updated_count >= 0),
    status TEXT NOT NULL CHECK (status IN ('COMPLETED', 'FAILED')),
    error_message TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_nexus_hovering_date_action_time
    ON nexus_hovering_date_action (created_at DESC);

COMMENT ON TABLE nexus_hovering_queue_sample IS
    'Bounded SentinelOps observations used to calculate active-window hovering throughput and stall posture.';
COMMENT ON TABLE nexus_hovering_date_action IS
    'Immutable custody history for manual and scheduled installment-date remediation.';
