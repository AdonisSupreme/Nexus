-- SentinelOps Reporting Custody: robot-setting mutation custody.
-- Apply after 2026_15_add_nexus_hovering_monitor.sql.

CREATE TABLE IF NOT EXISTS nexus_hovering_setting_action (
    action_id TEXT PRIMARY KEY,
    setting_key TEXT NOT NULL,
    setting_kind TEXT NOT NULL
        CHECK (setting_kind IN ('ROBOT_PASSWORD', 'GENERAL_CONFIGURATION')),
    actor TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('COMPLETED', 'FAILED')),
    error_message TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_nexus_hovering_setting_action_time
    ON nexus_hovering_setting_action (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_nexus_hovering_setting_action_key
    ON nexus_hovering_setting_action (setting_key, created_at DESC);

COMMENT ON TABLE nexus_hovering_setting_action IS
    'Immutable custody for hovering robot password rotations and general configuration changes. Values and hashes are deliberately excluded.';
