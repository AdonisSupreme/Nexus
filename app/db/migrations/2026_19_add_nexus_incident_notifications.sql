-- Durable, multi-worker-safe incident notification delivery for Sentinel Nexus.

CREATE TABLE IF NOT EXISTS nexus_incident_notification_setting (
    setting_key TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    notify_current_shift BOOLEAN NOT NULL DEFAULT TRUE,
    in_app_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    email_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_recovery BOOLEAN NOT NULL DEFAULT TRUE,
    additional_email_recipients TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT,
    CONSTRAINT nexus_incident_notification_setting_singleton
        CHECK (setting_key = 'default')
);

INSERT INTO nexus_incident_notification_setting (setting_key)
VALUES ('default')
ON CONFLICT (setting_key) DO NOTHING;

CREATE TABLE IF NOT EXISTS nexus_incident_notification_delivery (
    delivery_key TEXT PRIMARY KEY,
    incident_id UUID NOT NULL,
    incident_key TEXT NOT NULL,
    incident_started_at TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    payload JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at TIMESTAMPTZ,
    claimed_by TEXT,
    recipient_count INTEGER NOT NULL DEFAULT 0,
    delivered_count INTEGER NOT NULL DEFAULT 0,
    in_app_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    email_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT nexus_incident_notification_event_type_check
        CHECK (event_type IN ('OPENED', 'RECOVERED')),
    CONSTRAINT nexus_incident_notification_status_check
        CHECK (status IN (
            'PENDING', 'PROCESSING', 'RETRY', 'SENT', 'PARTIAL',
            'SUPPRESSED', 'NO_RECIPIENTS', 'FAILED'
        )),
    CONSTRAINT nexus_incident_notification_attempts_check CHECK (attempts >= 0),
    CONSTRAINT nexus_incident_notification_recipient_count_check CHECK (recipient_count >= 0),
    CONSTRAINT nexus_incident_notification_delivered_count_check CHECK (delivered_count >= 0)
);

ALTER TABLE nexus_incident_notification_delivery
    ADD COLUMN IF NOT EXISTS in_app_delivered BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE nexus_incident_notification_delivery
    ADD COLUMN IF NOT EXISTS email_delivered BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_nexus_incident_notification_delivery_queue
    ON nexus_incident_notification_delivery (next_attempt_at, created_at)
    WHERE status IN ('PENDING', 'RETRY', 'PROCESSING');

CREATE INDEX IF NOT EXISTS idx_nexus_incident_notification_delivery_incident
    ON nexus_incident_notification_delivery (incident_id, incident_started_at DESC);
