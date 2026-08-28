-- SentinelOps regulatory reporting: CRB extraction custody and retention.
-- Apply after the current Nexus migrations.

CREATE TABLE IF NOT EXISTS nexus_crb_report_run (
    run_id TEXT PRIMARY KEY,
    run_day DATE NOT NULL,
    trigger TEXT NOT NULL CHECK (trigger IN ('SCHEDULED', 'MANUAL')),
    status TEXT NOT NULL CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED')),
    requested_by TEXT NOT NULL,
    current_report TEXT NULL,
    started_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    error_message TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_nexus_crb_scheduled_day
    ON nexus_crb_report_run (run_day)
    WHERE trigger = 'SCHEDULED';

CREATE INDEX IF NOT EXISTS idx_nexus_crb_report_run_timeline
    ON nexus_crb_report_run (created_at DESC);

CREATE TABLE IF NOT EXISTS nexus_crb_report_artifact (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES nexus_crb_report_run(run_id) ON DELETE RESTRICT,
    report_key TEXT NOT NULL CHECK (report_key IN ('CONTRACT_DATA', 'INDIVIDUAL_DETAILS')),
    view_name TEXT NOT NULL,
    filename TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('GENERATED', 'REPLACED', 'PURGED', 'FAILED')),
    row_count BIGINT NOT NULL DEFAULT 0,
    byte_size BIGINT NOT NULL DEFAULT 0,
    sha256 CHAR(64) NULL,
    generated_at TIMESTAMPTZ NULL,
    purged_at TIMESTAMPTZ NULL,
    error_message TEXT NULL,
    UNIQUE (run_id, report_key)
);

CREATE INDEX IF NOT EXISTS idx_nexus_crb_report_artifact_current
    ON nexus_crb_report_artifact (report_key, generated_at DESC)
    WHERE status = 'GENERATED';

CREATE TABLE IF NOT EXISTS nexus_crb_maintenance (
    maintenance_key TEXT PRIMARY KEY CHECK (maintenance_key = 'daily-retention'),
    last_cleanup_day DATE NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO nexus_crb_maintenance (maintenance_key)
VALUES ('daily-retention')
ON CONFLICT (maintenance_key) DO NOTHING;

COMMENT ON TABLE nexus_crb_report_run IS
    'Immutable CRB extraction run history. Artifact files are retained only for their local business day.';
COMMENT ON TABLE nexus_crb_report_artifact IS
    'Two replaceable current-day CSV artifacts backed by immutable extraction metadata.';
