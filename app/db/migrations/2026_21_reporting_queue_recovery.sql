-- Apply to the SentinelOps/Nexus PostgreSQL database, never the loan source.
BEGIN;
CREATE TABLE IF NOT EXISTS nexus_queue_recovery (
 action_id text PRIMARY KEY,
 queue text NOT NULL CHECK (queue IN ('hovering', 'personal-loans')),
 actor text NOT NULL,
 state text NOT NULL CHECK (state IN ('PREPARED','APPLYING','COMPLETED','REJECTED','UNCERTAIN')),
 filters jsonb NOT NULL,
 evidence jsonb NOT NULL,
 updated_count integer NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now() + interval '10 minutes',
 completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS nexus_queue_recovery_history ON nexus_queue_recovery(queue, created_at DESC, action_id);
COMMIT;
