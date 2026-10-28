-- SOURCE database migration: run as the queue owner on SMSAL_DATABASE (postgres).
-- This is NOT a SentinelOps application database migration.
-- No message data or credentials are placed in the notification payload.
BEGIN;
SET LOCAL lock_timeout = '2s';
CREATE OR REPLACE FUNCTION public.sentinelops_sms_queue_notify()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    PERFORM pg_notify('sentinelops_sms_queue', 'changed');
  ELSIF TG_OP = 'INSERT' THEN
    IF NEW.channel = 'SMS' THEN PERFORM pg_notify('sentinelops_sms_queue', 'changed'); END IF;
  ELSIF TG_OP = 'DELETE' THEN
    IF OLD.channel = 'SMS' THEN PERFORM pg_notify('sentinelops_sms_queue', 'changed'); END IF;
  ELSE
    IF OLD.channel = 'SMS' OR NEW.channel = 'SMS' THEN
      PERFORM pg_notify('sentinelops_sms_queue', 'changed');
    END IF;
  END IF;
  RETURN NULL; -- AFTER trigger; never changes the source row.
END;
$$;
DROP TRIGGER IF EXISTS sentinelops_sms_queue_change ON public.queue;
CREATE TRIGGER sentinelops_sms_queue_change
AFTER INSERT OR UPDATE OR DELETE ON public.queue
FOR EACH ROW EXECUTE FUNCTION public.sentinelops_sms_queue_notify();
DROP TRIGGER IF EXISTS sentinelops_sms_queue_truncate ON public.queue;
CREATE TRIGGER sentinelops_sms_queue_truncate
AFTER TRUNCATE ON public.queue
FOR EACH STATEMENT EXECUTE FUNCTION public.sentinelops_sms_queue_notify();
COMMIT;
-- PostgreSQL emits NOTIFY only after commit and coalesces the identical payload
-- within a transaction. Rollback emits nothing. Existing status/retry logic stays
-- owned by the sending service. To disable, drop these two triggers as owner.
