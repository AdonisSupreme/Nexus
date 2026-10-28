-- Apply to the SentinelOps access database, NOT the SMS source database.
-- No existing section is granted SMS access automatically.
BEGIN;
INSERT INTO access_modules(module_key,name,description,page_key)
VALUES ('reports.sms','SMS queue monitoring','Read-only visibility into SMS queue health and message evidence','Reporting')
ON CONFLICT (module_key) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,page_key=EXCLUDED.page_key;
COMMIT;
