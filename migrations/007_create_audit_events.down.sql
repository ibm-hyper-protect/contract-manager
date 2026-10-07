-- 007_create_audit_events.down.sql

DROP INDEX IF EXISTS idx_audit_events_build_seq;
DROP INDEX IF EXISTS idx_audit_events_build_id;
DROP TABLE IF EXISTS audit_events;
