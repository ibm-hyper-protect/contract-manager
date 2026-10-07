-- 013_update_audit_events_table.down.sql
-- Reverts audit_events table updates.

-- Make build_id NOT NULL again (this may fail if there are system-level events)
ALTER TABLE audit_events ALTER COLUMN build_id SET NOT NULL;

-- Drop index
DROP INDEX IF EXISTS idx_audit_events_actor_fingerprint;

-- Remove actor_key_fingerprint column
ALTER TABLE audit_events DROP COLUMN IF EXISTS actor_key_fingerprint;


