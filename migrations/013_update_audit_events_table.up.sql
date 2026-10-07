-- 013_update_audit_events_table.up.sql
-- Updates audit_events table to add actor_key_fingerprint for identity-bound signatures.
-- The table already has most fields we need (previous_event_hash, event_hash, signature, actor_public_key).

-- Add actor_key_fingerprint column for efficient lookups
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_key_fingerprint VARCHAR(64);

-- Create index for fingerprint lookups
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_fingerprint ON audit_events (actor_key_fingerprint);

-- Make build_id nullable to support system-level events (user creation, role assignment, etc.)
ALTER TABLE audit_events ALTER COLUMN build_id DROP NOT NULL;

COMMENT ON COLUMN audit_events.actor_key_fingerprint IS 'SHA-256 fingerprint of the actor public key used for signature verification';
COMMENT ON COLUMN audit_events.build_id IS 'Build ID (nullable for system-level events like user creation)';


