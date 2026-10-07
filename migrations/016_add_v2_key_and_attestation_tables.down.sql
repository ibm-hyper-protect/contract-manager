-- 016_add_v2_key_and_attestation_tables.down.sql
-- Reverts backend-native key management and attestation evidence persistence.

DROP INDEX IF EXISTS idx_attestation_verifications_build_id;
DROP TABLE IF EXISTS attestation_verifications;

DROP INDEX IF EXISTS idx_attestation_evidence_build_id;
DROP TABLE IF EXISTS attestation_evidence;

ALTER TABLE builds
    DROP COLUMN IF EXISTS attestation_verified_by,
    DROP COLUMN IF EXISTS attestation_verified_at,
    DROP COLUMN IF EXISTS attestation_state;

DROP INDEX IF EXISTS idx_build_keys_type;
DROP INDEX IF EXISTS idx_build_keys_build_id;
DROP TABLE IF EXISTS build_keys;
