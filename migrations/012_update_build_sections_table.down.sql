-- 012_update_build_sections_table.down.sql
-- Reverts build_sections table updates.

-- Drop index
DROP INDEX IF EXISTS idx_build_sections_role_id;

-- Rename column back
ALTER TABLE build_sections RENAME COLUMN wrapped_symmetric_key TO encrypted_symmetric_key;

-- Remove role_id column
ALTER TABLE build_sections DROP COLUMN IF EXISTS role_id;


