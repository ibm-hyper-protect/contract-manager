-- 012_update_build_sections_table.up.sql
-- Updates build_sections table to add role_id reference and rename wrapped key column.

-- Add role_id column to reference the roles table
ALTER TABLE build_sections ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES roles(id);

-- Rename encrypted_symmetric_key to wrapped_symmetric_key for clarity
ALTER TABLE build_sections RENAME COLUMN encrypted_symmetric_key TO wrapped_symmetric_key;

-- Create index for role_id lookups
CREATE INDEX IF NOT EXISTS idx_build_sections_role_id ON build_sections (role_id);

COMMENT ON COLUMN build_sections.role_id IS 'Reference to the persona role that submitted this section';
COMMENT ON COLUMN build_sections.wrapped_symmetric_key IS 'AES-256 symmetric key wrapped with Auditor public key (RSA-OAEP) - only for DATA_OWNER sections';


