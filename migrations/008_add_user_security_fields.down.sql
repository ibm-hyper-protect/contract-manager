-- 008_add_user_security_fields.down.sql
-- Removes public key management and password rotation fields from users table.

-- Drop index
DROP INDEX IF EXISTS idx_users_public_key_fingerprint;

-- Remove password rotation fields
ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at;
ALTER TABLE users DROP COLUMN IF EXISTS must_change_password;

-- Remove public key fields
ALTER TABLE users DROP COLUMN IF EXISTS public_key_expires_at;
ALTER TABLE users DROP COLUMN IF EXISTS public_key_registered_at;
ALTER TABLE users DROP COLUMN IF EXISTS public_key_fingerprint;
ALTER TABLE users DROP COLUMN IF EXISTS public_key;


