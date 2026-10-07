-- 008_add_user_security_fields.up.sql
-- Adds public key management and password rotation fields to users table.

-- Add public key fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key_fingerprint VARCHAR(64);
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key_registered_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key_expires_at TIMESTAMPTZ;

-- Add password rotation fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ DEFAULT now();

-- Add index for public key fingerprint lookups
CREATE INDEX IF NOT EXISTS idx_users_public_key_fingerprint ON users (public_key_fingerprint);

-- Add comment for documentation
COMMENT ON COLUMN users.public_key IS 'RSA-4096 public key in PEM format for signature verification';
COMMENT ON COLUMN users.public_key_fingerprint IS 'SHA-256 fingerprint of the public key';
COMMENT ON COLUMN users.public_key_expires_at IS 'Public key expiry timestamp (default 90 days from registration)';
COMMENT ON COLUMN users.must_change_password IS 'Forces password change on next login';
COMMENT ON COLUMN users.password_changed_at IS 'Timestamp of last password change';


