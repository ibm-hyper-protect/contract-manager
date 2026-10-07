-- 018_add_build_keys_private_table.up.sql
-- Stores passphrase-encrypted private key material (AES-256-CBC PEM format).
-- Separated from build_keys to isolate sensitive key material.

CREATE TABLE IF NOT EXISTS build_keys_private (
    key_id          UUID PRIMARY KEY REFERENCES build_keys(id) ON DELETE CASCADE,
    encrypted_key   BYTEA       NOT NULL,
    encryption_algo TEXT        NOT NULL DEFAULT 'aes-256-cbc',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN build_keys_private.encrypted_key IS
    'Passphrase-encrypted private key in OpenSSL PEM format (Proc-Type: 4,ENCRYPTED). Never stored in plaintext.';
