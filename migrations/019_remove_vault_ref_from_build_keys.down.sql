-- 019_remove_vault_ref_from_build_keys.down.sql
ALTER TABLE build_keys ADD COLUMN IF NOT EXISTS vault_ref TEXT;
