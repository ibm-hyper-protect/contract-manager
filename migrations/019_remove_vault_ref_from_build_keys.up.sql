-- 019_remove_vault_ref_from_build_keys.up.sql
-- Remove vault_ref column since Vault provider has been removed.
ALTER TABLE build_keys DROP COLUMN IF EXISTS vault_ref;
