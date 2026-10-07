-- 011_update_builds_table.up.sql
-- Adds encryption_certificate field to builds table.
-- This stores the HPCR encryption certificate uploaded by the Solution Provider.

ALTER TABLE builds ADD COLUMN IF NOT EXISTS encryption_certificate TEXT;

COMMENT ON COLUMN builds.encryption_certificate IS 'HPCR encryption certificate (PEM format) provided by Solution Provider';


