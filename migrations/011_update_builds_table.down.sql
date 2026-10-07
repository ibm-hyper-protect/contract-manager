-- 011_update_builds_table.down.sql
-- Removes encryption_certificate field from builds table.

ALTER TABLE builds DROP COLUMN IF EXISTS encryption_certificate;


