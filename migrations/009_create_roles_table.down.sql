-- 009_create_roles_table.down.sql
-- Drops the roles reference table.

DROP INDEX IF EXISTS idx_roles_name;
DROP TABLE IF EXISTS roles CASCADE;


