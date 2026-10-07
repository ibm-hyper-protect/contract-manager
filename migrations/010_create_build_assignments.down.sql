-- 010_create_build_assignments.down.sql
-- Drops the build_assignments table.

DROP INDEX IF EXISTS idx_build_assignments_role_id;
DROP INDEX IF EXISTS idx_build_assignments_user_id;
DROP INDEX IF EXISTS idx_build_assignments_build_id;
DROP TABLE IF EXISTS build_assignments CASCADE;


