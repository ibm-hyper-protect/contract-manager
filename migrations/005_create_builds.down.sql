-- 005_create_builds.down.sql

DROP INDEX IF EXISTS idx_builds_created_by;
DROP INDEX IF EXISTS idx_builds_status;
DROP TABLE IF EXISTS builds;
