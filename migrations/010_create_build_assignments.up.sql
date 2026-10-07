-- 010_create_build_assignments.up.sql
-- Creates the build_assignments table for explicit user-to-role assignments per build.
-- This enforces that only assigned users can contribute to a specific build.

CREATE TABLE IF NOT EXISTS build_assignments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id    UUID        NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    role_id     UUID        NOT NULL REFERENCES roles(id),
    user_id     UUID        NOT NULL REFERENCES users(id),
    assigned_by UUID        NOT NULL REFERENCES users(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Each role can only be assigned once per build
    UNIQUE (build_id, role_id)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_build_assignments_build_id ON build_assignments (build_id);
CREATE INDEX IF NOT EXISTS idx_build_assignments_user_id ON build_assignments (user_id);
CREATE INDEX IF NOT EXISTS idx_build_assignments_role_id ON build_assignments (role_id);

COMMENT ON TABLE build_assignments IS 'Explicit user-to-role assignments for each build';
COMMENT ON COLUMN build_assignments.build_id IS 'The build this assignment belongs to';
COMMENT ON COLUMN build_assignments.role_id IS 'The persona role being assigned';
COMMENT ON COLUMN build_assignments.user_id IS 'The user assigned to perform this role';
COMMENT ON COLUMN build_assignments.assigned_by IS 'The admin who created this assignment';


