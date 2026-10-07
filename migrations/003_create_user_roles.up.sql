-- 003_create_user_roles.up.sql
-- Creates the user_roles table for RBAC.

CREATE TABLE IF NOT EXISTS user_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        persona_role NOT NULL,
    assigned_by UUID         NOT NULL REFERENCES users(id),
    assigned_at TIMESTAMPTZ  NOT NULL DEFAULT now(),

    UNIQUE (user_id, role)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles (user_id);
