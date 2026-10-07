-- 009_create_roles_table.up.sql
-- Creates the roles reference table and seeds initial persona roles.
-- This replaces the persona_role ENUM with a first-class table for better referential integrity.

CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the six persona roles
INSERT INTO roles (name, description) VALUES
    ('SOLUTION_PROVIDER', 'Provides workload definition and HPCR encryption certificate'),
    ('DATA_OWNER', 'Provides environment configuration with encrypted secrets'),
    ('AUDITOR', 'Generates attestation keys and assembles final signed contract'),
    ('ENV_OPERATOR', 'Downloads and deploys the finalized contract to HPCR instance'),
    ('ADMIN', 'System administrator with full access to user and build management'),
    ('VIEWER', 'Read-only access to builds and audit logs');

-- Create index for name lookups
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles (name);

COMMENT ON TABLE roles IS 'Reference table for persona roles in the system';
COMMENT ON COLUMN roles.name IS 'Unique role identifier (matches persona_role ENUM values)';


