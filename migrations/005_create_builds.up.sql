-- 005_create_builds.up.sql
-- Creates the builds table for the contract build lifecycle.

CREATE TABLE IF NOT EXISTS builds (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(255) NOT NULL,
    status        build_status NOT NULL DEFAULT 'CREATED',
    created_by    UUID         NOT NULL REFERENCES users(id),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    finalized_at  TIMESTAMPTZ,
    contract_hash TEXT,
    contract_yaml TEXT,
    is_immutable  BOOLEAN      NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_builds_status ON builds (status);
CREATE INDEX IF NOT EXISTS idx_builds_created_by ON builds (created_by);
