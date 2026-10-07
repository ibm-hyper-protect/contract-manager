-- 006_create_build_sections.up.sql
-- Creates the build_sections table for persona contributions.

CREATE TABLE IF NOT EXISTS build_sections (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id                UUID         NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    persona_role            persona_role NOT NULL,
    submitted_by            UUID         NOT NULL REFERENCES users(id),
    encrypted_payload       TEXT         NOT NULL,
    encrypted_symmetric_key TEXT,
    section_hash            TEXT         NOT NULL,
    signature               TEXT         NOT NULL,
    submitted_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),

    UNIQUE (build_id, persona_role)
);

CREATE INDEX IF NOT EXISTS idx_build_sections_build_id ON build_sections (build_id);
