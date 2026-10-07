-- 016_add_v2_key_and_attestation_tables.up.sql
-- Adds backend-native key management and attestation evidence persistence.

CREATE TABLE IF NOT EXISTS build_keys (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id               UUID        NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    key_type               TEXT        NOT NULL CHECK (key_type IN ('SIGNING', 'ATTESTATION')),
    mode                   TEXT        NOT NULL CHECK (mode IN ('generate', 'upload_public')),
    status                 TEXT        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
    vault_ref              TEXT,
    public_key             TEXT        NOT NULL,
    public_key_fingerprint TEXT        NOT NULL,
    created_by             UUID        NOT NULL REFERENCES users(id),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_build_keys_build_id ON build_keys (build_id);
CREATE INDEX IF NOT EXISTS idx_build_keys_type ON build_keys (build_id, key_type, status);

ALTER TABLE builds
    ADD COLUMN IF NOT EXISTS attestation_state TEXT NOT NULL DEFAULT 'PENDING_UPLOAD'
        CHECK (attestation_state IN ('PENDING_UPLOAD', 'UPLOADED', 'VERIFIED', 'REJECTED')),
    ADD COLUMN IF NOT EXISTS attestation_verified_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS attestation_verified_by UUID REFERENCES users(id);

CREATE TABLE IF NOT EXISTS attestation_evidence (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id            UUID        NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    uploaded_by         UUID        NOT NULL REFERENCES users(id),
    uploader_role       persona_role NOT NULL,
    records_file_name   TEXT        NOT NULL,
    records_content     BYTEA       NOT NULL,
    signature_file_name TEXT        NOT NULL,
    signature_content   BYTEA       NOT NULL,
    metadata            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_attestation_evidence_build_id ON attestation_evidence (build_id, created_at DESC);

CREATE TABLE IF NOT EXISTS attestation_verifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id    UUID        NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    evidence_id UUID        NOT NULL REFERENCES attestation_evidence(id) ON DELETE CASCADE,
    verified_by UUID        NOT NULL REFERENCES users(id),
    verdict     TEXT        NOT NULL CHECK (verdict IN ('VERIFIED', 'REJECTED')),
    details     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_attestation_verifications_build_id ON attestation_verifications (build_id, created_at DESC);
