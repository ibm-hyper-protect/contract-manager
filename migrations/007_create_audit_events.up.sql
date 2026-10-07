-- 007_create_audit_events.up.sql
-- Creates the audit_events table for the tamper-evident hash chain.

CREATE TABLE IF NOT EXISTS audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id            UUID             NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    sequence_no         INTEGER          NOT NULL,
    event_type          audit_event_type NOT NULL,
    actor_user_id       UUID             NOT NULL REFERENCES users(id),
    actor_public_key    TEXT,
    ip_address          INET,
    device_metadata     JSONB,
    event_data          JSONB            NOT NULL,
    previous_event_hash TEXT             NOT NULL,
    event_hash          TEXT             NOT NULL,
    signature           TEXT,
    created_at          TIMESTAMPTZ      NOT NULL DEFAULT now(),

    UNIQUE (build_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS idx_audit_events_build_id ON audit_events (build_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_build_seq ON audit_events (build_id, sequence_no);
