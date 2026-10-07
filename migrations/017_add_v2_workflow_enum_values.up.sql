-- 017_add_v2_workflow_enum_values.up.sql
-- Adds new build_status and audit_event_type enum values for the v2 workflow.

-- New build statuses for v2 workflow order
ALTER TYPE build_status ADD VALUE IF NOT EXISTS 'SIGNING_KEY_REGISTERED';
ALTER TYPE build_status ADD VALUE IF NOT EXISTS 'ATTESTATION_KEY_REGISTERED';

-- New audit event types for v2 workflow
ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS 'SIGNING_KEY_CREATED';
ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS 'ATTESTATION_KEY_REGISTERED';
ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS 'ATTESTATION_EVIDENCE_UPLOADED';
ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS 'ATTESTATION_VERIFIED';
