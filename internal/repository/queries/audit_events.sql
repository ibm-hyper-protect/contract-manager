-- name: CreateAuditEvent :one
INSERT INTO audit_events (build_id, sequence_no, event_type, actor_user_id, actor_public_key, actor_key_fingerprint, ip_address, device_metadata, event_data, previous_event_hash, event_hash, signature)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id, build_id, sequence_no, event_type, actor_user_id, actor_public_key, actor_key_fingerprint, ip_address, device_metadata, event_data, previous_event_hash, event_hash, signature, created_at;

-- name: GetAuditEventsByBuildID :many
SELECT id, build_id, sequence_no, event_type, actor_user_id, actor_public_key, actor_key_fingerprint, ip_address, device_metadata, event_data, previous_event_hash, event_hash, signature, created_at
FROM audit_events
WHERE build_id = $1
ORDER BY sequence_no ASC;

-- name: GetLatestAuditEvent :one
SELECT id, build_id, sequence_no, event_type, actor_user_id, actor_public_key, actor_key_fingerprint, ip_address, device_metadata, event_data, previous_event_hash, event_hash, signature, created_at
FROM audit_events
WHERE build_id = $1
ORDER BY sequence_no DESC
LIMIT 1;

-- name: CountAuditEventsByBuildID :one
SELECT count(*) FROM audit_events WHERE build_id = $1;
