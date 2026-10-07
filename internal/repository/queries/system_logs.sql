-- name: CreateSystemLog :one
INSERT INTO system_logs (actor_email, action, resource, ip_address, status, details)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, timestamp, actor_email, action, resource, ip_address, status, details;

-- name: ListSystemLogs :many
SELECT id, timestamp, actor_email, action, resource, ip_address, status, details
FROM system_logs
ORDER BY timestamp DESC
LIMIT $1 OFFSET $2;
