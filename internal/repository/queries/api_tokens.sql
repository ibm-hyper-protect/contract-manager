-- name: CreateAPIToken :one
INSERT INTO api_tokens (user_id, name, token_hash)
VALUES ($1, $2, $3)
RETURNING id, user_id, name, created_at;

-- name: GetAPITokenByHash :one
SELECT t.id, t.user_id, t.name, t.token_hash, t.last_used_at, t.revoked_at, t.created_at
FROM api_tokens t
WHERE t.token_hash = $1;

-- name: ListAPITokensByUserID :many
SELECT t.id, t.name, t.last_used_at, t.revoked_at, t.created_at
FROM api_tokens t
WHERE t.user_id = $1
ORDER BY t.created_at DESC;

-- name: RevokeAPIToken :exec
UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND user_id = $2;

-- name: UpdateTokenLastUsed :exec
UPDATE api_tokens SET last_used_at = now() WHERE id = $1;
