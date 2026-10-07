-- name: StoreBuildKeyPrivate :exec
INSERT INTO build_keys_private (key_id, encrypted_key, encryption_algo)
VALUES ($1, $2, $3);

-- name: GetBuildKeyPrivate :one
SELECT key_id, encrypted_key, encryption_algo, created_at
FROM build_keys_private
WHERE key_id = $1;

-- name: DeleteBuildKeyPrivate :exec
DELETE FROM build_keys_private WHERE key_id = $1;
