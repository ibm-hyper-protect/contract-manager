-- name: CreateBuild :one
INSERT INTO builds (name, created_by)
VALUES ($1, $2)
RETURNING id, name, status, created_by, created_at, finalized_at, contract_hash, contract_yaml, is_immutable;

-- name: GetBuildByID :one
SELECT id, name, status, created_by, created_at, finalized_at, contract_hash, contract_yaml, is_immutable
FROM builds
WHERE id = $1;

-- name: ListBuilds :many
SELECT id, name, status, created_by, created_at, finalized_at, contract_hash, is_immutable
FROM builds
WHERE (sqlc.narg('status')::build_status IS NULL OR status = sqlc.narg('status')::build_status)
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountBuilds :one
SELECT count(*) FROM builds
WHERE (sqlc.narg('status')::build_status IS NULL OR status = sqlc.narg('status')::build_status);

-- name: UpdateBuildStatus :exec
UPDATE builds SET status = $2 WHERE id = $1;

-- name: FinalizeBuild :exec
UPDATE builds
SET status = 'FINALIZED',
    contract_yaml = $2,
    contract_hash = $3,
    finalized_at = now(),
    is_immutable = true
WHERE id = $1;
