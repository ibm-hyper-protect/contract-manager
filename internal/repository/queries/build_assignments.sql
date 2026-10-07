-- name: CreateBuildAssignment :one
INSERT INTO build_assignments (
    build_id,
    role_id,
    user_id,
    assigned_by
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: GetBuildAssignmentByBuildAndRole :one
SELECT ba.*, r.name as role_name, u.name as user_name, u.email as user_email
FROM build_assignments ba
JOIN roles r ON ba.role_id = r.id
JOIN users u ON ba.user_id = u.id
WHERE ba.build_id = $1 AND ba.role_id = $2
LIMIT 1;

-- name: GetBuildAssignmentsByBuildID :many
SELECT ba.*, r.name as role_name, u.name as user_name, u.email as user_email
FROM build_assignments ba
JOIN roles r ON ba.role_id = r.id
JOIN users u ON ba.user_id = u.id
WHERE ba.build_id = $1
ORDER BY r.name;

-- name: GetBuildAssignmentsByUserID :many
SELECT ba.*, r.name as role_name, b.name as build_name, b.status as build_status
FROM build_assignments ba
JOIN roles r ON ba.role_id = r.id
JOIN builds b ON ba.build_id = b.id
WHERE ba.user_id = $1
ORDER BY ba.assigned_at DESC;

-- name: CheckUserAssignedToBuild :one
SELECT EXISTS(
    SELECT 1 FROM build_assignments
    WHERE build_id = $1 AND user_id = $2 AND role_id = $3
) as is_assigned;

-- name: DeleteBuildAssignmentsByBuildID :exec
DELETE FROM build_assignments
WHERE build_id = $1;


