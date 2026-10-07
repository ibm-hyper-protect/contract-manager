-- name: GetRolesByUserID :many
SELECT ur.id, ur.user_id, ur.role, ur.assigned_by, ur.assigned_at
FROM user_roles ur
WHERE ur.user_id = $1;

-- name: AssignRole :one
INSERT INTO user_roles (user_id, role, assigned_by)
VALUES ($1, $2, $3)
RETURNING id, user_id, role, assigned_by, assigned_at;

-- name: DeleteRolesByUserID :exec
DELETE FROM user_roles WHERE user_id = $1;
