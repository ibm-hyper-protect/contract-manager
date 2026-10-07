-- name: GetRoleByName :one
SELECT * FROM roles
WHERE name = $1
LIMIT 1;

-- name: GetRoleByID :one
SELECT * FROM roles
WHERE id = $1
LIMIT 1;

-- name: ListRoles :many
SELECT * FROM roles
ORDER BY name;


