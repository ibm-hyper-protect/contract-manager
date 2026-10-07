-- name: GetUserByEmail :one
SELECT u.id, u.name, u.email, u.password_hash, u.is_active, u.created_at,
       u.public_key, u.public_key_fingerprint, u.public_key_registered_at, u.public_key_expires_at,
       u.must_change_password, u.password_changed_at
FROM users u
WHERE u.email = $1;

-- name: GetUserByID :one
SELECT u.id, u.name, u.email, u.password_hash, u.is_active, u.created_at,
       u.public_key, u.public_key_fingerprint, u.public_key_registered_at, u.public_key_expires_at,
       u.must_change_password, u.password_changed_at
FROM users u
WHERE u.id = $1;

-- name: GetUserByPublicKeyFingerprint :one
SELECT u.id, u.name, u.email, u.public_key, u.public_key_fingerprint,
       u.public_key_registered_at, u.public_key_expires_at
FROM users u
WHERE u.public_key_fingerprint = $1;

-- name: ListUsers :many
SELECT u.id, u.name, u.email, u.is_active, u.created_at,
       u.public_key_fingerprint, u.public_key_expires_at, u.must_change_password
FROM users u
ORDER BY u.created_at DESC;

-- name: CreateUser :one
INSERT INTO users (name, email, password_hash)
VALUES ($1, $2, $3)
RETURNING id, name, email, is_active, created_at, must_change_password, password_changed_at;

-- name: DeactivateUser :exec
UPDATE users SET is_active = false WHERE id = $1;

-- name: RegisterPublicKey :exec
UPDATE users
SET public_key = $2,
    public_key_fingerprint = $3,
    public_key_registered_at = NOW(),
    public_key_expires_at = NOW() + INTERVAL '90 days'
WHERE id = $1;

-- name: UpdatePassword :exec
UPDATE users
SET password_hash = $2,
    must_change_password = false,
    password_changed_at = NOW()
WHERE id = $1;

-- name: ForcePasswordChange :exec
UPDATE users
SET must_change_password = true
WHERE id = $1;

-- name: GetUsersWithExpiredPasswords :many
SELECT id, name, email, password_changed_at, must_change_password, created_at
FROM users
WHERE is_active = true
  AND (
    must_change_password = true
    OR password_changed_at < NOW() - INTERVAL '90 days'
  );

-- name: GetUsersWithExpiredPublicKeys :many
SELECT id, name, email, public_key_fingerprint, public_key_registered_at, public_key_expires_at
FROM users
WHERE is_active = true
  AND (
    public_key_registered_at IS NULL
    OR public_key_expires_at < NOW()
  );

-- name: UpdateUser :one
UPDATE users
SET name = $2, email = $3
WHERE id = $1
RETURNING id, name, email, is_active, created_at, must_change_password, password_changed_at;

-- name: RevokePublicKey :exec
UPDATE users
SET public_key = NULL,
    public_key_fingerprint = NULL,
    public_key_registered_at = NULL,
    public_key_expires_at = NULL
WHERE id = $1;

-- name: ReactivateUser :exec
UPDATE users SET is_active = true WHERE id = $1;

-- name: AdminResetPassword :exec
UPDATE users
SET password_hash = $2,
    must_change_password = true,
    password_changed_at = NOW()
WHERE id = $1;
