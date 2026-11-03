-- Copyright (c) 2026 IBM Corp.
-- All rights reserved.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- name: CreateUserPublicKey :one
INSERT INTO user_public_keys (user_id, label, public_key, fingerprint, registered_at, expires_at)
VALUES ($1, $2, $3, $4, statement_timestamp(), statement_timestamp() + INTERVAL '90 days')
RETURNING *;

-- name: ListUserPublicKeys :many
SELECT * FROM user_public_keys WHERE user_id = $1
ORDER BY registered_at DESC, id DESC;

-- name: ListActiveUserPublicKeys :many
-- Recheck expiry after acquiring the user lock; NOW() is fixed at transaction start.
SELECT * FROM user_public_keys
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > statement_timestamp()
ORDER BY registered_at DESC, id DESC;

-- name: CountActiveUserPublicKeys :one
SELECT COUNT(*) FROM user_public_keys
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > statement_timestamp();

-- name: CountAllUserPublicKeys :one
SELECT COUNT(*) FROM user_public_keys WHERE user_id = $1;

-- name: LockUserForKeyChange :one
SELECT id FROM users WHERE id = $1 FOR UPDATE;

-- name: RevokeUserPublicKey :execrows
UPDATE user_public_keys SET revoked_at = statement_timestamp(), revoked_by = $3
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- name: RevokeAllUserPublicKeys :execrows
UPDATE user_public_keys SET revoked_at = statement_timestamp(), revoked_by = $2
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > statement_timestamp();

-- name: RevokeExpiredUserPublicKeys :execrows
UPDATE user_public_keys SET revoked_at = statement_timestamp(), revoked_by = $2
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at <= statement_timestamp();

-- name: ListExpiredUserPublicKeys :many
SELECT k.*, u.name AS user_name, u.email AS user_email
FROM user_public_keys k JOIN users u ON u.id = k.user_id
WHERE u.is_active = true AND k.revoked_at IS NULL AND k.expires_at <= statement_timestamp()
ORDER BY k.expires_at, k.id;

-- name: ListUsersWithoutActiveKey :many
SELECT u.id, u.name, u.email FROM users u
WHERE u.is_active = true AND NOT EXISTS (
    SELECT 1 FROM user_public_keys k
    WHERE k.user_id = u.id AND k.revoked_at IS NULL AND k.expires_at > statement_timestamp()
)
ORDER BY u.created_at DESC;
