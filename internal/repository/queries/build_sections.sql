-- name: CreateBuildSection :one
INSERT INTO build_sections (build_id, persona_role, role_id, submitted_by, encrypted_payload, wrapped_symmetric_key, section_hash, signature)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, build_id, persona_role, role_id, submitted_by, encrypted_payload, wrapped_symmetric_key, section_hash, signature, submitted_at;

-- name: GetBuildSectionsByBuildID :many
SELECT id, build_id, persona_role, role_id, submitted_by, encrypted_payload, wrapped_symmetric_key, section_hash, signature, submitted_at
FROM build_sections
WHERE build_id = $1
ORDER BY submitted_at ASC;

-- name: GetBuildSectionByRole :one
SELECT id, build_id, persona_role, role_id, submitted_by, encrypted_payload, wrapped_symmetric_key, section_hash, signature, submitted_at
FROM build_sections
WHERE build_id = $1 AND persona_role = $2;

-- name: GetBuildSectionByRoleID :one
SELECT bs.*, r.name as role_name
FROM build_sections bs
LEFT JOIN roles r ON bs.role_id = r.id
WHERE bs.build_id = $1 AND bs.role_id = $2;
