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

-- name: LockSecretCatalog :exec
SELECT pg_advisory_xact_lock(1397969746);

-- name: CreateSecretObject :one
INSERT INTO secret_catalog_objects(kind,owner_id,alias,description) VALUES($1,$2,$3,$4) RETURNING *;

-- name: GetSecretObject :one
SELECT * FROM secret_catalog_objects WHERE id=$1;

-- name: ListSecretObjects :many
SELECT o.*,u.name AS owner_name
FROM secret_catalog_objects o JOIN users u ON u.id=o.owner_id
WHERE o.kind=sqlc.arg(kind)
AND (o.alias ILIKE '%' || sqlc.arg(search)::text || '%' OR o.description ILIKE '%' || sqlc.arg(search)::text || '%')
AND o.owner_id=sqlc.arg(actor_id)
ORDER BY o.archived,o.updated_at DESC,o.id LIMIT $1 OFFSET $2;

-- name: UpdateSecretObject :one
UPDATE secret_catalog_objects SET alias=$2,description=$3,archived=$4,revision=revision+1,updated_at=now()
WHERE id=$1 AND revision=$5 RETURNING *;

-- name: ReserveSecretVersion :one
INSERT INTO secret_store_versions(secret_id,version,created_by)
VALUES($1,(SELECT COALESCE(max(version),0)+1 FROM secret_store_versions WHERE secret_id=$1),$2)
RETURNING id,secret_id,version,state,byte_length,created_by,created_at;

-- name: GetSecretVersion :one
SELECT id,secret_id,version,state,byte_length,created_by,created_at FROM secret_store_versions WHERE id=$1;

-- name: ListSecretVersions :many
SELECT id,secret_id,version,state,byte_length,created_by,created_at FROM secret_store_versions WHERE secret_id=$1 ORDER BY version DESC;

-- name: SealSecretVersion :execrows
UPDATE secret_store_versions SET sealed_payload=$2,byte_length=$3,state='SEALED'
WHERE id=$1 AND state='RESERVED';

-- name: GetSealedSecretPayload :one
SELECT sealed_payload FROM secret_store_versions WHERE id=$1 AND state='SEALED';

-- name: CreateSecretGroupRevision :one
INSERT INTO secret_group_revisions(group_id,revision,created_by)
VALUES($1,(SELECT COALESCE(max(revision),0)+1 FROM secret_group_revisions WHERE group_id=$1),$2) RETURNING *;

-- name: GetSecretGroupRevision :one
SELECT * FROM secret_group_revisions WHERE id=$1;

-- name: ListSecretGroupRevisions :many
SELECT * FROM secret_group_revisions WHERE group_id=$1 ORDER BY revision DESC;

-- name: AddSecretGroupMember :exec
INSERT INTO secret_group_members(group_revision_id,version_id) VALUES($1,$2);

-- name: ListSecretGroupMembers :many
SELECT m.version_id,v.secret_id,v.version,v.state,o.alias,o.archived
FROM secret_group_members m JOIN secret_store_versions v ON v.id=m.version_id
JOIN secret_catalog_objects o ON o.id=v.secret_id WHERE m.group_revision_id=$1 ORDER BY o.alias,v.id;

-- name: LockSecretBuild :one
SELECT id,status,is_immutable FROM builds WHERE id=$1 FOR UPDATE;

-- name: LockSecretBuildAssignments :many
SELECT ba.id,r.name AS role_name FROM build_assignments ba JOIN roles r ON ba.role_id=r.id
WHERE ba.build_id=$1 AND ba.user_id=$2 FOR SHARE OF ba;

-- name: InitSecretSourceSet :exec
INSERT INTO build_secret_source_sets(build_id) VALUES($1) ON CONFLICT DO NOTHING;

-- name: GetSecretSourceRevision :one
SELECT revision FROM build_secret_source_sets WHERE build_id=$1;

-- name: BumpSecretSourceRevision :exec
UPDATE build_secret_source_sets SET revision=revision+1 WHERE build_id=$1;

-- name: ListBuildSecretSources :many
SELECT s.id,s.build_id,s.secret_id,s.version_id,gr.id AS group_revision_id,s.added_by,s.added_at,
o.alias,v.version,v.state,o.archived, g.alias AS group_alias, gr.revision AS group_revision
FROM build_secret_sources s JOIN secret_catalog_objects o ON o.id=s.secret_id
JOIN secret_store_versions v ON v.id=s.version_id
LEFT JOIN secret_group_revisions gr ON gr.id=s.group_revision_id
AND EXISTS(SELECT 1 FROM secret_catalog_objects owned_group WHERE owned_group.id=gr.group_id AND owned_group.owner_id=sqlc.arg(owner_id))
LEFT JOIN secret_catalog_objects g ON g.id=gr.group_id AND g.owner_id=sqlc.arg(owner_id)
WHERE s.build_id=sqlc.arg(build_id) AND o.owner_id=sqlc.arg(owner_id) ORDER BY o.alias,s.id;

-- name: DeleteBuildSecretSources :exec
DELETE FROM build_secret_sources s USING secret_catalog_objects o
WHERE s.secret_id=o.id AND s.build_id=sqlc.arg(build_id) AND o.owner_id=sqlc.arg(owner_id);

-- name: AddBuildSecretSource :exec
INSERT INTO build_secret_sources(build_id,secret_id,version_id,group_revision_id,added_by) VALUES($1,$2,$3,$4,$5);

-- name: CountBuildSecretSources :one
SELECT count(*) FROM build_secret_sources WHERE build_id=$1;

-- name: RecordSecretEvent :exec
INSERT INTO secret_store_events(actor_id,action,object_id,build_id,details) VALUES($1,$2,$3,$4,$5);
