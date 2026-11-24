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

-- name: CreateDeploymentTarget :one
INSERT INTO deployment_targets(owner_id,name) VALUES($1,$2) RETURNING *;
-- name: CreateDeploymentTargetRevision :one
INSERT INTO deployment_target_revisions(target_id,revision,manifest,digest,created_by)
VALUES($1,(SELECT COALESCE(max(revision),0)+1 FROM deployment_target_revisions WHERE target_id=$1),$2,$3,$4) RETURNING *;
-- name: GetDeploymentTargetRevision :one
SELECT * FROM deployment_target_revisions WHERE id=$1;
-- name: ListPersonalDeploymentTargets :many
SELECT r.id,r.target_id,r.revision,r.digest,r.created_by,r.created_at,t.name FROM deployment_target_revisions r JOIN deployment_targets t ON t.id=r.target_id
WHERE t.owner_id=$1 ORDER BY r.created_at DESC LIMIT 50;
-- name: InitBuildSecretFlow :exec
INSERT INTO build_secret_flow(build_id) VALUES($1) ON CONFLICT DO NOTHING;
-- name: GetBuildSecretFlow :one
SELECT * FROM build_secret_flow WHERE build_id=$1;
-- name: SetBuildSecretTarget :exec
UPDATE build_secret_flow SET target_revision_id=$2,revision=revision+1,target_approval=NULL,target_evidence=NULL,
prepared_digest=NULL,prepared_payload=NULL,prepared_by=NULL,updated_at=now() WHERE build_id=$1;
-- name: SetBuildSecretRequirements :exec
UPDATE build_secret_flow SET requirements=$2,revision=revision+1,prepared_digest=NULL,prepared_payload=NULL,prepared_by=NULL,updated_at=now() WHERE build_id=$1;
-- name: ApproveBuildSecretTarget :exec
UPDATE build_secret_flow SET target_approval=$2,target_evidence=$3,revision=revision+1,prepared_digest=NULL,prepared_payload=NULL,prepared_by=NULL,updated_at=now() WHERE build_id=$1;
-- name: InvalidateSecretPreparation :exec
UPDATE build_secret_flow SET revision=revision+1,prepared_digest=NULL,prepared_payload=NULL,prepared_by=NULL,updated_at=now() WHERE build_id=$1;
-- name: ListBuildSecretApprovals :many
SELECT * FROM build_secret_approvals WHERE build_id=$1 ORDER BY logical_name;
-- name: ListBuildSecretApprovalDetails :many
SELECT a.logical_name, a.owner_id AS approved_by_id, u.name AS approved_by_name,
       a.created_at AS approved_at
FROM build_secret_approvals a JOIN users u ON u.id=a.owner_id
WHERE a.build_id=$1 ORDER BY a.logical_name;
-- name: DeleteBuildSecretApprovals :exec
DELETE FROM build_secret_approvals WHERE build_id=$1;
-- name: DeletePersonalSecretApprovals :exec
DELETE FROM build_secret_approvals WHERE build_id=$1 AND owner_id=$2;
-- name: AddBuildSecretApproval :exec
INSERT INTO build_secret_approvals(build_id,logical_name,version_id,owner_id,target_revision_id,consumer,secret_kind,secret_type,proof)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);
-- name: CreateSecretPreparationJob :one
INSERT INTO secret_preparation_jobs(build_id,actor_id,manifest_digest,state) VALUES($1,$2,$3,'PREPARING') RETURNING *;
-- name: FinishSecretPreparationJob :exec
UPDATE secret_preparation_jobs SET state=$2,error_code=$3,finished_at=now() WHERE id=$1;
-- name: SavePreparedSecretRequests :exec
UPDATE build_secret_flow SET prepared_digest=$2,prepared_payload=$3,prepared_by=$4,revision=revision+1,updated_at=now() WHERE build_id=$1;
-- name: FreezeSecretPreparation :exec
UPDATE build_secret_flow SET frozen=true,updated_at=now() WHERE build_id=$1;
-- name: LockSecretApprovalUser :one
SELECT id FROM users WHERE id=$1 FOR SHARE;
-- name: LockSecretApprovalRoles :many
SELECT role FROM user_roles WHERE user_id=$1 ORDER BY role FOR SHARE;
-- name: LockSecretApprovalKeys :many
SELECT * FROM user_public_keys WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>statement_timestamp() ORDER BY id FOR SHARE;
-- name: BuildRequiresSecretFlow :one
SELECT EXISTS(SELECT 1 FROM build_secret_flow f WHERE f.build_id=sqlc.arg(build_id)::uuid AND jsonb_array_length(f.requirements)>0)
OR EXISTS(SELECT 1 FROM build_secret_sources s WHERE s.build_id=sqlc.arg(build_id)::uuid) AS required;
