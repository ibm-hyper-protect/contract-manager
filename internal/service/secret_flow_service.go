// Copyright (c) 2026 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
)

func flowError(code, msg string, status int) error {
	return &model.AppError{Code: code, Message: msg, HTTPStatus: status}
}
func flowDomain(err error) error {
	var e *secretflow.Error
	if errors.As(err, &e) {
		return flowError(e.Code, e.Message, http.StatusUnprocessableEntity)
	}
	return err
}
func marshalFlow(v any) []byte { b, _ := json.Marshal(v); return b }
func flowRole(ctx context.Context, q *repository.Queries, a SecretActor, build uuid.UUID, role string) error {
	if _, e := q.LockSecretApprovalUser(ctx, a.ID); e != nil {
		return e
	}
	user, e := q.GetUserByID(ctx, a.ID)
	if e != nil {
		return e
	}
	if !user.IsActive {
		return model.ErrForbidden("This account is no longer active.")
	}
	roles, e := q.LockSecretApprovalRoles(ctx, a.ID)
	if e != nil {
		return e
	}
	a.Roles = roles
	if !a.Has(role) {
		return model.ErrForbidden("The assigned " + role + " role is required.")
	}
	rows, e := q.LockSecretBuildAssignments(ctx, repository.LockSecretBuildAssignmentsParams{BuildID: build, UserID: a.ID})
	if e != nil {
		return e
	}
	for _, r := range rows {
		if r.RoleName == role {
			return nil
		}
	}
	return model.ErrForbidden("The required role is not assigned to you on this build.")
}
func loadFlow(ctx context.Context, q *repository.Queries, id uuid.UUID) (repository.BuildSecretFlow, error) {
	if e := q.InitBuildSecretFlow(ctx, id); e != nil {
		return repository.BuildSecretFlow{}, e
	}
	return q.GetBuildSecretFlow(ctx, id)
}
func (s *SecretStoreService) flowChange(ctx context.Context, a SecretActor, id uuid.UUID, expected int32, role string, fn func(*repository.Queries, repository.BuildSecretFlow) (any, error)) (any, error) {
	out, err := s.tx(ctx, a, func(q *repository.Queries) (any, error) {
		b, e := q.LockSecretBuild(ctx, id)
		if e != nil {
			return nil, e
		}
		if e = secretBuildAccess(ctx, q, a, id, true); e != nil {
			return nil, e
		}
		if role != "" {
			if e = flowRole(ctx, q, a, id, role); e != nil {
				return nil, e
			}
		}
		f, e := loadFlow(ctx, q, id)
		if e != nil {
			return nil, e
		}
		if f.Frozen || b.IsImmutable || !secretPreparationMutable(b.Status) {
			return nil, flowError("SECRET_PREPARATION_FROZEN", "Secret preparation is frozen after workload submission; create a new build for changes.", 409)
		}
		if f.Revision != expected {
			return nil, secretConflict()
		}
		return fn(q, f)
	})
	return out, flowDomain(err)
}
func (s *SecretStoreService) SetFlowTarget(ctx context.Context, a SecretActor, id uuid.UUID, expected int32, target secretflow.Target, reuse uuid.UUID) (any, error) {
	_, e := s.flowChange(ctx, a, id, expected, "ENV_OPERATOR", func(q *repository.Queries, f repository.BuildSecretFlow) (any, error) {
		var revision repository.DeploymentTargetRevision
		if reuse != uuid.Nil {
			var e error
			revision, e = q.GetDeploymentTargetRevision(ctx, reuse)
			if e != nil || revision.CreatedBy != a.ID {
				return nil, model.ErrNotFound("Personal target revision not found.")
			}
			if e = json.Unmarshal(revision.Manifest, &target); e != nil {
				return nil, e
			}
		} else {
			if e := target.Validate(); e != nil {
				return nil, e
			}
			t, e := q.CreateDeploymentTarget(ctx, repository.CreateDeploymentTargetParams{OwnerID: a.ID, Name: target.Name})
			if e != nil {
				return nil, e
			}
			revision, e = q.CreateDeploymentTargetRevision(ctx, repository.CreateDeploymentTargetRevisionParams{TargetID: t.ID, Manifest: marshalFlow(target), Digest: secretflow.Digest(target), CreatedBy: a.ID})
			if e != nil {
				return nil, e
			}
		}
		var rs []secretflow.Requirement
		if e := json.Unmarshal(f.Requirements, &rs); e != nil {
			return nil, e
		}
		if e := target.CheckRequirements(rs); e != nil {
			return nil, e
		}
		if e := q.DeleteBuildSecretApprovals(ctx, id); e != nil {
			return nil, e
		}
		if e := q.SetBuildSecretTarget(ctx, repository.SetBuildSecretTargetParams{BuildID: id, TargetRevisionID: optionalUUID(revision.ID)}); e != nil {
			return nil, e
		}
		return nil, recordSecretEvent(ctx, q, a, "SECRET_TARGET_SELECTED", revision.ID, id, map[string]any{"digest": revision.Digest, "mode": target.Mode})
	})
	if e != nil {
		return nil, e
	}
	return s.Flow(ctx, a, id)
}
func (s *SecretStoreService) Targets(ctx context.Context, a SecretActor) (any, error) {
	if !a.Has("ENV_OPERATOR") {
		return nil, model.ErrForbidden("Environment Operator role required.")
	}
	return repository.New(s.pool).ListPersonalDeploymentTargets(ctx, a.ID)
}
func (s *SecretStoreService) SetFlowRequirements(ctx context.Context, a SecretActor, id uuid.UUID, expected int32, rs []secretflow.Requirement) (any, error) {
	if len(rs) > secretflow.MaxRequests {
		return nil, flowError("SECRET_REQUEST_LIMIT", "A build supports at most eight runtime requests.", 422)
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if e := r.Validate(); e != nil {
			return nil, flowDomain(e)
		}
		if seen[r.Name] {
			return nil, model.ErrInvalidRequest("Logical secret names must be unique.")
		}
		seen[r.Name] = true
	}
	_, e := s.flowChange(ctx, a, id, expected, "SOLUTION_PROVIDER", func(q *repository.Queries, f repository.BuildSecretFlow) (any, error) {
		if f.TargetRevisionID.Valid {
			t, e := flowTarget(ctx, q, f)
			if e != nil {
				return nil, e
			}
			if e = t.CheckRequirements(rs); e != nil {
				return nil, e
			}
		}
		if e := q.DeleteBuildSecretApprovals(ctx, id); e != nil {
			return nil, e
		}
		if e := q.SetBuildSecretRequirements(ctx, repository.SetBuildSecretRequirementsParams{BuildID: id, Requirements: marshalFlow(rs)}); e != nil {
			return nil, e
		}
		return nil, recordSecretEvent(ctx, q, a, "SECRET_REQUIREMENTS_UPDATED", uuid.Nil, id, map[string]any{"count": len(rs)})
	})
	if e != nil {
		return nil, e
	}
	return s.Flow(ctx, a, id)
}
func flowTarget(ctx context.Context, q *repository.Queries, f repository.BuildSecretFlow) (secretflow.Target, error) {
	var t secretflow.Target
	if !f.TargetRevisionID.Valid {
		return t, flowError("SECRET_TARGET_REQUIRED", "The assigned Environment Operator must select a target profile.", 422)
	}
	r, e := q.GetDeploymentTargetRevision(ctx, uuid.UUID(f.TargetRevisionID.Bytes))
	if e != nil {
		return t, e
	}
	if e = json.Unmarshal(r.Manifest, &t); e != nil {
		return t, e
	}
	if secretflow.Digest(t) != r.Digest {
		return t, flowError("SECRET_TARGET_CHANGED", "Target integrity check failed.", 409)
	}
	return t, t.Validate()
}

// Check stored proofs against today's account, role, build assignment and key directory.
func liveProof(ctx context.Context, q *repository.Queries, id uuid.UUID, p secretflow.Proof, role string) error {
	if e := p.Verify(); e != nil {
		return e
	}
	if _, e := q.LockSecretApprovalUser(ctx, p.SignerID); e != nil {
		return e
	}
	u, e := q.GetUserByID(ctx, p.SignerID)
	if e != nil || !u.IsActive {
		return flowError("SECRET_APPROVAL_REVOKED", "An approving account is no longer active.", 409)
	}
	roles, e := q.LockSecretApprovalRoles(ctx, p.SignerID)
	if e != nil {
		return e
	}
	a := SecretActor{ID: p.SignerID}
	for _, r := range roles {
		a.Roles = append(a.Roles, r)
	}
	if role != "" {
		e = flowRole(ctx, q, a, id, role)
	} else {
		e = secretBuildAccess(ctx, q, a, id, true)
	}
	if e != nil {
		return flowError("SECRET_APPROVAL_REVOKED", "An approving role or build assignment is no longer active.", 409)
	}
	keys, e := q.LockSecretApprovalKeys(ctx, p.SignerID)
	if e != nil {
		return e
	}
	for _, k := range keys {
		if k.Fingerprint == p.Fingerprint && k.PublicKey == p.PublicKey {
			return nil
		}
	}
	return flowError("SECRET_APPROVAL_KEY_REVOKED", "An approval signing key has expired or been revoked; renew the approval before proceeding.", 409)
}
func (s *SecretStoreService) ApproveFlowTarget(ctx context.Context, a SecretActor, id uuid.UUID, expected int32, proof secretflow.Proof) (any, error) {
	if s.processor == nil {
		return nil, secretUnavailable()
	}
	var target secretflow.Target
	var revision pgtype.UUID
	_, e := s.flowChange(ctx, a, id, expected, "AUDITOR", func(q *repository.Queries, f repository.BuildSecretFlow) (any, error) {
		var e error
		target, e = flowTarget(ctx, q, f)
		revision = f.TargetRevisionID
		return nil, e
	})
	if e != nil {
		return nil, e
	}
	// No database locks are held while IBM tooling validates certificates and header.
	evidence, e := s.processor.ValidateTarget(ctx, target)
	if e != nil {
		return nil, flowDomain(e)
	}
	_, e = s.flowChange(ctx, a, id, expected, "AUDITOR", func(q *repository.Queries, f repository.BuildSecretFlow) (any, error) {
		if f.TargetRevisionID != revision {
			return nil, secretConflict()
		}
		if proof.SignerID != a.ID {
			return nil, model.ErrForbidden("The current Auditor must sign this target approval.")
		}
		if e := liveProof(ctx, q, id, proof, "AUDITOR"); e != nil {
			return nil, e
		}
		var body struct {
			TargetRevisionID          uuid.UUID `json:"target_revision_id"`
			TargetDigest              string    `json:"target_digest"`
			HeaderProvenanceConfirmed bool      `json:"header_provenance_confirmed"`
		}
		if json.Unmarshal(proof.Body, &body) != nil || body.TargetRevisionID != uuid.UUID(revision.Bytes) || body.TargetDigest != secretflow.Digest(target) || !body.HeaderProvenanceConfirmed || proof.Path != "/builds/"+id.String()+"/secret-flow/target-approval" {
			return nil, model.ErrInvalidRequest("Confirm the exact target revision and trusted SE-header provenance.")
		}
		if e := q.ApproveBuildSecretTarget(ctx, repository.ApproveBuildSecretTargetParams{BuildID: id, TargetApproval: marshalFlow(proof), TargetEvidence: marshalFlow(evidence)}); e != nil {
			return nil, e
		}
		return nil, recordSecretEvent(ctx, q, a, "SECRET_TARGET_APPROVED", uuid.UUID(revision.Bytes), id, evidence)
	})
	if e != nil {
		return nil, e
	}
	return s.Flow(ctx, a, id)
}
func validateBindingSource(ctx context.Context, q *repository.Queries, a SecretActor, b secretflow.Binding) error {
	v, e := q.GetSecretVersion(ctx, b.VersionID)
	if e != nil {
		return model.ErrNotFound("Secret version not found.")
	}
	o, e := ownedSecretObject(ctx, q, a, v.SecretID)
	if e != nil {
		return e
	}
	if o.Archived || v.State != "SEALED" {
		return model.ErrInvalidRequest("Select an available sealed secret version.")
	}
	if b.GroupRevisionID != uuid.Nil {
		r, e := q.GetSecretGroupRevision(ctx, b.GroupRevisionID)
		if e != nil {
			return model.ErrNotFound("Group revision not found.")
		}
		g, e := ownedSecretObject(ctx, q, a, r.GroupID)
		if e != nil {
			return e
		}
		if g.Archived {
			return model.ErrInvalidRequest("Selected group is archived.")
		}
		members, e := q.ListSecretGroupMembers(ctx, r.ID)
		if e != nil {
			return e
		}
		found := false
		for _, m := range members {
			if m.VersionID == v.ID {
				found = true
			}
		}
		if !found {
			return model.ErrInvalidRequest("The pinned version is not part of the selected group revision.")
		}
	}
	return nil
}
func (s *SecretStoreService) ApproveFlowSources(ctx context.Context, a SecretActor, id uuid.UUID, in secretflow.Approval, proof secretflow.Proof) (any, error) {
	if len(in.Sources) > secretflow.MaxRequests {
		return nil, flowError("SECRET_REQUEST_LIMIT", "Group expansion must contain no more than eight runtime requests.", 422)
	}
	_, e := s.flowChange(ctx, a, id, in.ExpectedRevision, "", func(q *repository.Queries, f repository.BuildSecretFlow) (any, error) {
		t, e := flowTarget(ctx, q, f)
		if e != nil {
			return nil, e
		}
		if in.TargetRevisionID != uuid.UUID(f.TargetRevisionID.Bytes) || in.TargetDigest != secretflow.Digest(t) {
			return nil, secretConflict()
		}
		if e = liveProof(ctx, q, id, proof, ""); e != nil {
			return nil, e
		}
		if proof.SignerID != a.ID || proof.Path != "/builds/"+id.String()+"/secret-flow/approvals" {
			return nil, model.ErrInvalidRequest("Approval purpose does not match.")
		}
		var signed secretflow.Approval
		if json.Unmarshal(proof.Body, &signed) != nil || secretflow.Digest(signed) != secretflow.Digest(in) {
			return nil, model.ErrInvalidRequest("Approval payload does not match the authenticated request.")
		}
		if e = q.InitSecretSourceSet(ctx, id); e != nil {
			return nil, e
		}
		rev, e := q.GetSecretSourceRevision(ctx, id)
		if e != nil {
			return nil, e
		}
		if in.SourceRevision != rev {
			return nil, secretConflict()
		}
		var requirements []secretflow.Requirement
		if e = json.Unmarshal(f.Requirements, &requirements); e != nil {
			return nil, e
		}
		seen := map[string]bool{}
		versions := map[uuid.UUID]bool{}
		for _, b := range in.Sources {
			if !slices.Contains(requirements, b.Requirement()) || seen[b.Name] || versions[b.VersionID] {
				return nil, model.ErrInvalidRequest("Map one distinct owned version to each matching declared requirement.")
			}
			seen[b.Name] = true
			versions[b.VersionID] = true
			if e = validateBindingSource(ctx, q, a, b); e != nil {
				return nil, e
			}
		}
		if e = q.DeletePersonalSecretApprovals(ctx, repository.DeletePersonalSecretApprovalsParams{BuildID: id, OwnerID: a.ID}); e != nil {
			return nil, e
		}
		if e = q.DeleteBuildSecretSources(ctx, repository.DeleteBuildSecretSourcesParams{BuildID: id, OwnerID: a.ID}); e != nil {
			return nil, e
		}
		approvals, e := q.ListBuildSecretApprovals(ctx, id)
		if e != nil {
			return nil, e
		}
		if len(approvals)+len(in.Sources) > secretflow.MaxRequests {
			return nil, model.ErrInvalidRequest("A build supports at most eight runtime requests in total.")
		}
		for _, b := range in.Sources {
			v, e := q.GetSecretVersion(ctx, b.VersionID)
			if e != nil {
				return nil, e
			}
			if e = q.AddBuildSecretSource(ctx, repository.AddBuildSecretSourceParams{BuildID: id, SecretID: v.SecretID, VersionID: v.ID, GroupRevisionID: optionalUUID(b.GroupRevisionID), AddedBy: a.ID}); e != nil {
				return nil, e
			}
			if e = q.AddBuildSecretApproval(ctx, repository.AddBuildSecretApprovalParams{BuildID: id, LogicalName: b.Name, VersionID: b.VersionID, OwnerID: a.ID, TargetRevisionID: in.TargetRevisionID, Consumer: b.Consumer, SecretKind: b.Kind, SecretType: b.Type, Proof: marshalFlow(proof)}); e != nil {
				return nil, e
			}
		}
		if e = q.BumpSecretSourceRevision(ctx, id); e != nil {
			return nil, e
		}
		if e = q.InvalidateSecretPreparation(ctx, id); e != nil {
			return nil, e
		}
		return nil, recordSecretEvent(ctx, q, a, "SECRET_SOURCES_APPROVED", uuid.Nil, id, map[string]any{"count": len(in.Sources), "target_digest": in.TargetDigest})
	})
	if e != nil {
		return nil, e
	}
	return s.Flow(ctx, a, id)
}
func buildSecretJob(ctx context.Context, q *repository.Queries, id uuid.UUID, f repository.BuildSecretFlow) (secretflow.Job, error) {
	j := secretflow.Job{BuildID: id, TargetRevisionID: uuid.UUID(f.TargetRevisionID.Bytes), Items: []secretflow.Item{}}
	var e error
	j.Target, e = flowTarget(ctx, q, f)
	if e != nil {
		return j, e
	}
	targetRevision, e := q.GetDeploymentTargetRevision(ctx, j.TargetRevisionID)
	if e != nil {
		return j, e
	}
	if _, e = q.LockSecretApprovalUser(ctx, targetRevision.CreatedBy); e != nil {
		return j, e
	}
	targetUser, e := q.GetUserByID(ctx, targetRevision.CreatedBy)
	if e != nil || !targetUser.IsActive {
		return j, flowError("SECRET_TARGET_OWNER_INACTIVE", "The target provider is no longer active.", 409)
	}
	targetRoles, e := q.LockSecretApprovalRoles(ctx, targetRevision.CreatedBy)
	if e != nil {
		return j, e
	}
	provider := SecretActor{ID: targetRevision.CreatedBy}
	for _, r := range targetRoles {
		provider.Roles = append(provider.Roles, r)
	}
	if e = flowRole(ctx, q, provider, id, "ENV_OPERATOR"); e != nil {
		return j, e
	}
	if json.Unmarshal(f.TargetApproval, &j.TargetApproval) != nil {
		return j, flowError("SECRET_TARGET_APPROVAL_REQUIRED", "The assigned Auditor must approve the selected target.", 422)
	}
	if e = liveProof(ctx, q, id, j.TargetApproval, "AUDITOR"); e != nil {
		return j, e
	}
	rs := []secretflow.Requirement{}
	if e = json.Unmarshal(f.Requirements, &rs); e != nil {
		return j, e
	}
	rows, e := q.ListBuildSecretApprovals(ctx, id)
	if e != nil {
		return j, e
	}
	if len(rs) == 0 || len(rows) != len(rs) {
		return j, flowError("SECRET_APPROVALS_PENDING", "Each declared requirement needs a signed owner approval.", 422)
	}
	count, e := q.CountBuildSecretSources(ctx, id)
	if e != nil {
		return j, e
	}
	if count != int64(len(rows)) {
		return j, flowError("SECRET_APPROVALS_PENDING", "Unapproved legacy sources remain; map or remove them before preparation.", 422)
	}
	for _, r := range rows {
		item := secretflow.Item{OwnerID: r.OwnerID, Binding: secretflow.Binding{VersionID: r.VersionID, Name: r.LogicalName, Consumer: r.Consumer, Kind: r.SecretKind, Type: r.SecretType}}
		if !slices.Contains(rs, item.Binding.Requirement()) || r.TargetRevisionID != j.TargetRevisionID {
			return j, secretConflict()
		}
		if json.Unmarshal(r.Proof, &item.Proof) != nil {
			return j, model.ErrInvalidRequest("Stored approval is invalid.")
		}
		if e = liveProof(ctx, q, id, item.Proof, ""); e != nil {
			return j, e
		}
		// Preserve group provenance exactly as signed, then recheck its current availability.
		var ownerApproval secretflow.Approval
		if e = json.Unmarshal(item.Proof.Body, &ownerApproval); e != nil {
			return j, e
		}
		for _, b := range ownerApproval.Sources {
			if b.VersionID == r.VersionID && b.Name == r.LogicalName {
				item.Binding = b
			}
		}
		if e = validateBindingSource(ctx, q, SecretActor{ID: r.OwnerID}, item.Binding); e != nil {
			return j, e
		}
		sealed, e := q.GetSealedSecretPayload(ctx, r.VersionID)
		if e != nil {
			return j, e
		}
		if e = json.Unmarshal(sealed, &item.Envelope); e != nil {
			return j, e
		}
		j.Items = append(j.Items, item)
	}
	j.Digest = j.Hash()
	return j, j.Validate()
}
func validatePrepared(ctx context.Context, q *repository.Queries, id uuid.UUID) (secretflow.Job, secretflow.Result, error) {
	var j secretflow.Job
	var r secretflow.Result
	f, e := q.GetBuildSecretFlow(ctx, id)
	if errors.Is(e, pgx.ErrNoRows) {
		count, err := q.CountBuildSecretSources(ctx, id)
		if err != nil {
			return j, r, err
		}
		if count > 0 {
			return j, r, PendingSecretSourcesError()
		}
		return j, r, nil
	}
	if e != nil {
		return j, r, e
	}
	var rs []secretflow.Requirement
	if e = json.Unmarshal(f.Requirements, &rs); e != nil {
		return j, r, e
	}
	if len(rs) == 0 {
		count, err := q.CountBuildSecretSources(ctx, id)
		if err != nil {
			return j, r, err
		}
		if count > 0 {
			return j, r, PendingSecretSourcesError()
		}
		return j, r, nil
	}
	j, e = buildSecretJob(ctx, q, id, f)
	if e != nil {
		return j, r, e
	}
	if f.PreparedDigest == nil || *f.PreparedDigest != j.Digest || json.Unmarshal(f.PreparedPayload, &r) != nil {
		return j, r, PendingSecretSourcesError()
	}
	if e = validateResult(j, r); e != nil {
		return j, r, e
	}
	if !f.PreparedBy.Valid {
		return j, r, PendingSecretSourcesError()
	}
	roles, e := q.GetRolesByUserID(ctx, uuid.UUID(f.PreparedBy.Bytes))
	if e != nil {
		return j, r, e
	}
	a := SecretActor{ID: uuid.UUID(f.PreparedBy.Bytes)}
	for _, role := range roles {
		a.Roles = append(a.Roles, role.Role)
	}
	if e = flowRole(ctx, q, a, id, "AUDITOR"); e != nil {
		return j, r, e
	}
	return j, r, nil
}
func (s *SecretStoreService) PrepareFlow(ctx context.Context, a SecretActor, id uuid.UUID, expected int32) (any, error) {
	if s.processor == nil {
		return nil, secretUnavailable()
	}
	var job secretflow.Job
	var jobID uuid.UUID
	cached := false
	_, e := s.flowChange(ctx, a, id, expected, "AUDITOR", func(q *repository.Queries, f repository.BuildSecretFlow) (any, error) {
		var e error
		job, e = buildSecretJob(ctx, q, id, f)
		if e != nil {
			return nil, e
		}
		if f.PreparedDigest != nil && *f.PreparedDigest == job.Digest {
			var r secretflow.Result
			if json.Unmarshal(f.PreparedPayload, &r) == nil && validateResult(job, r) == nil {
				cached = true
				return nil, nil
			}
		}
		row, e := q.CreateSecretPreparationJob(ctx, repository.CreateSecretPreparationJobParams{BuildID: id, ActorID: a.ID, ManifestDigest: job.Digest})
		jobID = row.ID
		return nil, e
	})
	if e != nil {
		return nil, e
	}
	if cached {
		return s.Flow(ctx, a, id)
	}
	result, workerErr := s.processor.Prepare(ctx, job)
	if workerErr == nil {
		workerErr = validateResult(job, result)
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if workerErr != nil {
		code := "SECRET_PREPARATION_FAILED"
		var typed *secretflow.Error
		if errors.As(workerErr, &typed) {
			code = typed.Code
		}
		_ = repository.New(s.pool).FinishSecretPreparationJob(finishCtx, repository.FinishSecretPreparationJobParams{ID: jobID, State: "FAILED", ErrorCode: &code})
		return nil, flowDomain(workerErr)
	}
	_, e = s.flowChange(finishCtx, a, id, expected, "AUDITOR", func(q *repository.Queries, f repository.BuildSecretFlow) (any, error) {
		current, e := buildSecretJob(finishCtx, q, id, f)
		if e != nil {
			return nil, e
		}
		if current.Digest != job.Digest {
			return nil, secretConflict()
		}
		if e = q.SavePreparedSecretRequests(finishCtx, repository.SavePreparedSecretRequestsParams{BuildID: id, PreparedDigest: &job.Digest, PreparedPayload: marshalFlow(result), PreparedBy: optionalUUID(a.ID)}); e != nil {
			return nil, e
		}
		if e = q.FinishSecretPreparationJob(finishCtx, repository.FinishSecretPreparationJobParams{ID: jobID, State: "PREPARED"}); e != nil {
			return nil, e
		}
		return nil, recordSecretEvent(finishCtx, q, a, "SECRET_REQUESTS_PREPARED", jobID, id, map[string]any{"digest": job.Digest, "count": len(result.Artifacts), "mode": result.Mode})
	})
	if e != nil {
		code := "SECRET_PREPARATION_STALE"
		_ = repository.New(s.pool).FinishSecretPreparationJob(finishCtx, repository.FinishSecretPreparationJobParams{ID: jobID, State: "STALE", ErrorCode: &code})
		return nil, e
	}
	return s.Flow(finishCtx, a, id)
}
func (s *SecretStoreService) Flow(ctx context.Context, a SecretActor, id uuid.UUID) (any, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	q := repository.New(tx)
	b, e := q.LockSecretBuild(ctx, id)
	if e != nil {
		return nil, e
	}
	if e = secretBuildAccess(ctx, q, a, id, false); e != nil {
		return nil, e
	}
	f, e := loadFlow(ctx, q, id)
	if e != nil {
		return nil, e
	}
	can := a.CatalogRole() && secretBuildAccess(ctx, q, a, id, true) == nil
	mutable := can && !f.Frozen && !b.IsImmutable && secretPreparationMutable(b.Status)
	out := map[string]any{"revision": f.Revision, "frozen": f.Frozen, "requirements": json.RawMessage(f.Requirements), "can_contribute": mutable, "can_target": mutable && flowRole(ctx, q, a, id, "ENV_OPERATOR") == nil, "can_requirements": mutable && flowRole(ctx, q, a, id, "SOLUTION_PROVIDER") == nil, "can_approve_target": mutable && flowRole(ctx, q, a, id, "AUDITOR") == nil, "can_prepare": mutable && flowRole(ctx, q, a, id, "AUDITOR") == nil, "prepared": false}
	if !can {
		out["requirements"] = []any{}
		return out, nil
	}
	if f.TargetRevisionID.Valid {
		t, e := flowTarget(ctx, q, f)
		if e != nil {
			return nil, flowDomain(e)
		}
		out["target"] = t
		out["artifact_fingerprints"] = t.Fingerprints()
		out["target_revision_id"] = uuid.UUID(f.TargetRevisionID.Bytes)
		out["target_digest"] = secretflow.Digest(t)
	}
	out["target_approved"] = len(f.TargetApproval) > 0
	if len(f.TargetEvidence) > 0 {
		out["target_evidence"] = json.RawMessage(f.TargetEvidence)
	}
	rows, e := q.ListBuildSecretApprovals(ctx, id)
	if e != nil {
		return nil, e
	}
	own := []secretflow.Binding{}
	states := map[string]string{}
	for _, r := range rows {
		states[r.LogicalName] = "APPROVED"
		if r.OwnerID == a.ID {
			own = append(own, secretflow.Binding{VersionID: r.VersionID, Name: r.LogicalName, Kind: r.SecretKind, Type: r.SecretType, Consumer: r.Consumer})
		}
	}
	ownSources, e := q.ListBuildSecretSources(ctx, repository.ListBuildSecretSourcesParams{BuildID: id, OwnerID: a.ID})
	if e != nil {
		return nil, e
	}
	out["own_sources"] = ownSources
	out["own_approvals"] = own
	out["approval_states"] = states
	// Only build contributors reach this point. Publish the authenticated signer
	// and server timestamp without exposing another owner's catalog references.
	details, e := q.ListBuildSecretApprovalDetails(ctx, id)
	if e != nil {
		return nil, e
	}
	approvalDetails := map[string]any{}
	for _, detail := range details {
		approvalDetails[detail.LogicalName] = map[string]any{
			"approved_by": map[string]any{"id": detail.ApprovedByID, "name": detail.ApprovedByName},
			"approved_at": detail.ApprovedAt,
		}
	}
	out["approval_details"] = approvalDetails
	rev, e := q.GetSecretSourceRevision(ctx, id)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	out["source_revision"] = rev
	if f.PreparedDigest != nil {
		_, r, validErr := validatePrepared(ctx, q, id)
		if validErr != nil {
			out["preparation_error"] = "Approvals or target changed; refresh the approvals and prepare again."
		} else {
			out["prepared"] = true
			out["manifest_digest"] = r.Digest
			artifacts := []map[string]string{}
			for _, a := range r.Artifacts {
				artifacts = append(artifacts, map[string]string{"name": a.Name, "consumer": a.Consumer, "kind": a.Kind, "type": a.Type, "secret_id": a.SecretID, "request_sha256": a.RequestSHA256})
			}
			out["artifacts"] = artifacts
		}
	}
	return out, nil
}
