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
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretstore"
)

type SecretActor struct {
	ID    uuid.UUID
	Roles []string
	Email string
	IP    string
}

func (a SecretActor) Has(roles ...string) bool {
	for _, r := range roles {
		for _, actual := range a.Roles {
			if actual == r {
				return true
			}
		}
	}
	return false
}
func (a SecretActor) CatalogRole() bool {
	return a.ID != uuid.Nil && a.Has("ADMIN", "AUDITOR", "SOLUTION_PROVIDER", "DATA_OWNER", "ENV_OPERATOR")
}

type SecretStoreService struct {
	processor secretflow.Processor
	pool      *pgxpool.Pool
	verifier  secretstore.Verifier
	logs      *SystemLogService
}

func NewSecretStoreService(pool *pgxpool.Pool, verifier secretstore.Verifier, logs *SystemLogService) *SecretStoreService {
	return &SecretStoreService{pool: pool, verifier: verifier, logs: logs}
}
func (s *SecretStoreService) WithProcessor(p secretflow.Processor) *SecretStoreService {
	s.processor = p
	return s
}
func secretConflict() *model.AppError {
	return &model.AppError{Code: "SECRET_REVISION_CONFLICT", Message: "This selection changed. Refresh and try again.", HTTPStatus: http.StatusConflict}
}
func secretUnavailable() *model.AppError {
	return &model.AppError{Code: "SECRET_STORE_UNAVAILABLE", Message: "The secret import service is not configured or is unavailable.", HTTPStatus: http.StatusServiceUnavailable}
}
func secretError(err error) error {
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		if pgerr.Code == "23505" {
			return &model.AppError{Code: "SECRET_CONFLICT", Message: "An entry with that alias or reference already exists.", HTTPStatus: http.StatusConflict}
		}
		if pgerr.Code == "23503" {
			return model.ErrInvalidRequest("A referenced object is no longer available.")
		}
	}
	return err
}
func (s *SecretStoreService) tx(ctx context.Context, a SecretActor, fn func(*repository.Queries) (any, error)) (any, error) {
	if !a.CatalogRole() {
		return nil, model.ErrForbidden("A secret catalog role is required.")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := repository.New(tx)
	// Short catalog transactions serialize version and multi-object group operations.
	// No worker call or other external operation is made while this lock is held.
	if err = q.LockSecretCatalog(ctx); err != nil {
		return nil, err
	}
	result, err := fn(q)
	if err != nil {
		return nil, secretError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, secretError(err)
	}
	return result, nil
}
func optionalUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil} }
func recordSecretEvent(ctx context.Context, q *repository.Queries, a SecretActor, action string, objectID, buildID uuid.UUID, details any) error {
	data, err := json.Marshal(details)
	if err != nil {
		return err
	}
	return q.RecordSecretEvent(ctx, repository.RecordSecretEventParams{ActorID: a.ID, Action: action, ObjectID: optionalUUID(objectID), BuildID: optionalUUID(buildID), Details: data})
}
func (s *SecretStoreService) log(ctx context.Context, a SecretActor, action string) {
	if s.logs != nil {
		s.logs.LogEvent(ctx, a.Email, action, "SECRET_STORE", a.IP, "SUCCESS", "Secret catalog metadata updated; no secret values recorded.")
	}
}
func (s *SecretStoreService) Info(ctx context.Context, a SecretActor) (secretstore.ImportKey, error) {
	if !a.CatalogRole() {
		return secretstore.ImportKey{}, model.ErrForbidden("A secret catalog role is required.")
	}
	if s.verifier == nil {
		return secretstore.ImportKey{}, secretUnavailable()
	}
	info, err := s.verifier.Info(ctx)
	if err != nil {
		return secretstore.ImportKey{}, secretUnavailable()
	}
	return info, nil
}

// Ownership is the only catalog authority. Neither administrator privileges,
// build membership nor historical sharing grants grant access to another store.
func ownedSecretObject(ctx context.Context, q *repository.Queries, a SecretActor, id uuid.UUID) (repository.SecretCatalogObject, error) {
	o, err := q.GetSecretObject(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && o.OwnerID != a.ID {
		return repository.SecretCatalogObject{}, model.ErrNotFound("Secret catalog entry not found.")
	}
	return o, err
}
func catalogCapabilities(o repository.SecretCatalogObject) map[string]bool {
	return map[string]bool{"can_edit_metadata": true, "can_write_versions": !o.Archived}
}
func metadataValid(alias, description string) bool {
	return utf8.ValidString(alias) && utf8.ValidString(description) && utf8.RuneCountInString(alias) > 0 && utf8.RuneCountInString(alias) <= 100 && utf8.RuneCountInString(description) <= 1000 && !strings.ContainsAny(alias, "\r\n\t\x00") && !strings.ContainsRune(description, '\x00')
}
func (s *SecretStoreService) List(ctx context.Context, a SecretActor, kind, search string, limit, offset int32) (any, error) {
	if !a.CatalogRole() {
		return nil, model.ErrForbidden("A secret catalog role is required.")
	}
	if (kind != "SECRET" && kind != "GROUP") || len(search) > 200 {
		return nil, model.ErrInvalidRequest("kind must be SECRET or GROUP.")
	}
	q := repository.New(s.pool)
	rows, err := q.ListSecretObjects(ctx, repository.ListSecretObjectsParams{Limit: limit, Offset: offset, Kind: kind, Search: search, ActorID: a.ID})
	if err != nil {
		return nil, err
	}
	objects := make([]any, 0, len(rows))
	for _, r := range rows {
		o := repository.SecretCatalogObject{ID: r.ID, Kind: r.Kind, OwnerID: r.OwnerID, Alias: r.Alias, Description: r.Description, Revision: r.Revision, Archived: r.Archived, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
		caps := catalogCapabilities(o)
		objects = append(objects, map[string]any{"object": o, "owner_name": r.OwnerName, "permissions": caps})
	}
	return map[string]any{"objects": objects, "has_more": len(rows) == int(limit), "limit": limit, "offset": offset}, nil
}
func (s *SecretStoreService) Create(ctx context.Context, a SecretActor, kind, alias, description string) (any, error) {
	alias = strings.TrimSpace(alias)
	if (kind != "SECRET" && kind != "GROUP") || !metadataValid(alias, description) {
		return nil, model.ErrInvalidRequest("Provide a kind, an alias of 1–100 characters, and a description of at most 1000 characters.")
	}
	out, err := s.tx(ctx, a, func(q *repository.Queries) (any, error) {
		o, err := q.CreateSecretObject(ctx, repository.CreateSecretObjectParams{Kind: kind, OwnerID: a.ID, Alias: alias, Description: description})
		if err != nil {
			return nil, err
		}
		return o, recordSecretEvent(ctx, q, a, "SECRET_ENTRY_CREATED", o.ID, uuid.Nil, map[string]any{"kind": kind})
	})
	if err == nil {
		s.log(ctx, a, "SECRET_ENTRY_CREATED")
	}
	return out, err
}
func (s *SecretStoreService) Detail(ctx context.Context, a SecretActor, id uuid.UUID) (any, error) {
	if !a.CatalogRole() {
		return nil, model.ErrForbidden("A secret catalog role is required.")
	}
	q := repository.New(s.pool)
	o, err := ownedSecretObject(ctx, q, a, id)
	if err != nil {
		return nil, err
	}
	caps := catalogCapabilities(o)
	out := map[string]any{"object": o, "permissions": caps}
	if o.Kind == "SECRET" {
		versions, err := q.ListSecretVersions(ctx, id)
		if err != nil {
			return nil, err
		}
		out["versions"] = versions
	} else {
		revisions, err := q.ListSecretGroupRevisions(ctx, id)
		if err != nil {
			return nil, err
		}
		publicRevisions := make([]any, 0, len(revisions))
		for _, r := range revisions {
			members, err := q.ListSecretGroupMembers(ctx, r.ID)
			if err != nil {
				return nil, err
			}
			visible := make([]any, 0, len(members))
			restricted := 0
			for _, m := range members {
				if _, err := ownedSecretObject(ctx, q, a, m.SecretID); err != nil {
					var app *model.AppError
					if errors.As(err, &app) && app.HTTPStatus == 404 {
						restricted++
						continue
					}
					return nil, err
				}
				visible = append(visible, m)
			}
			publicRevisions = append(publicRevisions, map[string]any{"id": r.ID, "revision": r.Revision, "created_at": r.CreatedAt, "members": visible, "restricted_members": restricted})
		}
		out["revisions"] = publicRevisions
	}

	return out, nil
}
func (s *SecretStoreService) Update(ctx context.Context, a SecretActor, id uuid.UUID, revision int32, alias, description string, archived bool) (any, error) {
	alias = strings.TrimSpace(alias)
	if !metadataValid(alias, description) {
		return nil, model.ErrInvalidRequest("Invalid alias or description.")
	}
	out, err := s.tx(ctx, a, func(q *repository.Queries) (any, error) {
		if _, err := ownedSecretObject(ctx, q, a, id); err != nil {
			return nil, err
		}
		o, err := q.UpdateSecretObject(ctx, repository.UpdateSecretObjectParams{ID: id, Alias: alias, Description: description, Archived: archived, Revision: revision})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, secretConflict()
		}
		if err != nil {
			return nil, err
		}
		return o, recordSecretEvent(ctx, q, a, "SECRET_ENTRY_UPDATED", id, uuid.Nil, map[string]any{"archived": archived, "revision": o.Revision})
	})
	if err == nil {
		s.log(ctx, a, "SECRET_ENTRY_UPDATED")
	}
	return out, err
}
func (s *SecretStoreService) Reserve(ctx context.Context, a SecretActor, id uuid.UUID) (any, error) {
	if _, err := s.Info(ctx, a); err != nil {
		return nil, err
	}
	out, err := s.tx(ctx, a, func(q *repository.Queries) (any, error) {
		o, err := ownedSecretObject(ctx, q, a, id)
		if err != nil {
			return nil, err
		}
		if o.Kind != "SECRET" || o.Archived {
			return nil, model.ErrInvalidRequest("A non-archived secret is required.")
		}
		version, err := q.ReserveSecretVersion(ctx, repository.ReserveSecretVersionParams{SecretID: id, CreatedBy: a.ID})
		if err != nil {
			return nil, err
		}
		return version, recordSecretEvent(ctx, q, a, "SECRET_VERSION_RESERVED", id, uuid.Nil, map[string]any{"version_id": version.ID, "version": version.Version})
	})
	return out, err
}
func (s *SecretStoreService) Seal(ctx context.Context, a SecretActor, id, versionID uuid.UUID, e secretstore.Envelope) (any, error) {
	if !a.CatalogRole() {
		return nil, model.ErrForbidden("A secret catalog role is required.")
	}
	if e.SecretID != id || e.VersionID != versionID {
		return nil, model.ErrInvalidRequest("Sealed import context does not match the reserved version.")
	}
	if err := e.ValidateShape(); err != nil {
		return nil, model.ErrInvalidRequest("Invalid sealed import package.")
	}
	if s.verifier == nil {
		return nil, secretUnavailable()
	}
	// Authorize before asking the isolated worker to process any ciphertext.
	q := repository.New(s.pool)
	o, err := ownedSecretObject(ctx, q, a, id)
	if err != nil {
		return nil, err
	}
	v, err := q.GetSecretVersion(ctx, versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound("Reserved version not found.")
	}
	if err != nil {
		return nil, err
	}
	if v.SecretID != id || o.Archived {
		return nil, model.ErrNotFound("Reserved version not found.")
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	n, err := s.verifier.Verify(ctx, e)
	if errors.Is(err, secretstore.ErrUnavailable) {
		return nil, secretUnavailable()
	}
	if err != nil {
		return nil, model.ErrInvalidRequest("The sealed value could not be verified. Check the import key and retry.")
	}
	if n < 0 || n > secretstore.MaxSecretBytes {
		return nil, model.ErrInvalidRequest("Secret value exceeds the import limit.")
	}
	out, err := s.tx(ctx, a, func(q *repository.Queries) (any, error) {
		current, err := ownedSecretObject(ctx, q, a, id)
		if err != nil {
			return nil, err
		}
		if current.Archived {
			return nil, model.ErrInvalidRequest("This entry was archived.")
		}
		currentVersion, err := q.GetSecretVersion(ctx, versionID)
		if err != nil {
			return nil, err
		}
		if currentVersion.State == "SEALED" {
			stored, err := q.GetSealedSecretPayload(ctx, versionID)
			if err != nil {
				return nil, err
			}
			var previous secretstore.Envelope
			if json.Unmarshal(stored, &previous) != nil || previous != e {
				return nil, secretConflict()
			}
			return currentVersion, nil
		}
		updated, err := q.SealSecretVersion(ctx, repository.SealSecretVersionParams{ID: versionID, SealedPayload: payload, ByteLength: ptrInt32(int32(n))})
		if err != nil {
			return nil, err
		}
		if updated != 1 {
			return nil, secretConflict()
		}
		if err := recordSecretEvent(ctx, q, a, "SECRET_VERSION_SEALED", id, uuid.Nil, map[string]any{"version_id": versionID}); err != nil {
			return nil, err
		}
		return q.GetSecretVersion(ctx, versionID)
	})
	if err == nil {
		s.log(ctx, a, "SECRET_VERSION_SEALED")
	}
	return out, err
}

func (s *SecretStoreService) GroupRevision(ctx context.Context, a SecretActor, id uuid.UUID, expected int32, versions []uuid.UUID) (any, error) {
	if len(versions) == 0 || len(versions) > 64 {
		return nil, model.ErrInvalidRequest("A group revision needs between 1 and 64 distinct secret versions.")
	}
	out, err := s.tx(ctx, a, func(q *repository.Queries) (any, error) {
		o, err := ownedSecretObject(ctx, q, a, id)
		if err != nil {
			return nil, err
		}
		if o.Kind != "GROUP" || o.Archived {
			return nil, model.ErrInvalidRequest("A non-archived group is required.")
		}
		if o.Revision != expected {
			return nil, secretConflict()
		}
		seen := map[uuid.UUID]bool{}
		for _, vid := range versions {
			v, err := q.GetSecretVersion(ctx, vid)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, model.ErrNotFound("A member version is not available.")
			}
			if err != nil {
				return nil, err
			}
			member, err := ownedSecretObject(ctx, q, a, v.SecretID)
			if err != nil {
				return nil, err
			}
			if member.Archived || v.State != "SEALED" || seen[member.ID] {
				return nil, model.ErrInvalidRequest("Members must be available sealed versions, with one version per secret.")
			}
			seen[member.ID] = true
		}
		r, err := q.CreateSecretGroupRevision(ctx, repository.CreateSecretGroupRevisionParams{GroupID: id, CreatedBy: a.ID})
		if err != nil {
			return nil, err
		}
		for _, vid := range versions {
			if err = q.AddSecretGroupMember(ctx, repository.AddSecretGroupMemberParams{GroupRevisionID: r.ID, VersionID: vid}); err != nil {
				return nil, err
			}
		}
		if _, err = q.UpdateSecretObject(ctx, repository.UpdateSecretObjectParams{ID: id, Alias: o.Alias, Description: o.Description, Archived: false, Revision: expected}); err != nil {
			return nil, err
		}
		return r, recordSecretEvent(ctx, q, a, "SECRET_GROUP_REVISION_CREATED", id, uuid.Nil, map[string]any{"group_revision_id": r.ID, "members": len(versions)})
	})
	if err == nil {
		s.log(ctx, a, "SECRET_GROUP_REVISION_CREATED")
	}
	return out, err
}

type SecretSourceInput struct {
	VersionID       uuid.UUID `json:"version_id"`
	GroupRevisionID uuid.UUID `json:"group_revision_id"`
}

func secretBuildAccess(ctx context.Context, q *repository.Queries, a SecretActor, id uuid.UUID, write bool) error {
	assignments, err := q.LockSecretBuildAssignments(ctx, repository.LockSecretBuildAssignmentsParams{BuildID: id, UserID: a.ID})
	if err != nil {
		return err
	}
	if write {
		if !a.CatalogRole() {
			return model.ErrForbidden("Viewer cannot prepare build secrets.")
		}
		for _, assignment := range assignments {
			if assignment.RoleName != "VIEWER" && a.Has(assignment.RoleName) {
				return nil
			}
		}
		return model.ErrForbidden("You must be assigned to this build in a contributing role.")
	}
	if a.Has("ADMIN") || len(assignments) > 0 {
		return nil
	}
	return model.ErrNotFound("Build not found.")
}
func (s *SecretStoreService) BuildSources(ctx context.Context, a SecretActor, id uuid.UUID) (any, error) {
	if a.ID == uuid.Nil {
		return nil, model.ErrUnauthorized()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := repository.New(tx)
	build, err := q.LockSecretBuild(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrBuildNotFound(id.String())
	}
	if err != nil {
		return nil, err
	}
	if err = secretBuildAccess(ctx, q, a, id, false); err != nil {
		return nil, err
	}
	revision, err := q.GetSecretSourceRevision(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		revision = 0
	} else if err != nil {
		return nil, err
	}
	ownerID := a.ID
	if !a.CatalogRole() {
		ownerID = uuid.Nil
	}
	sources, err := q.ListBuildSecretSources(ctx, repository.ListBuildSecretSourcesParams{BuildID: id, OwnerID: ownerID})
	if err != nil {
		return nil, err
	}
	canEdit := secretBuildAccess(ctx, q, a, id, true) == nil && secretPreparationMutable(build.Status) && !build.IsImmutable
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"sources": sources, "revision": revision, "can_edit": canEdit, "phase": "PREPARATION", "runtime_requests_available": false}, nil
}
func secretPreparationMutable(status string) bool {
	state := model.BuildStatus(status)
	return state == model.StatusCreated || state.CanTransitionTo(model.StatusWorkloadSubmitted)
}
func (s *SecretStoreService) SetBuildSources(ctx context.Context, a SecretActor, id uuid.UUID, expected int32, sources []SecretSourceInput) (any, error) {
	if !a.CatalogRole() {
		return nil, model.ErrForbidden("Viewer cannot prepare build secrets.")
	}
	if len(sources) > 64 {
		return nil, model.ErrInvalidRequest("At most 64 source references may be prepared.")
	}
	_, err := s.tx(ctx, a, func(q *repository.Queries) (any, error) {
		build, err := q.LockSecretBuild(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, model.ErrBuildNotFound(id.String())
		}
		if err != nil {
			return nil, err
		}
		if err = secretBuildAccess(ctx, q, a, id, true); err != nil {
			return nil, err
		}
		if !secretPreparationMutable(build.Status) || build.IsImmutable {
			return nil, &model.AppError{Code: "SECRET_PREPARATION_FROZEN", Message: "Secret source preparation is frozen after workload submission or build closure.", HTTPStatus: http.StatusConflict}
		}
		if flow, e := q.GetBuildSecretFlow(ctx, id); e == nil && flow.TargetRevisionID.Valid {
			return nil, flowError("SECRET_FLOW_APPROVAL_REQUIRED", "Use the signed build Secret Flow approval to change these sources.", 409)
		} else if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
		if err = q.InitSecretSourceSet(ctx, id); err != nil {
			return nil, err
		}
		rev, err := q.GetSecretSourceRevision(ctx, id)
		if err != nil {
			return nil, err
		}
		if rev != expected {
			return nil, secretConflict()
		}
		seen := map[uuid.UUID]bool{}
		for _, source := range sources {
			v, err := q.GetSecretVersion(ctx, source.VersionID)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, model.ErrNotFound("Secret version not found.")
			}
			if err != nil {
				return nil, err
			}
			o, err := q.GetSecretObject(ctx, v.SecretID)
			if err != nil {
				return nil, err
			}
			if o.OwnerID != a.ID {
				return nil, model.ErrNotFound("Secret version not found.")
			}
			if o.Archived || v.State != "SEALED" || seen[o.ID] {
				return nil, model.ErrInvalidRequest("Select one available sealed version per secret.")
			}
			seen[o.ID] = true
			if source.GroupRevisionID != uuid.Nil {
				revision, err := q.GetSecretGroupRevision(ctx, source.GroupRevisionID)
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, model.ErrNotFound("Group revision not found.")
				}
				if err != nil {
					return nil, err
				}
				group, err := q.GetSecretObject(ctx, revision.GroupID)
				if err != nil {
					return nil, err
				}
				if group.OwnerID != a.ID {
					return nil, model.ErrNotFound("Group revision not found.")
				}
				if group.Archived {
					return nil, model.ErrInvalidRequest("The selected group is archived.")
				}
				members, err := q.ListSecretGroupMembers(ctx, revision.ID)
				if err != nil {
					return nil, err
				}
				member := false
				for _, m := range members {
					if m.VersionID == v.ID {
						member = true
					}
				}
				if !member {
					return nil, model.ErrInvalidRequest("The version is not part of the selected group revision.")
				}
			}
		}
		if err = q.DeleteBuildSecretSources(ctx, repository.DeleteBuildSecretSourcesParams{BuildID: id, OwnerID: a.ID}); err != nil {
			return nil, err
		}
		remaining, err := q.CountBuildSecretSources(ctx, id)
		if err != nil {
			return nil, err
		}
		if remaining+int64(len(sources)) > 64 {
			return nil, model.ErrInvalidRequest("A build supports at most 64 source references in total.")
		}
		for _, source := range sources {
			v, err := q.GetSecretVersion(ctx, source.VersionID)
			if err != nil {
				return nil, err
			}
			if err = q.AddBuildSecretSource(ctx, repository.AddBuildSecretSourceParams{BuildID: id, SecretID: v.SecretID, VersionID: v.ID, GroupRevisionID: optionalUUID(source.GroupRevisionID), AddedBy: a.ID}); err != nil {
				return nil, err
			}
		}
		if err = q.BumpSecretSourceRevision(ctx, id); err != nil {
			return nil, err
		}
		return nil, recordSecretEvent(ctx, q, a, "BUILD_SECRET_SOURCES_UPDATED", uuid.Nil, id, map[string]any{"source_count": len(sources), "revision": rev + 1})
	})
	if err != nil {
		return nil, err
	}
	s.log(ctx, a, "BUILD_SECRET_SOURCES_UPDATED")
	return s.BuildSources(ctx, a, id)
}

// Pending sources must never be silently omitted from a deployable contract.
func PendingSecretSourcesError() *model.AppError {
	return &model.AppError{Code: "SECRET_REQUESTS_PENDING", Message: "This build has secret source preparations, but the approved runtime manifest is not ready. Complete Secret Flow preparation or remove the unprepared sources.", HTTPStatus: http.StatusUnprocessableEntity}
}

func ptrInt32(n int32) *int32 { return &n }
