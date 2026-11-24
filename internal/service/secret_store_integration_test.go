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
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretstore"
)

// Service tests use a verifier stub; envelope authentication is exercised separately
// with RSA-4096/AES-GCM and through the real Unix worker in the desktop flow.
type catalogTestVerifier struct{}

func (catalogTestVerifier) Info(context.Context) (secretstore.ImportKey, error) {
	return secretstore.ImportKey{}, nil
}
func (catalogTestVerifier) Verify(context.Context, secretstore.Envelope) (int, error) { return 3, nil }
func catalogDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SECRET_STORE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set SECRET_STORE_TEST_DATABASE_URL for isolated PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	schema := "secret_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	files, err := filepath.Glob("../../migrations/*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		sql, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	return pool
}
func catalogActor(t *testing.T, pool *pgxpool.Pool, role string) SecretActor {
	t.Helper()
	id := uuid.New()
	email := id.String() + "@example.test"
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "INSERT INTO users(id,name,email,password_hash,must_change_password) VALUES($1,$2,$3,'test-only',false)", id, role, email); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO user_roles(user_id,role,assigned_by) VALUES($1,$2,$1)", id, role); err != nil {
		t.Fatal(err)
	}
	return SecretActor{ID: id, Email: email, Roles: []string{role}, IP: "127.0.0.1"}
}
func catalogBuild(t *testing.T, pool *pgxpool.Pool, actors ...SecretActor) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO builds(id,name,created_by) VALUES($1,'Secret store test',$2)", id, actors[0].ID); err != nil {
		t.Fatal(err)
	}
	for _, a := range actors {
		if _, err := pool.Exec(ctx, "INSERT INTO build_assignments(build_id,role_id,user_id,assigned_by) SELECT $1,id,$2,$2 FROM roles WHERE name=$3", id, a.ID, a.Roles[0]); err != nil {
			t.Fatal(err)
		}
	}
	return id
}
func mustCatalogObject(t *testing.T, s *SecretStoreService, a SecretActor, kind, alias string) repository.SecretCatalogObject {
	t.Helper()
	out, err := s.Create(context.Background(), a, kind, alias, "")
	if err != nil {
		t.Fatal(err)
	}
	return out.(repository.SecretCatalogObject)
}
func catalogEnvelope(id, vid uuid.UUID) secretstore.Envelope {
	b64 := base64.StdEncoding.EncodeToString
	return secretstore.Envelope{Format: 1, SecretID: id, VersionID: vid, KeyID: "test-only", WrappedKey: b64(make([]byte, 512)), Nonce: b64(make([]byte, 12)), Tag: b64(make([]byte, 16)), Ciphertext: b64([]byte{1, 2, 3})}
}
func mustCatalogVersion(t *testing.T, s *SecretStoreService, a SecretActor, id uuid.UUID) uuid.UUID {
	t.Helper()
	out, err := s.Reserve(context.Background(), a, id)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	var v struct {
		ID uuid.UUID `json:"id"`
	}
	json.Unmarshal(raw, &v)
	if _, err = s.Seal(context.Background(), a, id, v.ID, catalogEnvelope(id, v.ID)); err != nil {
		t.Fatal(err)
	}
	return v.ID
}
func catalogStatus(t *testing.T, err error, status int) {
	t.Helper()
	var app *model.AppError
	if !errors.As(err, &app) || app.HTTPStatus != status {
		t.Fatalf("want HTTP %d, got %v", status, err)
	}
}

var catalogRoles = []string{"ADMIN", "AUDITOR", "SOLUTION_PROVIDER", "DATA_OWNER", "ENV_OPERATOR"}

func catalogData(t *testing.T, out any, err error) map[string]json.RawMessage {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]json.RawMessage
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return data
}
func catalogSources(t *testing.T, s *SecretStoreService, a SecretActor, build uuid.UUID) ([]repository.ListBuildSecretSourcesRow, int32, bool) {
	t.Helper()
	out, err := s.BuildSources(context.Background(), a, build)
	data := catalogData(t, out, err)
	var refs []repository.ListBuildSecretSourcesRow
	var revision int32
	var editable bool
	if err = json.Unmarshal(data["sources"], &refs); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(data["revision"], &revision)
	json.Unmarshal(data["can_edit"], &editable)
	return refs, revision, editable
}

func TestSecretPersonalStoresAllContributorRoles(t *testing.T) {
	pool := catalogDB(t)
	s := NewSecretStoreService(pool, catalogTestVerifier{}, nil)
	ctx := context.Background()
	actors := []SecretActor{}
	objects := []repository.SecretCatalogObject{}
	for _, role := range catalogRoles {
		a := catalogActor(t, pool, role)
		actors = append(actors, a)
		// Identical aliases in different personal stores must not conflict.
		object := mustCatalogObject(t, s, a, "SECRET", "database-password")
		objects = append(objects, object)
		vid := mustCatalogVersion(t, s, a, object.ID)
		group := mustCatalogObject(t, s, a, "GROUP", "application")
		if _, err := s.GroupRevision(ctx, a, group.ID, group.Revision, []uuid.UUID{vid}); err != nil {
			t.Fatal(role, err)
		}
	}
	for i, a := range actors {
		t.Run(a.Roles[0], func(t *testing.T) {
			out, err := s.List(ctx, a, "SECRET", "", 1, 0)
			data := catalogData(t, out, err)
			var entries []struct {
				Object repository.SecretCatalogObject `json:"object"`
			}
			if err = json.Unmarshal(data["objects"], &entries); err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Object.ID != objects[i].ID {
				t.Fatal("foreign entry in personal list")
			}
			out, err = s.List(ctx, a, "SECRET", "", 1, 1)
			data = catalogData(t, out, err)
			if string(data["objects"]) != "[]" {
				t.Fatal("pagination exposes another owner")
			}
			for j, other := range objects {
				if i == j {
					continue
				}
				_, err = s.Detail(ctx, a, other.ID)
				catalogStatus(t, err, 404)
				_, err = s.Update(ctx, a, other.ID, other.Revision, "stolen", "", false)
				catalogStatus(t, err, 404)
				_, err = s.Reserve(ctx, a, other.ID)
				catalogStatus(t, err, 404)
			}
			detail, err := s.Detail(ctx, a, objects[i].ID)
			data = catalogData(t, detail, err)
			raw, _ := json.Marshal(data)
			for _, forbidden := range []string{"sealed_payload", "wrapped_key", "ciphertext", "grants", "can_manage_grants"} {
				if strings.Contains(string(raw), forbidden) {
					t.Fatalf("personal metadata exposes %s", forbidden)
				}
			}
		})
	}
	viewer := catalogActor(t, pool, "VIEWER")
	_, err := s.Create(ctx, viewer, "SECRET", "forbidden", "")
	catalogStatus(t, err, 403)
	_, err = s.Create(ctx, viewer, "GROUP", "forbidden", "")
	catalogStatus(t, err, 403)
	_, err = s.List(ctx, viewer, "SECRET", "", 50, 0)
	catalogStatus(t, err, 403)
	_, err = s.Detail(ctx, viewer, objects[0].ID)
	catalogStatus(t, err, 403)
	_, err = s.Info(ctx, viewer)
	catalogStatus(t, err, 403)
}

func TestSecretPersonalVersionsRemainImmutable(t *testing.T) {
	pool := catalogDB(t)
	s := NewSecretStoreService(pool, catalogTestVerifier{}, nil)
	ctx := context.Background()
	owner := catalogActor(t, pool, "DATA_OWNER")
	other := catalogActor(t, pool, "ADMIN")
	object := mustCatalogObject(t, s, owner, "SECRET", "immutable")
	vid := mustCatalogVersion(t, s, owner, object.ID)
	if _, err := s.Seal(ctx, owner, object.ID, vid, catalogEnvelope(object.ID, vid)); err != nil {
		t.Fatal("idempotent retry:", err)
	}
	changed := catalogEnvelope(object.ID, vid)
	changed.Ciphertext = base64.StdEncoding.EncodeToString([]byte{4, 5, 6})
	_, err := s.Seal(ctx, owner, object.ID, vid, changed)
	catalogStatus(t, err, 409)
	_, err = s.Seal(ctx, other, object.ID, vid, catalogEnvelope(object.ID, vid))
	catalogStatus(t, err, 404)
	_, err = s.Update(ctx, owner, object.ID, object.Revision+1, "new", "", false)
	catalogStatus(t, err, 409)
	if _, err = s.Update(ctx, owner, object.ID, object.Revision, object.Alias, "", true); err != nil {
		t.Fatal(err)
	}
	_, err = s.Reserve(ctx, owner, object.ID)
	catalogStatus(t, err, 400)
}

func TestSecretPersonalGroupsAndPinnedVersions(t *testing.T) {
	pool := catalogDB(t)
	s := NewSecretStoreService(pool, catalogTestVerifier{}, nil)
	ctx := context.Background()
	owner := catalogActor(t, pool, "ENV_OPERATOR")
	other := catalogActor(t, pool, "AUDITOR")
	build := catalogBuild(t, pool, owner, other)
	one := mustCatalogObject(t, s, owner, "SECRET", "database")
	two := mustCatalogObject(t, s, owner, "SECRET", "token")
	v1 := mustCatalogVersion(t, s, owner, one.ID)
	v2 := mustCatalogVersion(t, s, owner, two.ID)
	foreign := mustCatalogObject(t, s, other, "SECRET", "foreign")
	foreignID := mustCatalogVersion(t, s, other, foreign.ID)
	group := mustCatalogObject(t, s, owner, "GROUP", "application")
	_, err := s.GroupRevision(ctx, owner, group.ID, group.Revision, []uuid.UUID{v1, foreignID})
	catalogStatus(t, err, 404)
	out, err := s.GroupRevision(ctx, owner, group.ID, group.Revision, []uuid.UUID{v1, v2})
	if err != nil {
		t.Fatal(err)
	}
	revision := out.(repository.SecretGroupRevision)
	sources := []SecretSourceInput{{VersionID: v1, GroupRevisionID: revision.ID}, {VersionID: v2, GroupRevisionID: revision.ID}}
	if _, err = s.SetBuildSources(ctx, owner, build, 0, sources); err != nil {
		t.Fatal(err)
	}
	rotated := mustCatalogVersion(t, s, owner, one.ID)
	refs, _, editable := catalogSources(t, s, owner, build)
	if !editable || len(refs) != 2 {
		t.Fatal("bundled addition failed")
	}
	for _, ref := range refs {
		if ref.VersionID == rotated {
			t.Fatal("rotation changed pinned selection")
		}
	}
	_, err = s.SetBuildSources(ctx, owner, build, 1, []SecretSourceInput{{VersionID: rotated, GroupRevisionID: revision.ID}})
	catalogStatus(t, err, 400)
	_, err = s.GroupRevision(ctx, other, group.ID, group.Revision, []uuid.UUID{foreignID})
	catalogStatus(t, err, 404)
	_, err = s.SetBuildSources(ctx, other, build, 1, sources)
	catalogStatus(t, err, 404)
	// A group owned by someone else must not be usable even with a guessed revision ID.
	foreignGroup := mustCatalogObject(t, s, other, "GROUP", "foreign-group")
	r, err := s.GroupRevision(ctx, other, foreignGroup.ID, foreignGroup.Revision, []uuid.UUID{foreignID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SetBuildSources(ctx, owner, build, 1, []SecretSourceInput{{VersionID: v1, GroupRevisionID: r.(repository.SecretGroupRevision).ID}})
	catalogStatus(t, err, 404)
	// Legacy mixed-owner members must never expose foreign aliases.
	if _, err = pool.Exec(ctx, "INSERT INTO secret_group_members(group_revision_id,version_id) VALUES($1,$2)", revision.ID, foreignID); err != nil {
		t.Fatal(err)
	}
	detail, err := s.Detail(ctx, owner, group.ID)
	data := catalogData(t, detail, err)
	if strings.Contains(string(data["revisions"]), "foreign") {
		t.Fatal("legacy group leaked foreign metadata")
	}
}

func TestSecretPersonalBuildContributionsStayIsolated(t *testing.T) {
	pool := catalogDB(t)
	s := NewSecretStoreService(pool, catalogTestVerifier{}, nil)
	ctx := context.Background()
	actors := []SecretActor{}
	for _, role := range catalogRoles {
		actors = append(actors, catalogActor(t, pool, role))
	}
	viewer := catalogActor(t, pool, "VIEWER")
	build := catalogBuild(t, pool, append(actors, viewer)...)
	for i, a := range actors {
		object := mustCatalogObject(t, s, a, "SECRET", "personal")
		vid := mustCatalogVersion(t, s, a, object.ID)
		_, revision, editable := catalogSources(t, s, a, build)
		if !editable {
			t.Fatal("assigned contributor cannot add own source", a.Roles)
		}
		if _, err := s.SetBuildSources(ctx, a, build, revision, []SecretSourceInput{{VersionID: vid}}); err != nil {
			t.Fatal(err)
		}
		var total int
		pool.QueryRow(ctx, "SELECT count(*) FROM build_secret_sources WHERE build_id=$1", build).Scan(&total)
		if total != i+1 {
			t.Fatal("adding a personal contribution erased someone else's source")
		}
	}
	for _, a := range actors {
		refs, revision, editable := catalogSources(t, s, a, build)
		if len(refs) != 1 || !editable {
			t.Fatal("personal source view is incorrect")
		}
		for _, other := range actors {
			if other.ID == a.ID {
				continue
			}
			_, err := s.SetBuildSources(ctx, other, build, revision, []SecretSourceInput{{VersionID: refs[0].VersionID}})
			catalogStatus(t, err, 404)
		}
	}
	refs, _, editable := catalogSources(t, s, viewer, build)
	if len(refs) != 0 || editable {
		t.Fatal("viewer received private source metadata")
	}
	_, err := s.SetBuildSources(ctx, viewer, build, 5, nil)
	catalogStatus(t, err, 403)
	outsider := catalogActor(t, pool, "ADMIN")
	_, err = s.SetBuildSources(ctx, outsider, build, 5, nil)
	catalogStatus(t, err, 403)
	stranger := catalogActor(t, pool, "DATA_OWNER")
	_, err = s.BuildSources(ctx, stranger, build)
	catalogStatus(t, err, 404)
	for i, a := range actors {
		_, revision, _ := catalogSources(t, s, a, build)
		if _, err = s.SetBuildSources(ctx, a, build, revision, nil); err != nil {
			t.Fatal(err)
		}
		var total int
		pool.QueryRow(ctx, "SELECT count(*) FROM build_secret_sources WHERE build_id=$1", build).Scan(&total)
		if total != len(actors)-i-1 {
			t.Fatal("removing a personal contribution erased someone else's source")
		}
	}
}

func TestSecretBuildPreparationConcurrencyAndSubmission(t *testing.T) {
	pool := catalogDB(t)
	s := NewSecretStoreService(pool, catalogTestVerifier{}, nil)
	ctx := context.Background()
	owner := catalogActor(t, pool, "DATA_OWNER")
	sp := catalogActor(t, pool, "SOLUTION_PROVIDER")
	build := catalogBuild(t, pool, owner, sp)
	object := mustCatalogObject(t, s, owner, "SECRET", "owned")
	vid := mustCatalogVersion(t, s, owner, object.ID)
	sources := []SecretSourceInput{{VersionID: vid}}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.SetBuildSources(ctx, owner, build, 0, sources); errs <- err }()
	}
	wg.Wait()
	close(errs)
	success, conflict := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else {
			catalogStatus(t, err, 409)
			conflict++
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent updates did not CAS")
	}
	if _, err := pool.Exec(ctx, "UPDATE builds SET status='SIGNING_KEY_REGISTERED' WHERE id=$1", build); err != nil {
		t.Fatal(err)
	}
	contract := &ContractService{db: pool}
	signature, signatureHash := "test-only signature", strings.Repeat("a", 64)
	params := submitSectionParams{requestSignature: &signature, requestSignatureHash: &signatureHash, buildID: build, personaRole: model.RoleSolutionProvider, submittedBy: sp.ID, actorRoles: sp.Roles, actorIP: sp.IP, encryptedPayload: "test envelope", requiredStatus: model.StatusSigningKeyRegistered, nextStatus: model.StatusWorkloadSubmitted}
	_, err := contract.submitSection(ctx, params)
	catalogStatus(t, err, 422)
	// The Solution Provider cannot clear the Data Owner's hidden references.
	if _, err = s.SetBuildSources(ctx, sp, build, 1, nil); err != nil {
		t.Fatal(err)
	}
	_, err = contract.submitSection(ctx, params)
	catalogStatus(t, err, 422)
	if _, err = s.SetBuildSources(ctx, owner, build, 2, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = contract.submitSection(ctx, params); err != nil {
		t.Fatal("secret-free submission:", err)
	}
	_, err = s.SetBuildSources(ctx, owner, build, 3, sources)
	catalogStatus(t, err, 409)
}

func TestSecretSharingRetirementPreservesEncryptedValuesAndPins(t *testing.T) {
	pool := catalogDB(t)
	ctx := context.Background()
	s := NewSecretStoreService(pool, catalogTestVerifier{}, nil)
	owner := catalogActor(t, pool, "DATA_OWNER")
	admin := catalogActor(t, pool, "ADMIN")
	build := catalogBuild(t, pool, owner, admin)
	object := mustCatalogObject(t, s, owner, "SECRET", "legacy")
	vid := mustCatalogVersion(t, s, owner, object.ID)
	if _, err := s.SetBuildSources(ctx, owner, build, 0, []SecretSourceInput{{VersionID: vid}}); err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"down", "up"} {
		migration, err := os.ReadFile("../../migrations/024_personal_secret_store." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(migration)); err != nil {
			t.Fatal(err)
		}
		if direction == "down" {
			if _, err = pool.Exec(ctx, "INSERT INTO secret_store_grants(object_id,grantee_id,permission,granted_by) VALUES($1,$2,'VIEW',$3)", object.ID, admin.ID, owner.ID); err != nil {
				t.Fatal(err)
			}
			_, err = s.Detail(ctx, admin, object.ID)
			catalogStatus(t, err, 404)
		}
	}
	refs, _, _ := catalogSources(t, s, owner, build)
	if len(refs) != 1 || refs[0].VersionID != vid {
		t.Fatal("migration removed pinned source")
	}
	var state string
	if err := pool.QueryRow(ctx, "SELECT state FROM secret_store_versions WHERE id=$1 AND sealed_payload IS NOT NULL", vid).Scan(&state); err != nil || state != "SEALED" {
		t.Fatal("migration removed ciphertext", err)
	}
}
