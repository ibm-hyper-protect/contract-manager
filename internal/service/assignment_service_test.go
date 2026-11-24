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
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

func TestMultipleUsersPerRole(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback(ctx) })
	q := repository.New(tx)
	svc := NewAssignmentService(q, NewAuditService(q))

	newAuditor := func() uuid.UUID {
		t.Helper()
		user, err := q.CreateUser(ctx, repository.CreateUserParams{
			Name: "Auditor", Email: uuid.NewString() + "@example.test", PasswordHash: "unused",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.AssignRole(ctx, repository.AssignRoleParams{UserID: user.ID, Role: "AUDITOR", AssignedBy: user.ID}); err != nil {
			t.Fatal(err)
		}
		return user.ID
	}
	first, second, unassigned := newAuditor(), newAuditor(), newAuditor()
	build, err := q.CreateBuild(ctx, repository.CreateBuildParams{Name: "Two auditors", CreatedBy: first})
	if err != nil {
		t.Fatal(err)
	}
	assign := func(userID uuid.UUID) error {
		_, err := svc.CreateAssignment(ctx, CreateAssignmentInput{
			BuildID: build.ID, RoleName: "AUDITOR", UserID: userID, AssignedBy: first,
		})
		return err
	}

	for _, userID := range []uuid.UUID{first, second} {
		if err := assign(userID); err != nil {
			t.Fatalf("assign auditor: %v", err)
		}
	}
	requireUserKeyError(t, assign(first), "INVALID_REQUEST")

	assignments, err := svc.GetBuildAssignments(ctx, build.ID)
	if err != nil || len(assignments) != 2 {
		t.Fatalf("assignments = %d, %v; want 2", len(assignments), err)
	}
	for _, userID := range []uuid.UUID{first, second} {
		if err := svc.ValidateAssignmentForSubmission(ctx, build.ID, userID, model.RoleAuditor.String()); err != nil {
			t.Errorf("assigned auditor rejected: %v", err)
		}
	}
	requireUserKeyError(t, svc.ValidateAssignmentForSubmission(ctx, build.ID, unassigned, model.RoleAuditor.String()), "FORBIDDEN")
}
