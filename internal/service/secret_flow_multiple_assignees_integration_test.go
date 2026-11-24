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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
)

// Exercise collaboration without turning a shared persona into access to a
// colleague's catalog or treating another assignee as a substitute for consent.
func TestSecretFlowMultipleOwnersAndAuditors(t *testing.T) {
	binary := os.Getenv("PVSECRET_TEST_BINARY")
	if binary == "" {
		t.Skip("set PVSECRET_TEST_BINARY for actual request creation")
	}
	pool := catalogDB(t)
	ctx := context.Background()
	q := repository.New(pool)
	eo, sp := catalogActor(t, pool, "ENV_OPERATOR"), catalogActor(t, pool, "SOLUTION_PROVIDER")
	owners := []SecretActor{catalogActor(t, pool, "DATA_OWNER"), catalogActor(t, pool, "DATA_OWNER")}
	auditors := []SecretActor{catalogActor(t, pool, "AUDITOR"), catalogActor(t, pool, "AUDITOR")}
	outsider := catalogActor(t, pool, "AUDITOR")
	id := catalogBuild(t, pool, eo, sp, owners[0], owners[1], auditors[0], auditors[1])
	keys := map[uuid.UUID]*rsa.PrivateKey{}
	for _, actor := range append(append([]SecretActor{}, owners...), auditors...) {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatal(err)
		}
		keys[actor.ID] = key
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if _, err = q.CreateUserPublicKey(ctx, repository.CreateUserPublicKeyParams{
			UserID: actor.ID, Label: "isolated test device", Fingerprint: secretflow.Hash(der),
			PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		}); err != nil {
			t.Fatal(err)
		}
	}
	workerKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	runtimeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "multi-owner simulation"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &runtimeKey.PublicKey, runtimeKey)
	if err != nil {
		t.Fatal(err)
	}
	header, err := os.ReadFile("../secretflow/testdata/runtime.hdr")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.ReadFile("../secretflow/testdata/host.crt")
	if err != nil {
		t.Fatal(err)
	}
	target := secretflow.Target{Name: "Multi-owner development target", Platform: "ccrv", RuntimeVersion: "fixture", ImageSource: "development-fixture://multiple-assignees", ImageDigest: secretflow.Hash([]byte("development fixture only")), Header: header, HeaderSHA256: secretflow.Hash(header), Hosts: []secretflow.Host{{ID: "HKD-9175-0271A28", Data: host}}, RuntimeCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})), Mode: "SIMULATION"}
	processor := &flowProcessor{Processor: &secretflow.Tool{Binary: binary, AllowSimulation: true, Key: workerKey, TempDir: t.TempDir()}}
	s := NewSecretStoreService(pool, flowVerifier{workerKey}, nil).WithProcessor(processor)
	f := flowState(t, s, eo, id)
	if _, err = s.SetFlowTarget(ctx, eo, id, f.Revision, target, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	requirements := []secretflow.Requirement{{Name: "OWNER_A_TOKEN", Consumer: "application", Kind: "retrievable", Type: "plain"}, {Name: "OWNER_B_TOKEN", Consumer: "application", Kind: "retrievable", Type: "plain"}}
	f = flowState(t, s, sp, id)
	if _, err = s.SetFlowRequirements(ctx, sp, id, f.Revision, requirements); err != nil {
		t.Fatal(err)
	}
	f = flowState(t, s, auditors[0], id)
	targetBody := map[string]any{"expected_revision": f.Revision, "target_revision_id": uuid.UUID(f.TargetRevisionID.Bytes), "target_digest": secretflow.Digest(target), "header_provenance_confirmed": true}
	proof := flowTestProof(t, keys[auditors[0].ID], auditors[0], "/builds/"+id.String()+"/secret-flow/target-approval", targetBody)
	if _, err = s.ApproveFlowTarget(ctx, auditors[0], id, f.Revision, proof); err != nil {
		t.Fatal(err)
	}
	if err = q.InitSecretSourceSet(ctx, id); err != nil {
		t.Fatal(err)
	}
	for i, owner := range owners {
		object := mustCatalogObject(t, s, owner, "SECRET", "private-owner-"+string(rune('a'+i)))
		reserved, err := s.Reserve(ctx, owner, object.ID)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(reserved)
		var version struct{ ID uuid.UUID }
		if err = json.Unmarshal(raw, &version); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Seal(ctx, owner, object.ID, version.ID, flowSeal(t, workerKey, object.ID, version.ID, []byte("disposable test value"))); err != nil {
			t.Fatal(err)
		}
		other := owners[1-i]
		if _, err = s.Detail(ctx, other, object.ID); err == nil {
			t.Fatal("another assigned Data Owner read a foreign catalog entry")
		} else {
			catalogStatus(t, err, 404)
		}
		group := mustCatalogObject(t, s, owner, "GROUP", "personal credentials")
		out, err := s.GroupRevision(ctx, owner, group.ID, group.Revision, []uuid.UUID{version.ID})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = json.Marshal(out)
		var revision struct{ ID uuid.UUID }
		if err = json.Unmarshal(raw, &revision); err != nil {
			t.Fatal(err)
		}
		f = flowState(t, s, owner, id)
		sourceRevision, err := q.GetSecretSourceRevision(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		r := requirements[i]
		approval := secretflow.Approval{ExpectedRevision: f.Revision, SourceRevision: sourceRevision, TargetRevisionID: uuid.UUID(f.TargetRevisionID.Bytes), TargetDigest: secretflow.Digest(target), Sources: []secretflow.Binding{{VersionID: version.ID, GroupRevisionID: revision.ID, Name: r.Name, Consumer: r.Consumer, Kind: r.Kind, Type: r.Type}}}
		path := "/builds/" + id.String() + "/secret-flow/approvals"
		foreignProof := flowTestProof(t, keys[other.ID], other, path, approval)
		if _, err = s.ApproveFlowSources(ctx, other, id, approval, foreignProof); err == nil {
			t.Fatal("another assigned Data Owner approved a foreign version")
		} else {
			catalogStatus(t, err, 404)
		}
		proof = flowTestProof(t, keys[owner.ID], owner, path, approval)
		if _, err = s.ApproveFlowSources(ctx, owner, id, approval, proof); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			f = flowState(t, s, auditors[1], id)
			_, err = s.PrepareFlow(ctx, auditors[1], id, f.Revision)
			requireUserKeyError(t, err, "SECRET_APPROVALS_PENDING")
		}
	}
	f = flowState(t, s, auditors[1], id)
	if _, err = s.PrepareFlow(ctx, outsider, id, f.Revision); err == nil {
		t.Fatal("unassigned auditor prepared requests")
	} else {
		catalogStatus(t, err, 403)
	}
	if _, err = s.PrepareFlow(ctx, auditors[1], id, f.Revision); err != nil {
		t.Fatal(err)
	}
	f = flowState(t, s, auditors[0], id)
	payload := string(f.PreparedPayload)
	if _, err = s.PrepareFlow(ctx, auditors[0], id, f.Revision); err != nil {
		t.Fatal(err)
	}
	f = flowState(t, s, auditors[0], id)
	if string(f.PreparedPayload) != payload || processor.calls.Load() != 1 {
		t.Fatal("auditor handoff recreated prepared requests")
	}
	var result secretflow.Result
	if err = json.Unmarshal(f.PreparedPayload, &result); err != nil || len(result.Artifacts) != 2 {
		t.Fatalf("combined owner requests missing: %v", err)
	}
	for _, owner := range owners {
		view, err := s.Flow(ctx, owner, id)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(view)
		foreign := "private-owner-b"
		if owner.ID == owners[1].ID {
			foreign = "private-owner-a"
		}
		if strings.Contains(string(raw), foreign) || strings.Contains(string(raw), "disposable test value") {
			t.Fatal("shared build leaked another owner's private metadata or value")
		}
		var response struct {
			ApprovalDetails map[string]struct {
				ApprovedBy struct {
					ID   uuid.UUID `json:"id"`
					Name string    `json:"name"`
				} `json:"approved_by"`
				ApprovedAt time.Time `json:"approved_at"`
			} `json:"approval_details"`
		}
		if err = json.Unmarshal(raw, &response); err != nil || len(response.ApprovalDetails) != 2 {
			t.Fatalf("approver metadata missing: %v", err)
		}
		for i, requirement := range requirements {
			detail := response.ApprovalDetails[requirement.Name]
			if detail.ApprovedBy.ID != owners[i].ID || detail.ApprovedBy.Name != "DATA_OWNER" || detail.ApprovedAt.IsZero() {
				t.Fatalf("approval must show its actual source owner and timestamp: %s", requirement.Name)
			}
		}
	}
	for _, actor := range []SecretActor{owners[1], auditors[0]} {
		t.Run("revoking_"+actor.Roles[0]+"_invalidates_own_proof", func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, "DELETE FROM build_assignments WHERE build_id=$1 AND user_id=$2", id, actor.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err = validatePrepared(ctx, repository.New(tx), id); err == nil {
				t.Fatal("another assignee kept a revoked signer's approval valid")
			}
		})
	}
}
