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
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v3"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract/contractgo"
	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
	"github.com/ibm-hyper-protect/contract-manager/internal/keymgmt/db"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretstore"
)

type flowVerifier struct{ key *rsa.PrivateKey }

func (v flowVerifier) Info(context.Context) (secretstore.ImportKey, error) {
	return secretstore.PublicKeyInfo(&v.key.PublicKey)
}
func (v flowVerifier) Verify(_ context.Context, e secretstore.Envelope) (int, error) {
	return secretstore.Verify(e, v.key)
}

type flowProcessor struct {
	secretflow.Processor
	calls  atomic.Int32
	before func()
}

func (p *flowProcessor) Prepare(ctx context.Context, j secretflow.Job) (secretflow.Result, error) {
	p.calls.Add(1)
	if p.before != nil {
		p.before()
	}
	return p.Processor.Prepare(ctx, j)
}
func flowTestProof(t *testing.T, key *rsa.PrivateKey, actor SecretActor, path string, body any) secretflow.Proof {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	raw, _ := json.Marshal(body)
	p := secretflow.Proof{SignerID: actor.ID, PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Fingerprint: secretflow.Hash(der), Method: "PUT", Path: path, Body: raw, Timestamp: time.Now().UnixMilli()}
	p.Hash = secretflow.Hash([]byte(fmt.Sprintf(`{"method":%q,"path":%q,"data":%s,"timestamp":%d}`, p.Method, p.Path, p.Body, p.Timestamp)))
	digest := sha256.Sum256([]byte(p.Hash))
	sig, e := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if e != nil {
		t.Fatal(e)
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return p
}
func flowSeal(t *testing.T, key *rsa.PrivateKey, id, vid uuid.UUID, value []byte) secretstore.Envelope {
	t.Helper()
	info, _ := secretstore.PublicKeyInfo(&key.PublicKey)
	dek := make([]byte, 32)
	rand.Read(dek)
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	data := gcm.Seal(nil, nonce, value, secretstore.Context(id, vid))
	wrapped, e := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, dek, nil)
	if e != nil {
		t.Fatal(e)
	}
	enc := base64.StdEncoding.EncodeToString
	return secretstore.Envelope{Format: 1, SecretID: id, VersionID: vid, KeyID: info.KeyID, WrappedKey: enc(wrapped), Nonce: enc(nonce), Tag: enc(data[len(data)-16:]), Ciphertext: enc(data[:len(data)-16])}
}
func flowState(t *testing.T, s *SecretStoreService, a SecretActor, id uuid.UUID) repository.BuildSecretFlow {
	t.Helper()
	if _, e := s.Flow(context.Background(), a, id); e != nil {
		t.Fatal(e)
	}
	f, e := repository.New(s.pool).GetBuildSecretFlow(context.Background(), id)
	if e == pgx.ErrNoRows {
		return repository.BuildSecretFlow{BuildID: id, Requirements: []byte("[]")}
	}
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func TestSecretFlowFullContract(t *testing.T) {
	binary := os.Getenv("PVSECRET_TEST_BINARY")
	if binary == "" {
		t.Skip("set PVSECRET_TEST_BINARY for actual request creation")
	}
	pool := catalogDB(t)
	ctx := context.Background()
	q := repository.New(pool)
	eo := catalogActor(t, pool, "ENV_OPERATOR")
	auditor := catalogActor(t, pool, "AUDITOR")
	sp := catalogActor(t, pool, "SOLUTION_PROVIDER")
	owner := catalogActor(t, pool, "DATA_OWNER")
	admin := catalogActor(t, pool, "ADMIN")
	viewer := catalogActor(t, pool, "VIEWER")
	id := catalogBuild(t, pool, eo, auditor, sp, owner, viewer)
	if required, err := q.BuildRequiresSecretFlow(ctx, id); err != nil || required == nil || *required {
		t.Fatalf("ordinary build incorrectly requires secret metadata: %v", err)
	}
	key, e := rsa.GenerateKey(rand.Reader, 4096)
	if e != nil {
		t.Fatal(e)
	}
	auditKey, e := rsa.GenerateKey(rand.Reader, 4096)
	if e != nil {
		t.Fatal(e)
	}
	for _, pair := range []struct {
		actor SecretActor
		key   *rsa.PrivateKey
	}{{owner, key}, {auditor, auditKey}} {
		der, _ := x509.MarshalPKIXPublicKey(&pair.key.PublicKey)
		public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		if _, e = q.CreateUserPublicKey(ctx, repository.CreateUserPublicKeyParams{UserID: pair.actor.ID, Label: "test device", PublicKey: public, Fingerprint: secretflow.Hash(der)}); e != nil {
			t.Fatal(e)
		}
	}

	// Self-signed test certificate is used only for outer-contract encryption in SIMULATION.
	runtimeKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable test runtime"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &runtimeKey.PublicKey, runtimeKey)
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	hdr, e := os.ReadFile("../secretflow/testdata/runtime.hdr")
	if e != nil {
		t.Fatal(e)
	}
	host, e := os.ReadFile("../secretflow/testdata/host.crt")
	if e != nil {
		t.Fatal(e)
	}
	target := secretflow.Target{Name: "Remote runtime", Platform: "ccrv", RuntimeVersion: "1.1", ImageSource: "https://runtime.example.test/release", ImageDigest: secretflow.Hash([]byte("runtime disk")), Header: hdr, HeaderSHA256: secretflow.Hash(hdr), Hosts: []secretflow.Host{{ID: "HKD-9175-0271A28", Data: host}}, RuntimeCertificate: cert, Mode: "SIMULATION"}
	processor := &flowProcessor{Processor: &secretflow.Tool{Binary: binary, AllowSimulation: true, Key: key, TempDir: t.TempDir()}}
	s := NewSecretStoreService(pool, flowVerifier{key}, nil).WithProcessor(processor)
	f := flowState(t, s, eo, id)
	if _, e = s.SetFlowTarget(ctx, owner, id, f.Revision, target, uuid.Nil); e == nil {
		t.Fatal("data owner selected deployment target")
	}
	if _, e = s.SetFlowTarget(ctx, eo, id, f.Revision, target, uuid.Nil); e != nil {
		t.Fatal(e)
	}
	f = flowState(t, s, sp, id)
	requirements := []secretflow.Requirement{{Name: "DATABASE_PASSWORD", Consumer: "api", Kind: "retrievable", Type: "plain"}, {Name: "DISK_RESOURCE", Consumer: "crypto", Kind: "association", Type: "association"}}
	if _, e = s.SetFlowRequirements(ctx, sp, id, f.Revision, requirements); e != nil {
		t.Fatal(e)
	}
	if required, err := q.BuildRequiresSecretFlow(ctx, id); err != nil || required == nil || !*required {
		t.Fatalf("secret build not advertised for strict metadata transport: %v", err)
	}
	f = flowState(t, s, auditor, id)
	targetBody := map[string]any{"expected_revision": f.Revision, "target_revision_id": uuid.UUID(f.TargetRevisionID.Bytes), "target_digest": secretflow.Digest(target), "header_provenance_confirmed": true}
	proof := flowTestProof(t, auditKey, auditor, "/builds/"+id.String()+"/secret-flow/target-approval", targetBody)
	if _, e = s.ApproveFlowTarget(ctx, auditor, id, f.Revision, proof); e != nil {
		t.Fatal(e)
	}
	versions := []uuid.UUID{}
	for i, value := range [][]byte{[]byte(" \t\x00\xff dummy password\n "), bytes.Repeat([]byte{0x73}, 32)} {
		o := mustCatalogObject(t, s, owner, "SECRET", fmt.Sprintf("private-alias-%d", i))
		reserved, e := s.Reserve(ctx, owner, o.ID)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(reserved)
		var version struct {
			ID uuid.UUID `json:"id"`
		}
		json.Unmarshal(raw, &version)
		if _, e = s.Seal(ctx, owner, o.ID, version.ID, flowSeal(t, key, o.ID, version.ID, value)); e != nil {
			t.Fatal(e)
		}
		versions = append(versions, version.ID)
	}
	group := mustCatalogObject(t, s, owner, "GROUP", "private group")
	out, e := s.GroupRevision(ctx, owner, group.ID, group.Revision, versions)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(out)
	var gr struct {
		ID uuid.UUID `json:"id"`
	}
	json.Unmarshal(raw, &gr)
	f = flowState(t, s, owner, id)
	approval := secretflow.Approval{ExpectedRevision: f.Revision, TargetRevisionID: uuid.UUID(f.TargetRevisionID.Bytes), TargetDigest: secretflow.Digest(target)}
	for i, r := range requirements {
		approval.Sources = append(approval.Sources, secretflow.Binding{VersionID: versions[i], GroupRevisionID: gr.ID, Name: r.Name, Consumer: r.Consumer, Kind: r.Kind, Type: r.Type})
	}
	// Different personas cannot select another person's catalog entry, even an admin.
	adminProof := flowTestProof(t, key, admin, "/builds/"+id.String()+"/secret-flow/approvals", approval)
	if _, e = s.ApproveFlowSources(ctx, admin, id, approval, adminProof); e == nil {
		t.Fatal("unassigned admin contributed foreign sources")
	}
	proof = flowTestProof(t, key, owner, "/builds/"+id.String()+"/secret-flow/approvals", approval)
	if _, e = s.ApproveFlowSources(ctx, owner, id, approval, proof); e != nil {
		t.Fatal(e)
	}
	f = flowState(t, s, auditor, id)
	// Publication must fail if requirements change while the worker runs.
	processor.before = func() {
		processor.before = nil
		if _, err := s.SetFlowRequirements(ctx, sp, id, f.Revision, requirements); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PrepareFlow(ctx, auditor, id, f.Revision); err == nil {
		t.Fatal("stale worker result was published")
	}
	f = flowState(t, s, owner, id)
	if f.PreparedDigest != nil {
		t.Fatal("stale result retained prepared data")
	}
	var staleCount int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM secret_preparation_jobs WHERE build_id=$1 AND state='STALE'", id).Scan(&staleCount); e != nil || staleCount != 1 {
		t.Fatal("stale job was not recorded")
	}
	approval.ExpectedRevision = f.Revision
	approval.SourceRevision = 1
	proof = flowTestProof(t, key, owner, "/builds/"+id.String()+"/secret-flow/approvals", approval)
	if _, e = s.ApproveFlowSources(ctx, owner, id, approval, proof); e != nil {
		t.Fatal(e)
	}
	f = flowState(t, s, auditor, id)
	if _, e = s.PrepareFlow(ctx, auditor, id, f.Revision); e != nil {
		t.Fatal(e)
	}
	f = flowState(t, s, auditor, id)
	originalDigest := *f.PreparedDigest
	originalPayload := string(f.PreparedPayload)
	if _, e = s.PrepareFlow(ctx, auditor, id, f.Revision); e != nil {
		t.Fatal(e)
	}
	f = flowState(t, s, auditor, id)
	if processor.calls.Load() != 2 || *f.PreparedDigest != originalDigest || string(f.PreparedPayload) != originalPayload {
		t.Fatal("idempotent preparation recreated requests")
	}
	ownerView, e := s.Flow(ctx, sp, id)
	if e != nil {
		t.Fatal(e)
	}
	safe, _ := json.Marshal(ownerView)
	if bytes.Contains(safe, []byte("private-alias")) || bytes.Contains(safe, []byte("dummy password")) || bytes.Contains(safe, []byte("ciphertext")) {
		t.Fatal("owner catalog data leaked")
	}
	viewerView, e := s.Flow(ctx, viewer, id)
	if e != nil {
		t.Fatal(e)
	}
	safe, _ = json.Marshal(viewerView)
	if bytes.Contains(safe, []byte("DATABASE_PASSWORD")) || bytes.Contains(safe, []byte("secret_id")) {
		t.Fatal("viewer sees secret bindings")
	}
	if bytes.Contains(safe, []byte("approval_details")) {
		t.Fatal("viewer sees secret approver metadata")
	}
	engine := contractgo.New()
	audit := NewAuditService(q)
	builds := NewBuildService(q, audit)
	assignments := NewAssignmentService(q, audit)
	provider := db.New(q)
	keys := NewKeyService(q, pool, builds, assignments, audit, provider, engine)
	contracts := NewContractService(q, pool, builds, assignments, keys, provider, engine)
	passphrase := "DisposableTest123!"
	signature, signatureHash := proof.Signature, proof.Hash
	if _, e = keys.RegisterSigningKey(ctx, id, auditor.ID, model.BuildKeyModeGenerate, nil, &passphrase, "127.0.0.1", auditor.Roles, &signature, &signatureHash); e != nil {
		t.Fatal(e)
	}
	workload := ccrvWorkloadTemplate
	if _, e = contracts.SubmitWorkloadSection(ctx, SubmitSectionV2Input{BuildID: id, ActorID: sp.ID, ActorRoles: sp.Roles, ActorIP: "127.0.0.1", RequestSignature: &signature, RequestSignatureHash: &signatureHash, Plaintext: workload, CertificatePEM: cert}); e != nil {
		t.Fatal(e)
	}
	f = flowState(t, s, eo, id)
	if !f.Frozen {
		t.Fatal("manifest not frozen atomically with workload")
	}
	if _, e = s.SetFlowTarget(ctx, eo, id, f.Revision, target, uuid.Nil); e == nil {
		t.Fatal("frozen target changed")
	}
	env := "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.test\n    iamApiKey: dummy-test-key\n    port: 443\nenv:\n  APP_MODE: test\nauths:\n  registry.example.test:\n    username: test\n    password: dummy-only\nvolumes:\n  data:\n    seed: TestEnvironmentSeed123\n"
	section, e := contracts.SubmitEnvironmentSection(ctx, SubmitSectionV2Input{BuildID: id, ActorID: owner.ID, ActorRoles: owner.Roles, ActorIP: "127.0.0.1", RequestSignature: &signature, RequestSignatureHash: &signatureHash, Plaintext: env, CertificatePEM: cert})
	if e != nil {
		t.Fatal(e)
	}
	plaintext := flowDecrypt(t, runtimeKey, section.EncryptedPayload)
	parsed, e := validation.ValidateForProfile(plaintext, "env", "ccrv")
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"logging", "env", "auths", "volumes", "uv-secrets", "host-attestation", "signingKey"} {
		if parsed[field] == nil {
			t.Fatalf("environment field lost: %s", field)
		}
	}
	if strings.Contains(plaintext, "dummy password") {
		t.Fatal("catalog plaintext reached environment")
	}
	var prepared secretflow.Result
	if e = json.Unmarshal(f.PreparedPayload, &prepared); e != nil {
		t.Fatal(e)
	}
	variables := parsed["env"].(map[string]any)
	if variables["APP_MODE"] != "test" {
		t.Fatal("existing environment variable changed")
	}
	for _, artifact := range prepared.Artifacts {
		if variables[artifact.Name+"_SECRET_ID"] != artifact.SecretID {
			t.Fatalf("approved UV reference missing from environment: %s", artifact.Name)
		}
	}
	if _, _, e = keys.RegisterAttestationKey(ctx, id, auditor.ID, model.BuildKeyModeGenerate, nil, &passphrase, &cert, "127.0.0.1", auditor.Roles, &signature, &signatureHash); e != nil {
		t.Fatal(e)
	}
	if _, e = contracts.FinalizeContract(ctx, FinalizeContractV2Input{BuildID: id, ActorID: auditor.ID, ActorRoles: auditor.Roles, ActorIP: "127.0.0.1", SigningKeyPassphrase: passphrase, RequestSignature: &signature, RequestSignatureHash: &signatureHash}); e != nil {
		t.Fatal(e)
	}
	build, e := q.GetBuildByID(ctx, id)
	if e != nil || build.ContractYaml == nil || build.Status != "FINALIZED" {
		t.Fatalf("final contract missing: %v", e)
	}
	var contract map[string]any
	if yaml.Unmarshal([]byte(*build.ContractYaml), &contract) != nil {
		t.Fatal("invalid final contract")
	}
	if contract["env"] != section.EncryptedPayload {
		t.Fatal("final contract changed the approved environment")
	}
	decryptedWorkload := flowDecrypt(t, runtimeKey, contract["workload"].(string))
	for _, artifact := range prepared.Artifacts {
		if strings.Contains(decryptedWorkload, artifact.SecretID) || strings.Contains(decryptedWorkload, artifact.Name+"_SECRET_ID") {
			t.Fatal("generated secret configuration reached the workload section")
		}
	}
	// A key revocation after preparation must block any later reuse/finalization.
	if _, e = pool.Exec(ctx, "UPDATE user_public_keys SET revoked_at=now() WHERE user_id=$1", owner.ID); e != nil {
		t.Fatal(e)
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, _, e = validatePrepared(ctx, repository.New(tx), id); e == nil {
		t.Fatal("revoked approval accepted")
	}
	t.Log("PASS personal encrypted imports → pinned group → target review → signed owner approval → actual IBM requests → stable UV IDs → frozen workload → environment injection preserving existing fields → final signed encrypted contract; role isolation and revocation enforced. No native UV Add/Retrieve claimed.")
}
func flowDecrypt(t *testing.T, key *rsa.PrivateKey, value string) string {
	t.Helper()
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected encrypted section format: %d components", len(parts))
	}
	enc := base64.StdEncoding
	wrapped, e := enc.DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	password, e := rsa.DecryptPKCS1v15(rand.Reader, key, wrapped)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(password)
	blob, e := enc.DecodeString(parts[2])
	if e != nil {
		t.Fatal(e)
	}
	if len(blob) < 32 || !bytes.HasPrefix(blob, []byte("Salted__")) {
		t.Fatal("unexpected AES envelope")
	}
	material := pbkdf2.Key(password, blob[8:16], 10000, 48, sha256.New)
	defer clear(material)
	block, e := aes.NewCipher(material[:32])
	if e != nil {
		t.Fatal(e)
	}
	ciphertext := blob[16:]
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, material[32:]).CryptBlocks(plain, ciphertext)
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > 16 {
		t.Fatal("invalid CBC padding")
	}
	return string(plain[:len(plain)-padding])
}
