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

package secretflow

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/secretstore"
)

func testTarget(t *testing.T) Target {
	t.Helper()
	hdr, e := os.ReadFile("testdata/runtime.hdr")
	if e != nil {
		t.Fatal(e)
	}
	h, e := os.ReadFile("testdata/host.crt")
	if e != nil {
		t.Fatal(e)
	}
	runtimeKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "simulation runtime"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &runtimeKey.PublicKey, runtimeKey)
	if e != nil {
		t.Fatal(e)
	}
	runtimeCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return Target{Name: "Separate deployment machine", Platform: "ccrv", RuntimeVersion: "1.1.0", ImageSource: "https://runtime.example.test/image", ImageDigest: Hash([]byte("runtime-image")), Header: hdr, HeaderSHA256: Hash(hdr), Hosts: []Host{{ID: "HKD-9175-0271A28", Description: "Development fixture only", Data: h}}, RuntimeCertificate: string(runtimeCert), Mode: "SIMULATION"}
}
func testProof(t *testing.T, key *rsa.PrivateKey, user uuid.UUID, path string, body any) Proof {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	data, _ := json.Marshal(body)
	p := Proof{SignerID: user, PublicKey: public, Fingerprint: Hash(der), Method: "PUT", Path: path, Body: data, Timestamp: time.Now().UnixMilli()}
	payload := fmt.Sprintf(`{"method":%q,"path":%q,"data":%s,"timestamp":%d}`, p.Method, p.Path, p.Body, p.Timestamp)
	p.Hash = Hash([]byte(payload))
	digest := sha256.Sum256([]byte(p.Hash))
	signature, e := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if e != nil {
		t.Fatal(e)
	}
	p.Signature = base64.StdEncoding.EncodeToString(signature)
	return p
}
func testJob(t *testing.T) (Job, *rsa.PrivateKey) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 4096)
	if e != nil {
		t.Fatal(e)
	}
	target := testTarget(t)
	id, rid, owner := uuid.New(), uuid.New(), uuid.New()
	b := Binding{VersionID: uuid.New(), Name: "DATABASE_PASSWORD", Kind: "retrievable", Type: "plain", Consumer: "api"}
	info, _ := secretstore.PublicKeyInfo(&key.PublicKey)
	secretID := uuid.New()
	dek := make([]byte, 32)
	rand.Read(dek)
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	data := gcm.Seal(nil, nonce, []byte(" \x00\xff dummy value\n "), secretstore.Context(secretID, b.VersionID))
	wrapped, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, dek, nil)
	enc := base64.StdEncoding.EncodeToString
	envelope := secretstore.Envelope{Format: 1, SecretID: secretID, VersionID: b.VersionID, KeyID: info.KeyID, WrappedKey: enc(wrapped), Nonce: enc(nonce), Ciphertext: enc(data[:len(data)-16]), Tag: enc(data[len(data)-16:])}
	j := Job{BuildID: id, TargetRevisionID: rid, Target: target}
	j.TargetApproval = testProof(t, key, uuid.New(), "/builds/"+id.String()+"/secret-flow/target-approval", map[string]any{"target_revision_id": rid, "target_digest": Digest(target), "header_provenance_confirmed": true})
	j.Items = []Item{{OwnerID: owner, Binding: b, Envelope: envelope, Proof: testProof(t, key, owner, "/builds/"+id.String()+"/secret-flow/approvals", Approval{TargetRevisionID: rid, TargetDigest: Digest(target), Sources: []Binding{b}})}}
	j.Digest = j.Hash()
	return j, key
}
func TestPurposeBoundApprovals(t *testing.T) {
	j, _ := testJob(t)
	if e := j.Validate(); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*Job){"different build": func(j *Job) { j.BuildID = uuid.New() }, "different target": func(j *Job) { j.Target.ImageDigest = Hash([]byte("other image")) }, "different version": func(j *Job) { j.Items[0].Binding.VersionID = uuid.New() }, "different consumer": func(j *Job) { j.Items[0].Binding.Consumer = "another consumer" }, "different kind": func(j *Job) { j.Items[0].Binding.Kind = "association" }, "wrong owner": func(j *Job) { j.Items[0].OwnerID = uuid.New() }, "changed signature": func(j *Job) { j.Items[0].Proof.Signature = "bad" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var changed Job
			raw, _ := json.Marshal(j)
			json.Unmarshal(raw, &changed)
			mutate(&changed)
			changed.Digest = changed.Hash()
			if changed.Validate() == nil {
				t.Fatal("unapproved change accepted")
			}
		})
	}
	// JSONB and worker HTTP must preserve the exact bytes of signed JSON, including whitespace.
	p := j.Items[0].Proof
	raw, _ := json.Marshal(p)
	var roundTrip Proof
	json.Unmarshal(raw, &roundTrip)
	if e := roundTrip.Verify(); e != nil {
		t.Fatal(e)
	}
}
func TestTargetSafety(t *testing.T) {
	target := testTarget(t)
	if e := target.Validate(); e != nil {
		t.Fatal(e)
	}
	bad := target
	bad.HeaderSHA256 = Hash([]byte("different"))
	if bad.Validate() == nil {
		t.Fatal("header mismatch accepted")
	}
	bad = target
	bad.Platform = "ccrt"
	if bad.Validate() == nil {
		t.Fatal("unsupported profile accepted")
	}
	bad = target
	bad.Mode = "AUTO"
	if bad.Validate() == nil {
		t.Fatal("automatic fallback accepted")
	}
	if _, e := (&Tool{}).ValidateTarget(context.Background(), target); e == nil {
		t.Fatal("simulation did not require opt-in")
	}
	// Use a currently valid local certificate solely to test capability gating, never IBM trust.
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	cert, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, &k.PublicKey, k)
	target.Mode = "NATIVE"
	target.Hosts[0].Data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	target.RuntimeCertificate = string(target.Hosts[0].Data)
	target.Capabilities = &CapabilityReport{Add: true, List: true, Lock: true, Retrieve: false, SecretTypes: []string{"association"}, RecordedAt: now, Evidence: "Recorded isolated Z16 probe"}
	e := target.CheckRequirements([]Requirement{{Name: "PASSWORD", Consumer: "api", Kind: "retrievable", Type: "plain"}})
	typed, ok := e.(*Error)
	if !ok || typed.Code != "SECRET_TARGET_UNSUPPORTED" {
		t.Fatalf("missing retrieve not rejected: %v", e)
	}
	if e = target.CheckRequirements([]Requirement{{Name: "RESOURCE", Consumer: "crypto", Kind: "association", Type: "association"}}); e != nil {
		t.Fatal(e)
	}
}
func TestIBMRequestCreation(t *testing.T) {
	binary := os.Getenv("PVSECRET_TEST_BINARY")
	if binary == "" {
		t.Skip("set PVSECRET_TEST_BINARY for actual IBM pvsecret interoperability")
	}
	j, key := testJob(t)
	tool := &Tool{Binary: binary, Key: key, AllowSimulation: true, TempDir: t.TempDir()}
	result, e := tool.Prepare(context.Background(), j)
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Artifacts) != 1 || len(result.Artifacts[0].SecretID) != 66 || result.Evidence.HardwareStatus != "NOT_TESTED_ON_TARGET" {
		t.Fatal("incorrect public artifact or evidence")
	}
	files, _ := os.ReadDir(tool.TempDir)
	if len(files) != 0 {
		t.Fatal("temporary preparation files left behind")
	}
	// A second invalid item must not publish a partial manifest.
	invalid := j.Items[0]
	invalid.Binding.Name = "OTHER"
	invalid.Binding.VersionID = uuid.New()
	j.Items = append(j.Items, invalid)
	j.Digest = j.Hash()
	if out, e := tool.Prepare(context.Background(), j); e == nil || len(out.Artifacts) != 0 {
		t.Fatal("partial manifest published")
	}
}

func TestRealIBMTypeMatrix(t *testing.T) {
	binary := os.Getenv("PVSECRET_TEST_BINARY")
	if binary == "" {
		t.Skip("set PVSECRET_TEST_BINARY for actual IBM type matrix")
	}
	target := testTarget(t)
	tool := Tool{Binary: binary, AllowSimulation: true, TempDir: t.TempDir()}
	for _, tc := range []struct {
		kind, typ string
		size      int
	}{{"association", "association", 32}, {"retrievable", "plain", 0}, {"retrievable", "plain", 8190}, {"retrievable", "aes", 16}, {"retrievable", "aes", 24}, {"retrievable", "aes", 32}, {"retrievable", "aes-xts", 32}, {"retrievable", "aes-xts", 64}, {"retrievable", "hmac-sha", 64}, {"retrievable", "hmac-sha", 128}} {
		t.Run(fmt.Sprintf("%s/%d", tc.typ, tc.size), func(t *testing.T) {
			artifact, e := tool.create(context.Background(), target, tc.kind, tc.typ, "matrix-"+tc.typ+fmt.Sprint(tc.size), make([]byte, tc.size))
			if e != nil {
				t.Fatal(e)
			}
			if artifact.SecretID != "0x"+Hash([]byte("matrix-"+tc.typ+fmt.Sprint(tc.size))) {
				t.Fatal("incorrect real ID")
			}
		})
	}
	for _, tc := range []struct {
		typ  string
		size int
	}{{"plain", 8191}, {"aes", 17}, {"aes-xts", 33}, {"hmac-sha", 65}} {
		if _, e := tool.create(context.Background(), target, "retrievable", tc.typ, "invalid-value", make([]byte, tc.size)); e == nil {
			t.Fatalf("invalid %s size %d accepted", tc.typ, tc.size)
		}
	}
}

func TestUVNameScopeAndRetryStability(t *testing.T) {
	j := Job{BuildID: uuid.New(), Target: Target{Name: "Original target"}}
	b := Binding{VersionID: uuid.New(), Name: "PASSWORD", Consumer: "api", Kind: "retrievable", Type: "plain"}
	original := RequestName(j, b)
	if original != RequestName(j, b) {
		t.Fatal("unchanged intent changed ID")
	}
	other := j
	other.Target.Name = "Another approved target"
	if RequestName(other, b) == original {
		t.Fatal("target change retained old ID")
	}
	changed := b
	changed.Consumer = "another workload"
	if RequestName(j, changed) == original {
		t.Fatal("consumer change retained old ID")
	}
	changed = b
	changed.Type = "aes"
	if RequestName(j, changed) == original {
		t.Fatal("secret type change retained old ID")
	}
}

func TestRealIBMEllipticSecretTypes(t *testing.T) {
	binary := os.Getenv("PVSECRET_TEST_BINARY")
	if binary == "" {
		t.Skip("set PVSECRET_TEST_BINARY for elliptic-curve interoperability")
	}
	target := testTarget(t)
	tool := Tool{Binary: binary, AllowSimulation: true, TempDir: t.TempDir()}
	keys := map[string]any{}
	for name, curve := range map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384(), "p521": elliptic.P521()} {
		key, e := ecdsa.GenerateKey(curve, rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		keys[name] = key
	}
	_, ed, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	keys["ed25519"] = ed
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			der, e := x509.MarshalPKCS8PrivateKey(key)
			if e != nil {
				t.Fatal(e)
			}
			value := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			defer clear(value)
			if _, e = tool.create(context.Background(), target, "retrievable", "ec", "ec-"+name, value); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestNativeExpiredHKDIsNeverAccepted(t *testing.T) {
	target := testTarget(t)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	expired := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "expired diagnostic HKD"}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, expired, expired, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	target.Hosts[0].Data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	target.Mode = "NATIVE"
	err := target.Validate()
	typed, ok := err.(*Error)
	if !ok || typed.Code != "SECRET_HKD_EXPIRED" {
		t.Fatalf("expired native HKD not rejected clearly: %v", err)
	}
	target.Mode = "SIMULATION"
	if e = target.Validate(); e != nil {
		t.Fatalf("explicit development simulation could not use diagnostic HKD: %v", e)
	}
}
func TestRealWorkerGroupFailurePublishesNothing(t *testing.T) {
	binary := os.Getenv("PVSECRET_TEST_BINARY")
	if binary == "" {
		t.Skip("set PVSECRET_TEST_BINARY for real all-or-nothing preparation")
	}
	j, key := testJob(t)
	second := j.Items[0]
	second.Binding.Name = "INVALID_AES"
	second.Binding.Type = "aes"
	second.Binding.VersionID = uuid.New()
	second.Envelope = testEnvelopeForJob(t, key, second.Binding.VersionID, make([]byte, 17))
	j.Items = append(j.Items, second)
	sources := []Binding{j.Items[0].Binding, second.Binding}
	proof := testProof(t, key, second.OwnerID, "/builds/"+j.BuildID.String()+"/secret-flow/approvals", Approval{TargetRevisionID: j.TargetRevisionID, TargetDigest: Digest(j.Target), Sources: sources})
	for i := range j.Items {
		j.Items[i].Proof = proof
	}
	j.Digest = j.Hash()
	if e := j.Validate(); e != nil {
		t.Fatal(e)
	}
	tool := Tool{Binary: binary, Key: key, AllowSimulation: true, TempDir: t.TempDir()}
	out, e := tool.Prepare(context.Background(), j)
	if e == nil || len(out.Artifacts) != 0 || out.Digest != "" {
		t.Fatal("partially successful group escaped the worker")
	}
	files, _ := os.ReadDir(tool.TempDir)
	if len(files) != 0 {
		t.Fatal("private request workspaces remained after failure")
	}
}
func testEnvelopeForJob(t *testing.T, key *rsa.PrivateKey, version uuid.UUID, value []byte) secretstore.Envelope {
	t.Helper()
	id := uuid.New()
	info, _ := secretstore.PublicKeyInfo(&key.PublicKey)
	dek := make([]byte, 32)
	rand.Read(dek)
	defer clear(dek)
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	data := gcm.Seal(nil, nonce, value, secretstore.Context(id, version))
	wrapped, e := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, dek, nil)
	if e != nil {
		t.Fatal(e)
	}
	enc := base64.StdEncoding.EncodeToString
	return secretstore.Envelope{Format: 1, SecretID: id, VersionID: version, KeyID: info.KeyID, WrappedKey: enc(wrapped), Nonce: enc(nonce), Ciphertext: enc(data[:len(data)-16]), Tag: enc(data[len(data)-16:])}
}
