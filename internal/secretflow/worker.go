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
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	hpcontract "github.com/ibm-hyper-protect/contract-go/v3/contract"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretstore"
)

type TargetEvidence struct {
	Mode           string    `json:"mode"`
	HKDTrust       string    `json:"hkd_trust"`
	HeaderDigest   string    `json:"header_digest"`
	HardwareStatus string    `json:"hardware_status"`
	VerifiedAt     time.Time `json:"verified_at"`
}
type Item struct {
	OwnerID  uuid.UUID            `json:"owner_id"`
	Binding  Binding              `json:"binding"`
	Envelope secretstore.Envelope `json:"envelope"`
	Proof    Proof                `json:"proof"`
}
type Job struct {
	BuildID          uuid.UUID `json:"build_id"`
	TargetRevisionID uuid.UUID `json:"target_revision_id"`
	Target           Target    `json:"target"`
	TargetApproval   Proof     `json:"target_approval"`
	Items            []Item    `json:"items"`
	Digest           string    `json:"digest"`
}

func (j Job) Hash() string { j.Digest = ""; return Digest(j) }

type Artifact struct {
	Name          string `json:"name"`
	Consumer      string `json:"consumer"`
	Kind          string `json:"kind"`
	Type          string `json:"type"`
	SecretID      string `json:"secret_id"`
	RequestSHA256 string `json:"request_sha256"`
	Data          []byte `json:"data"`
	Certificate   []byte `json:"certificate,omitempty"`
}
type Result struct {
	Digest    string         `json:"digest"`
	Mode      string         `json:"mode"`
	Evidence  TargetEvidence `json:"evidence"`
	Artifacts []Artifact     `json:"artifacts"`
}
type Processor interface {
	ValidateTarget(context.Context, Target) (TargetEvidence, error)
	Prepare(context.Context, Job) (Result, error)
}

type Tool struct {
	Binary             string
	Certificates       []string
	RootCA             string
	CRLs               []string
	SigningKey         string
	SigningCertificate []byte
	AllowSimulation    bool
	AllowInGuest       bool
	TempDir            string
	Key                *rsa.PrivateKey
}

// boundedOutput discards excess diagnostics without returning them to callers.
type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < b.limit {
		end := b.limit - b.Len()
		if end > len(p) {
			end = len(p)
		}
		b.Buffer.Write(p[:end])
	}
	return n, nil
}
func (t *Tool) execute(ctx context.Context, dir string, stdin []byte, args ...string) error {
	if t.Binary == "" {
		return Fail("PVSECRET_UNAVAILABLE", "The trusted worker has no configured pvsecret executable.")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, t.Binary, args...)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(stdin)
	stdout, stderr := &boundedOutput{limit: 4096}, &boundedOutput{limit: 8192}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Fail("PVSECRET_TIMEOUT", "Secret preparation exceeded its execution limit.")
		}
		var ee *exec.Error
		if errors.As(err, &ee) {
			return Fail("PVSECRET_UNAVAILABLE", "Install a compatible pvsecret binary on the trusted worker.")
		}
		return Fail("PVSECRET_REQUEST_REJECTED", "pvsecret rejected the target, trust chain, request format or secret type. Check the public target artifacts and worker configuration; raw diagnostics are withheld.")
	}
	return nil
}
func (t *Tool) configuration(target Target) error {
	if err := target.Validate(); err != nil {
		return err
	}
	if target.Mode == "SIMULATION" {
		if !t.AllowSimulation {
			return Fail("SECRET_SIMULATION_DISABLED", "This worker is not configured to allow development simulation.")
		}
		return nil
	}
	if len(t.Certificates) == 0 || t.SigningKey == "" || len(t.SigningCertificate) == 0 {
		return Fail("SECRET_NATIVE_WORKER_UNCONFIGURED", "Configure trusted host-signing certificates and a request-signing key/certificate on the worker before native preparation.")
	}
	c, e := Certificates(t.SigningCertificate)
	if e != nil || len(c) != 1 || time.Now().Before(c[0].NotBefore) || time.Now().After(c[0].NotAfter) {
		return Fail("SECRET_REQUEST_CERT_INVALID", "The worker request-signing certificate is invalid or expired.")
	}
	stat, e := os.Lstat(t.SigningKey)
	if e != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 {
		return Fail("SECRET_REQUEST_KEY_UNSAFE", "The request-signing key must be a private regular file accessible only to its worker owner.")
	}
	return nil
}
func writePublic(dir, name string, data []byte) (string, error) {
	p := filepath.Join(dir, name)
	return p, os.WriteFile(p, data, 0600)
}
func (t *Tool) create(ctx context.Context, target Target, kind, typ, name string, value []byte) (Artifact, error) {
	if err := t.configuration(target); err != nil {
		return Artifact{}, err
	}
	dir, e := os.MkdirTemp(t.TempDir, "secret-request-")
	if e != nil {
		return Artifact{}, Fail("SECRET_WORKER_STORAGE", "Private temporary workspace is unavailable.")
	}
	defer os.RemoveAll(dir)
	header, e := writePublic(dir, "image.hdr", target.Header)
	if e != nil {
		return Artifact{}, e
	}
	output := filepath.Join(dir, "request.bin")
	args := []string{"create", "--offline", "--hdr", header, "--output", output}
	for i, h := range target.Hosts {
		path, e := writePublic(dir, "host-"+strings.Repeat("x", i+1)+".crt", h.Data)
		if e != nil {
			return Artifact{}, e
		}
		args = append(args, "--host-key-document", path)
	}
	if target.Mode == "SIMULATION" {
		args = append(args, "--no-verify")
	} else {
		for _, c := range t.Certificates {
			args = append(args, "--cert", c)
		}
		for _, c := range t.CRLs {
			args = append(args, "--crl", c)
		}
		if t.RootCA != "" {
			args = append(args, "--root-ca", t.RootCA)
		}
	}
	if t.AllowInGuest {
		args = append(args, "--force")
	}
	cert := []byte(nil)
	if t.SigningKey != "" && len(t.SigningCertificate) > 0 {
		args = append(args, "--user-sign-key", t.SigningKey)
		cert = t.SigningCertificate
	}
	// The value is supplied on stdin, never in argv, logs or a plaintext file.
	if kind == "association" {
		args = append(args, "association", name, "--stdout", "--input-secret", "/dev/stdin")
	} else {
		args = append(args, "retrievable", name, "--stdout", "--type", typ, "--secret", "/dev/stdin")
	}
	if err := t.execute(ctx, dir, value, args...); err != nil {
		return Artifact{}, err
	}
	file, e := os.Open(output)
	if e != nil {
		return Artifact{}, Fail("SECRET_REQUEST_INVALID", "The worker did not produce a request.")
	}
	defer file.Close()
	data, e := io.ReadAll(io.LimitReader(file, 256*1024+1))
	if e != nil || len(data) > 256*1024 {
		return Artifact{}, Fail("SECRET_REQUEST_INVALID", "The generated request exceeds the allowed size.")
	}
	verify := []string{"verify", "--input", output, "--output", filepath.Join(dir, "verified-user-data")}
	if len(cert) > 0 {
		certPath, e := writePublic(dir, "request-signing.crt", cert)
		if e != nil {
			return Artifact{}, e
		}
		verify = append(verify, "--user-cert", certPath)
	}
	if err := t.execute(ctx, dir, nil, verify...); err != nil {
		return Artifact{}, err
	}
	info, e := hpcontract.InspectPreparedSecretRequest(data)
	if e != nil {
		return Artifact{}, Fail("SECRET_REQUEST_INVALID", "The generated request has no valid listable secret ID.")
	}
	if info.SecretID != "0x"+Hash([]byte(name)) || !MatchesUVType(kind, typ, info.SecretType) {
		return Artifact{}, Fail("SECRET_REQUEST_INVALID", "The generated ID or UV type does not match the approved binding.")
	}
	return Artifact{Kind: kind, Type: typ, SecretID: info.SecretID, RequestSHA256: info.RequestSHA256, Data: data, Certificate: cert}, nil
}
func (t *Tool) ValidateTarget(ctx context.Context, target Target) (TargetEvidence, error) {
	// A throwaway local request validates parsing and the actual IBM trust path;
	// no request is added to a UV store and no hardware acceptance is implied.
	if _, e := t.create(ctx, target, "association", "association", "target-validation", make([]byte, 32)); e != nil {
		return TargetEvidence{}, e
	}
	trust := "IBM_TOOL_VERIFIED"
	if target.Mode == "SIMULATION" {
		trust = "UNVERIFIED_DEVELOPMENT_ONLY"
	}
	return TargetEvidence{Mode: target.Mode, HKDTrust: trust, HeaderDigest: target.HeaderSHA256, HardwareStatus: "NOT_TESTED_ON_TARGET", VerifiedAt: time.Now().UTC()}, nil
}
func (j Job) Validate() error {
	if j.BuildID == uuid.Nil || j.TargetRevisionID == uuid.Nil || j.Digest != j.Hash() || len(j.Items) < 1 || len(j.Items) > MaxRequests {
		return Fail("SECRET_JOB_INVALID", "The approved preparation manifest is invalid or changed.")
	}
	if err := j.TargetApproval.Verify(); err != nil {
		return err
	}
	var ta struct {
		TargetRevisionID          uuid.UUID `json:"target_revision_id"`
		TargetDigest              string    `json:"target_digest"`
		HeaderProvenanceConfirmed bool      `json:"header_provenance_confirmed"`
	}
	if json.Unmarshal(j.TargetApproval.Body, &ta) != nil || ta.TargetRevisionID != j.TargetRevisionID || ta.TargetDigest != Digest(j.Target) || !ta.HeaderProvenanceConfirmed || j.TargetApproval.Path != "/builds/"+j.BuildID.String()+"/secret-flow/target-approval" {
		return Fail("SECRET_TARGET_APPROVAL_INVALID", "The auditor approval does not cover this exact target and image provenance.")
	}
	rs := make([]Requirement, 0, len(j.Items))
	versions := map[uuid.UUID]bool{}
	for _, item := range j.Items {
		if err := item.Proof.Verify(); err != nil {
			return err
		}
		var approval Approval
		if json.Unmarshal(item.Proof.Body, &approval) != nil || approval.TargetRevisionID != j.TargetRevisionID || approval.TargetDigest != Digest(j.Target) || item.Proof.SignerID != item.OwnerID || item.Proof.Path != "/builds/"+j.BuildID.String()+"/secret-flow/approvals" {
			return Fail("SECRET_APPROVAL_INVALID", "Owner approval does not cover this deployment target.")
		}
		matched := false
		for _, b := range approval.Sources {
			if b == item.Binding {
				matched = true
			}
		}
		if !matched || item.Binding.VersionID != item.Envelope.VersionID || versions[item.Binding.VersionID] {
			return Fail("SECRET_APPROVAL_INVALID", "The selected version, type or consumer is not covered by its owner approval.")
		}
		versions[item.Binding.VersionID] = true
		rs = append(rs, item.Binding.Requirement())
	}
	return j.Target.CheckRequirements(rs)
}
func (t *Tool) Prepare(ctx context.Context, j Job) (Result, error) {
	if err := j.Validate(); err != nil {
		return Result{}, err
	}
	evidence, e := t.ValidateTarget(ctx, j.Target)
	if e != nil {
		return Result{}, e
	}
	out := Result{Digest: j.Digest, Mode: j.Target.Mode, Evidence: evidence, Artifacts: []Artifact{}}
	ids := map[string]bool{}
	for _, item := range j.Items {
		var a Artifact
		e = secretstore.WithPlaintext(item.Envelope, t.Key, func(value []byte) error {
			if item.Binding.Kind == "association" && len(value) != 32 {
				return Fail("SECRET_VALUE_INVALID", "An Association secret must contain exactly 32 bytes.")
			}
			if item.Binding.Type == "plain" && len(value) > 8190 {
				return Fail("SECRET_VALUE_INVALID", "Retrievable plain secrets may contain at most 8190 bytes; values are never truncated.")
			}
			var err error
			a, err = t.create(ctx, j.Target, item.Binding.Kind, item.Binding.Type, RequestName(j, item.Binding), value)
			return err
		})
		if e != nil {
			return Result{}, e
		}
		if ids[a.SecretID] {
			return Result{}, Fail("SECRET_ID_DUPLICATE", "The generated manifest contains a duplicate UV secret ID.")
		}
		ids[a.SecretID] = true
		a.Name = item.Binding.Name
		a.Consumer = item.Binding.Consumer
		out.Artifacts = append(out.Artifacts, a)
	}
	return out, nil
}

// RequestName binds the actual UV ID to the exact intended target and consumer.
// Renewing an identical signed approval keeps the ID stable; changing target,
// consumer or type creates a different ID even when the catalog version is equal.
func RequestName(j Job, b Binding) string {
	scope := struct {
		Target      string
		Requirement Requirement
	}{Digest(j.Target), b.Requirement()}
	return "cm-" + j.BuildID.String() + "-" + b.VersionID.String() + "-" + Digest(scope)
}
