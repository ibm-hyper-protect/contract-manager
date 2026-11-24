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

// Package secretflow defines purpose-bound, public target manifests and worker jobs.
// Plaintext catalog values are never part of its API responses.
package secretflow

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
)

const MaxRequests = 8

var namePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
var hostPattern = regexp.MustCompile(`^HKD-[0-9]{4}-[A-Za-z0-9]{7,32}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string        { return e.Code + ": " + e.Message }
func Fail(code, message string) error { return &Error{code, message} }
func Digest(v any) string             { raw, _ := json.Marshal(v); return Hash(raw) }
func Hash(data []byte) string         { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

type Host struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Data        []byte `json:"data"`
}
type CapabilityReport struct {
	Add         bool      `json:"add"`
	List        bool      `json:"list"`
	Lock        bool      `json:"lock"`
	Retrieve    bool      `json:"retrieve"`
	SecretTypes []string  `json:"secret_types"`
	RecordedAt  time.Time `json:"recorded_at"`
	Evidence    string    `json:"evidence"`
}
type Target struct {
	Name               string            `json:"name"`
	Platform           string            `json:"platform"`
	RuntimeVersion     string            `json:"runtime_version"`
	ImageDigest        string            `json:"image_digest"`
	ImageSource        string            `json:"image_source"`
	Header             []byte            `json:"header"`
	HeaderSHA256       string            `json:"header_sha256"`
	Hosts              []Host            `json:"hosts"`
	RuntimeCertificate string            `json:"runtime_certificate"`
	Mode               string            `json:"mode"`
	Capabilities       *CapabilityReport `json:"capabilities,omitempty"`
}

func (t Target) Validate() error {
	if len(t.Name) < 1 || len(t.Name) > 100 || len(t.RuntimeVersion) < 1 || len(t.RuntimeVersion) > 80 || len(t.ImageSource) < 1 || len(t.ImageSource) > 1000 {
		return Fail("SECRET_TARGET_INVALID", "Provide a target name, runtime version and trusted runtime-image source.")
	}
	if t.Platform != "ccrv" {
		return Fail("RETRIEVABLE_SECRETS_UNSUPPORTED_PLATFORM", "Prepared secret contracts currently support the CCRV profile only; the manager host is not the target.")
	}
	if t.Mode != "NATIVE" && t.Mode != "SIMULATION" {
		return Fail("SECRET_MODE_REQUIRED", "Choose NATIVE or explicit development SIMULATION.")
	}
	if !digestPattern.MatchString(strings.TrimPrefix(t.ImageDigest, "sha256:")) || !digestPattern.MatchString(t.HeaderSHA256) || Hash(t.Header) != t.HeaderSHA256 {
		return Fail("SECRET_TARGET_DIGEST_MISMATCH", "Runtime image and SE-header SHA-256 values must be explicit; the uploaded header must match its expected digest.")
	}
	if len(t.Header) < 16 || len(t.Header) > 64*1024 || !bytes.Equal(t.Header[:8], []byte("IBMSecEx")) {
		return Fail("SECRET_HEADER_INVALID", "Upload the public SE header from the intended protected runtime image, not a workload container.")
	}
	if len(t.Hosts) < 1 || len(t.Hosts) > 16 {
		return Fail("SECRET_HKD_REQUIRED", "Provide 1–16 explicitly permitted target-machine HKDs.")
	}
	seen := map[string]bool{}
	for _, h := range t.Hosts {
		if !hostPattern.MatchString(h.ID) || seen[h.ID] || len(h.Description) > 200 || len(h.Data) > 64*1024 {
			return Fail("SECRET_HKD_INVALID", "Host identifiers must be unique HKD-MODEL-PLANTSERIAL names and documents must be bounded public certificates.")
		}
		seen[h.ID] = true
		certs, err := Certificates(h.Data)
		if err != nil || len(certs) < 1 || len(certs) > 2 {
			return Fail("SECRET_HKD_INVALID", "Each HKD must contain one certificate or the complete two-certificate hybrid document.")
		}
		if t.Mode == "NATIVE" {
			for _, c := range certs {
				if time.Now().Before(c.NotBefore) || time.Now().After(c.NotAfter) {
					return Fail("SECRET_HKD_EXPIRED", "A target HKD is not currently valid; obtain a current verified document.")
				}
			}
		}
	}
	certs, err := Certificates([]byte(t.RuntimeCertificate))
	if err != nil || len(certs) != 1 {
		return Fail("SECRET_RUNTIME_CERT_INVALID", "Provide the matching runtime contract-encryption certificate.")
	}
	runtimeKey, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok || runtimeKey.N.BitLen() < 2048 || (certs[0].KeyUsage != 0 && certs[0].KeyUsage&x509.KeyUsageKeyEncipherment == 0) {
		return Fail("SECRET_RUNTIME_CERT_INVALID", "The runtime encryption certificate must permit RSA key encipherment with at least 2048 bits; an HKD is not a runtime encryption certificate.")
	}
	if time.Now().Before(certs[0].NotBefore) || time.Now().After(certs[0].NotAfter) {
		return Fail("SECRET_RUNTIME_CERT_EXPIRED", "The runtime encryption certificate is not currently valid.")
	}
	if c := t.Capabilities; c != nil {
		if len(c.Evidence) == 0 || len(c.Evidence) > 4096 || c.RecordedAt.IsZero() || c.RecordedAt.After(time.Now().Add(5*time.Minute)) {
			return Fail("SECRET_CAPABILITY_REPORT_INVALID", "Provide the target report's source and a valid observation time.")
		}
	}
	return nil
}
func Certificates(data []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		c, e := x509.ParseCertificate(data)
		if e != nil {
			return nil, e
		}
		return []*x509.Certificate{c}, nil
	}
	for len(bytes.TrimSpace(data)) > 0 {
		b, rest := pem.Decode(data)
		if b == nil || b.Type != "CERTIFICATE" {
			return nil, errors.New("public certificate required")
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			return nil, e
		}
		certs = append(certs, c)
		data = rest
	}
	return certs, nil
}

type Requirement struct {
	Name     string `json:"name"`
	Consumer string `json:"consumer"`
	Kind     string `json:"kind"`
	Type     string `json:"type"`
}

func (r Requirement) Validate() error {
	if !namePattern.MatchString(r.Name) || len(r.Consumer) < 1 || len(r.Consumer) > 100 || strings.ContainsAny(r.Consumer, "\r\n\x00") {
		return Fail("SECRET_REQUIREMENT_INVALID", "Use an uppercase logical name and an explicit workload consumer.")
	}
	if r.Kind == "association" && r.Type == "association" {
		return nil
	}
	if r.Kind == "retrievable" {
		switch r.Type {
		case "plain", "aes", "aes-xts", "hmac-sha", "ec":
			return nil
		}
	}
	return Fail("SECRET_TYPE_UNSUPPORTED", "Select Association or a supported retrievable plain/AES/AES-XTS/HMAC-SHA/EC type.")
}
func (t Target) CheckRequirements(rs []Requirement) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if len(rs) > MaxRequests {
		return Fail("SECRET_REQUEST_LIMIT", "This runtime contract supports at most eight requests after group expansion.")
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if err := r.Validate(); err != nil {
			return err
		}
		if seen[r.Name] {
			return Fail("SECRET_REQUIREMENT_DUPLICATE", "Logical secret names must be unique.")
		}
		seen[r.Name] = true
		if t.Mode == "NATIVE" && t.Capabilities != nil {
			c := t.Capabilities
			if time.Since(c.RecordedAt) > 7*24*time.Hour || !c.Add || !c.List || !c.Lock || (r.Kind == "retrievable" && !c.Retrieve) {
				return Fail("SECRET_TARGET_UNSUPPORTED", "The supplied target report is stale or reports missing kernel/Ultravisor operations; select a supported target or explicit development simulation.")
			}
			supported := false
			for _, v := range c.SecretTypes {
				if v == r.Type {
					supported = true
				}
			}
			if !supported {
				return Fail("SECRET_TYPE_UNSUPPORTED", "The supplied target report does not support the requested secret type.")
			}
		}
	}
	return nil
}

type Binding struct {
	VersionID       uuid.UUID `json:"version_id"`
	GroupRevisionID uuid.UUID `json:"group_revision_id,omitempty"`
	Name            string    `json:"name"`
	Consumer        string    `json:"consumer"`
	Kind            string    `json:"kind"`
	Type            string    `json:"type"`
}

func (b Binding) Requirement() Requirement { return Requirement{b.Name, b.Consumer, b.Kind, b.Type} }

type Approval struct {
	ExpectedRevision int32     `json:"expected_revision"`
	SourceRevision   int32     `json:"source_revision"`
	TargetRevisionID uuid.UUID `json:"target_revision_id"`
	TargetDigest     string    `json:"target_digest"`
	Sources          []Binding `json:"sources"`
}

// Proof captures the exact request already authenticated by signature middleware.
// The worker verifies its hash, signature and purpose again; the Manager remains
// trusted for the account-to-public-key directory and current authorization.
type Proof struct {
	SignerID    uuid.UUID `json:"signer_id"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	Body        []byte    `json:"body"`
	Timestamp   int64     `json:"timestamp"`
	Hash        string    `json:"hash"`
	Signature   string    `json:"signature"`
}

func (p Proof) Verify() error {
	if p.SignerID == uuid.Nil || p.Method != "PUT" || p.Timestamp <= 0 || len(p.Body) > 128*1024 {
		return Fail("SECRET_APPROVAL_INVALID", "A signed, purpose-bound owner approval is required.")
	}
	fp, e := appcrypto.ComputePublicKeyFingerprint(p.PublicKey)
	if e != nil || fp != p.Fingerprint {
		return Fail("SECRET_APPROVAL_INVALID", "Approval signing-key identity does not match.")
	}
	payload := fmt.Sprintf(`{"method":%q,"path":%q,"data":%s,"timestamp":%d}`, p.Method, p.Path, p.Body, p.Timestamp)
	if Hash([]byte(payload)) != p.Hash || appcrypto.VerifySignature(p.PublicKey, p.Hash, p.Signature) != nil {
		return Fail("SECRET_APPROVAL_INVALID", "Approval request signature could not be verified.")
	}
	return nil
}

// MatchesUVType follows the IBM s390-tools UV secret type constants.
func MatchesUVType(kind, typ string, n uint16) bool {
	if kind == "association" {
		return typ == "association" && n == 2
	}
	if kind != "retrievable" {
		return false
	}
	switch typ {
	case "plain":
		return n == 3
	case "aes":
		return n >= 4 && n <= 6
	case "aes-xts":
		return n == 7 || n == 8
	case "hmac-sha":
		return n == 9 || n == 10
	case "ec":
		return n >= 0x11 && n <= 0x15
	}
	return false
}

func (t Target) Fingerprints() map[string]any {
	out := map[string]any{}
	if cs, e := Certificates([]byte(t.RuntimeCertificate)); e == nil && len(cs) == 1 {
		out["runtime_certificate_sha256"] = Hash(cs[0].Raw)
	}
	hosts := map[string][]string{}
	for _, h := range t.Hosts {
		cs, _ := Certificates(h.Data)
		for _, c := range cs {
			hosts[h.ID] = append(hosts[h.ID], Hash(c.Raw))
		}
	}
	out["host_certificates_sha256"] = hosts
	return out
}
