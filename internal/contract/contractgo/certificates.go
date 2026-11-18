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

package contractgo

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"

	hpcertificate "github.com/ibm-hyper-protect/contract-go/v3/certificate"
	hpencryption "github.com/ibm-hyper-protect/contract-go/v3/encryption"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract"
)

type CertificateRelease struct {
	Mod      string   `json:"mod"`
	Fixpacks []string `json:"fixpacks"`
}
type CertificatePlatform struct {
	ID                string               `json:"id"`
	Versions          []string             `json:"versions,omitempty"`
	Releases          []CertificateRelease `json:"releases,omitempty"`
	ContractSupported bool                 `json:"contract_supported"`
}

// ListEncryptionCertificates returns deterministic platform/version data from the pinned library.
func (e *Engine) ListEncryptionCertificates(ctx context.Context) (*contract.CertificateCatalog, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := hpcertificate.HpcrListAvailableEncCertVersions("", "json")
	if err != nil {
		return nil, fmt.Errorf("list runtime certificates: %w", err)
	}
	var platforms map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &platforms); err != nil {
		return nil, fmt.Errorf("decode runtime certificate catalog: %w", err)
	}
	result := &contract.CertificateCatalog{Versions: []string{}, Platforms: []contract.CertificatePlatform{}}
	unique := make(map[string]bool)
	for id, rawVersions := range platforms {
		versions, releases, err := parseVersions(rawVersions)
		if err != nil {
			return nil, fmt.Errorf("decode %s versions: %w", id, err)
		}
		sortVersions(versions)
		result.Platforms = append(result.Platforms, contract.CertificatePlatform{ID: id, Versions: versions, Releases: releases, ContractSupported: supportsContract(id)})
		for _, version := range versions {
			unique[version] = true
		}
	}
	sort.Slice(result.Platforms, func(i, j int) bool { return result.Platforms[i].ID < result.Platforms[j].ID })
	for version := range unique {
		result.Versions = append(result.Versions, version)
	}
	sortVersions(result.Versions)
	return result, nil
}
func parseVersions(raw json.RawMessage) ([]string, []contract.CertificateRelease, error) {
	var plain []string
	if json.Unmarshal(raw, &plain) == nil {
		return plain, nil, nil
	}
	var releases []contract.CertificateRelease
	if err := json.Unmarshal(raw, &releases); err != nil {
		return nil, nil, err
	}
	var versions []string
	for i := range releases {
		if releases[i].Fixpacks == nil {
			releases[i].Fixpacks = []string{}
		}
		sortVersions(releases[i].Fixpacks)
		versions = append(versions, releases[i].Mod)
		versions = append(versions, releases[i].Fixpacks...)
	}
	sort.Slice(releases, func(i, j int) bool {
		return hpencryption.CompareVersions(releases[i].Mod, releases[j].Mod) > 0
	})
	return versions, releases, nil
}

func sortVersions(versions []string) {
	sort.Slice(versions, func(i, j int) bool { return hpencryption.CompareVersions(versions[i], versions[j]) > 0 })
}

// GetEncryptionCertificate reads an exact embedded certificate; it never downloads arbitrary URLs.
func (e *Engine) GetEncryptionCertificate(ctx context.Context, platform, version string) (*contract.RuntimeCertificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	text, ok := hpencryption.CertificateMap[platform][version]
	if !ok {
		return nil, contract.ErrCertificateNotFound
	}
	block, rest := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("invalid embedded runtime certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse embedded runtime certificate: %w", err)
	}
	digest := sha256.Sum256(cert.Raw)
	return &contract.RuntimeCertificate{
		Platform: platform, Version: version, CertificatePEM: text,
		FingerprintSHA256: hex.EncodeToString(digest[:]),
		NotBefore:         cert.NotBefore, NotAfter: cert.NotAfter,
		ContractSupported: supportsContract(platform),
	}, nil
}

// contract-go v3 uses the CCRT schema for both CCRT and legacy HPVS.
// CCRV/CCCO have different schemas and remain unavailable in this workflow.
func supportsContract(platform string) bool {
	return platform == hpencryption.OsTypeCcrt || platform == hpencryption.OsTypeHpvs
}

// Identify HPVS by the certificate DER, including custom uploads of the exact
// same certificate. Display labels and PEM whitespace cannot change the format.
func encryptionPrefix(certificate *x509.Certificate) string {
	for _, text := range hpencryption.CertificateMap[hpencryption.OsTypeHpvs] {
		block, _ := pem.Decode([]byte(text))
		if block != nil && certificate.Equal(&x509.Certificate{Raw: block.Bytes}) {
			return "hyper-protect-basic."
		}
	}
	return "contract-basic."
}
