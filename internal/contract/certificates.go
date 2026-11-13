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

package contract

import (
	"errors"
	"time"
)

// ErrCertificateNotFound identifies an unknown platform/version pair.
var ErrCertificateNotFound = errors.New("runtime certificate not found")

// CertificatePlatform preserves the library's platform-to-version association.
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

// CertificateCatalog adds platform information without removing the legacy flat list.
type CertificateCatalog struct {
	Versions  []string              `json:"versions"`
	Platforms []CertificatePlatform `json:"platforms"`
}

// RuntimeCertificate contains an exact embedded certificate and its public metadata.
type RuntimeCertificate struct {
	Platform          string    `json:"platform"`
	Version           string    `json:"version"`
	CertificatePEM    string    `json:"certificate_pem"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	ContractSupported bool      `json:"contract_supported"`
}
