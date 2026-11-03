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
	"errors"
	"fmt"
	"strings"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract"
	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

// ListEncryptionCertificates preserves platform membership and the legacy versions field.
func (s *ContractService) ListEncryptionCertificates(ctx context.Context) (*contract.CertificateCatalog, error) {
	catalog, err := s.engine.ListEncryptionCertificates(ctx)
	if err != nil {
		return nil, fmt.Errorf("list runtime certificates: %w", err)
	}
	return catalog, nil
}

// GetEncryptionCertificate validates an exact library certificate before it reaches the client.
func (s *ContractService) GetEncryptionCertificate(ctx context.Context, platform, version string) (*contract.RuntimeCertificate, error) {
	platform = strings.ToLower(strings.TrimSpace(platform))
	version = strings.TrimSpace(version)
	if platform == "" || version == "" {
		return nil, model.ErrInvalidRequest("platform and version are required")
	}
	cert, err := s.engine.GetEncryptionCertificate(ctx, platform, version)
	if errors.Is(err, contract.ErrCertificateNotFound) {
		return nil, model.ErrNotFound("no encryption certificate exists for this platform and version")
	}
	if err != nil {
		return nil, fmt.Errorf("load runtime certificate: %w", err)
	}
	if err := validation.EncryptionCertificate(cert.CertificatePEM); err != nil {
		return nil, model.ErrInvalidCertificate("selected runtime certificate is unusable: " + err.Error())
	}
	return cert, nil
}
