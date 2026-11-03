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
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// Pin atomically to prevent different personas encrypting the same contract for
// different runtime keys. Existing contracts pin on their next submission.
func pinBuildEncryptionCertificate(ctx context.Context, queries repository.Querier, buildID uuid.UUID, certificate string, status model.BuildStatus) error {
	if err := validation.EncryptionCertificate(certificate); err != nil {
		return model.ErrInvalidCertificate(err.Error())
	}
	block, _ := pem.Decode([]byte(certificate))
	canonical := string(pem.EncodeToMemory(block))
	rows, err := queries.EnsureBuildEncryptionCertificate(ctx, repository.EnsureBuildEncryptionCertificateParams{ID: buildID, EncryptionCertificate: &canonical, Status: status.String()})
	if err != nil {
		return fmt.Errorf("pin build encryption certificate: %w", err)
	}
	if rows != 1 {
		return model.ErrInvalidRequest("the build is not at the required stage or its encryption certificate differs; use the same runtime certificate for workload, environment and attestation")
	}
	return nil
}
