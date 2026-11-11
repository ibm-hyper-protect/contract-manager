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
	"encoding/base64"
	"fmt"
	"strings"

	hpattestation "github.com/ibm-hyper-protect/contract-go/v2/attestation"

	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
)

// HpcrVerifySignatureAttestationRecords verifies the HPCR attestation records signature
// against the IBM attestation certificate using contract-go. The signature may be raw
// bytes (se-signature.bin) or their base64 encoding.
func (e *Engine) HpcrVerifySignatureAttestationRecords(ctx context.Context, attestationRecords, signature, attestationCert string) error {
	_ = ctx
	trimmedSignature := strings.TrimSpace(signature)
	if trimmedSignature == "" {
		return fmt.Errorf("attestation signature is empty")
	}
	if strings.TrimSpace(attestationCert) == "" {
		return fmt.Errorf("attestation certificate is required")
	}
	if _, err := appcrypto.ParseCertificatePEM(attestationCert); err != nil {
		return fmt.Errorf("invalid attestation certificate: %w", err)
	}

	// Raw signature bytes are used untrimmed; only a base64 form may carry surrounding whitespace.
	rawSignature := signature
	if decoded, err := base64.StdEncoding.DecodeString(trimmedSignature); err == nil {
		rawSignature = string(decoded)
	}

	if err := hpattestation.HpcrVerifySignatureAttestationRecords(attestationRecords, rawSignature, attestationCert); err != nil {
		return fmt.Errorf("attestation signature verification failed: %w", err)
	}
	return nil
}
