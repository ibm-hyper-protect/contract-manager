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

package validation

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// EncryptionCertificate validates a single, currently valid RSA encryption certificate.
func EncryptionCertificate(certPEM string) error {
	block, rest := pem.Decode([]byte(certPEM))
	if !strings.HasPrefix(strings.TrimSpace(certPEM), "-----BEGIN CERTIFICATE-----") || block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return fmt.Errorf("provide one PEM encryption certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid encryption certificate")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return fmt.Errorf("encryption certificate is not currently valid")
	}
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 {
		return fmt.Errorf("encryption certificate must have an RSA key of at least 2048 bits")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return fmt.Errorf("certificate does not permit key encipherment")
	}
	return nil
}
