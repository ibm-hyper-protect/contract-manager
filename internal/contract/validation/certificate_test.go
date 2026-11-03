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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestEncryptionCertificate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	create := func(key crypto.Signer, before, after time.Time, usage x509.KeyUsage) string {
		t.Helper()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "disposable validation test"},
			NotBefore:    before, NotAfter: after, KeyUsage: usage,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	valid := create(rsaKey, now.Add(-time.Hour), now.Add(time.Hour), x509.KeyUsageKeyEncipherment)
	publicDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"RSA encryption certificate", valid, true},
		{"absent key usage extension", create(rsaKey, now.Add(-time.Hour), now.Add(time.Hour), 0), true},
		{"surrounding whitespace", "\n" + valid + "\n", true},
		{"expired", create(rsaKey, now.Add(-2*time.Hour), now.Add(-time.Hour), x509.KeyUsageKeyEncipherment), false},
		{"not yet valid", create(rsaKey, now.Add(time.Hour), now.Add(2*time.Hour), x509.KeyUsageKeyEncipherment), false},
		{"signature-only usage", create(rsaKey, now.Add(-time.Hour), now.Add(time.Hour), x509.KeyUsageDigitalSignature), false},
		{"weak RSA", create(weakKey, now.Add(-time.Hour), now.Add(time.Hour), x509.KeyUsageKeyEncipherment), false},
		{"non-RSA", create(ecKey, now.Add(-time.Hour), now.Add(time.Hour), x509.KeyUsageDigitalSignature), false},
		{"public key without certificate", publicPEM, false},
		{"multiple certificates", valid + valid, false},
		{"trailing data", valid + "unexpected", false},
		{"malformed DER", "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----\n", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := EncryptionCertificate(tc.input)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
