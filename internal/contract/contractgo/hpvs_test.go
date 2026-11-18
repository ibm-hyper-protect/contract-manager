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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	hpencryption "github.com/ibm-hyper-protect/contract-go/v3/encryption"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
)

func TestHPVSCertificateChoosesLegacyEnvelope(t *testing.T) {
	engine := New()
	usable := 0
	for version, text := range hpencryption.CertificateMap["hpvs"] {
		block, _ := pem.Decode([]byte(text))
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if encryptionPrefix(certificate) != "hyper-protect-basic." {
			t.Fatal("HPVS prefix not selected")
		}
		if validation.EncryptionCertificate(text) != nil {
			continue
		}
		usable++
		result, err := engine.GetEncryptionCertificate(context.Background(), "hpvs", version)
		if err != nil || !result.ContractSupported {
			t.Fatalf("HPVS support: %v", err)
		}
		// The same server engine handles workload, environment and attestation.
		for _, plaintext := range []string{"type: workload\n", "type: env\n", "public-attestation-key"} {
			encrypted, err := engine.EncryptString(context.Background(), plaintext, "\n"+text+"\n")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(encrypted, "hyper-protect-basic.") {
				t.Fatal("wrong wire format")
			}
			if err := validation.EncryptedSection(encrypted); err != nil {
				t.Fatal(err)
			}
		}
	}
	if usable == 0 {
		t.Fatal("no currently usable embedded HPVS certificate")
	}
}

func TestCCRTCertificatesKeepContractBasic(t *testing.T) {
	for _, text := range hpencryption.CertificateMap["ccrt"] {
		block, _ := pem.Decode([]byte(text))
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if encryptionPrefix(certificate) != "contract-basic." {
			t.Fatal("CCRT format changed")
		}
	}
}

// A disposable catalog entry lets us independently decrypt the legacy envelope
// without access to IBM runtime private keys. The real-certificate test above
// verifies that the shipped HPVS certificates select the same path.
func TestHPVSEnvelopeRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "disposable HPVS test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	hpencryption.CertificateMap["hpvs"]["local-round-trip"] = certPEM
	t.Cleanup(func() { delete(hpencryption.CertificateMap["hpvs"], "local-round-trip") })
	for _, plain := range []string{"type: workload\n# Grüße \n", "type: env\n# exact seed \n", "attestation-public-key\n"} {
		encrypted, err := New().EncryptString(context.Background(), plain, certPEM)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(encrypted, "hyper-protect-basic.") {
			t.Fatal("wrong envelope")
		}
		decoded, err := decryptEnvelope(context.Background(), encrypted, keyPEM, "")
		if err != nil || decoded != plain {
			t.Fatalf("legacy round-trip changed plaintext: %v", err)
		}
	}
}
