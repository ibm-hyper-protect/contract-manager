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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	contractengine "github.com/ibm-hyper-protect/contract-manager/internal/contract"
	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
)

func TestEncryptedContractRoundTripAndSignature(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable-test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	key := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}))
	engine := New()
	ctx := context.Background()
	var workload, env, attestation string
	for i := 0; i < 24; i++ {
		plaintext := "type: workload\n# round trip: spaces, ü, secret-value\nplay:\n  archive: YWJjZA==\n"
		if i == 1 {
			plaintext = "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-key\n    port: 443\nenv:\n  HELLO: world\n"
		}
		if i == 2 {
			public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			plaintext = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
		}
		encrypted, err := engine.EncryptString(ctx, plaintext, cert)
		if err != nil {
			t.Fatalf("encrypt iteration %d: %v", i, err)
		}
		if err := validation.EncryptedSection(encrypted); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(encrypted, "secret-value") {
			t.Fatal("plaintext leaked into ciphertext")
		}
		decrypted, err := decryptEnvelope(ctx, encrypted, key, "")
		// Preserve the exact plaintext, including its trailing newline.
		if err != nil || decrypted != plaintext {
			t.Fatalf("decrypt iteration %d: %v", i, err)
		}
		if i == 0 {
			if !strings.HasPrefix(encrypted, "contract-basic.") {
				t.Fatal("CCRT envelope must use contract-basic")
			}
			legacy := strings.Replace(encrypted, "contract-basic.", "hyper-protect-basic.", 1)
			if value, err := decryptEnvelope(ctx, legacy, key, ""); err != nil || value != plaintext {
				t.Fatal("legacy envelope prefix could not be decrypted")
			}

			workload = encrypted
		}
		if i == 1 {
			env = encrypted
		}
		if i == 2 {
			attestation = encrypted
		}
		if i == 3 && encrypted == workload {
			t.Fatal("encryption reused its randomness")
		}
	}
	assembled, _, err := engine.AssembleContract(ctx, contractengine.AssembleInput{EncryptedWorkload: workload, EncryptedEnvironment: env, EncryptedAttestationKey: attestation})
	if err != nil {
		t.Fatal(err)
	}
	signed, _, _, err := engine.HpcrContractSign(ctx, assembled, key, "")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]string
	if err := yaml.Unmarshal([]byte(signed), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["workload"] != workload || doc["env"] != env || doc["attestationPublicKey"] != attestation {
		t.Fatal("final assembly changed encrypted sections")
	}
	signature, err := base64.StdEncoding.DecodeString(doc["envWorkloadSignature"])
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(workload + env))
	if err := rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, hash[:], signature); err != nil {
		t.Fatalf("final contract signature: %v", err)
	}
	tampered := sha256.Sum256([]byte(workload + env + "changed"))
	if rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, tampered[:], signature) == nil {
		t.Fatal("tampered sections passed signature verification")
	}
	if _, err := engine.EncryptString(ctx, "secret", ""); err == nil {
		t.Fatal("missing certificate accepted")
	}
	if _, err := engine.EncryptString(ctx, "secret", "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----"); err == nil {
		t.Fatal("fake certificate accepted")
	}
}

func TestOpenSSLBytesPreservesBinaryOutput(t *testing.T) {
	data := []byte{0x20, 0x09, 0x0a, 0x00, 0xff, 0x0d, 0x20}
	// base64 -d provides a deterministic binary output fixture without requiring keys.
	output, err := opensslBytes(context.Background(), []byte(base64.StdEncoding.EncodeToString(data)+"\n"), "base64", "-d")
	if err != nil || string(output) != string(data) {
		t.Fatalf("binary output changed: %x, %v", output, err)
	}
}

func TestContractStarterTemplates(t *testing.T) {
	for _, kind := range []string{"workload", "env", ""} {
		template, err := New().HpcrContractTemplate(context.Background(), kind)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validation.Validate(template, kind); err != nil {
			t.Fatalf("%q template fails its own schema: %v", kind, err)
		}
	}
}
