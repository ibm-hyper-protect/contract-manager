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

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

func TestValidatePrivateKeyPassphrase(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := "  Correct!Passphrase2026  "
	encode := func(kind string, der []byte, encrypted bool) []byte {
		t.Helper()
		block := &pem.Block{Type: kind, Bytes: der}
		if encrypted {
			var err error
			//nolint:staticcheck // Exercise the existing stored-key format.
			block, err = x509.EncryptPEMBlock(rand.Reader, kind, der, []byte(passphrase), x509.PEMCipherAES256)
			if err != nil {
				t.Fatal(err)
			}
		}
		return pem.EncodeToMemory(block)
	}
	encrypted := encode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), true)
	brokenHeader, _ := pem.Decode(encrypted)
	brokenHeader.Headers["DEK-Info"] = "AES-256-CBC,not-hex"
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		pem      []byte
		password string
		want     error
		internal bool
	}{
		{"encrypted PKCS1", encrypted, passphrase, nil, false},
		{"encrypted PKCS8", encode("PRIVATE KEY", pkcs8, true), passphrase, nil, false},
		{"plain PKCS1", encode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), false), "", nil, false},
		{"plain PKCS8", encode("PRIVATE KEY", pkcs8, false), "", nil, false},
		{"required", encrypted, "", ErrPassphraseRequired, false},
		{"wrong", encrypted, "Wrong!Passphrase2026", ErrPrivateKeyUnlock, false},
		{"whitespace significant", encrypted, strings.TrimSpace(passphrase), ErrPrivateKeyUnlock, false},
		{"valid padding invalid DER", encode("RSA PRIVATE KEY", []byte("not RSA DER"), true), passphrase, ErrPrivateKeyUnlock, false},
		{"bad PEM", []byte("malformed stored key"), passphrase, nil, true},
		{"bad DER", encode("RSA PRIVATE KEY", []byte("not RSA DER"), false), passphrase, nil, true},
		{"wrong key type", encode("PRIVATE KEY", ecDER, false), passphrase, nil, true},
		{"malformed encryption header", pem.EncodeToMemory(brokenHeader), passphrase, nil, true},
		{"extra PEM", append(append([]byte{}, encrypted...), encrypted...), passphrase, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePrivateKeyPassphrase(tc.pem, tc.password)
			if tc.internal {
				if err == nil || errors.Is(err, ErrPassphraseRequired) || errors.Is(err, ErrPrivateKeyUnlock) {
					t.Fatalf("expected stored-key error, got %v", err)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), passphrase) {
				t.Fatal("error includes passphrase")
			}
		})
	}
}
