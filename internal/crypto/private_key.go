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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ErrPassphraseRequired means an encrypted private key was supplied without its passphrase.
var ErrPassphraseRequired = errors.New("private key passphrase is required")

// ErrPrivateKeyUnlock means an encrypted key cannot be unlocked with the supplied passphrase.
// Legacy PEM encryption is unauthenticated, so ciphertext damage can produce the same error.
var ErrPrivateKeyUnlock = errors.New("unable to unlock private key")

// ValidatePrivateKeyPassphrase checks that a PEM-encoded RSA key can be unlocked.
// It distinguishes passphrase errors from malformed storage or unsupported formats
// without returning plaintext key material to its caller.
func ValidatePrivateKeyPassphrase(privateKeyPEM []byte, passphrase string) error {
	block, rest := pem.Decode(privateKeyPEM)
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return fmt.Errorf("invalid private key PEM")
	}
	if block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return fmt.Errorf("unsupported private key PEM type")
	}
	//nolint:staticcheck // Existing OpenSSL-compatible key storage uses legacy PEM encryption.
	encrypted := x509.IsEncryptedPEMBlock(block)
	der := block.Bytes
	if encrypted {
		if passphrase == "" {
			return ErrPassphraseRequired
		}
		//nolint:staticcheck // Existing OpenSSL-compatible key storage uses legacy PEM encryption.
		var err error
		der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if errors.Is(err, x509.IncorrectPasswordError) {
			return ErrPrivateKeyUnlock
		}
		if err != nil {
			return fmt.Errorf("invalid encrypted private key: %w", err)
		}
	}
	defer func() {
		for i := range der {
			der[i] = 0
		}
	}()

	var key *rsa.PrivateKey
	var err error
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(der)
	} else {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(der)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				err = fmt.Errorf("private key is not RSA")
			}
		}
	}
	if err == nil {
		err = key.Validate()
	}
	if key != nil {
		defer func() {
			key.D.SetInt64(0)
			for _, prime := range key.Primes {
				prime.SetInt64(0)
			}
		}()
	}
	if err != nil {
		// Incorrect CBC passwords can produce valid padding but invalid DER.
		if encrypted {
			return ErrPrivateKeyUnlock
		}
		return fmt.Errorf("invalid RSA private key: %w", err)
	}
	return nil
}
