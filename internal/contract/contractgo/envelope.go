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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ibm-hyper-protect/contract-go/v3/common/general"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
)

// OpenSSL's password input is line-oriented; raw random bytes may contain NUL
// or newlines. Encoding preserves 256 bits of entropy and a single password line.
// Binary ciphertext must never pass through text helpers that trim whitespace.
func encryptEnvelope(ctx context.Context, plaintext, certPEM string) (string, error) {
	if err := validation.EncryptionCertificate(certPEM); err != nil {
		return "", err
	}
	block, _ := pem.Decode([]byte(certPEM))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	password := []byte(base64.StdEncoding.EncodeToString(random))
	clear(random)
	defer clear(password)
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, certificate.PublicKey.(*rsa.PublicKey), password)
	if err != nil {
		return "", fmt.Errorf("wrap section password: %w", err)
	}
	dir, err := os.MkdirTemp("", "contract-encryption-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	input := filepath.Join(dir, "plaintext")
	if err := os.WriteFile(input, []byte(plaintext), 0600); err != nil {
		return "", err
	}
	encrypted, err := opensslBytes(ctx, password, "enc", "-aes-256-cbc", "-pbkdf2", "-pass", "stdin", "-in", input)
	if err != nil {
		return "", fmt.Errorf("encrypt section: %w", err)
	}
	// HPVS needs its legacy prefix; the cryptography and payload are identical.
	return encryptionPrefix(certificate) + base64.StdEncoding.EncodeToString(wrapped) + "." + base64.StdEncoding.EncodeToString(encrypted), nil
}

func decryptEnvelope(ctx context.Context, encrypted, privateKey, passphrase string) (string, error) {
	if err := validation.EncryptedSection(encrypted); err != nil {
		return "", err
	}
	parts := strings.Split(encrypted, ".")
	wrapped, _ := base64.StdEncoding.Strict().DecodeString(parts[1])
	ciphertext, _ := base64.StdEncoding.Strict().DecodeString(parts[2])
	dir, err := os.MkdirTemp("", "contract-decryption-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	for name, data := range map[string][]byte{"key": []byte(privateKey), "wrapped": wrapped, "ciphertext": ciphertext, "passphrase": []byte(passphrase)} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return "", err
		}
	}
	passin := "pass:"
	if passphrase != "" {
		passin = "file:" + filepath.Join(dir, "passphrase")
	}
	args := []string{"pkeyutl", "-decrypt", "-inkey", filepath.Join(dir, "key"), "-in", filepath.Join(dir, "wrapped"), "-passin", passin}
	password, err := opensslBytes(ctx, nil, args...)
	if err != nil {
		return "", fmt.Errorf("unwrap section password: %w", err)
	}
	defer clear(password)
	plaintext, err := opensslBytes(ctx, password, "enc", "-aes-256-cbc", "-d", "-pbkdf2", "-pass", "stdin", "-in", filepath.Join(dir, "ciphertext"))
	if err != nil {
		return "", fmt.Errorf("decrypt section: %w", err)
	}
	return string(plaintext), nil
}

func opensslBytes(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, general.GetOpenSSLPath(), args...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("OpenSSL command failed: %w", err)
	}
	return output, nil
}
