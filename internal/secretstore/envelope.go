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

// Package secretstore implements the binary-safe, sealed catalog import protocol.
package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"regexp"

	"github.com/google/uuid"
)

const MaxSecretBytes = 64 * 1024

type ImportKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
	Fingerprint  string `json:"fingerprint"`
	MaxBytes     int    `json:"max_bytes"`
}

type Envelope struct {
	Format     int       `json:"format"`
	SecretID   uuid.UUID `json:"secret_id"`
	VersionID  uuid.UUID `json:"version_id"`
	KeyID      string    `json:"key_id"`
	WrappedKey string    `json:"wrapped_key"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
	Tag        string    `json:"tag"`
}

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`)

func Context(secretID, versionID uuid.UUID) []byte {
	return []byte("contract-secret-import-v1\n" + secretID.String() + "\n" + versionID.String() + "\n")
}

func PublicKeyInfo(key *rsa.PublicKey) (ImportKey, error) {
	if key.N.BitLen() != 4096 || key.E != 65537 {
		return ImportKey{}, errors.New("RSA-4096 import key required")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return ImportKey{}, err
	}
	digest := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(digest[:])
	return ImportKey{KeyID: fingerprint, PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Fingerprint: fingerprint, MaxBytes: MaxSecretBytes}, nil
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 {
		return nil, errors.New("worker private key must be a regular file accessible only by its owner")
	}
	if stat.Size() > 32*1024 {
		return nil, errors.New("worker private key file too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(stat, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 {
		return nil, errors.New("worker key changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 32*1024+1))
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if len(data) > 32*1024 {
		return nil, errors.New("worker private key file too large")
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("one PEM private key required")
	}
	defer clear(block.Bytes)
	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("RSA private key required")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if err = key.Validate(); err != nil {
		return nil, err
	}
	_, err = PublicKeyInfo(&key.PublicKey)
	return key, err
}

func (e Envelope) ValidateShape() error {
	if e.Format != 1 || e.SecretID == uuid.Nil || e.VersionID == uuid.Nil || !keyIDPattern.MatchString(e.KeyID) {
		return errors.New("invalid sealed import context")
	}
	lengths := []struct {
		value    string
		min, max int
	}{{e.WrappedKey, 512, 512}, {e.Nonce, 12, 12}, {e.Tag, 16, 16}, {e.Ciphertext, 0, MaxSecretBytes}}
	for _, item := range lengths {
		if len(item.value) > base64.StdEncoding.EncodedLen(item.max) {
			return errors.New("sealed import field exceeds limit")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(item.value)
		if err != nil || len(decoded) < item.min || len(decoded) > item.max || base64.StdEncoding.EncodeToString(decoded) != item.value {
			return errors.New("invalid sealed import encoding")
		}
	}
	return nil
}

// Verify decrypts only inside the trusted worker. No plaintext leaves this function.
func Verify(e Envelope, key *rsa.PrivateKey) (int, error) {
	n := 0
	err := WithPlaintext(e, key, func(value []byte) error { n = len(value); return nil })
	return n, err
}

// WithPlaintext is worker-only processing. It clears the authenticated buffer
// after the callback, and must never be exposed as a plaintext-return endpoint.
func WithPlaintext(e Envelope, key *rsa.PrivateKey, use func([]byte) error) error {
	if key == nil || use == nil {
		return errors.New("worker decryption is not configured")
	}
	if err := e.ValidateShape(); err != nil {
		return err
	}
	info, err := PublicKeyInfo(&key.PublicKey)
	if err != nil {
		return err
	}
	if e.KeyID != info.KeyID {
		return errors.New("unknown import key")
	}
	wrapped, _ := base64.StdEncoding.DecodeString(e.WrappedKey)
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, nil)
	if err != nil {
		return errors.New("invalid sealed import")
	}
	defer clear(dek)
	if len(dek) != 32 {
		return errors.New("invalid data key")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce, _ := base64.StdEncoding.DecodeString(e.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(e.Ciphertext)
	tag, _ := base64.StdEncoding.DecodeString(e.Tag)
	plaintext, err := gcm.Open(nil, nonce, append(ct, tag...), Context(e.SecretID, e.VersionID))
	if err != nil {
		return errors.New("invalid sealed import authentication")
	}
	defer clear(plaintext)
	return use(plaintext)
}
