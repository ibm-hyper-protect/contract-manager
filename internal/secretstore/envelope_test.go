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

package secretstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
)

var testKeyOnce sync.Once
var testKey *rsa.PrivateKey
var testKeyErr error

func keyForTest(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() { testKey, testKeyErr = rsa.GenerateKey(rand.Reader, 4096) })
	if testKeyErr != nil {
		t.Fatal(testKeyErr)
	}
	return testKey
}
func sealForTest(t *testing.T, key *rsa.PrivateKey, value []byte) Envelope {
	t.Helper()
	info, err := PublicKeyInfo(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dek := make([]byte, 32)
	rand.Read(dek)
	defer clear(dek)
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	id, vid := uuid.New(), uuid.New()
	encrypted := gcm.Seal(nil, nonce, value, Context(id, vid))
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, dek, nil)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	return Envelope{1, id, vid, info.KeyID, b64(wrapped), b64(nonce), b64(encrypted[:len(encrypted)-16]), b64(encrypted[len(encrypted)-16:])}
}
func TestSealedImportBinarySafeAndBounded(t *testing.T) {
	key := keyForTest(t)
	for _, value := range [][]byte{nil, []byte("  whitespace\n\t "), {0, 255, 128, 1}, bytes.Repeat([]byte{0x91}, MaxSecretBytes)} {
		e := sealForTest(t, key, value)
		n, err := Verify(e, key)
		if err != nil || n != len(value) {
			t.Fatalf("length %d: n=%d err=%v", len(value), n, err)
		}
	}
	e := sealForTest(t, key, make([]byte, MaxSecretBytes+1))
	if _, err := Verify(e, key); err == nil {
		t.Fatal("oversized value accepted")
	}
}
func TestSealedImportRejectsSubstitutionAndTampering(t *testing.T) {
	key := keyForTest(t)
	original := sealForTest(t, key, []byte("a dummy value"))
	cases := map[string]func(*Envelope){
		"entry": func(e *Envelope) { e.SecretID = uuid.New() }, "version": func(e *Envelope) { e.VersionID = uuid.New() },
		"tag":        func(e *Envelope) { e.Tag = base64.StdEncoding.EncodeToString(make([]byte, 16)) },
		"nonce":      func(e *Envelope) { e.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 12)) },
		"ciphertext": func(e *Envelope) { e.Ciphertext = base64.StdEncoding.EncodeToString([]byte("changed")) },
		"wrong key":  func(e *Envelope) { e.KeyID = "another-key" }, "wrapped key": func(e *Envelope) { e.WrappedKey = base64.StdEncoding.EncodeToString(make([]byte, 512)) },
		"noncanonical base64": func(e *Envelope) { e.Tag += "\n" }, "format": func(e *Envelope) { e.Format = 2 }, "zero entry": func(e *Envelope) { e.SecretID = uuid.Nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e := original
			change(&e)
			if _, err := Verify(e, key); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
}
func TestPrivateImportKeyPermissions(t *testing.T) {
	key := keyForTest(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "worker.pem")
	if err = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPrivateKey(p); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPrivateKey(p); err == nil {
		t.Fatal("publicly readable key accepted")
	}
	link := p + ".link"
	if err = os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadPrivateKey(link); err == nil {
		t.Fatal("key symlink accepted")
	}
}

// Optional real Electron/Node -> Go interoperability fixture, created outside the repository.
func TestDesktopImportInteroperability(t *testing.T) {
	fixture := os.Getenv("SECRET_IMPORT_INTEROP_FIXTURE")
	if fixture == "" {
		t.Skip("set SECRET_IMPORT_INTEROP_FIXTURE for desktop interoperability")
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		KeyPath  string   `json:"key_path"`
		Envelope Envelope `json:"envelope"`
		Length   int      `json:"length"`
	}
	if err = json.Unmarshal(data, &in); err != nil {
		t.Fatal(err)
	}
	key, err := LoadPrivateKey(in.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Verify(in.Envelope, key)
	if err != nil || n != in.Length {
		t.Fatalf("desktop envelope rejected: n=%d err=%v", n, err)
	}
}
