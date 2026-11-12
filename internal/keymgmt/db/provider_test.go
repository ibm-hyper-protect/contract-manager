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

package db

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

func TestGeneratedKeyPassphraseErrorsAreClientErrors(t *testing.T) {
	provider := New(nil)
	for _, kind := range []model.BuildKeyType{model.BuildKeyTypeSigning, model.BuildKeyTypeAttestation} {
		for _, value := range []string{"", "Short!1", "longpassword!1"} {
			var err error
			if kind == model.BuildKeyTypeSigning {
				_, err = provider.CreateSigningKey(context.Background(), uuid.New(), uuid.New(), model.BuildKeyModeGenerate, nil, &value)
			} else {
				_, _, err = provider.CreateAttestationKey(context.Background(), uuid.New(), uuid.New(), model.BuildKeyModeGenerate, nil, &value)
			}
			var appErr *model.AppError
			if !errors.As(err, &appErr) || appErr.HTTPStatus != http.StatusBadRequest {
				t.Fatalf("%s: expected client error, got %v", kind, err)
			}
		}
	}
}

func TestGeneratedKeyPreservesPassphraseWhitespace(t *testing.T) {
	passphrase := "  Correct!Passphrase2026  "
	record, err := New(nil).CreateSigningKey(context.Background(), uuid.New(), uuid.New(), model.BuildKeyModeGenerate, nil, &passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := appcrypto.ValidatePrivateKeyPassphrase(record.EncryptedPrivateKeyPEM, passphrase); err != nil {
		t.Fatal(err)
	}
	if err := appcrypto.ValidatePrivateKeyPassphrase(record.EncryptedPrivateKeyPEM, strings.TrimSpace(passphrase)); !errors.Is(err, appcrypto.ErrPrivateKeyUnlock) {
		t.Fatalf("trimmed passphrase accepted: %v", err)
	}
}
