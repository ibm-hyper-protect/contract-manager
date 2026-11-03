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

package keymgmt

import (
	"strings"

	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

// ValidateGenerationPassphrase reports actionable input errors before any key or build is changed.
// Uploaded public keys do not require a passphrase. Accepted passphrases are never trimmed.
func ValidateGenerationPassphrase(mode model.BuildKeyMode, passphrase *string) error {
	if mode != model.BuildKeyModeGenerate {
		return nil
	}
	if passphrase == nil || strings.TrimSpace(*passphrase) == "" {
		return model.ErrInvalidRequest("A passphrase is required to generate this key.")
	}
	if err := appcrypto.ValidatePassphraseStrength(*passphrase); err != nil {
		return model.ErrInvalidRequest(err.Error())
	}
	return nil
}
