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

package service

import (
	"errors"
	"fmt"
	"strings"

	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

func validateBuildKeyPassphrase(privateKeyPEM []byte, passphrase string, keyType model.BuildKeyType) error {
	label := strings.ToLower(string(keyType))
	err := appcrypto.ValidatePrivateKeyPassphrase(privateKeyPEM, passphrase)
	switch {
	case errors.Is(err, appcrypto.ErrPassphraseRequired):
		return model.ErrInvalidRequest(fmt.Sprintf("The %s key passphrase is required. Use the passphrase set when registering this key.", label))
	case errors.Is(err, appcrypto.ErrPrivateKeyUnlock):
		return model.ErrInvalidRequest(fmt.Sprintf("Unable to unlock the %s key. Check the passphrase set when registering this key.", label))
	case err != nil:
		return fmt.Errorf("unlock %s private key: %w", keyType, err)
	default:
		return nil
	}
}
