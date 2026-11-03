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

package validation

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// EncryptedSection checks the wire envelope without needing the runtime's private key.
func EncryptedSection(text string) error {
	if strings.ContainsAny(text, "\r\n") {
		return fmt.Errorf("encrypted envelope must fit on one line")
	}
	parts := strings.Split(text, ".")
	if len(parts) != 3 || (parts[0] != "hyper-protect-basic" && parts[0] != "contract-basic") {
		return fmt.Errorf("expected encrypted contract envelope")
	}
	password, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(password) < 256 {
		return fmt.Errorf("invalid encrypted password")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(ciphertext) < 32 || !bytes.Equal(ciphertext[:8], []byte("Salted__")) || (len(ciphertext)-16)%16 != 0 {
		return fmt.Errorf("invalid encrypted section data")
	}
	return nil
}
