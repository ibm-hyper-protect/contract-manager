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
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptedSectionFraming(t *testing.T) {
	wrapped := base64.StdEncoding.EncodeToString(make([]byte, 256))
	// The framing check needs no runtime private key: an OpenSSL header, an
	// eight-byte salt and one complete ciphertext block form the smallest body.
	body := append([]byte("Salted__"), make([]byte, 24)...)
	encoded := base64.StdEncoding.EncodeToString(body)
	valid := "contract-basic." + wrapped + "." + encoded
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"current prefix", valid, true},
		{"legacy prefix", strings.Replace(valid, "contract-basic", "hyper-protect-basic", 1), true},
		{"plaintext", "type: workload", false},
		{"unknown prefix", strings.Replace(valid, "contract-basic", "unknown", 1), false},
		{"missing field", "contract-basic." + wrapped, false},
		{"extra field", valid + ".extra", false},
		{"short RSA ciphertext", "contract-basic." + base64.StdEncoding.EncodeToString(make([]byte, 128)) + "." + encoded, false},
		{"invalid password base64", "contract-basic.?." + encoded, false},
		{"invalid data base64", "contract-basic." + wrapped + ".?", false},
		{"missing OpenSSL header", "contract-basic." + wrapped + "." + base64.StdEncoding.EncodeToString(make([]byte, 32)), false},
		{"header and salt only", "contract-basic." + wrapped + "." + base64.StdEncoding.EncodeToString(body[:16]), false},
		{"truncated CBC block", "contract-basic." + wrapped + "." + base64.StdEncoding.EncodeToString(body[:31]), false},
		{"newline in password", "contract-basic." + wrapped[:20] + "\n" + wrapped[20:] + "." + encoded, false},
		{"CRLF in data", "contract-basic." + wrapped + "." + encoded[:20] + "\r\n" + encoded[20:], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := EncryptedSection(tc.input)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
