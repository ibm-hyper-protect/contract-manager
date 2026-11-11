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
	"strings"
	"testing"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
)

func TestEnvironmentSigningKeyCannotBeOverridden(t *testing.T) {
	// Use a DER block to exercise matching without spending time generating keys;
	// the registered signing key is validated separately when it is registered.
	key := "-----BEGIN PUBLIC KEY-----\nYWJjZA==\n-----END PUBLIC KEY-----"
	env := "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-key\n    port: 443\nenv:\n  signingKey: nested-is-only-an-env-variable\n"
	result, err := ensureEnvironmentHasSigningKey(env, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := validation.Validate(result, "env")
	if err != nil || parsed["signingKey"] != key {
		t.Fatalf("registered key was not injected: %v", err)
	}
	if _, err := ensureEnvironmentHasSigningKey(env+"signingKey: unregistered-key\n", key); err == nil {
		t.Fatal("unregistered signing key accepted")
	}
	if _, err := ensureEnvironmentHasSigningKey(strings.Replace(result, "YWJjZA==", "YWJjZQ==", 1), key); err == nil {
		t.Fatal("different signing key accepted")
	}
	if _, err := ensureEnvironmentHasSigningKey(result, key); err != nil {
		t.Fatalf("matching signing key rejected: %v", err)
	}
	if _, err := ensureEnvironmentHasSigningKey(env, ""); err == nil {
		t.Fatal("missing registered key accepted")
	}
}
