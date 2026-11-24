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
	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
)

func TestSecretEnvironmentReferences(t *testing.T) {
	id := "0x" + strings.Repeat("ab", 32)
	artifacts := []secretflow.Artifact{{Name: "DATABASE_PASSWORD", Consumer: "application", Kind: "retrievable", Type: "plain", SecretID: id}}
	for _, input := range []string{
		"type: env\n",
		"type: env\nenv:\n  APP_MODE: test\nlogging:\n  logRouter:\n    hostname: logs.example.test\n",
		"type: env\nenv:\n  DATABASE_PASSWORD_SECRET_ID: '" + id + "'\n",
	} {
		out, err := environmentWithSecretIDs(input, artifacts)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := validation.ParseMapping(out)
		if err != nil || parsed["env"].(map[string]any)["DATABASE_PASSWORD_SECRET_ID"] != id {
			t.Fatalf("missing environment reference: %v", err)
		}
		if strings.Contains(input, "APP_MODE") && (parsed["env"].(map[string]any)["APP_MODE"] != "test" || parsed["logging"] == nil) {
			t.Fatal("existing variables or logging changed")
		}
		if again, err := environmentWithSecretIDs(out, artifacts); err != nil || again != out {
			t.Fatalf("reference merge is not idempotent: %v", err)
		}
	}
	for _, input := range []string{
		"type: env\nenv:\n  DATABASE_PASSWORD_SECRET_ID: other\n",
		"type: env\nenv:\n  DATABASE_PASSWORD_SECRET_ID: 1\n",
		"type: env\nenv:\n  DATABASE_PASSWORD_SECRET_ID: {wrong: value}\n",
	} {
		_, err := environmentWithSecretIDs(input, artifacts)
		requireUserKeyError(t, err, "SECRET_ENVIRONMENT_BINDING_MISMATCH")
	}
	for _, input := range []string{"type: workload\n", "type: env\nenv: []\n", "type: env\nenv: null\n", "type: env\ntype: env\n", "type: env\n---\ntype: env\n"} {
		_, err := environmentWithSecretIDs(input, artifacts)
		requireUserKeyError(t, err, "SECRET_ENVIRONMENT_INVALID")
	}
}
