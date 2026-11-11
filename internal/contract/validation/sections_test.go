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
	"strings"
	"testing"
)

func TestValidateSections(t *testing.T) {
	workload := "type: workload\ncompose:\n  archive: YWJjZA==\n"
	env := "type: env\nlogging:\n  logRouter:\n    hostname: example.com\n    iamApiKey: test-key\n    port: 443\nenv:\n  HELLO: world\n"
	pair := "workload: |\n  " + strings.ReplaceAll(workload, "\n", "\n  ") + "\nenv: |\n  " + strings.ReplaceAll(env, "\n", "\n  ")
	for _, tc := range []struct {
		name, input, kind string
		valid             bool
	}{
		{"compose", workload, "workload", true},
		{"environment variables", env, "env", true},
		{"podman archive", "type: workload\nplay:\n  archive: YWJjZA==", "workload", true},
		{"inline pod", "type: workload\nplay:\n  resources:\n    - apiVersion: v1\n      kind: Pod\n      metadata:\n        name: demo\n      spec:\n        containers:\n          - name: demo\n            image: example/image:1\n", "workload", true},
		{"both", pair, "", true},
		{"extract workload after pair validation", pair, "workload", true},
		{"extract env after pair validation", pair, "env", true},
		{"wrong type", workload, "env", false},
		{"missing type", "compose:\n  archive: YWJjZA==", "workload", false},
		{"duplicate key", workload + "type: env\n", "workload", false},
		{"multiple docs", workload + "---\n" + workload, "workload", false},
		{"ambiguous runtime", workload + "play:\n  archive: YWJjZA==\n", "workload", false},
		{"empty play", "type: workload\nplay: {}", "workload", false},
		{"bad env type", "type: env\nenv:\n  PORT: 8080", "env", false},
		{"bad pair companion", strings.Replace(pair, "HELLO: world", "HELLO: true", 1), "workload", false},
		{"standalone is not both", env, "", false},
		{"scalar", "hello", "env", false},
		{"empty", "", "env", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(tc.input, tc.kind)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
