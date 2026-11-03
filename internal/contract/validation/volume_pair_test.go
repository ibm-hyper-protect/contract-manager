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
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidatePairedVolumeDeclarations(t *testing.T) {
	workload := "type: workload\nplay:\n  resources:\n    - apiVersion: v1\n      kind: Pod\n      metadata:\n        name: demo\n      spec:\n        containers:\n          - name: demo\n            image: example/image:1\n"
	env := "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-key\n    port: 443\n"
	wvolume := "volumes:\n  data:\n    mount: /mnt/data\n    filesystem: ext4\n    seed: WorkloadSeed12345\n"
	evolume := "volumes:\n  data:\n    seed: EnvironmentSeed12345\n"
	for _, tc := range []struct {
		name, wvolume, evolume string
		valid                  bool
	}{
		{"no persistent volumes", "", "", true},
		{"workload seed alone", wvolume, "", true},
		{"separate persona seed contributions", wvolume, evolume, true},
		{"environment UV secret contribution", wvolume, "volumes:\n  data:\n    uv-secret-id: index-1\n", true},
		{"dangling environment volume", "", evolume, false},
		{"mismatched volume names", wvolume, "volumes:\n  other:\n    seed: EnvironmentSeed12345\n", false},
		{"missing workload seed", "volumes:\n  data:\n    mount: /mnt/data\n", evolume, false},
		{"invalid short environment seed", wvolume, "volumes:\n  data:\n    seed: short\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair, err := yaml.Marshal(map[string]string{"workload": workload + tc.wvolume, "env": env + tc.evolume})
			if err != nil {
				t.Fatal(err)
			}
			// Selecting either section must still validate the complete pair.
			for _, kind := range []string{"", "workload", "env"} {
				_, err := Validate(string(pair), kind)
				if (err == nil) != tc.valid {
					t.Fatalf("section=%q, valid=%v, error=%v", kind, tc.valid, err)
				}
			}
		})
	}
}
