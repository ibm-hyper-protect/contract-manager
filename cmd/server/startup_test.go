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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestStartupProbe(t *testing.T) {
	if os.Getenv("CONTRACT_MANAGER_STARTUP_PROBE") == "1" {
		main()
	}
}

func TestStartupErrorCodesDoNotDiscloseCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		values     []string
	}{
		{"required database", "CONFIG_REQUIRED", nil},
		{"invalid port", "CONFIG_INVALID_VALUE", []string{"DATABASE_URL=postgres://localhost/test", "SERVER_PORT=private-sentinel"}},
		{"invalid DSN", "CONFIG_INVALID_VALUE", []string{"DATABASE_URL=postgres://user:private-sentinel@%zz"}},
		{"database unreachable", "DATABASE_CONNECT_FAILED", []string{"DATABASE_URL=postgres://user:private-sentinel@127.0.0.1:1/test?sslmode=disable&connect_timeout=1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestStartupProbe$")
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if key == "DATABASE_URL" || strings.HasPrefix(key, "ADMIN_") || strings.HasPrefix(key, "APPID_") || strings.HasPrefix(key, "PG") || key == "SERVER_PORT" || key == "LOG_LEVEL" || key == "LOG_FORMAT" {
					continue
				}
				cmd.Env = append(cmd.Env, entry)
			}
			cmd.Env = append(cmd.Env, "CONTRACT_MANAGER_STARTUP_PROBE=1")
			cmd.Env = append(cmd.Env, tc.values...)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("expected startup exit status 1, got %v", err)
			}
			if bytes.Contains(output, []byte("private-sentinel")) {
				t.Fatal("startup log disclosed a configured secret")
			}
			var line struct{ Code, Variable, Hint string }
			if err := json.Unmarshal(bytes.TrimSpace(output), &line); err != nil || line.Code != tc.code || line.Hint == "" {
				t.Fatalf("expected structured code %s with an actionable hint", tc.code)
			}
		})
	}
}
