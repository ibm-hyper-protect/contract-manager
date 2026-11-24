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

package config

import (
	"strings"
	"testing"
)

func TestSecretWorkerRequiresExplicitFingerprint(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test-only")
	t.Setenv("SECRET_STORE_WORKER_SOCKET", "/private/test-only.sock")
	for _, pin := range []string{"", "short", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		t.Setenv("SECRET_STORE_IMPORT_KEY_FINGERPRINT", pin)
		if _, err := Load(); err == nil {
			t.Fatal("worker configured without a valid explicit pin")
		}
	}
	t.Setenv("SECRET_STORE_IMPORT_KEY_FINGERPRINT", strings.Repeat("a", 64))
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRET_STORE_WORKER_SOCKET", "")
	t.Setenv("SECRET_STORE_IMPORT_KEY_FINGERPRINT", "")
	if _, err := Load(); err != nil {
		t.Fatal("existing worker-free deployment stopped working:", err)
	}
}
