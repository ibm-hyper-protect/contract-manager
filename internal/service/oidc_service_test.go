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
	"net/url"
	"testing"
)

func TestOIDCRequiresCompleteRuntimeConfiguration(t *testing.T) {
	complete := []string{"client", "secret", "https://id.example/oauth/", "https://app.example/callback"}
	for missing := -1; missing < len(complete); missing++ {
		values := append([]string(nil), complete...)
		if missing >= 0 {
			values[missing] = ""
		}
		s := NewOIDCService(values[0], values[1], values[2], values[3])
		if s.Enabled() != (missing == -1) {
			t.Fatalf("missing configuration index %d: unexpected SSO enablement", missing)
		}
		if missing == -1 {
			u, err := url.Parse(s.GetAuthURL("test-state"))
			if err != nil {
				t.Fatal(err)
			}
			if u.Path != "/oauth/authorize" || u.Query().Get("client_id") != values[0] || u.Query().Get("redirect_uri") != values[3] || u.Query().Get("state") != "test-state" {
				t.Fatal("authorization URL did not use the runtime configuration")
			}
			if u.Query().Has("client_secret") {
				t.Fatal("authorization URL must not disclose the client secret")
			}
		}
	}
}
