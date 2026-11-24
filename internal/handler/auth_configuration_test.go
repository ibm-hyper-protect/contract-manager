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

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

func TestUnconfiguredSSOHasSpecificErrorCode(t *testing.T) {
	h := NewAuthHandler(nil, service.NewOIDCService("", "", "", ""), nil)
	for _, call := range []http.HandlerFunc{h.OIDCLogin, h.OIDCCallback} {
		w := httptest.NewRecorder()
		call(w, httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d", w.Code)
		}
		var body struct {
			Error struct{ Code string }
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Error.Code != "SSO_NOT_CONFIGURED" {
			t.Fatal("missing stable SSO configuration error code")
		}
	}
}
