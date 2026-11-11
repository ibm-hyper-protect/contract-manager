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
	"strings"
	"testing"
)

func TestValidateContractHTTP(t *testing.T) {
	workload := "type: workload\nplay:\n  archive: YWJjZA==\n"
	for _, tc := range []struct {
		name, plaintext, section string
		status                   int
	}{
		{"workload", workload, "workload", http.StatusOK},
		{"wrong role", workload, "env", http.StatusBadRequest},
		{"bad YAML", "type: [", "workload", http.StatusBadRequest},
		{"empty Podman play", "type: workload\nplay: {}", "workload", http.StatusBadRequest},
		{"missing companion", workload, "", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"plaintext": tc.plaintext, "section": tc.section})
			request := httptest.NewRequest(http.MethodPost, "/v2/contract-validate", strings.NewReader(string(body)))
			response := httptest.NewRecorder()
			(&ContractHandler{}).ValidateContract(response, request)
			if response.Code != tc.status {
				t.Fatalf("status %d: %s", response.Code, response.Body.String())
			}
		})
	}
	for _, suffix := range []string{` {"section":"env"}`, ` garbage`} {
		response := httptest.NewRecorder()
		(&ContractHandler{}).ValidateContract(response, httptest.NewRequest(http.MethodPost, "/v2/contract-validate", strings.NewReader(`{"plaintext":"type: workload","section":"workload"}`+suffix)))
		if response.Code != http.StatusBadRequest {
			t.Fatal("appended request data accepted")
		}
	}
}
