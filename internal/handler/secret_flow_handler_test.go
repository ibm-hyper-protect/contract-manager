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
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

func TestSecretFlowHTTPRoleMatrix(t *testing.T) {
	router := chi.NewRouter()
	h := NewSecretStoreHandler(service.NewSecretStoreService(nil, nil, nil))
	router.Route("/builds/{id}", h.RegisterFlowRoutes)
	cases := []struct {
		method, path string
		allowed      []string
	}{{"PUT", "target", []string{"ENV_OPERATOR"}}, {"PUT", "requirements", []string{"SOLUTION_PROVIDER"}}, {"PUT", "target-approval", []string{"AUDITOR"}}, {"POST", "prepare", []string{"AUDITOR"}}, {"PUT", "approvals", []string{"ADMIN", "AUDITOR", "SOLUTION_PROVIDER", "DATA_OWNER", "ENV_OPERATOR"}}}
	for _, role := range []string{"ADMIN", "AUDITOR", "SOLUTION_PROVIDER", "DATA_OWNER", "ENV_OPERATOR", "VIEWER"} {
		for _, tc := range cases {
			allowed := false
			for _, r := range tc.allowed {
				if r == role {
					allowed = true
				}
			}
			if allowed {
				continue
			}
			t.Run(role+"/"+tc.path, func(t *testing.T) {
				ctx := middleware.SetAuthContext(context.Background(), uuid.New(), "person@example.test", []string{role}, "test", false, nil)
				req := httptest.NewRequest(tc.method, "/builds/"+uuid.NewString()+"/secret-flow/"+tc.path, strings.NewReader(`{}`)).WithContext(ctx)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != 403 {
					t.Fatalf("forbidden role returned %d", w.Code)
				}
			})
		}
	}
}
func TestFlowMutationRequiresVerifiedIdentityContext(t *testing.T) {
	h := NewSecretStoreHandler(service.NewSecretStoreService(nil, nil, nil))
	router := chi.NewRouter()
	router.Route("/builds/{id}", h.RegisterFlowRoutes)
	ctx := middleware.SetAuthContext(context.Background(), uuid.New(), "operator@example.test", []string{"ENV_OPERATOR"}, "test", false, nil)
	req := httptest.NewRequest("PUT", "/builds/"+uuid.NewString()+"/secret-flow/target", strings.NewReader(`{"expected_revision":0,"target":{}}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "authenticated request-signing key") {
		t.Fatalf("missing signature context accepted: %d", w.Code)
	}
}
