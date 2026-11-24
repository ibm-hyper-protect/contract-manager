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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

func TestSecretCatalogHTTPRolesAndRetiredSharingRoutes(t *testing.T) {
	router := chi.NewRouter()
	NewSecretStoreHandler(service.NewSecretStoreService(nil, nil, nil)).RegisterCatalogRoutes(router)
	for _, role := range []string{"ADMIN", "AUDITOR", "SOLUTION_PROVIDER", "DATA_OWNER", "ENV_OPERATOR", "VIEWER"} {
		t.Run(role, func(t *testing.T) {
			ctx := middleware.SetAuthContext(context.Background(), uuid.New(), "person@example.test", []string{role}, "test-only", false, nil)
			req := httptest.NewRequest(http.MethodGet, "/secret-store/import-key", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			want := http.StatusServiceUnavailable // role accepted; no import worker configured
			if role == "VIEWER" {
				want = http.StatusForbidden
			}
			if w.Code != want {
				t.Fatalf("catalog gate: want %d, got %d", want, w.Code)
			}
			if role == "VIEWER" {
				return
			}
			for _, route := range []struct{ method, suffix string }{
				{http.MethodPost, "/grants"}, {http.MethodDelete, "/grants/" + uuid.NewString()},
				{http.MethodGet, "/recipients"}, {http.MethodGet, "/build-scopes"},
			} {
				req = httptest.NewRequest(route.method, "/secret-store/objects/"+uuid.NewString()+route.suffix, strings.NewReader(`{}`)).WithContext(ctx)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != http.StatusNotFound {
					t.Fatalf("retired %s %s is still reachable: %d", route.method, route.suffix, w.Code)
				}
			}
			// A client cannot choose an owner ID when creating an entry.
			req = httptest.NewRequest(http.MethodPost, "/secret-store/objects", strings.NewReader(`{"kind":"SECRET","alias":"personal","owner_id":"`+uuid.NewString()+`"}`)).WithContext(ctx)
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("owner injection was accepted: %d", w.Code)
			}
		})
	}
}
