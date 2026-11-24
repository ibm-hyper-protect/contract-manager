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
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretstore"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

type SecretStoreHandler struct{ service *service.SecretStoreService }

func NewSecretStoreHandler(s *service.SecretStoreService) *SecretStoreHandler {
	return &SecretStoreHandler{service: s}
}

func (h *SecretStoreHandler) RegisterCatalogRoutes(r chi.Router) {
	r.Route("/secret-store", func(r chi.Router) {
		r.Use(middleware.RequireRole("ADMIN", "AUDITOR", "SOLUTION_PROVIDER", "DATA_OWNER", "ENV_OPERATOR"))
		r.Get("/import-key", h.Info)
		r.With(middleware.RequireRole("ENV_OPERATOR")).Get("/targets", h.FlowTargets)
		r.Get("/objects", h.List)
		r.Post("/objects", h.Create)
		r.Route("/objects/{objectID}", func(r chi.Router) {
			r.Get("/", h.Detail)
			r.Patch("/", h.Update)
			r.Post("/versions", h.Reserve)
			r.Put("/versions/{versionID}/payload", h.Seal)
			r.Post("/revisions", h.GroupRevision)
		})
	})
}
func secretActor(r *http.Request) service.SecretActor {
	id, _ := middleware.GetUserID(r.Context())
	return service.SecretActor{ID: id, Roles: middleware.GetUserRoles(r.Context()), Email: middleware.GetUserEmail(r.Context()), IP: requestIP(r)}
}
func secretParam(r *http.Request, key string) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, key))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, model.ErrInvalidRequest("Invalid identifier.")
	}
	return id, nil
}
func secretBody(r *http.Request, dst any) error {
	if err := readJSON(r, dst); err != nil {
		return model.ErrInvalidRequest("Invalid request body.")
	}
	return nil
}
func (h *SecretStoreHandler) serve(w http.ResponseWriter, r *http.Request, status int, fn func(service.SecretActor) (any, error)) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Body != nil {
		defer drainBody(r)
	}
	a := secretActor(r)
	if a.ID == uuid.Nil {
		writeError(w, model.ErrUnauthorized())
		return
	}
	data, err := fn(a)
	if err != nil {
		var typed *secretflow.Error
		if errors.As(err, &typed) {
			writeError(w, &model.AppError{Code: typed.Code, Message: typed.Message, HTTPStatus: 422})
			return
		}
		var app *model.AppError
		if errors.As(err, &app) {
			writeError(w, app)
			return
		}
		slog.ErrorContext(r.Context(), "secret catalog operation failed", "error", err)
		writeError(w, model.ErrInternal("The secret catalog operation could not be completed."))
		return
	}
	writeJSON(w, status, data)
}
func (h *SecretStoreHandler) Info(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) { return h.service.Info(r.Context(), a) })
}
func (h *SecretStoreHandler) List(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		limit := int64(50)
		offset := int64(0)
		for name, target := range map[string]*int64{"limit": &limit, "offset": &offset} {
			if value := r.URL.Query().Get(name); value != "" {
				n, err := strconv.ParseInt(value, 10, 32)
				if err != nil {
					return nil, model.ErrInvalidRequest("Invalid pagination.")
				}
				*target = n
			}
		}
		if limit < 1 || limit > 100 || offset < 0 {
			return nil, model.ErrInvalidRequest("Invalid pagination.")
		}
		kind := r.URL.Query().Get("kind")
		if kind == "" {
			kind = "SECRET"
		}
		return h.service.List(r.Context(), a, kind, r.URL.Query().Get("search"), int32(limit), int32(offset))
	})
}
func (h *SecretStoreHandler) Create(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 201, func(a service.SecretActor) (any, error) {
		var in struct {
			Kind        string `json:"kind"`
			Alias       string `json:"alias"`
			Description string `json:"description"`
		}
		if err := secretBody(r, &in); err != nil {
			return nil, err
		}
		return h.service.Create(r.Context(), a, in.Kind, in.Alias, in.Description)
	})
}
func (h *SecretStoreHandler) Detail(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, err := secretParam(r, "objectID")
		if err != nil {
			return nil, err
		}
		return h.service.Detail(r.Context(), a, id)
	})
}
func (h *SecretStoreHandler) Update(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, err := secretParam(r, "objectID")
		if err != nil {
			return nil, err
		}
		var in struct {
			ExpectedRevision int32  `json:"expected_revision"`
			Alias            string `json:"alias"`
			Description      string `json:"description"`
			Archived         bool   `json:"archived"`
		}
		if err := secretBody(r, &in); err != nil {
			return nil, err
		}
		return h.service.Update(r.Context(), a, id, in.ExpectedRevision, in.Alias, in.Description, in.Archived)
	})
}
func (h *SecretStoreHandler) Reserve(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 201, func(a service.SecretActor) (any, error) {
		id, err := secretParam(r, "objectID")
		if err != nil {
			return nil, err
		}
		var in struct{}
		if err := secretBody(r, &in); err != nil {
			return nil, err
		}
		return h.service.Reserve(r.Context(), a, id)
	})
}
func (h *SecretStoreHandler) Seal(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, err := secretParam(r, "objectID")
		if err != nil {
			return nil, err
		}
		vid, err := secretParam(r, "versionID")
		if err != nil {
			return nil, err
		}
		var e secretstore.Envelope
		if err := secretBody(r, &e); err != nil {
			return nil, err
		}
		return h.service.Seal(r.Context(), a, id, vid, e)
	})
}
func (h *SecretStoreHandler) GroupRevision(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 201, func(a service.SecretActor) (any, error) {
		id, err := secretParam(r, "objectID")
		if err != nil {
			return nil, err
		}
		var in struct {
			ExpectedRevision int32       `json:"expected_revision"`
			VersionIDs       []uuid.UUID `json:"version_ids"`
		}
		if err := secretBody(r, &in); err != nil {
			return nil, err
		}
		return h.service.GroupRevision(r.Context(), a, id, in.ExpectedRevision, in.VersionIDs)
	})
}
func (h *SecretStoreHandler) BuildSources(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, err := secretParam(r, "id")
		if err != nil {
			return nil, err
		}
		return h.service.BuildSources(r.Context(), a, id)
	})
}
func (h *SecretStoreHandler) SetBuildSources(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, err := secretParam(r, "id")
		if err != nil {
			return nil, err
		}
		var in struct {
			ExpectedRevision int32                       `json:"expected_revision"`
			Sources          []service.SecretSourceInput `json:"sources"`
		}
		if err := secretBody(r, &in); err != nil {
			return nil, err
		}
		return h.service.SetBuildSources(r.Context(), a, id, in.ExpectedRevision, in.Sources)
	})
}
