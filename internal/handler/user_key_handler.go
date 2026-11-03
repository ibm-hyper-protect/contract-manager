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
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// UserKeyHandler handles identity-key history and revocation endpoints.
type UserKeyHandler struct {
	userKeyService   *service.UserKeyService
	systemLogService *service.SystemLogService
}

// NewUserKeyHandler creates a new UserKeyHandler.
func NewUserKeyHandler(userKeyService *service.UserKeyService, systemLogService *service.SystemLogService) *UserKeyHandler {
	return &UserKeyHandler{
		userKeyService:   userKeyService,
		systemLogService: systemLogService,
	}
}

// ListKeys handles GET /users/{id}/public-keys.
func (h *UserKeyHandler) ListKeys(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}
	keys, err := h.userKeyService.ListKeys(r.Context(), userID)
	if err != nil {
		var appErr *model.AppError
		if errors.As(err, &appErr) {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to list public keys."))
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// RevokeKey handles DELETE /users/{id}/public-keys/{key_id}.
func (h *UserKeyHandler) RevokeKey(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	keyID, err := uuid.Parse(chi.URLParam(r, "key_id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid key ID."))
		return
	}

	actorID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}

	err = h.userKeyService.RevokeKey(r.Context(), userID, keyID, actorID)
	if err != nil {
		logSystemEvent(h.systemLogService, r, "unknown", "PUBLIC_KEY_REVOKED",
			"User: "+userID.String(), "FAILED", "Failed to revoke public key "+keyID.String()+": "+err.Error())
		var appErr *model.AppError
		if errors.As(err, &appErr) {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to revoke key."))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"PUBLIC_KEY_REVOKED",
		"User: "+userID.String(),
		"SUCCESS",
		"Revoked public key "+keyID.String(),
	)

	w.WriteHeader(http.StatusNoContent)
}

// RevokeAllKeys handles POST /users/{id}/public-keys/revoke-all (ADMIN only).
func (h *UserKeyHandler) RevokeAllKeys(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	actorID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}

	count, err := h.userKeyService.RevokeAllKeys(r.Context(), userID, actorID)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"PUBLIC_KEY_REVOKED",
			"User: "+userID.String(),
			"FAILED",
			"Failed to revoke all active public keys: "+err.Error(),
		)
		var appErr *model.AppError
		if errors.As(err, &appErr) {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to revoke keys."))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"PUBLIC_KEY_REVOKED",
		"User: "+userID.String(),
		"SUCCESS",
		"Revoked all active public keys",
	)

	writeJSON(w, http.StatusOK, map[string]any{"revoked_count": count})
}
