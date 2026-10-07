package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// BuildHandler handles build management endpoints.
type BuildHandler struct {
	buildService     *service.BuildService
	systemLogService *service.SystemLogService
}

// NewBuildHandler creates a new BuildHandler.
func NewBuildHandler(buildService *service.BuildService, systemLogService *service.SystemLogService) *BuildHandler {
	return &BuildHandler{
		buildService:     buildService,
		systemLogService: systemLogService,
	}
}

// createBuildRequest is the JSON request body for POST /builds.
type createBuildRequest struct {
	Name string `json:"name"`
}

// CreateBuild handles POST /builds.
func (h *BuildHandler) CreateBuild(w http.ResponseWriter, r *http.Request) {
	var req createBuildRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	if req.Name == "" {
		writeError(w, model.ErrInvalidRequest("Build name is required."))
		return
	}

	actorID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}
	requestSignature := middleware.GetRequestSignature(r.Context())
	requestSignatureHash := middleware.GetRequestSignatureHash(r.Context())

	ip := requestIP(r)

	var sigPtr *string
	var sigHashPtr *string
	if requestSignature != "" {
		sigPtr = &requestSignature
	}
	if requestSignatureHash != "" {
		sigHashPtr = &requestSignatureHash
	}

	build, err := h.buildService.CreateBuild(r.Context(), req.Name, actorID, ip, sigPtr, sigHashPtr)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"BUILD_CREATED",
			"Build Management",
			"FAILED",
			"Failed to create build: "+err.Error(),
		)
		writeError(w, model.ErrInternal("Failed to create build."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"BUILD_CREATED",
		"Build: "+build.ID.String(),
		"SUCCESS",
		"Created build "+build.Name,
	)

	writeJSON(w, http.StatusCreated, build)
}

// GetBuild handles GET /builds/{id}.
func (h *BuildHandler) GetBuild(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	build, err := h.buildService.GetBuild(r.Context(), buildID)
	if err != nil {
		writeError(w, model.ErrBuildNotFound(buildID.String()))
		return
	}

	writeJSON(w, http.StatusOK, build)
}

// ListBuilds handles GET /builds.
func (h *BuildHandler) ListBuilds(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	status := r.URL.Query().Get("status")

	limit := int32(50) // default
	if limitStr != "" {
		if l, err := strconv.ParseInt(limitStr, 10, 32); err == nil && l > 0 && l <= 100 {
			limit = int32(l)
		}
	}

	offset := int32(0) // default
	if offsetStr != "" {
		if o, err := strconv.ParseInt(offsetStr, 10, 32); err == nil && o >= 0 {
			offset = int32(o)
		}
	}

	actorID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}
	roles := middleware.GetUserRoles(r.Context())

	builds, err := h.buildService.ListBuildsForUser(r.Context(), actorID, roles, limit, offset, status)
	if err != nil {
		writeError(w, model.ErrInternal("Failed to list builds."))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"builds": builds,
		"limit":  limit,
		"offset": offset,
	})
}

// CancelBuild handles POST /builds/{id}/cancel. ADMIN or AUDITOR.
func (h *BuildHandler) CancelBuild(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	actorID, _ := middleware.GetUserID(r.Context())
	roles := middleware.GetUserRoles(r.Context())
	ip := requestIP(r)

	// Transition to Cancelled
	err = h.buildService.TransitionStatus(r.Context(), buildID, model.StatusCancelled, actorID, ip, roles, nil, nil)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"BUILD_CANCELLED",
			"Build: "+buildID.String(),
			"FAILED",
			"Failed to cancel build: "+err.Error(),
		)
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to cancel build."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"BUILD_CANCELLED",
		"Build: "+buildID.String(),
		"SUCCESS",
		"Cancelled build",
	)

	writeJSON(w, http.StatusOK, map[string]string{"status": "CANCELLED"})
}
