package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// AssignmentHandler handles HTTP requests for build assignments.
type AssignmentHandler struct {
	assignmentService *service.AssignmentService
	systemLogService  *service.SystemLogService
}

// NewAssignmentHandler creates a new AssignmentHandler.
func NewAssignmentHandler(assignmentService *service.AssignmentService, systemLogService *service.SystemLogService) *AssignmentHandler {
	return &AssignmentHandler{
		assignmentService: assignmentService,
		systemLogService:  systemLogService,
	}
}

// CreateAssignmentRequest represents the request body for creating an assignment.
type CreateAssignmentRequest struct {
	RoleID   *uuid.UUID `json:"role_id,omitempty"`
	RoleName string     `json:"role_name,omitempty"` // backward compatible
	UserID   uuid.UUID  `json:"user_id"`
}

// CreateAssignment handles POST /builds/{id}/assignments
// @Summary Create a build assignment
// @Description Assign a user to a specific role for a build (Admin only)
// @Tags assignments
// @Accept json
// @Produce json
// @Param id path string true "Build ID"
// @Param request body CreateAssignmentRequest true "Assignment details"
// @Success 201 {object} repository.BuildAssignment
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /builds/{id}/assignments [post]
func (h *AssignmentHandler) CreateAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get build ID from URL
	buildIDStr := chi.URLParam(r, "id")
	buildID, err := uuid.Parse(buildIDStr)
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID format"))
		return
	}

	// Parse request body
	var req CreateAssignmentRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	// Validate required fields
	if req.RoleID == nil && req.RoleName == "" {
		writeError(w, model.ErrInvalidRequest("role_id is required"))
		return
	}
	if req.UserID == uuid.Nil {
		writeError(w, model.ErrInvalidRequest("user_id is required"))
		return
	}

	// Get authenticated user from context
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}
	requestSignature := middleware.GetRequestSignature(ctx)
	requestSignatureHash := middleware.GetRequestSignatureHash(ctx)
	ip := requestIP(r)

	var sigPtr *string
	var sigHashPtr *string
	if requestSignature != "" {
		sigPtr = &requestSignature
	}
	if requestSignatureHash != "" {
		sigHashPtr = &requestSignatureHash
	}

	// Create assignment
	assignment, err := h.assignmentService.CreateAssignment(ctx, service.CreateAssignmentInput{
		BuildID:    buildID,
		RoleID:     req.RoleID,
		RoleName:   req.RoleName,
		UserID:     req.UserID,
		AssignedBy: userID,
		IPAddress:  ip,
		Signature:  sigPtr,
		SigHash:    sigHashPtr,
	})
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"ASSIGNMENT_CREATED",
			"Build: "+buildID.String(),
			"FAILED",
			"Failed to create assignment: "+err.Error(),
		)
		// Check if it's an AppError
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to create assignment"))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"ASSIGNMENT_CREATED",
		"Build: "+buildID.String(),
		"SUCCESS",
		"Created assignment for user "+req.UserID.String(),
	)

	writeJSON(w, http.StatusCreated, assignment)
}

// GetBuildAssignments handles GET /builds/{id}/assignments
// @Summary Get build assignments
// @Description Get all user assignments for a build
// @Tags assignments
// @Produce json
// @Param id path string true "Build ID"
// @Success 200 {array} repository.GetBuildAssignmentsByBuildIDRow
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /builds/{id}/assignments [get]
func (h *AssignmentHandler) GetBuildAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get build ID from URL
	buildIDStr := chi.URLParam(r, "id")
	buildID, err := uuid.Parse(buildIDStr)
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID format"))
		return
	}

	// Get assignments
	assignments, err := h.assignmentService.GetBuildAssignments(ctx, buildID)
	if err != nil {
		writeError(w, model.ErrInternal("Failed to get build assignments"))
		return
	}

	writeJSON(w, http.StatusOK, assignments)
}

// GetUserAssignments handles GET /users/{id}/assignments
// @Summary Get user assignments
// @Description Get all builds a user is assigned to
// @Tags assignments
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {array} repository.GetBuildAssignmentsByUserIDRow
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /users/{id}/assignments [get]
func (h *AssignmentHandler) GetUserAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from URL
	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID format"))
		return
	}

	// Get assignments
	assignments, err := h.assignmentService.GetUserAssignments(ctx, userID)
	if err != nil {
		writeError(w, model.ErrInternal("Failed to get user assignments"))
		return
	}

	writeJSON(w, http.StatusOK, assignments)
}

// DeleteBuildAssignments handles DELETE /builds/{id}/assignments
// @Summary Delete all build assignments
// @Description Remove all user assignments for a build (Admin only)
// @Tags assignments
// @Param id path string true "Build ID"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /builds/{id}/assignments [delete]
func (h *AssignmentHandler) DeleteBuildAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get build ID from URL
	buildIDStr := chi.URLParam(r, "id")
	buildID, err := uuid.Parse(buildIDStr)
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID format"))
		return
	}

	// Get authenticated user from context
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}
	ip := requestIP(r)

	// Delete assignments
	err = h.assignmentService.DeleteBuildAssignments(ctx, buildID, userID, ip)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"ASSIGNMENTS_CLEARED",
			"Build: "+buildID.String(),
			"FAILED",
			"Failed to clear assignments: "+err.Error(),
		)
		// Check if it's an AppError
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to delete assignments"))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"ASSIGNMENTS_CLEARED",
		"Build: "+buildID.String(),
		"SUCCESS",
		"Cleared all assignments for build",
	)

	w.WriteHeader(http.StatusNoContent)
}
