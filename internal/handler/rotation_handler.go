package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// RotationHandler handles credential rotation endpoints
type RotationHandler struct {
	rotationService  *service.RotationService
	systemLogService *service.SystemLogService
}

// NewRotationHandler creates a new rotation handler
func NewRotationHandler(rotationService *service.RotationService, systemLogService *service.SystemLogService) *RotationHandler {
	return &RotationHandler{
		rotationService:  rotationService,
		systemLogService: systemLogService,
	}
}

// GetExpiredCredentials returns a report of expired credentials
// GET /api/v1/rotation/expired
func (h *RotationHandler) GetExpiredCredentials(w http.ResponseWriter, r *http.Request) {
	report, err := h.rotationService.CheckExpiredCredentials(r.Context())
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"CREDENTIAL_ROTATION_CHECKED",
			"Rotation",
			"FAILED",
			"Failed to check expired credentials: "+err.Error(),
		)
		writeError(w, model.ErrInternal("Failed to check expired credentials"))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"CREDENTIAL_ROTATION_CHECKED",
		"Rotation",
		"SUCCESS",
		"Checked expired credentials",
	)

	writeJSON(w, http.StatusOK, report)
}

// ForcePasswordChange forces a user to change their password
// POST /api/v1/rotation/force-password-change/{user_id}
func (h *RotationHandler) ForcePasswordChange(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		writeError(w, model.ErrInvalidRequest("User ID is required"))
		return
	}

	err := h.rotationService.ForcePasswordChange(r.Context(), userID)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"FORCE_PASSWORD_CHANGE",
			"User: "+userID,
			"FAILED",
			"Failed to force password change: "+err.Error(),
		)
		writeError(w, model.ErrInternal("Failed to force password change"))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"FORCE_PASSWORD_CHANGE",
		"User: "+userID,
		"SUCCESS",
		"Forced password change",
	)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Password change forced successfully",
	})
}

// RevokeExpiredPublicKey revokes an expired public key
// POST /api/v1/rotation/revoke-key/{user_id}
func (h *RotationHandler) RevokeExpiredPublicKey(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		writeError(w, model.ErrInvalidRequest("User ID is required"))
		return
	}

	err := h.rotationService.RevokeExpiredPublicKey(r.Context(), userID)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"PUBLIC_KEY_REVOKED",
			"User: "+userID,
			"FAILED",
			"Failed to revoke public key: "+err.Error(),
		)
		writeError(w, model.ErrInternal("Failed to revoke public key"))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"PUBLIC_KEY_REVOKED",
		"User: "+userID,
		"SUCCESS",
		"Revoked public key",
	)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Public key revoked successfully",
	})
}
