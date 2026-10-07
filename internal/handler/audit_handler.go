package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// AuditHandler handles audit trail endpoints.
type AuditHandler struct {
	auditService *service.AuditService
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(auditService *service.AuditService) *AuditHandler {
	return &AuditHandler{auditService: auditService}
}

// GetAuditTrail handles GET /builds/{id}/audit-trail.
func (h *AuditHandler) GetAuditTrail(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	events, err := h.auditService.GetAuditTrail(r.Context(), buildID)
	if err != nil {
		writeError(w, model.ErrInternal("Failed to get audit events."))
		return
	}

	if events == nil {
		events = []service.EnrichedAuditEvent{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"audit_events": events})
}
