package handler

import (
	"net/http"
	"strconv"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

type SystemLogHandler struct {
	systemLogService *service.SystemLogService
}

func NewSystemLogHandler(systemLogService *service.SystemLogService) *SystemLogHandler {
	return &SystemLogHandler{systemLogService: systemLogService}
}

// ListSystemLogs mapping to GET /system-logs
func (h *SystemLogHandler) ListSystemLogs(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 100
	offset := 0

	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	logs, err := h.systemLogService.ListSystemLogs(r.Context(), int32(limit), int32(offset))
	if err != nil {
		writeError(w, model.ErrInternal("Failed to fetch system logs."))
		return
	}

	// Make sure we never return null for empty slices
	if logs == nil {
		logs = []repository.SystemLog{} // fallback empty slice
	}

	writeJSON(w, http.StatusOK, logs)
}
