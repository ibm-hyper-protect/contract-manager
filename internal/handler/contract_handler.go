package handler

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// ContractHandler handles backend-native contract operations.
type ContractHandler struct {
	contractService  *service.ContractService
	systemLogService *service.SystemLogService
}

// NewContractHandler creates a new ContractHandler.
func NewContractHandler(contractService *service.ContractService, systemLogService *service.SystemLogService) *ContractHandler {
	return &ContractHandler{
		contractService:  contractService,
		systemLogService: systemLogService,
	}
}

type submitWorkloadV2Request struct {
	Plaintext      string `json:"plaintext"`
	CertificatePEM string `json:"certificate_pem"`
}

type contractTemplateRequest struct {
	Type string `json:"type"`
}

// GetContractTemplate handles POST /contract-template.
// Contract templates are common and not tied to any specific build.
func (h *ContractHandler) GetContractTemplate(w http.ResponseWriter, r *http.Request) {
	var req contractTemplateRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}
	templateType := strings.TrimSpace(req.Type)
	resolvedType, content, err := h.contractService.GetContractTemplate(r.Context(), templateType)
	if err != nil {
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to load contract template."))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"template_type": resolvedType,
		"content":       content,
	})
}

// ListAvailableEncCertVersions handles GET /encryption-certificates/versions
func (h *ContractHandler) ListAvailableEncCertVersions(w http.ResponseWriter, r *http.Request) {
	versions, err := h.contractService.ListAvailableEncCertVersions(r.Context())
	if err != nil {
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to retrieve available encryption certificate versions."))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"versions": versions,
	})
}

// SubmitWorkload handles POST /builds/{id}/v2/sections/workload
func (h *ContractHandler) SubmitWorkload(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	var req submitWorkloadV2Request
	if err := readJSONLarge(r, &req, 50<<20); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	actorID, _ := middleware.GetUserID(r.Context())
	actorRoles := middleware.GetUserRoles(r.Context())
	ip := requestIP(r)
	sig := middleware.GetRequestSignature(r.Context())
	sigHash := middleware.GetRequestSignatureHash(r.Context())
	var sigPtr, sigHashPtr *string
	if sig != "" {
		sigPtr = &sig
	}
	if sigHash != "" {
		sigHashPtr = &sigHash
	}

	section, err := h.contractService.SubmitWorkloadSection(r.Context(), service.SubmitSectionV2Input{
		BuildID:              buildID,
		ActorID:              actorID,
		ActorRoles:           actorRoles,
		ActorIP:              ip,
		RequestSignature:     sigPtr,
		RequestSignatureHash: sigHashPtr,
		Plaintext:            req.Plaintext,
		CertificatePEM:       req.CertificatePEM,
	})
	if err != nil {
		logSystemEvent(h.systemLogService, r, "unknown", "WORKLOAD_SUBMITTED", "Build: "+buildID.String(), "FAILED", "Failed to submit workload: "+err.Error())
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to submit workload section."))
		return
	}

	logSystemEvent(h.systemLogService, r, "unknown", "WORKLOAD_SUBMITTED", "Build: "+buildID.String(), "SUCCESS", "Submitted workload section")
	writeJSON(w, http.StatusCreated, section)
}

type submitEnvironmentV2Request struct {
	Plaintext      string `json:"plaintext"`
	CertificatePEM string `json:"certificate_pem"`
}

// SubmitEnvironment handles POST /builds/{id}/v2/sections/environment
func (h *ContractHandler) SubmitEnvironment(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	var req submitEnvironmentV2Request
	if err := readJSONLarge(r, &req, 50<<20); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	actorID, _ := middleware.GetUserID(r.Context())
	actorRoles := middleware.GetUserRoles(r.Context())
	ip := requestIP(r)
	sig := middleware.GetRequestSignature(r.Context())
	sigHash := middleware.GetRequestSignatureHash(r.Context())
	var sigPtr, sigHashPtr *string
	if sig != "" {
		sigPtr = &sig
	}
	if sigHash != "" {
		sigHashPtr = &sigHash
	}

	section, err := h.contractService.SubmitEnvironmentSection(r.Context(), service.SubmitSectionV2Input{
		BuildID:              buildID,
		ActorID:              actorID,
		ActorRoles:           actorRoles,
		ActorIP:              ip,
		RequestSignature:     sigPtr,
		RequestSignatureHash: sigHashPtr,
		Plaintext:            req.Plaintext,
		CertificatePEM:       req.CertificatePEM,
	})
	if err != nil {
		logSystemEvent(h.systemLogService, r, "unknown", "ENVIRONMENT_SUBMITTED", "Build: "+buildID.String(), "FAILED", "Failed to submit environment: "+err.Error())
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to submit environment section."))
		return
	}

	logSystemEvent(h.systemLogService, r, "unknown", "ENVIRONMENT_SUBMITTED", "Build: "+buildID.String(), "SUCCESS", "Submitted environment section")
	writeJSON(w, http.StatusCreated, section)
}

type finalizeContractV2Request struct {
	SigningKeyPassphrase string `json:"signing_key_passphrase"`
}

// FinalizeContract handles POST /builds/{id}/finalize
func (h *ContractHandler) FinalizeContract(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	var req finalizeContractV2Request
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	actorID, _ := middleware.GetUserID(r.Context())
	actorRoles := middleware.GetUserRoles(r.Context())
	ip := requestIP(r)
	sig := middleware.GetRequestSignature(r.Context())
	sigHash := middleware.GetRequestSignatureHash(r.Context())
	var sigPtr, sigHashPtr *string
	if sig != "" {
		sigPtr = &sig
	}
	if sigHash != "" {
		sigHashPtr = &sigHash
	}

	result, err := h.contractService.FinalizeContract(r.Context(), service.FinalizeContractV2Input{
		BuildID:              buildID,
		ActorID:              actorID,
		ActorRoles:           actorRoles,
		ActorIP:              ip,
		RequestSignature:     sigPtr,
		RequestSignatureHash: sigHashPtr,
		SigningKeyPassphrase: req.SigningKeyPassphrase,
	})
	if err != nil {
		logSystemEvent(h.systemLogService, r, "unknown", "CONTRACT_FINALIZED", "Build: "+buildID.String(), "FAILED", "Failed to finalize contract: "+err.Error())
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		// Include actual error message for debugging
		writeError(w, model.ErrInternal("Failed to finalize contract: "+err.Error()))
		return
	}

	logSystemEvent(h.systemLogService, r, "unknown", "CONTRACT_FINALIZED", "Build: "+buildID.String(), "SUCCESS", "Finalized contract")
	writeJSON(w, http.StatusOK, result)
}
