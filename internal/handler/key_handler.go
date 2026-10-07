package handler

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

type KeyHandler struct {
	keyService       *service.KeyService
	systemLogService *service.SystemLogService
}

func NewKeyHandler(keyService *service.KeyService, systemLogService *service.SystemLogService) *KeyHandler {
	return &KeyHandler{
		keyService:       keyService,
		systemLogService: systemLogService,
	}
}

type registerKeyRequest struct {
	Mode              string  `json:"mode"`
	PublicKey         *string `json:"public_key,omitempty"`
	Passphrase        *string `json:"passphrase,omitempty"`
	EncryptionCertPEM *string `json:"encryption_cert_pem,omitempty"`
}

// RegisterSigningKey handles POST /builds/{id}/keys/signing
func (h *KeyHandler) RegisterSigningKey(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	var req registerKeyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}
	mode := model.BuildKeyMode(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = model.BuildKeyModeGenerate
	}
	if mode == model.BuildKeyModeGenerate && (req.Passphrase == nil || strings.TrimSpace(*req.Passphrase) == "") {
		writeError(w, model.ErrInvalidRequest("Signing key passphrase is required."))
		return
	}

	actorID, _ := middleware.GetUserID(r.Context())
	actorRoles := middleware.GetUserRoles(r.Context())
	ip := requestIP(r)
	sig := middleware.GetRequestSignature(r.Context())
	sigHash := middleware.GetRequestSignatureHash(r.Context())
	var sigPtr *string
	var sigHashPtr *string
	if sig != "" {
		sigPtr = &sig
	}
	if sigHash != "" {
		sigHashPtr = &sigHash
	}

	result, err := h.keyService.RegisterSigningKey(
		r.Context(),
		buildID,
		actorID,
		mode,
		req.PublicKey,
		req.Passphrase,
		ip,
		actorRoles,
		sigPtr,
		sigHashPtr,
	)
	if err != nil {
		slog.Error("failed to register signing key", "build_id", buildID.String(), "actor_id", actorID.String(), "error", err)
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to register signing key."))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"signing_key_id": result.KeyID,
		"public_key":     result.PublicKey,
		"fingerprint":    result.Fingerprint,
		"mode":           result.Mode,
	})
}

// RegisterAttestationKey handles POST /builds/{id}/keys/attestation
func (h *KeyHandler) RegisterAttestationKey(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	var req registerKeyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}
	mode := model.BuildKeyMode(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = model.BuildKeyModeGenerate
	}
	if mode == model.BuildKeyModeGenerate && (req.Passphrase == nil || strings.TrimSpace(*req.Passphrase) == "") {
		writeError(w, model.ErrInvalidRequest("Attestation key passphrase is required."))
		return
	}
	if mode == model.BuildKeyModeGenerate && (req.EncryptionCertPEM == nil || strings.TrimSpace(*req.EncryptionCertPEM) == "") {
		writeError(w, model.ErrInvalidRequest("Encryption certificate is required to encrypt attestation public key."))
		return
	}

	actorID, _ := middleware.GetUserID(r.Context())
	actorRoles := middleware.GetUserRoles(r.Context())
	ip := requestIP(r)
	sig := middleware.GetRequestSignature(r.Context())
	sigHash := middleware.GetRequestSignatureHash(r.Context())
	var sigPtr *string
	var sigHashPtr *string
	if sig != "" {
		sigPtr = &sig
	}
	if sigHash != "" {
		sigHashPtr = &sigHash
	}

	result, exportToken, err := h.keyService.RegisterAttestationKey(
		r.Context(),
		buildID,
		actorID,
		mode,
		req.PublicKey,
		req.Passphrase,
		req.EncryptionCertPEM,
		ip,
		actorRoles,
		sigPtr,
		sigHashPtr,
	)
	if err != nil {
		slog.Error("failed to register attestation key", "build_id", buildID.String(), "actor_id", actorID.String(), "error", err)
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to register attestation key."))
		return
	}

	payload := map[string]interface{}{
		"attestation_key_id": result.KeyID,
		"public_key":         result.PublicKey,
		"fingerprint":        result.Fingerprint,
		"mode":               result.Mode,
	}
	if exportToken != nil {
		payload["private_export"] = exportToken
	}
	writeJSON(w, http.StatusCreated, payload)
}

// GetSigningPublicKey handles GET /builds/{id}/keys/signing/public
func (h *KeyHandler) GetSigningPublicKey(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}
	actorID, _ := middleware.GetUserID(r.Context())
	actorRoles := middleware.GetUserRoles(r.Context())

	result, err := h.keyService.GetLatestSigningPublicKey(r.Context(), buildID, actorID, actorRoles)
	if err != nil {
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to fetch signing public key."))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"signing_key_id": result.KeyID,
		"public_key":     result.PublicKey,
		"fingerprint":    result.Fingerprint,
		"mode":           result.Mode,
	})
}
