package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

const maxRequestBodySize = 1 << 20 // 1MB default for JSON requests

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// writeError writes a structured error response using AppError.
func writeError(w http.ResponseWriter, err *model.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    err.Code,
			"message": err.Message,
			"details": err.Details,
		},
	})
}

// readJSON decodes a JSON request body into dst, enforcing a size limit.
func readJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxRequestBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Ensure only one JSON object in body
	if decoder.More() {
		return fmt.Errorf("request body must contain a single JSON object")
	}

	return nil
}

// readJSONLarge decodes a JSON request body with a custom size limit (for large payloads like encrypted data).
func readJSONLarge(r *http.Request, dst any, maxSize int64) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxSize)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// drainBody reads and discards the remaining request body to allow connection reuse.
func drainBody(r *http.Request) {
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
}
