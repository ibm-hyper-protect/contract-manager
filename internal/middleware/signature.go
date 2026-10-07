package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

const signatureTolerance = 5 * time.Minute

// RequireRequestSignature enforces signed mutating requests.
func RequireRequestSignature(queries repository.Querier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isMutatingMethod(r.Method) || isSignatureExempt(r) {
				next.ServeHTTP(w, r)
				return
			}

			signature := r.Header.Get("X-Signature")
			signatureHash := r.Header.Get("X-Signature-Hash")
			timestampRaw := r.Header.Get("X-Timestamp")
			keyFingerprint := r.Header.Get("X-Key-Fingerprint")
			if signature == "" || signatureHash == "" || timestampRaw == "" {
				writeSignatureError(r, w, http.StatusBadRequest, "INVALID_SIGNATURE_HEADERS", "Missing signature headers.")
				return
			}

			tsMillis, err := strconv.ParseInt(timestampRaw, 10, 64)
			if err != nil {
				writeSignatureError(r, w, http.StatusBadRequest, "INVALID_SIGNATURE_HEADERS", "Invalid X-Timestamp.")
				return
			}
			ts := time.UnixMilli(tsMillis)
			if delta := time.Since(ts); delta > signatureTolerance || delta < -signatureTolerance {
				writeSignatureError(r, w, http.StatusUnauthorized, "SIGNATURE_EXPIRED", "Signature timestamp outside allowed window.")
				return
			}

			userID, ok := GetUserID(r.Context())
			if !ok {
				writeSignatureError(r, w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authentication context.")
				return
			}
			user, err := queries.GetUserByID(r.Context(), userID)
			if err != nil || user.PublicKey == nil {
				writeSignatureError(r, w, http.StatusForbidden, "SIGNATURE_KEY_MISSING", "Registered public key is required.")
				return
			}
			if user.PublicKeyFingerprint == nil || *user.PublicKeyFingerprint == "" {
				writeSignatureError(r, w, http.StatusForbidden, "SIGNATURE_KEY_MISSING", "Registered public key fingerprint is required.")
				return
			}
			if keyFingerprint != "" && keyFingerprint != *user.PublicKeyFingerprint {
				writeSignatureError(r, w, http.StatusForbidden, "INVALID_SIGNATURE", "Key fingerprint mismatch.")
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				writeSignatureError(r, w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to read request body.")
				return
			}
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			expectedHash, err := computeRequestHash(r.Method, r.URL.Path, tsMillis, bodyBytes)
			if err != nil {
				writeSignatureError(r, w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to compute request hash.")
				return
			}
			if signatureHash != expectedHash {
				writeSignatureError(r, w, http.StatusBadRequest, "HASH_MISMATCH", "Request hash does not match payload.")
				return
			}

			if err := crypto.VerifySignature(*user.PublicKey, expectedHash, signature); err != nil {
				writeSignatureError(r, w, http.StatusBadRequest, "INVALID_SIGNATURE", "Signature verification failed.")
				return
			}

			ctx := SetRequestSignatureContext(r.Context(), signature, signatureHash)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isMutatingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isSignatureExempt(r *http.Request) bool {
	// Setup-only endpoints must remain reachable before key registration.
	if r.Method == http.MethodPost && r.URL.Path == "/auth/logout" {
		return true
	}
	if r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/users/") && strings.HasSuffix(r.URL.Path, "/password") {
		return true
	}
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/users/") && strings.HasSuffix(r.URL.Path, "/public-key") {
		return true
	}
	return false
}

func computeRequestHash(method, path string, timestamp int64, body []byte) (string, error) {
	bodyPart := "null"
	if len(bytes.TrimSpace(body)) > 0 {
		// Ensure body is valid JSON before hashing.
		var raw json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			return "", fmt.Errorf("invalid json body: %w", err)
		}
		bodyPart = string(raw)
	}
	payload := fmt.Sprintf(`{"method":%q,"path":%q,"data":%s,"timestamp":%d}`, strings.ToUpper(method), path, bodyPart, timestamp)
	return crypto.SHA256HexString(payload), nil
}

func writeSignatureError(r *http.Request, w http.ResponseWriter, status int, code, message string) {
	emitSystemLog(
		r.Context(),
		actorEmailFromContext(r, "unknown"),
		"SIGNATURE_VALIDATION_FAILED",
		"Signature Middleware",
		requestIP(r),
		"FAILED",
		code+": "+message,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(fmt.Sprintf(`{"error":{"code":"%s","message":"%s"}}`, code, message)))
}
