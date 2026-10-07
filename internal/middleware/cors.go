package middleware

import (
	"net/http"
	"strings"
)

// CORS adds Cross-Origin Resource Sharing headers using explicit allow-listing.
// Use CORS_ALLOW_ALL=true only for local development.
func CORS(allowedOrigins []string, allowAll bool) func(http.Handler) http.Handler {
	originSet := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" {
			continue
		}
		originSet[trimmed] = struct{}{}
	}

	isOriginAllowed := func(origin string) bool {
		if origin == "" {
			return true
		}
		if allowAll {
			return true
		}
		_, ok := originSet[origin]
		return ok
	}

	setHeaders := func(w http.ResponseWriter, origin string) {
		if allowAll {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, X-Request-ID, X-Signature, X-Signature-Hash, X-Timestamp, X-Key-Fingerprint")
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if !isOriginAllowed(origin) {
				http.Error(w, "CORS origin not allowed", http.StatusForbidden)
				return
			}

			setHeaders(w, origin)

			// Handle preflight requests.
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
