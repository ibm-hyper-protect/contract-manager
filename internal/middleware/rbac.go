package middleware

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// RequireRole returns middleware that checks if the authenticated user has at least
// one of the specified roles. Must be used after Auth middleware.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasRole(r.Context(), roles...) {
				emitSystemLog(
					r.Context(),
					actorEmailFromContext(r, "unknown"),
					"ACCESS_FORBIDDEN",
					"RBAC",
					requestIP(r),
					"FAILED",
					"Missing required role(s): "+strings.Join(roles, ","),
				)
				writeForbidden(w, "You do not have the required role to access this resource.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOwnerOrAdmin returns middleware that checks if the authenticated user
// is either the resource owner (matching the URL param) or has the ADMIN role.
// This is used for token management endpoints where users can manage their own tokens.
func RequireOwnerOrAdmin(paramName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the resource owner ID from URL param
			paramValue := chi.URLParam(r, paramName)
			resourceOwnerID, err := uuid.Parse(paramValue)
			if err != nil {
				emitSystemLog(
					r.Context(),
					actorEmailFromContext(r, "unknown"),
					"ACCESS_FORBIDDEN",
					"RBAC",
					requestIP(r),
					"FAILED",
					"Invalid owner ID in URL parameter",
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":{"code":"INVALID_REQUEST","message":"Invalid user ID in URL."}}`))
				return
			}

			// Check if user is the owner or an admin
			userID, ok := GetUserID(r.Context())
			if !ok {
				emitSystemLog(
					r.Context(),
					"unknown",
					"AUTH_REQUEST_DENIED",
					"RBAC",
					requestIP(r),
					"FAILED",
					"Missing authenticated user context",
				)
				writeUnauthorized(w)
				return
			}

			if userID != resourceOwnerID && !HasRole(r.Context(), "ADMIN") {
				emitSystemLog(
					r.Context(),
					actorEmailFromContext(r, "unknown"),
					"ACCESS_FORBIDDEN",
					"RBAC",
					requestIP(r),
					"FAILED",
					"Owner-or-admin policy denied",
				)
				writeForbidden(w, "You can only access your own resources or must have ADMIN role.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireBuildAccess enforces build-level visibility:
// - ADMIN can access any build.
// - Non-admin users can only access builds where they have at least one assignment.
func RequireBuildAccess(queries repository.Querier, paramName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if HasRole(r.Context(), "ADMIN") {
				next.ServeHTTP(w, r)
				return
			}

			userID, ok := GetUserID(r.Context())
			if !ok {
				emitSystemLog(
					r.Context(),
					"unknown",
					"AUTH_REQUEST_DENIED",
					"RBAC",
					requestIP(r),
					"FAILED",
					"Missing authenticated user context for build access check",
				)
				writeUnauthorized(w)
				return
			}

			paramValue := chi.URLParam(r, paramName)
			buildID, err := uuid.Parse(paramValue)
			if err != nil {
				emitSystemLog(
					r.Context(),
					actorEmailFromContext(r, "unknown"),
					"ACCESS_FORBIDDEN",
					"RBAC",
					requestIP(r),
					"FAILED",
					"Invalid build ID in URL parameter",
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":{"code":"INVALID_REQUEST","message":"Invalid build ID in URL."}}`))
				return
			}

			assignments, err := queries.GetBuildAssignmentsByUserID(r.Context(), userID)
			if err != nil {
				emitSystemLog(
					r.Context(),
					actorEmailFromContext(r, "unknown"),
					"ACCESS_FORBIDDEN",
					"RBAC",
					requestIP(r),
					"FAILED",
					"Failed to evaluate build assignment access",
				)
				writeForbidden(w, "Unable to validate build access for this request.")
				return
			}

			for _, assignment := range assignments {
				if assignment.BuildID == buildID {
					next.ServeHTTP(w, r)
					return
				}
			}

			emitSystemLog(
				r.Context(),
				actorEmailFromContext(r, "unknown"),
				"ACCESS_FORBIDDEN",
				"RBAC",
				requestIP(r),
				"FAILED",
				"Build access denied: user is not assigned to this build",
			)
			writeForbidden(w, "You are not assigned to this build.")
		})
	}
}

func writeForbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":{"code":"FORBIDDEN","message":"` + msg + `"}}`))
}
