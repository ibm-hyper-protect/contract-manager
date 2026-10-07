package middleware

import (
	"context"

	"github.com/google/uuid"
)

// contextKey is an unexported type used for context keys in this package.
type contextKey string

const (
	userIDKey       contextKey = "user_id"
	userEmailKey    contextKey = "user_email"
	userRolesKey    contextKey = "user_roles"
	tokenHashKey    contextKey = "token_hash"
	setupNeededKey  contextKey = "setup_needed"
	setupPendingKey contextKey = "setup_pending"
	requestSigKey   contextKey = "request_signature"
	requestHashKey  contextKey = "request_signature_hash"
	requestIDKey    contextKey = "request_id"
)

// AuthenticatedUser holds the user info extracted from a valid token.
type AuthenticatedUser struct {
	UserID uuid.UUID
	Roles  []string
}

// SetAuthContext stores authentication information in the request context.
func SetAuthContext(ctx context.Context, userID uuid.UUID, userEmail string, roles []string, tokenHash string, setupNeeded bool, setupPending []string) context.Context {
	ctx = context.WithValue(ctx, userIDKey, userID)
	ctx = context.WithValue(ctx, userEmailKey, userEmail)
	ctx = context.WithValue(ctx, userRolesKey, roles)
	ctx = context.WithValue(ctx, tokenHashKey, tokenHash)
	ctx = context.WithValue(ctx, setupNeededKey, setupNeeded)
	ctx = context.WithValue(ctx, setupPendingKey, setupPending)
	return ctx
}

// GetUserID retrieves the authenticated user's ID from the context.
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

// GetUserEmail retrieves the authenticated user's email from the context.
func GetUserEmail(ctx context.Context) string {
	email, ok := ctx.Value(userEmailKey).(string)
	if !ok {
		return ""
	}
	return email
}

// GetUserRoles retrieves the authenticated user's roles from the context.
func GetUserRoles(ctx context.Context) []string {
	roles, ok := ctx.Value(userRolesKey).([]string)
	if !ok {
		return nil
	}
	return roles
}

// GetTokenHash retrieves the token hash from the context.
func GetTokenHash(ctx context.Context) string {
	hash, ok := ctx.Value(tokenHashKey).(string)
	if !ok {
		return ""
	}
	return hash
}

// IsSetupRequired indicates if the authenticated user is restricted to setup-only endpoints.
func IsSetupRequired(ctx context.Context) bool {
	required, ok := ctx.Value(setupNeededKey).(bool)
	if !ok {
		return false
	}
	return required
}

// GetSetupPending returns the pending setup actions for the authenticated user.
func GetSetupPending(ctx context.Context) []string {
	pending, ok := ctx.Value(setupPendingKey).([]string)
	if !ok {
		return nil
	}
	return pending
}

// HasRole checks if the authenticated user has any of the specified roles.
func HasRole(ctx context.Context, roles ...string) bool {
	userRoles := GetUserRoles(ctx)
	for _, required := range roles {
		for _, userRole := range userRoles {
			if userRole == required {
				return true
			}
		}
	}
	return false
}

// SetRequestSignatureContext stores validated request signature metadata in context.
func SetRequestSignatureContext(ctx context.Context, signature, signatureHash string) context.Context {
	ctx = context.WithValue(ctx, requestSigKey, signature)
	ctx = context.WithValue(ctx, requestHashKey, signatureHash)
	return ctx
}

// GetRequestSignature retrieves the validated request signature from context.
func GetRequestSignature(ctx context.Context) string {
	sig, ok := ctx.Value(requestSigKey).(string)
	if !ok {
		return ""
	}
	return sig
}

// GetRequestSignatureHash retrieves the validated request signature hash from context.
func GetRequestSignatureHash(ctx context.Context) string {
	hash, ok := ctx.Value(requestHashKey).(string)
	if !ok {
		return ""
	}
	return hash
}

// SetRequestIDContext stores the request ID in context.
func SetRequestIDContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves the request ID from context.
func GetRequestID(ctx context.Context) string {
	id, ok := ctx.Value(requestIDKey).(string)
	if !ok {
		return ""
	}
	return id
}
