package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// SystemLogFn defines the function signature used by middleware to emit system logs.
type SystemLogFn func(ctx context.Context, email, action, resource, ipAddress, status, details string)

var (
	systemLogHookMu sync.RWMutex
	systemLogHook   SystemLogFn
	trustProxyIPs   atomic.Bool
)

// SetSystemLogHook wires a function used by middleware to persist security/system events.
func SetSystemLogHook(fn SystemLogFn) {
	systemLogHookMu.Lock()
	defer systemLogHookMu.Unlock()
	systemLogHook = fn
}

func emitSystemLog(ctx context.Context, email, action, resource, ipAddress, status, details string) {
	systemLogHookMu.RLock()
	hook := systemLogHook
	systemLogHookMu.RUnlock()
	if hook == nil {
		return
	}
	hook(ctx, email, action, resource, ipAddress, status, details)
}

// SetTrustProxyHeaders controls whether X-Forwarded-For / X-Real-IP should be trusted.
func SetTrustProxyHeaders(enabled bool) {
	trustProxyIPs.Store(enabled)
}

// RequestIP extracts the best-effort client IP from a request.
func RequestIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	if trustProxyIPs.Load() {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			if len(parts) > 0 {
				if ip := normalizeIP(parts[0]); ip != "" {
					return ip
				}
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			if ip := normalizeIP(realIP); ip != "" {
				return ip
			}
		}
	}

	if ip := normalizeIP(r.RemoteAddr); ip != "" {
		return ip
	}
	return "unknown"
}

func requestIP(r *http.Request) string {
	return RequestIP(r)
}

func actorEmailFromContext(r *http.Request, fallback string) string {
	if r == nil {
		return fallback
	}
	if email := GetUserEmail(r.Context()); email != "" {
		return email
	}
	return fallback
}

func normalizeIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")

	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	return ip.String()
}
