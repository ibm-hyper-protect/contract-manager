package middleware

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements token bucket rate limiting per IP address.
type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	cleanup  time.Duration
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter.
// rate: requests per second
// burst: maximum burst size
// cleanup: how often to clean up old visitors
func NewRateLimiter(r rate.Limit, b int, cleanup time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     r,
		burst:    b,
		cleanup:  cleanup,
	}

	// Start cleanup goroutine
	go rl.cleanupVisitors()

	return rl
}

// getVisitor returns the rate limiter for the given IP address.
func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = &visitor{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupVisitors removes old visitors that haven't been seen recently.
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > rl.cleanup {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Limit returns a middleware that rate limits requests per IP address.
func (rl *RateLimiter) Limit() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP
			ip := requestIP(r)

			// Get rate limiter for this IP
			limiter := rl.getVisitor(ip)

			// Check if request is allowed
			if !limiter.Allow() {
				emitSystemLog(
					r.Context(),
					actorEmailFromContext(r, "unknown"),
					"RATE_LIMIT_EXCEEDED",
					"Rate Limiter",
					ip,
					"FAILED",
					"Request blocked due to rate limiting",
				)
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GlobalRateLimiter is a package-level rate limiter for convenience.
// Default: 10 requests per second, burst of 20, cleanup every 5 minutes
var GlobalRateLimiter = NewRateLimiter(10, 20, 5*time.Minute)

// RateLimit is a convenience middleware using the global rate limiter.
func RateLimit() func(http.Handler) http.Handler {
	return GlobalRateLimiter.Limit()
}

// StrictRateLimit returns a stricter rate limiter for sensitive endpoints.
// 2 requests per second, burst of 5
func StrictRateLimit() func(http.Handler) http.Handler {
	strictLimiter := NewRateLimiter(2, 5, 5*time.Minute)
	return strictLimiter.Limit()
}

// AuthRateLimit returns a rate limiter specifically for authentication endpoints.
// 5 requests per minute, burst of 3 (to prevent brute force)
func AuthRateLimit() func(http.Handler) http.Handler {
	authLimiter := NewRateLimiter(rate.Every(12*time.Second), 3, 10*time.Minute)
	return authLimiter.Limit()
}
