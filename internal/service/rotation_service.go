package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// RotationService handles credential rotation and expiry checks.
type RotationService struct {
	queries repository.Querier
}

// NewRotationService creates a new RotationService.
func NewRotationService(queries repository.Querier) *RotationService {
	return &RotationService{queries: queries}
}

// ExpiredCredentialsReport contains information about expired credentials.
type ExpiredCredentialsReport struct {
	ExpiredPasswords  []ExpiredPasswordInfo  `json:"expired_passwords"`
	ExpiredPublicKeys []ExpiredPublicKeyInfo `json:"expired_public_keys"`
	TotalExpired      int                    `json:"total_expired"`
	CheckedAt         time.Time              `json:"checked_at"`
}

// ExpiredPasswordInfo contains information about an expired password.
type ExpiredPasswordInfo struct {
	UserID      string    `json:"user_id"`
	UserName    string    `json:"user_name"`
	UserEmail   string    `json:"user_email"`
	PasswordAge string    `json:"password_age"`
	LastChanged time.Time `json:"last_changed"`
	MustChange  bool      `json:"must_change"`
}

// ExpiredPublicKeyInfo contains information about an expired public key.
type ExpiredPublicKeyInfo struct {
	UserID       string    `json:"user_id"`
	UserName     string    `json:"user_name"`
	UserEmail    string    `json:"user_email"`
	KeyAge       string    `json:"key_age"`
	RegisteredAt time.Time `json:"registered_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	DaysOverdue  int       `json:"days_overdue"`
}

// CheckExpiredCredentials checks for expired passwords and public keys.
func (s *RotationService) CheckExpiredCredentials(ctx context.Context) (*ExpiredCredentialsReport, error) {
	report := &ExpiredCredentialsReport{
		ExpiredPasswords:  []ExpiredPasswordInfo{},
		ExpiredPublicKeys: []ExpiredPublicKeyInfo{},
		CheckedAt:         time.Now(),
	}

	// Check expired passwords (90 days)
	expiredPasswords, err := s.queries.GetUsersWithExpiredPasswords(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get users with expired passwords: %w", err)
	}

	for _, user := range expiredPasswords {
		var lastChanged time.Time
		var passwordAge string

		if user.PasswordChangedAt.Valid {
			lastChanged = user.PasswordChangedAt.Time
			passwordAge = time.Since(lastChanged).Round(24 * time.Hour).String()
		} else {
			lastChanged = user.CreatedAt
			passwordAge = fmt.Sprintf("%s (never changed)", time.Since(lastChanged).Round(24*time.Hour))
		}

		report.ExpiredPasswords = append(report.ExpiredPasswords, ExpiredPasswordInfo{
			UserID:      user.ID.String(),
			UserName:    user.Name,
			UserEmail:   user.Email,
			PasswordAge: passwordAge,
			LastChanged: lastChanged,
			MustChange:  user.MustChangePassword,
		})
	}

	// Check expired public keys (90 days)
	expiredKeys, err := s.queries.GetUsersWithExpiredPublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get users with expired public keys: %w", err)
	}

	for _, user := range expiredKeys {
		var keyAge string
		var registeredAt, expiresAt time.Time
		var daysOverdue int

		if user.PublicKeyRegisteredAt.Valid {
			registeredAt = user.PublicKeyRegisteredAt.Time
			keyAge = time.Since(registeredAt).Round(24 * time.Hour).String()
		} else {
			keyAge = "never registered"
		}

		if user.PublicKeyExpiresAt.Valid {
			expiresAt = user.PublicKeyExpiresAt.Time
			daysOverdue = int(time.Since(expiresAt).Hours() / 24)
		}

		report.ExpiredPublicKeys = append(report.ExpiredPublicKeys, ExpiredPublicKeyInfo{
			UserID:       user.ID.String(),
			UserName:     user.Name,
			UserEmail:    user.Email,
			KeyAge:       keyAge,
			RegisteredAt: registeredAt,
			ExpiresAt:    expiresAt,
			DaysOverdue:  daysOverdue,
		})
	}

	report.TotalExpired = len(report.ExpiredPasswords) + len(report.ExpiredPublicKeys)

	return report, nil
}

// StartRotationMonitor starts a background goroutine that periodically checks for expired credentials.
// This should be called once at application startup.
func (s *RotationService) StartRotationMonitor(ctx context.Context, checkInterval time.Duration) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	slog.Info("credential rotation monitor started", "check_interval", checkInterval)

	for {
		select {
		case <-ctx.Done():
			slog.Info("credential rotation monitor stopped")
			return
		case <-ticker.C:
			report, err := s.CheckExpiredCredentials(ctx)
			if err != nil {
				slog.Error("failed to check expired credentials", "error", err)
				continue
			}

			if report.TotalExpired > 0 {
				slog.Warn("expired credentials detected",
					"expired_passwords", len(report.ExpiredPasswords),
					"expired_public_keys", len(report.ExpiredPublicKeys),
					"total", report.TotalExpired,
				)

				// Log details for each expired credential
				for _, pwd := range report.ExpiredPasswords {
					slog.Warn("expired password",
						"user_id", pwd.UserID,
						"user_email", pwd.UserEmail,
						"password_age", pwd.PasswordAge,
						"must_change", pwd.MustChange,
					)
				}

				for _, key := range report.ExpiredPublicKeys {
					slog.Warn("expired public key",
						"user_id", key.UserID,
						"user_email", key.UserEmail,
						"days_overdue", key.DaysOverdue,
					)
				}
			} else {
				slog.Debug("no expired credentials found")
			}
		}
	}
}

// ForcePasswordChange marks a user's password as requiring change.
func (s *RotationService) ForcePasswordChange(ctx context.Context, userID string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}

	err = s.queries.ForcePasswordChange(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("failed to force password change: %w", err)
	}
	return nil
}

// RevokeExpiredPublicKey revokes an expired public key.
func (s *RotationService) RevokeExpiredPublicKey(ctx context.Context, userID string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}

	err = s.queries.RevokePublicKey(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("failed to revoke public key: %w", err)
	}
	return nil
}
