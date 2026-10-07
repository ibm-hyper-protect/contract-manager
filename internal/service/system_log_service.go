package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// SystemLogService handles recording and fetching system-wide audit logs.
type SystemLogService struct {
	queries repository.Querier
}

// NewSystemLogService creates a new SystemLogService.
func NewSystemLogService(queries repository.Querier) *SystemLogService {
	return &SystemLogService{queries: queries}
}

// LogEvent records a new system log event across the backend cleanly.
func (s *SystemLogService) LogEvent(ctx context.Context, email, action, resource, ipAddress, status, details string) {
	// Attempt to store the log, but don't block/fail the parent request if it fails.
	// Instead, log heavily to stdout.
	var dbDetails *string
	if details != "" {
		dbDetails = &details
	}

	_, err := s.queries.CreateSystemLog(ctx, repository.CreateSystemLogParams{
		ActorEmail: email,
		Action:     action,
		Resource:   resource,
		IpAddress:  ipAddress,
		Status:     status,
		Details:    dbDetails,
	})

	if err != nil {
		slog.Error("failed to record system event securely", "action", action, "error", err)
	}
}

// ListSystemLogs retrieves paginated system logs.
func (s *SystemLogService) ListSystemLogs(ctx context.Context, limit, offset int32) ([]repository.SystemLog, error) {
	logs, err := s.queries.ListSystemLogs(ctx, repository.ListSystemLogsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch system logs: %w", err)
	}
	return logs, nil
}
