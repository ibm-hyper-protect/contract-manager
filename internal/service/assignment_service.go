package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// AssignmentService handles build-to-user-to-role assignments.
type AssignmentService struct {
	queries      repository.Querier
	auditService *AuditService
}

// NewAssignmentService creates a new AssignmentService.
func NewAssignmentService(queries repository.Querier, auditService *AuditService) *AssignmentService {
	return &AssignmentService{
		queries:      queries,
		auditService: auditService,
	}
}

// CreateAssignmentInput contains data for creating a build assignment.
type CreateAssignmentInput struct {
	BuildID    uuid.UUID
	RoleID     *uuid.UUID
	RoleName   string // Backward-compatible
	UserID     uuid.UUID
	AssignedBy uuid.UUID
	IPAddress  string
	Signature  *string
	SigHash    *string
}

// CreateAssignment assigns a user to a specific role for a build.
// This implements the two-layer access control: role + explicit assignment.
func (s *AssignmentService) CreateAssignment(ctx context.Context, input CreateAssignmentInput) (*repository.BuildAssignment, error) {
	// 1. Validate build exists and is not finalized
	build, err := s.queries.GetBuildByID(ctx, input.BuildID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, model.ErrNotFound("build not found")
		}
		return nil, fmt.Errorf("failed to get build: %w", err)
	}

	buildStatus := model.BuildStatus(build.Status)
	if buildStatus.IsTerminal() {
		return nil, model.ErrInvalidRequest(fmt.Sprintf("cannot assign users to %s build", buildStatus))
	}

	// 2. Validate role exists
	var role repository.Role
	if input.RoleID != nil && *input.RoleID != uuid.Nil {
		role, err = s.queries.GetRoleByID(ctx, *input.RoleID)
		if err != nil {
			if strings.Contains(err.Error(), "no rows") {
				return nil, model.ErrNotFound("role not found")
			}
			return nil, fmt.Errorf("failed to get role: %w", err)
		}
	} else {
		role, err = s.queries.GetRoleByName(ctx, input.RoleName)
		if err != nil {
			if strings.Contains(err.Error(), "no rows") {
				return nil, model.ErrNotFound(fmt.Sprintf("role '%s' not found", input.RoleName))
			}
			return nil, fmt.Errorf("failed to get role: %w", err)
		}
	}

	// Build-level persona assignments are intentionally restricted to workflow roles.
	switch model.PersonaRole(role.Name) {
	case model.RoleSolutionProvider, model.RoleDataOwner, model.RoleAuditor, model.RoleEnvOperator:
		// allowed
	default:
		return nil, model.ErrInvalidRequest(fmt.Sprintf("role '%s' is not assignable for build workflow", role.Name))
	}

	// 3. Validate user exists
	_, err = s.queries.GetUserByID(ctx, input.UserID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, model.ErrNotFound("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// User must hold the target persona role globally to be assignable for that role on a build.
	userRoles, err := s.queries.GetRolesByUserID(ctx, input.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	hasTargetRole := false
	for _, userRole := range userRoles {
		if userRole.Role == role.Name {
			hasTargetRole = true
			break
		}
	}
	if !hasTargetRole {
		return nil, model.ErrForbidden(fmt.Sprintf("user does not have role '%s'", role.Name))
	}

	// 4. Check if this specific user is already assigned to this role for this build
	alreadyAssigned, err := s.queries.CheckUserAssignedToBuild(ctx, repository.CheckUserAssignedToBuildParams{
		BuildID: input.BuildID,
		UserID:  input.UserID,
		RoleID:  role.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to check existing assignment: %w", err)
	}
	if alreadyAssigned {
		return nil, model.ErrInvalidRequest(fmt.Sprintf("user is already assigned to role '%s' for this build", input.RoleName))
	}

	// 5. Create the assignment
	assignment, err := s.queries.CreateBuildAssignment(ctx, repository.CreateBuildAssignmentParams{
		BuildID:    input.BuildID,
		RoleID:     role.ID,
		UserID:     input.UserID,
		AssignedBy: input.AssignedBy,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create assignment: %w", err)
	}

	// 6. Audit log the assignment
	eventData := map[string]string{
		"assignment_id": assignment.ID.String(),
		"role_name":     role.Name,
		"role_id":       role.ID.String(),
		"user_id":       input.UserID.String(),
	}
	if input.SigHash != nil && *input.SigHash != "" {
		eventData["request_signature_hash"] = *input.SigHash
	}

	_, err = s.auditService.LogEvent(ctx, LogEventInput{
		BuildID:     input.BuildID,
		EventType:   model.EventRoleAssigned,
		ActorUserID: input.AssignedBy,
		IpAddress:   input.IPAddress,
		EventData:   eventData,
		Signature:   input.Signature,
	})
	if err != nil {
		// Best effort audit logging: assignment should still succeed.
		slog.Error("failed to log assignment audit event",
			"error", err,
			"assignment_id", assignment.ID,
			"build_id", input.BuildID,
			"role_id", role.ID,
			"user_id", input.UserID,
		)
	}

	return &assignment, nil
}

// GetBuildAssignments returns all assignments for a build with enriched data.
func (s *AssignmentService) GetBuildAssignments(ctx context.Context, buildID uuid.UUID) ([]repository.GetBuildAssignmentsByBuildIDRow, error) {
	assignments, err := s.queries.GetBuildAssignmentsByBuildID(ctx, buildID)
	if err != nil {
		return nil, fmt.Errorf("failed to get build assignments: %w", err)
	}
	return assignments, nil
}

// GetUserAssignments returns all builds a user is assigned to.
func (s *AssignmentService) GetUserAssignments(ctx context.Context, userID uuid.UUID) ([]repository.GetBuildAssignmentsByUserIDRow, error) {
	assignments, err := s.queries.GetBuildAssignmentsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user assignments: %w", err)
	}
	return assignments, nil
}

// CheckUserAssignment verifies if a user is assigned to a specific role for a build.
func (s *AssignmentService) CheckUserAssignment(ctx context.Context, buildID, userID uuid.UUID, roleName string) (bool, error) {
	// Get role ID from name
	role, err := s.queries.GetRoleByName(ctx, roleName)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return false, nil // Role doesn't exist, so user can't be assigned
		}
		return false, fmt.Errorf("failed to get role: %w", err)
	}

	isAssigned, err := s.queries.CheckUserAssignedToBuild(ctx, repository.CheckUserAssignedToBuildParams{
		BuildID: buildID,
		UserID:  userID,
		RoleID:  role.ID,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check assignment: %w", err)
	}

	return isAssigned, nil
}

// DeleteBuildAssignments removes all assignments for a build (used when cancelling).
func (s *AssignmentService) DeleteBuildAssignments(ctx context.Context, buildID uuid.UUID, actorID uuid.UUID, ip string) error {
	// Verify build exists
	build, err := s.queries.GetBuildByID(ctx, buildID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return model.ErrNotFound("build not found")
		}
		return fmt.Errorf("failed to get build: %w", err)
	}

	buildStatus := model.BuildStatus(build.Status)
	if buildStatus.IsTerminal() {
		return model.ErrInvalidRequest(fmt.Sprintf("cannot delete assignments from %s build", buildStatus))
	}

	// Delete assignments
	err = s.queries.DeleteBuildAssignmentsByBuildID(ctx, buildID)
	if err != nil {
		return fmt.Errorf("failed to delete assignments: %w", err)
	}

	// Audit log
	_, err = s.auditService.LogEvent(ctx, LogEventInput{
		BuildID:     buildID,
		EventType:   model.EventRoleAssigned, // Reuse event type with negative context
		ActorUserID: actorID,
		IpAddress:   ip,
		EventData: map[string]string{
			"action": "delete_all_assignments",
		},
	})
	if err != nil {
		return fmt.Errorf("assignments deleted but failed to log audit event: %w", err)
	}

	return nil
}

// ValidateAssignmentForSubmission checks if a user can submit a section for a role.
// This enforces the two-layer access control.
func (s *AssignmentService) ValidateAssignmentForSubmission(ctx context.Context, buildID, userID uuid.UUID, roleName string) error {
	// Layer 1: RBAC (user must have the role globally).
	userRoles, err := s.queries.GetRolesByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to load user roles: %w", err)
	}
	hasRole := false
	for _, r := range userRoles {
		if r.Role == roleName {
			hasRole = true
			break
		}
	}
	if !hasRole {
		return model.ErrForbidden(fmt.Sprintf("user does not have role '%s'", roleName))
	}

	// Layer 2: Explicit build assignment.
	isAssigned, err := s.CheckUserAssignment(ctx, buildID, userID, roleName)
	if err != nil {
		return fmt.Errorf("failed to check assignment: %w", err)
	}

	if !isAssigned {
		return model.ErrForbidden(fmt.Sprintf("user is not assigned to role '%s' for this build", roleName))
	}

	return nil
}
