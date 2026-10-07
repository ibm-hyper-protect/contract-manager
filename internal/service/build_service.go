package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// BuildService handles the core state machine for contract builds.
type BuildService struct {
	queries      repository.Querier
	auditService *AuditService
}

// NewBuildService creates a new BuildService.
func NewBuildService(queries repository.Querier, auditService *AuditService) *BuildService {
	return &BuildService{
		queries:      queries,
		auditService: auditService,
	}
}

// CreateBuild initializes a new build and logs the genesis audit event.
func (s *BuildService) CreateBuild(ctx context.Context, name string, createdBy uuid.UUID, ip string, requestSignature *string, requestSignatureHash *string) (*repository.Build, error) {
	// 1. Create the build
	row, err := s.queries.CreateBuild(ctx, repository.CreateBuildParams{
		Name:      name,
		CreatedBy: createdBy,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create build: %w", err)
	}

	// Convert Row to Build
	build := &repository.Build{
		ID:                    row.ID,
		Name:                  row.Name,
		Status:                row.Status,
		CreatedBy:             row.CreatedBy,
		CreatedAt:             row.CreatedAt,
		FinalizedAt:           row.FinalizedAt,
		ContractHash:          row.ContractHash,
		ContractYaml:          row.ContractYaml,
		IsImmutable:           row.IsImmutable,
		EncryptionCertificate: nil, // Not returned by CreateBuild query
	}

	// 2. Log creation event via AuditService
	eventData := map[string]string{
		"build_id":   build.ID.String(),
		"build_name": name,
	}
	if requestSignatureHash != nil && *requestSignatureHash != "" {
		eventData["request_signature_hash"] = *requestSignatureHash
	}

	_, err = s.auditService.LogEvent(ctx, LogEventInput{
		BuildID:     build.ID,
		EventType:   model.EventBuildCreated,
		ActorUserID: createdBy,
		IpAddress:   ip,
		EventData:   eventData,
		Signature:   requestSignature,
	})
	if err != nil {
		// Log the error but don't fail the build creation entirely
		return build, fmt.Errorf("build created but failed to log audit event: %w", err)
	}

	return build, nil
}

// GetBuild returns a build by its ID.
func (s *BuildService) GetBuild(ctx context.Context, id uuid.UUID) (*repository.Build, error) {
	row, err := s.queries.GetBuildByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get build: %w", err)
	}

	// Convert Row to Build
	build := &repository.Build{
		ID:                    row.ID,
		Name:                  row.Name,
		Status:                row.Status,
		CreatedBy:             row.CreatedBy,
		CreatedAt:             row.CreatedAt,
		FinalizedAt:           row.FinalizedAt,
		ContractHash:          row.ContractHash,
		ContractYaml:          row.ContractYaml,
		IsImmutable:           row.IsImmutable,
		EncryptionCertificate: nil, // Not returned by GetBuildByID query
	}

	return build, nil
}

// ListBuilds returns a paginated list of builds, optionally filtered by status.
func (s *BuildService) ListBuilds(ctx context.Context, limit, offset int32, status string) ([]repository.ListBuildsRow, error) {
	var statusPtr *repository.BuildStatus
	if status != "" {
		bs := repository.BuildStatus(status)
		statusPtr = &bs
	}

	builds, err := s.queries.ListBuilds(ctx, repository.ListBuildsParams{
		Limit:  limit,
		Offset: offset,
		Status: statusPtr,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list builds: %w", err)
	}
	return builds, nil
}

func hasRole(userRoles []string, target string) bool {
	for _, role := range userRoles {
		if role == target {
			return true
		}
	}
	return false
}

func (s *BuildService) isUserAssignedToRoleForBuild(ctx context.Context, buildID, userID uuid.UUID, roleName string) (bool, error) {
	role, err := s.queries.GetRoleByName(ctx, roleName)
	if err != nil {
		return false, fmt.Errorf("failed to load role %s: %w", roleName, err)
	}

	assigned, err := s.queries.CheckUserAssignedToBuild(ctx, repository.CheckUserAssignedToBuildParams{
		BuildID: buildID,
		UserID:  userID,
		RoleID:  role.ID,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check build assignment: %w", err)
	}
	return assigned, nil
}

// ListBuildsForUser returns builds visible to the requesting user:
// - ADMIN sees all builds.
// - Non-admin users see only builds where they are explicitly assigned.
func (s *BuildService) ListBuildsForUser(ctx context.Context, userID uuid.UUID, userRoles []string, limit, offset int32, status string) ([]repository.ListBuildsRow, error) {
	if hasRole(userRoles, model.RoleAdmin.String()) {
		return s.ListBuilds(ctx, limit, offset, status)
	}

	assignments, err := s.queries.GetBuildAssignmentsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user assignments: %w", err)
	}

	seen := make(map[uuid.UUID]struct{})
	builds := make([]repository.ListBuildsRow, 0, len(assignments))
	statusFilter := strings.ToUpper(strings.TrimSpace(status))

	for _, assignment := range assignments {
		if _, exists := seen[assignment.BuildID]; exists {
			continue
		}
		seen[assignment.BuildID] = struct{}{}

		build, err := s.queries.GetBuildByID(ctx, assignment.BuildID)
		if err != nil {
			return nil, fmt.Errorf("failed to load assigned build %s: %w", assignment.BuildID, err)
		}

		if statusFilter != "" && strings.ToUpper(build.Status) != statusFilter {
			continue
		}

		builds = append(builds, repository.ListBuildsRow{
			ID:           build.ID,
			Name:         build.Name,
			Status:       build.Status,
			CreatedBy:    build.CreatedBy,
			CreatedAt:    build.CreatedAt,
			FinalizedAt:  build.FinalizedAt,
			ContractHash: build.ContractHash,
			IsImmutable:  build.IsImmutable,
		})
	}

	sort.Slice(builds, func(i, j int) bool {
		return builds[i].CreatedAt.After(builds[j].CreatedAt)
	})

	start := int(offset)
	if start >= len(builds) {
		return []repository.ListBuildsRow{}, nil
	}
	if start < 0 {
		start = 0
	}

	end := len(builds)
	if limit > 0 {
		candidate := start + int(limit)
		if candidate < end {
			end = candidate
		}
	}

	return builds[start:end], nil
}

// mapStatusToEvent helper matches build status with its corresponding audit event
func mapStatusToEvent(status model.BuildStatus) model.AuditEventType {
	switch status {
	case model.StatusSigningKeyRegistered:
		return model.EventSigningKeyCreated
	case model.StatusWorkloadSubmitted:
		return model.EventWorkloadSubmitted
	case model.StatusEnvironmentStaged:
		return model.EventEnvironmentStaged
	case model.StatusAttestationKeyRegistered:
		return model.EventAttestationKeyCreated
	case model.StatusFinalized:
		return model.EventBuildFinalized
	case model.StatusContractDownloaded:
		return model.EventContractDownloaded
	case model.StatusCancelled:
		return model.EventBuildCancelled
	default:
		return ""
	}
}

func statusEventRequiresRequestSignature(eventType model.AuditEventType) bool {
	switch eventType {
	case model.EventSigningKeyCreated,
		model.EventWorkloadSubmitted,
		model.EventEnvironmentStaged,
		model.EventAttestationKeyCreated:
		return true
	default:
		return false
	}
}

// TransitionStatus securely advances the build state.
func (s *BuildService) TransitionStatus(
	ctx context.Context,
	buildID uuid.UUID,
	newStatus model.BuildStatus,
	actorID uuid.UUID,
	ip string,
	userRoles []string,
	requestSignature *string,
	requestSignatureHash *string,
) error {
	if newStatus == model.StatusContractDownloaded {
		return model.ErrInvalidRequest("CONTRACT_DOWNLOADED is set by the acknowledge-download endpoint")
	}

	// 1. Get current build
	row, err := s.queries.GetBuildByID(ctx, buildID)
	if err != nil {
		return fmt.Errorf("build not found: %w", err)
	}

	currentStatus := model.BuildStatus(row.Status)

	// 2. Validate transition sequence
	if !currentStatus.CanTransitionTo(newStatus) {
		// Report the true expected next state from the current status when available.
		expected := newStatus.String()
		if next, ok := model.ValidTransitions[currentStatus]; ok {
			expected = next.String()
		}
		return model.ErrInvalidStateTransition(currentStatus.String(), expected)
	}

	// 3. Verify user has the required persona role for this specific transition
	roleRequired, exists := model.RequiredRoleForTransition[newStatus]
	if exists {
		hasRole := false
		for _, r := range userRoles {
			if r == roleRequired.String() {
				hasRole = true
				break
			}
		}
		if !hasRole {
			return model.ErrForbidden(fmt.Sprintf("Transition to %s requires %s role", newStatus, roleRequired))
		}

		assigned, err := s.isUserAssignedToRoleForBuild(ctx, buildID, actorID, roleRequired.String())
		if err != nil {
			return err
		}
		if !assigned {
			return model.ErrForbidden(fmt.Sprintf("Transition to %s requires assignment as %s for this build", newStatus, roleRequired))
		}
	}

	// 4. Resolve the event type and validate signature requirements before mutating state.
	eventType := mapStatusToEvent(newStatus)
	if statusEventRequiresRequestSignature(eventType) {
		if requestSignature == nil || *requestSignature == "" {
			return model.ErrInvalidRequest(fmt.Sprintf("request signature is required for status %s", newStatus))
		}
		if requestSignatureHash == nil || *requestSignatureHash == "" {
			return model.ErrInvalidRequest(fmt.Sprintf("request signature hash is required for status %s", newStatus))
		}
	}

	// 5. Update the build status in DB
	err = s.queries.UpdateBuildStatus(ctx, repository.UpdateBuildStatusParams{
		ID:     buildID,
		Status: newStatus.String(),
	})
	if err != nil {
		return fmt.Errorf("failed to update build status: %w", err)
	}

	// 6. Audit log
	if eventType != "" {
		eventData := map[string]string{
			"previous_status": currentStatus.String(),
			"new_status":      newStatus.String(),
		}
		signature := requestSignature
		if statusEventRequiresRequestSignature(eventType) {
			eventData["request_signature_hash"] = *requestSignatureHash
		} else {
			// Do not attach request signatures to events that verify against event_hash.
			signature = nil
		}

		_, err = s.auditService.LogEvent(ctx, LogEventInput{
			BuildID:     buildID,
			EventType:   eventType,
			ActorUserID: actorID,
			IpAddress:   ip,
			EventData:   eventData,
			Signature:   signature,
		})
		if err != nil {
			return fmt.Errorf("status updated but failed to log audit event: %w", err)
		}
	}

	return nil
}

// FinalizeBuild completes the contract build definitively.
func (s *BuildService) FinalizeBuild(ctx context.Context, buildID uuid.UUID, contractHash string, contractYaml string, actorID uuid.UUID, ip string, requestSignature *string, requestSignatureHash *string) error {
	row, err := s.queries.GetBuildByID(ctx, buildID)
	if err != nil {
		return fmt.Errorf("build not found: %w", err)
	}

	currentStatus := model.BuildStatus(row.Status)
	if !currentStatus.CanTransitionTo(model.StatusFinalized) {
		return model.ErrInvalidStateTransition(currentStatus.String(), model.StatusAttestationKeyRegistered.String())
	}

	assigned, err := s.isUserAssignedToRoleForBuild(ctx, buildID, actorID, model.RoleAuditor.String())
	if err != nil {
		return err
	}
	if !assigned {
		return model.ErrForbidden("only assigned AUDITOR can finalize this build")
	}

	// Finalize natively
	err = s.queries.FinalizeBuild(ctx, repository.FinalizeBuildParams{
		ID:           buildID,
		ContractYaml: &contractYaml,
		ContractHash: &contractHash,
	})
	if err != nil {
		return fmt.Errorf("failed to finalize build: %w", err)
	}

	// Audit Log the finalization
	// The request signature signs the finalization request (including passphrase hash)
	// The contract_hash in event data allows verification to use it as the signed content
	eventData := map[string]string{
		"contract_hash": contractHash,
	}
	if requestSignatureHash != nil && *requestSignatureHash != "" {
		eventData["request_signature_hash"] = *requestSignatureHash
	}

	_, err = s.auditService.LogEvent(ctx, LogEventInput{
		BuildID:     buildID,
		EventType:   model.EventBuildFinalized,
		ActorUserID: actorID,
		IpAddress:   ip,
		Signature:   requestSignature,
		EventData:   eventData,
	})
	if err != nil {
		return fmt.Errorf("build finalized but audit parsing failed: %w", err)
	}

	return nil
}
