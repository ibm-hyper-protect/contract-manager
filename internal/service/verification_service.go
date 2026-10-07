package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

func signatureHashForEvent(eventType string, eventData []byte, defaultHash string) string {
	var payload map[string]interface{}
	if err := json.Unmarshal(eventData, &payload); err != nil {
		return defaultHash
	}

	// For BUILD_FINALIZED and CONTRACT_DOWNLOADED, prefer request_signature_hash if present
	// (v2 workflow), otherwise fall back to contract_hash (v1 workflow)
	if eventType == "BUILD_FINALIZED" || eventType == "CONTRACT_DOWNLOADED" {
		if v, ok := payload["request_signature_hash"].(string); ok && v != "" {
			return v
		}
		if v, ok := payload["contract_hash"].(string); ok && v != "" {
			return v
		}
	}

	// For other events, use request_signature_hash
	if v, ok := payload["request_signature_hash"].(string); ok && v != "" {
		return v
	}

	return defaultHash
}

func decodeContractYAMLBytes(contractYAML string) []byte {
	trimmed := strings.TrimSpace(contractYAML)
	if trimmed == "" {
		return []byte{}
	}

	// Newer builds may store raw YAML directly.
	if strings.Contains(trimmed, "\n") ||
		strings.Contains(trimmed, "workload:") ||
		strings.Contains(trimmed, "env:") {
		return []byte(contractYAML)
	}

	// Backward-compatible: older builds may store base64-encoded YAML.
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil {
		return decoded
	}

	// Fallback to raw bytes if value is not valid base64.
	return []byte(contractYAML)
}

// VerificationService handles audit trail and signature verification.
type VerificationService struct {
	queries repository.Querier
}

// NewVerificationService creates a new VerificationService.
func NewVerificationService(queries repository.Querier) *VerificationService {
	return &VerificationService{queries: queries}
}

// VerificationResult contains the result of hash chain verification.
type VerificationResult struct {
	IsValid         bool                `json:"is_valid"`
	TotalEvents     int                 `json:"total_events"`
	VerifiedEvents  int                 `json:"verified_events"`
	FailedEvents    []FailedEventDetail `json:"failed_events,omitempty"`
	GenesisHash     string              `json:"genesis_hash"`
	ChainIntact     bool                `json:"chain_intact"`
	SignaturesValid bool                `json:"signatures_valid"`
}

// FailedEventDetail contains information about a failed verification.
type FailedEventDetail struct {
	EventID      string `json:"event_id"`
	SequenceNo   int32  `json:"sequence_no"`
	FailureType  string `json:"failure_type"` // "hash_mismatch", "signature_invalid", "missing_signature"
	ExpectedHash string `json:"expected_hash,omitempty"`
	ActualHash   string `json:"actual_hash,omitempty"`
	Details      string `json:"details,omitempty"`
}

// VerifyBuildAuditChain verifies the integrity of the audit hash chain for a build.
// This checks:
// 1. Genesis hash is correct
// 2. Each event's hash is correctly computed from its data + previous hash
// 3. All signatures are valid against registered public keys
func (s *VerificationService) VerifyBuildAuditChain(ctx context.Context, buildID uuid.UUID) (*VerificationResult, error) {
	// Convert uuid.UUID to pgtype.UUID
	buildIDPg := pgtype.UUID{
		Bytes: buildID,
		Valid: true,
	}

	// Get all audit events for the build
	rows, err := s.queries.GetAuditEventsByBuildID(ctx, buildIDPg)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit events: %w", err)
	}

	if len(rows) == 0 {
		return &VerificationResult{
			IsValid:         true,
			TotalEvents:     0,
			VerifiedEvents:  0,
			FailedEvents:    []FailedEventDetail{},
			GenesisHash:     crypto.ComputeGenesisHash(buildID.String()),
			ChainIntact:     true,
			SignaturesValid: true,
		}, nil
	}

	result := &VerificationResult{
		IsValid:         true,
		TotalEvents:     len(rows),
		VerifiedEvents:  0,
		FailedEvents:    []FailedEventDetail{},
		ChainIntact:     true,
		SignaturesValid: true,
	}

	// Compute expected genesis hash
	result.GenesisHash = crypto.ComputeGenesisHash(buildID.String())

	// Verify each event in sequence
	for i, row := range rows {
		eventID := row.ID.String()
		seqNo := row.SequenceNo

		// 1. Verify previous hash
		var expectedPrevHash string
		if i == 0 {
			// First event should reference genesis hash
			expectedPrevHash = result.GenesisHash
		} else {
			// Subsequent events should reference previous event's hash
			expectedPrevHash = rows[i-1].EventHash
		}

		if row.PreviousEventHash != expectedPrevHash {
			result.IsValid = false
			result.ChainIntact = false
			result.FailedEvents = append(result.FailedEvents, FailedEventDetail{
				EventID:      eventID,
				SequenceNo:   seqNo,
				FailureType:  "hash_chain_broken",
				ExpectedHash: expectedPrevHash,
				ActualHash:   row.PreviousEventHash,
				Details:      "previous_event_hash does not match expected value",
			})
			continue
		}

		// 2. Verify event hash computation
		computedHash := crypto.ComputeEventHash(row.EventData, row.PreviousEventHash)
		if computedHash != row.EventHash {
			result.IsValid = false
			result.ChainIntact = false
			result.FailedEvents = append(result.FailedEvents, FailedEventDetail{
				EventID:      eventID,
				SequenceNo:   seqNo,
				FailureType:  "hash_mismatch",
				ExpectedHash: computedHash,
				ActualHash:   row.EventHash,
				Details:      "computed hash does not match stored hash",
			})
			continue
		}

		// 3. Verify signature if present
		if row.Signature != nil && row.ActorPublicKey != nil {
			hashToVerify := signatureHashForEvent(row.EventType, row.EventData, row.EventHash)
			err := crypto.VerifySignature(*row.ActorPublicKey, hashToVerify, *row.Signature)
			if err != nil {
				result.IsValid = false
				result.SignaturesValid = false
				result.FailedEvents = append(result.FailedEvents, FailedEventDetail{
					EventID:     eventID,
					SequenceNo:  seqNo,
					FailureType: "signature_invalid",
					Details:     fmt.Sprintf("signature verification failed: %v", err),
				})
				continue
			}
		} else if row.Signature == nil && requiresSignature(row.EventType) {
			// Some events should always have signatures
			result.IsValid = false
			result.SignaturesValid = false
			result.FailedEvents = append(result.FailedEvents, FailedEventDetail{
				EventID:     eventID,
				SequenceNo:  seqNo,
				FailureType: "missing_signature",
				Details:     fmt.Sprintf("event type %s requires a signature", row.EventType),
			})
			continue
		}

		// Event passed all checks
		result.VerifiedEvents++
	}

	return result, nil
}

// requiresSignature determines if an event type should have a signature.
func requiresSignature(eventType string) bool {
	// Events that should always be signed by the actor (v2 workflow)
	signedEvents := map[string]bool{
		"BUILD_CREATED":                 true,
		"SIGNING_KEY_CREATED":           true,
		"WORKLOAD_SUBMITTED":            true,
		"ENVIRONMENT_STAGED":            true,
		"ATTESTATION_KEY_REGISTERED":    true,
		"BUILD_FINALIZED":               true,
		"CONTRACT_DOWNLOADED":           true,
		"ATTESTATION_EVIDENCE_UPLOADED": true,
		"ATTESTATION_VERIFIED":          true,
	}
	return signedEvents[eventType]
}

// VerifyContractIntegrity verifies the finalized contract's integrity.
func (s *VerificationService) VerifyContractIntegrity(ctx context.Context, buildID uuid.UUID) (*ContractIntegrityResult, error) {
	// Get build
	build, err := s.queries.GetBuildByID(ctx, buildID)
	if err != nil {
		return nil, model.ErrBuildNotFound(buildID.String())
	}

	result := &ContractIntegrityResult{
		BuildID:     buildID.String(),
		IsFinalized: model.BuildStatus(build.Status) == model.StatusFinalized || model.BuildStatus(build.Status) == model.StatusContractDownloaded,
		IsImmutable: build.IsImmutable,
	}

	// If not finalized, return early
	if !result.IsFinalized {
		result.IsValid = false
		result.Details = "build is not finalized"
		return result, nil
	}

	// Verify contract exists
	if build.ContractYaml == nil || build.ContractHash == nil {
		result.IsValid = false
		result.Details = "contract data missing"
		return result, nil
	}

	result.ContractHash = *build.ContractHash

	// Compute hash of contract YAML bytes (supports both raw YAML and base64-encoded YAML).
	contractYAMLBytes := decodeContractYAMLBytes(*build.ContractYaml)
	computedHash := crypto.SHA256Hex(contractYAMLBytes)
	result.ComputedHash = computedHash

	// Verify hash matches
	if computedHash != *build.ContractHash {
		result.IsValid = false
		result.HashMatches = false
		result.Details = "computed hash does not match stored hash"
		return result, nil
	}

	result.HashMatches = true

	// Find the BUILD_FINALIZED event to verify signature
	buildIDPg := pgtype.UUID{
		Bytes: buildID,
		Valid: true,
	}
	events, err := s.queries.GetAuditEventsByBuildID(ctx, buildIDPg)
	if err != nil {
		result.IsValid = false
		result.Details = fmt.Sprintf("failed to get audit events: %v", err)
		return result, nil
	}

	// Find finalization event
	var finalizeEvent *repository.GetAuditEventsByBuildIDRow
	for _, event := range events {
		if event.EventType == "BUILD_FINALIZED" {
			finalizeEvent = &event
			break
		}
	}

	if finalizeEvent == nil {
		result.IsValid = false
		result.Details = "BUILD_FINALIZED event not found"
		return result, nil
	}

	// Verify signature if present
	if finalizeEvent.Signature != nil && finalizeEvent.ActorPublicKey != nil {
		// Use the same hash resolution logic as audit trail verification
		hashToVerify := signatureHashForEvent(finalizeEvent.EventType, finalizeEvent.EventData, *build.ContractHash)
		err := crypto.VerifySignature(*finalizeEvent.ActorPublicKey, hashToVerify, *finalizeEvent.Signature)
		if err != nil {
			result.IsValid = false
			result.SignatureValid = false
			result.Details = fmt.Sprintf("signature verification failed: %v", err)
			return result, nil
		}
		result.SignatureValid = true
	} else {
		result.IsValid = false
		result.SignatureValid = false
		result.Details = "finalization signature missing"
		return result, nil
	}

	// All checks passed
	result.IsValid = true
	result.Details = "contract integrity verified"
	return result, nil
}

// ContractIntegrityResult contains the result of contract integrity verification.
type ContractIntegrityResult struct {
	BuildID        string `json:"build_id"`
	IsValid        bool   `json:"is_valid"`
	IsFinalized    bool   `json:"is_finalized"`
	IsImmutable    bool   `json:"is_immutable"`
	ContractHash   string `json:"contract_hash,omitempty"`
	ComputedHash   string `json:"computed_hash,omitempty"`
	HashMatches    bool   `json:"hash_matches"`
	SignatureValid bool   `json:"signature_valid"`
	Details        string `json:"details"`
}

// VerifyEventSignature verifies a single event's signature against the actor's registered public key.
func (s *VerificationService) VerifyEventSignature(ctx context.Context, eventID uuid.UUID) (*SignatureVerificationResult, error) {
	// This would require a query to get a single event by ID
	// For now, we'll return a placeholder
	return nil, fmt.Errorf("not implemented: single event signature verification")
}

// SignatureVerificationResult contains the result of signature verification.
type SignatureVerificationResult struct {
	EventID       string `json:"event_id"`
	IsValid       bool   `json:"is_valid"`
	ActorUserID   string `json:"actor_user_id"`
	PublicKeyUsed string `json:"public_key_used,omitempty"`
	Details       string `json:"details"`
}
