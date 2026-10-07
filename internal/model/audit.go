package model

// AuditEventType represents the type of an audit event.
type AuditEventType string

const (
	EventBuildCreated          AuditEventType = "BUILD_CREATED"
	EventWorkloadSubmitted     AuditEventType = "WORKLOAD_SUBMITTED"
	EventEnvironmentStaged     AuditEventType = "ENVIRONMENT_STAGED"
	EventBuildFinalized        AuditEventType = "BUILD_FINALIZED"
	EventBuildCancelled        AuditEventType = "BUILD_CANCELLED"
	EventSigningKeyCreated     AuditEventType = "SIGNING_KEY_CREATED"
	EventAttestationKeyCreated AuditEventType = "ATTESTATION_KEY_REGISTERED"
	EventAttestationUploaded   AuditEventType = "ATTESTATION_EVIDENCE_UPLOADED"
	EventAttestationVerified   AuditEventType = "ATTESTATION_VERIFIED"
	EventUserCreated           AuditEventType = "USER_CREATED"
	EventRoleAssigned          AuditEventType = "ROLE_ASSIGNED"
	EventTokenCreated          AuditEventType = "TOKEN_CREATED"
	EventTokenRevoked          AuditEventType = "TOKEN_REVOKED"
	EventContractDownloaded    AuditEventType = "CONTRACT_DOWNLOADED"
)

// String returns the string representation of the event type.
func (e AuditEventType) String() string {
	return string(e)
}
