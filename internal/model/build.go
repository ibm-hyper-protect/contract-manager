package model

// BuildStatus represents the lifecycle state of a build.
type BuildStatus string

const (
	StatusCreated                  BuildStatus = "CREATED"
	StatusSigningKeyRegistered     BuildStatus = "SIGNING_KEY_REGISTERED"
	StatusWorkloadSubmitted        BuildStatus = "WORKLOAD_SUBMITTED"
	StatusEnvironmentStaged        BuildStatus = "ENVIRONMENT_STAGED"
	StatusAttestationKeyRegistered BuildStatus = "ATTESTATION_KEY_REGISTERED"
	StatusFinalized                BuildStatus = "FINALIZED"
	StatusContractDownloaded       BuildStatus = "CONTRACT_DOWNLOADED"
	StatusCancelled                BuildStatus = "CANCELLED"
)

// AttestationState tracks post-finalization attestation evidence lifecycle.
type AttestationState string

const (
	AttestationStatePendingUpload AttestationState = "PENDING_UPLOAD"
	AttestationStateUploaded      AttestationState = "UPLOADED"
	AttestationStateVerified      AttestationState = "VERIFIED"
	AttestationStateRejected      AttestationState = "REJECTED"
)

// String returns the string representation of attestation state.
func (s AttestationState) String() string {
	return string(s)
}

// ValidTransitions defines the legal forward state transitions (v2 workflow).
var ValidTransitions = map[BuildStatus]BuildStatus{
	StatusCreated:                  StatusSigningKeyRegistered,
	StatusSigningKeyRegistered:     StatusWorkloadSubmitted,
	StatusWorkloadSubmitted:        StatusEnvironmentStaged,
	StatusEnvironmentStaged:        StatusAttestationKeyRegistered,
	StatusAttestationKeyRegistered: StatusFinalized,
	StatusFinalized:                StatusContractDownloaded,
}

// CanTransitionTo checks if a transition from the current status to the next is valid.
func (s BuildStatus) CanTransitionTo(next BuildStatus) bool {
	// Cancellation is allowed from any pre-finalized state.
	if next == StatusCancelled {
		return s != StatusFinalized && s != StatusContractDownloaded && s != StatusCancelled
	}
	expected, ok := ValidTransitions[s]
	return ok && expected == next
}

// IsTerminal returns true if the build is in a final state.
func (s BuildStatus) IsTerminal() bool {
	return s == StatusFinalized || s == StatusContractDownloaded || s == StatusCancelled
}

// String returns the string representation of the status.
func (s BuildStatus) String() string {
	return string(s)
}
