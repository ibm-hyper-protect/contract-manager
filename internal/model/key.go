package model

// BuildKeyType classifies build-scoped keys used by backend-native cryptography.
type BuildKeyType string

const (
	BuildKeyTypeSigning     BuildKeyType = "SIGNING"
	BuildKeyTypeAttestation BuildKeyType = "ATTESTATION"
)

// BuildKeyMode indicates how key material was registered.
type BuildKeyMode string

const (
	BuildKeyModeGenerate     BuildKeyMode = "generate"
	BuildKeyModeUploadPublic BuildKeyMode = "upload_public"
)

// BuildKeyStatus indicates whether a key is active.
type BuildKeyStatus string

const (
	BuildKeyStatusActive  BuildKeyStatus = "ACTIVE"
	BuildKeyStatusRevoked BuildKeyStatus = "REVOKED"
)

// AttestationVerdict is the verification outcome for uploaded evidence.
type AttestationVerdict string

const (
	AttestationVerdictVerified AttestationVerdict = "VERIFIED"
	AttestationVerdictRejected AttestationVerdict = "REJECTED"
)

// String returns the string form used in API responses.
func (v AttestationVerdict) String() string {
	return string(v)
}
