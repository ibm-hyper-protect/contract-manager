package contract

import "context"

// AssembleInput represents the sections needed to produce the final contract YAML.
type AssembleInput struct {
	EncryptedWorkload       string
	EncryptedEnvironment    string
	EncryptedAttestationKey string
	EnvWorkloadSignature    string
}

// Engine provides backend-native contract cryptography primitives.
type Engine interface {
	EncryptString(ctx context.Context, plaintext, certPEM string) (string, error)
	AssembleContract(ctx context.Context, in AssembleInput) (string, string, error)
	HpcrContractSign(ctx context.Context, contract, privateKey, password string) (string, string, string, error)
	HpcrContractTemplate(ctx context.Context, templateType string) (string, error)
	HpcrGetAttestationRecords(ctx context.Context, data, privateKey, password string) (string, error)
	HpcrVerifySignatureAttestationRecords(ctx context.Context, attestationRecords, signature, attestationCert string) error
	ListAvailableEncCertVersions(ctx context.Context) ([]string, error)
}
