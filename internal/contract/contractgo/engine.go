package contractgo

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	hpcertificate "github.com/ibm-hyper-protect/contract-go/v2/certificate"
	hpcontract "github.com/ibm-hyper-protect/contract-go/v2/contract"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract"
	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
)

type encryptedEnvelope struct {
	Algorithm  string `json:"algorithm"`
	WrappedKey string `json:"wrapped_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Engine is a Go-native replacement for contract-cli cryptography calls.
type Engine struct{}

// New returns a contract-go engine implementation.
func New() *Engine {
	return &Engine{}
}

// The archive contains a compose.yaml with a placeholder image. Replace it with
// the workload archive for the target runtime before deployment.
const fallbackWorkloadTemplate = `type: workload
# Replace this example TGZ (compose.yaml) with your own Base64-encoded archive.
# The example image is registry.example/namespace/image:tag.
compose:
  archive: H4sIAAAAAAAA/+3PwQqDMAzGcc8+RZ9A6xAPvk0oQQQ7S9uN+fZzCmPs7jbY/3f5QggkcbMPc9JqET8VB7Grrm23XL2nbWzzrLd+Y09dVxh71EGvLilLXNd/YtcPShqvo9PUl8ZICI8wZvQyaG+iDmPKcan0Jj5MWp/FawritN4nsgzltx8AAAAAAAAAAAAAAAAAgD91B51whugAKAAA
`

const fallbackEnvTemplate = `type: env
# Configure one logging provider for your deployment.
logging:
  logRouter:
    hostname: logs.example.com
    iamApiKey: REPLACE_WITH_YOUR_API_KEY
    port: 443
# The registered build signing key is added by the backend.
env:
  EXAMPLE: "replace-me"
`

// EncryptString encrypts plaintext using the official contract-go v2 format:
// "contract-basic.<encrypted-password>.<encrypted-data>" for CCRT.
func (e *Engine) EncryptString(ctx context.Context, plaintext, certPEM string) (string, error) {
	if strings.TrimSpace(plaintext) == "" {
		return "", fmt.Errorf("plaintext section is required")
	}
	return encryptEnvelope(ctx, plaintext, certPEM)
}

func aesCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	return aead, nil
}

// AssembleContract builds deterministic YAML and computes SHA-256 hash.
func (e *Engine) AssembleContract(ctx context.Context, in contract.AssembleInput) (string, string, error) {
	_ = ctx
	for _, section := range []string{in.EncryptedWorkload, in.EncryptedEnvironment, in.EncryptedAttestationKey} {
		if err := validation.EncryptedSection(section); err != nil {
			return "", "", fmt.Errorf("assemble encrypted contract: %w", err)
		}
	}
	contractYAML := strings.TrimSpace(fmt.Sprintf(
		"env: %s\nworkload: %s\nenvWorkloadSignature: %s\nattestationPublicKey: %s\n",
		in.EncryptedEnvironment,
		in.EncryptedWorkload,
		in.EnvWorkloadSignature,
		in.EncryptedAttestationKey,
	))
	contractYAML += "\n"

	hash := appcrypto.SHA256HexString(contractYAML)
	return contractYAML, hash, nil
}

// HpcrContractSign provides a runtime-compatible signing hook.
// It delegates to contract-go/v2 and returns:
// 1) final signed contract YAML
// 2) SHA-256 of input contract YAML
// 3) SHA-256 of output signed contract YAML
func (e *Engine) HpcrContractSign(ctx context.Context, contractData, privateKeyPEM, password string) (string, string, string, error) {
	_ = ctx
	signedContract, inputChecksum, outputChecksum, err := hpcontract.HpcrContractSign(contractData, privateKeyPEM, password)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to sign contract with contract-go v2: %w", err)
	}

	return signedContract, inputChecksum, outputChecksum, nil
}

// HpcrContractTemplate returns editable, schema-valid CCRT starter templates.
// Keep the interface method name compatible with existing callers.
func (e *Engine) HpcrContractTemplate(ctx context.Context, templateType string) (string, error) {
	_ = ctx
	normalized := strings.ToLower(strings.TrimSpace(templateType))
	switch normalized {
	case "docker_compose", "docker-compose", "podman_play", "podman-play":
		// Preserve legacy aliases; the UI also offers an inline Podman template.
		normalized = "workload"
	}
	if template, ok := fallbackContractTemplate(normalized); ok {
		return template, nil
	}
	return "", fmt.Errorf("unsupported contract template type: %s", normalized)
}

func fallbackContractTemplate(templateType string) (string, bool) {
	switch templateType {
	case "workload":
		return fallbackWorkloadTemplate, true
	case "env":
		return fallbackEnvTemplate, true
	case "":
		indentedWorkload := strings.ReplaceAll(strings.TrimRight(fallbackWorkloadTemplate, "\n"), "\n", "\n  ")
		indentedEnv := strings.ReplaceAll(strings.TrimRight(fallbackEnvTemplate, "\n"), "\n", "\n  ")
		return "workload: |\n  " + indentedWorkload + "\n" +
			"env: |\n  " + indentedEnv + "\n", true
	default:
		return "", false
	}
}

// HpcrGetAttestationRecords decrypts attestation records when they are provided
// in the contract-go envelope format; otherwise returns data as-is.
func (e *Engine) HpcrGetAttestationRecords(ctx context.Context, data, privateKeyPEM, password string) (string, error) {
	_ = ctx
	trimmed := strings.TrimSpace(data)
	if trimmed == "" {
		return "", fmt.Errorf("attestation records payload is empty")
	}
	if !strings.HasPrefix(trimmed, "contract-go.v1.") {
		// v2 official format from contract-go library.
		if strings.HasPrefix(trimmed, "hyper-protect-basic.") || strings.HasPrefix(trimmed, "contract-basic.") {
			decrypted, err := decryptEnvelope(ctx, trimmed, privateKeyPEM, password)
			if err != nil {
				return "", fmt.Errorf("failed to decrypt hyper-protect-basic payload: %w", err)
			}
			return decrypted, nil
		}
		return trimmed, nil
	}

	privateKey, err := parseRSAPrivateKey(privateKeyPEM, password)
	if err != nil {
		return "", err
	}

	rawEnvelope, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(trimmed, "contract-go.v1."))
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted attestation envelope: %w", err)
	}

	var env encryptedEnvelope
	if err := json.Unmarshal(rawEnvelope, &env); err != nil {
		return "", fmt.Errorf("failed to decode attestation envelope JSON: %w", err)
	}

	wrappedKey, err := base64.StdEncoding.DecodeString(env.WrappedKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode wrapped key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, wrappedKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to unwrap symmetric key: %w", err)
	}

	aead, err := aesCipher(aesKey)
	if err != nil {
		return "", err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt attestation records: %w", err)
	}
	return string(plaintext), nil
}

// HpcrVerifySignatureAttestationRecords verifies attestation signature against
// attestation cert/public key using the same backend signature semantics.
func (e *Engine) HpcrVerifySignatureAttestationRecords(ctx context.Context, attestationRecords, signature, attestationCert string) error {
	_ = ctx
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return fmt.Errorf("attestation signature is empty")
	}

	verifyKey := strings.TrimSpace(attestationCert)
	if verifyKey == "" {
		return fmt.Errorf("attestation certificate/public key is required")
	}

	// Allow either PEM certificate or PEM public key.
	if cert, err := appcrypto.ParseCertificatePEM(verifyKey); err == nil {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("attestation certificate does not contain RSA public key")
		}
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return fmt.Errorf("failed to marshal attestation certificate public key: %w", err)
		}
		verifyKey = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubDER,
		}))
	}

	recordsHash := appcrypto.SHA256HexString(attestationRecords)
	if err := appcrypto.VerifySignature(verifyKey, recordsHash, signature); err != nil {
		return fmt.Errorf("attestation signature verification failed: %w", err)
	}
	return nil
}

func parseEncryptionPublicKey(certPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate/public key PEM")
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate public key is not RSA")
		}
		return pub, nil
	default:
		pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		pub, ok := pubAny.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA")
		}
		return pub, nil
	}
}

func parseRSAPrivateKey(privateKeyPEM, password string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}

	privateDER := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if password == "" {
			return nil, fmt.Errorf("encrypted private key requires password")
		}
		decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
		privateDER = decrypted
	}

	if key, err := x509.ParsePKCS1PrivateKey(privateDER); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return key, nil
}

// ListAvailableEncCertVersions returns the list of available encryption certificate versions
// by calling HpcrListAvailableEncCertVersions from contract-go certificate package.
// It returns all available certificate versions in JSON format.
func (e *Engine) ListAvailableEncCertVersions(ctx context.Context) ([]string, error) {
	_ = ctx
	// Get all available certificate versions in JSON format
	// Empty osType returns all OS types, "json" format returns structured data
	versionsJSON, err := hpcertificate.HpcrListAvailableEncCertVersions("", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to list available encryption certificate versions: %w", err)
	}

	// Parse the JSON response to extract version strings
	var certData map[string][]string
	if err := json.Unmarshal([]byte(versionsJSON), &certData); err != nil {
		return nil, fmt.Errorf("failed to parse certificate versions JSON: %w", err)
	}

	// Collect all unique versions from all OS types
	versionSet := make(map[string]bool)
	for _, versions := range certData {
		for _, version := range versions {
			versionSet[version] = true
		}
	}

	// Convert set to slice
	result := make([]string, 0, len(versionSet))
	for version := range versionSet {
		result = append(result, version)
	}

	return result, nil
}
