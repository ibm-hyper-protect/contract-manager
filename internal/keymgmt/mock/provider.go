package mock

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sync"

	"github.com/google/uuid"

	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/keymgmt"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

type storedKey struct {
	record     keymgmt.KeyRecord
	privateKey *rsa.PrivateKey
}

// Provider is a development-only in-memory key provider.
type Provider struct {
	mu   sync.RWMutex
	keys map[uuid.UUID]storedKey
}

// New creates an in-memory mock key provider.
func New() *Provider {
	return &Provider{
		keys: make(map[uuid.UUID]storedKey),
	}
}

func (p *Provider) CreateSigningKey(ctx context.Context, buildID, actorID uuid.UUID, mode model.BuildKeyMode, publicKeyPEM *string, passphrase *string) (keymgmt.KeyRecord, error) {
	return p.createKey(ctx, buildID, actorID, model.BuildKeyTypeSigning, mode, publicKeyPEM, passphrase)
}

func (p *Provider) CreateAttestationKey(ctx context.Context, buildID, actorID uuid.UUID, mode model.BuildKeyMode, publicKeyPEM *string, passphrase *string) (keymgmt.KeyRecord, *keymgmt.OneTimePrivateExport, error) {
	record, err := p.createKey(ctx, buildID, actorID, model.BuildKeyTypeAttestation, mode, publicKeyPEM, passphrase)
	if err != nil {
		return keymgmt.KeyRecord{}, nil, err
	}
	// Mock provider intentionally does not export private keys by default.
	return record, nil, nil
}

func (p *Provider) GetPublicKey(ctx context.Context, keyID uuid.UUID) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	key, ok := p.keys[keyID]
	if !ok {
		return "", fmt.Errorf("key not found")
	}
	return key.record.PublicKey, nil
}

func (p *Provider) GetPrivateKey(ctx context.Context, keyID uuid.UUID) ([]byte, error) {
	_ = ctx
	p.mu.RLock()
	key, ok := p.keys[keyID]
	p.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	if key.privateKey == nil {
		return nil, fmt.Errorf("private key unavailable for uploaded public-key mode")
	}

	privDER := x509.MarshalPKCS1PrivateKey(key.privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})
	if len(privPEM) == 0 {
		return nil, fmt.Errorf("failed to encode private key")
	}
	return privPEM, nil
}

func (p *Provider) SignDigest(ctx context.Context, keyID uuid.UUID, digestHex string) (string, error) {
	p.mu.RLock()
	key, ok := p.keys[keyID]
	p.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("key not found")
	}
	if key.privateKey == nil {
		return "", fmt.Errorf("key does not support signing")
	}

	// Match backend verifier semantics (RSA-SHA256 over the hash-hex string bytes).
	digest := sha256.Sum256([]byte(digestHex))
	signature, err := rsa.SignPSS(rand.Reader, key.privateKey, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return "", fmt.Errorf("failed to sign digest: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (p *Provider) createKey(ctx context.Context, buildID, actorID uuid.UUID, keyType model.BuildKeyType, mode model.BuildKeyMode, publicKeyPEM *string, passphrase *string) (keymgmt.KeyRecord, error) {
	_ = ctx
	record := keymgmt.KeyRecord{
		ID:        uuid.New(),
		BuildID:   buildID,
		Type:      keyType,
		Mode:      mode,
		Status:    model.BuildKeyStatusActive,
		CreatedBy: actorID,
	}

	var priv *rsa.PrivateKey
	switch mode {
	case model.BuildKeyModeGenerate:
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return keymgmt.KeyRecord{}, fmt.Errorf("failed to generate rsa key: %w", err)
		}
		priv = privateKey

		pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return keymgmt.KeyRecord{}, fmt.Errorf("failed to marshal public key: %w", err)
		}
		record.PublicKey = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubDER,
		}))
	case model.BuildKeyModeUploadPublic:
		if publicKeyPEM == nil || *publicKeyPEM == "" {
			return keymgmt.KeyRecord{}, fmt.Errorf("public key is required for upload_public mode")
		}
		if err := appcrypto.ValidatePublicKey(*publicKeyPEM); err != nil {
			return keymgmt.KeyRecord{}, fmt.Errorf("invalid public key: %w", err)
		}
		record.PublicKey = *publicKeyPEM
	default:
		return keymgmt.KeyRecord{}, fmt.Errorf("unsupported key mode: %s", mode)
	}

	fingerprint, err := appcrypto.ComputePublicKeyFingerprint(record.PublicKey)
	if err != nil {
		return keymgmt.KeyRecord{}, fmt.Errorf("failed to compute public key fingerprint: %w", err)
	}
	record.PublicKeyFingerprint = fingerprint

	p.mu.Lock()
	p.keys[record.ID] = storedKey{record: record, privateKey: priv}
	p.mu.Unlock()

	return record, nil
}
