package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

type v2Store struct {
	db repository.DBTX
}

func newV2Store(db repository.DBTX) *v2Store {
	return &v2Store{db: db}
}

type buildKeyRow struct {
	ID                   uuid.UUID
	BuildID              uuid.UUID
	KeyType              model.BuildKeyType
	Mode                 model.BuildKeyMode
	Status               model.BuildKeyStatus
	PublicKey            string
	PublicKeyFingerprint string
	CreatedBy            uuid.UUID
	CreatedAt            time.Time
}

func (s *v2Store) createBuildKey(ctx context.Context, row buildKeyRow) (*buildKeyRow, error) {
	const q = `
INSERT INTO build_keys (
	id, build_id, key_type, mode, status, public_key, public_key_fingerprint, created_by
)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING id, build_id, key_type, mode, status, public_key, public_key_fingerprint, created_by, created_at
`
	var out buildKeyRow
	if err := s.db.QueryRow(ctx, q,
		row.ID,
		row.BuildID,
		string(row.KeyType),
		string(row.Mode),
		string(row.Status),
		row.PublicKey,
		row.PublicKeyFingerprint,
		row.CreatedBy,
	).Scan(
		&out.ID,
		&out.BuildID,
		&out.KeyType,
		&out.Mode,
		&out.Status,
		&out.PublicKey,
		&out.PublicKeyFingerprint,
		&out.CreatedBy,
		&out.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to create build key: %w", err)
	}
	return &out, nil
}

func (s *v2Store) getBuildKeyByID(ctx context.Context, keyID uuid.UUID) (*buildKeyRow, error) {
	const q = `
SELECT id, build_id, key_type, mode, status, public_key, public_key_fingerprint, created_by, created_at
FROM build_keys
WHERE id = $1
`
	var out buildKeyRow
	if err := s.db.QueryRow(ctx, q, keyID).Scan(
		&out.ID,
		&out.BuildID,
		&out.KeyType,
		&out.Mode,
		&out.Status,
		&out.PublicKey,
		&out.PublicKeyFingerprint,
		&out.CreatedBy,
		&out.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *v2Store) getLatestActiveBuildKeyByType(ctx context.Context, buildID uuid.UUID, keyType model.BuildKeyType) (*buildKeyRow, error) {
	const q = `
SELECT id, build_id, key_type, mode, status, public_key, public_key_fingerprint, created_by, created_at
FROM build_keys
WHERE build_id = $1 AND key_type = $2 AND status = 'ACTIVE'
ORDER BY created_at DESC
LIMIT 1
`
	var out buildKeyRow
	if err := s.db.QueryRow(ctx, q, buildID, string(keyType)).Scan(
		&out.ID,
		&out.BuildID,
		&out.KeyType,
		&out.Mode,
		&out.Status,
		&out.PublicKey,
		&out.PublicKeyFingerprint,
		&out.CreatedBy,
		&out.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

type attestationEvidenceRow struct {
	ID                uuid.UUID
	BuildID           uuid.UUID
	UploadedBy        uuid.UUID
	UploaderRole      model.PersonaRole
	RecordsFileName   string
	RecordsContent    []byte
	SignatureFileName string
	SignatureContent  []byte
	Metadata          map[string]interface{}
	CreatedAt         time.Time
}

func (s *v2Store) createAttestationEvidence(ctx context.Context, row attestationEvidenceRow) (*attestationEvidenceRow, error) {
	const q = `
INSERT INTO attestation_evidence (
	build_id, uploaded_by, uploader_role, records_file_name, records_content,
	signature_file_name, signature_content, metadata
)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING id, build_id, uploaded_by, uploader_role, records_file_name, records_content,
	signature_file_name, signature_content, metadata, created_at
`
	metadataRaw, err := json.Marshal(row.Metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence metadata: %w", err)
	}

	var out attestationEvidenceRow
	var storedMetadataRaw []byte
	if err := s.db.QueryRow(ctx, q,
		row.BuildID,
		row.UploadedBy,
		string(row.UploaderRole),
		row.RecordsFileName,
		row.RecordsContent,
		row.SignatureFileName,
		row.SignatureContent,
		metadataRaw,
	).Scan(
		&out.ID,
		&out.BuildID,
		&out.UploadedBy,
		&out.UploaderRole,
		&out.RecordsFileName,
		&out.RecordsContent,
		&out.SignatureFileName,
		&out.SignatureContent,
		&storedMetadataRaw,
		&out.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to create attestation evidence: %w", err)
	}
	out.Metadata = map[string]interface{}{}
	_ = json.Unmarshal(storedMetadataRaw, &out.Metadata)
	return &out, nil
}

func (s *v2Store) getAttestationEvidenceByID(ctx context.Context, evidenceID uuid.UUID) (*attestationEvidenceRow, error) {
	const q = `
SELECT id, build_id, uploaded_by, uploader_role, records_file_name, records_content,
	signature_file_name, signature_content, metadata, created_at
FROM attestation_evidence
WHERE id = $1
`
	var out attestationEvidenceRow
	var metadataRaw []byte
	if err := s.db.QueryRow(ctx, q, evidenceID).Scan(
		&out.ID,
		&out.BuildID,
		&out.UploadedBy,
		&out.UploaderRole,
		&out.RecordsFileName,
		&out.RecordsContent,
		&out.SignatureFileName,
		&out.SignatureContent,
		&metadataRaw,
		&out.CreatedAt,
	); err != nil {
		return nil, err
	}
	out.Metadata = map[string]interface{}{}
	_ = json.Unmarshal(metadataRaw, &out.Metadata)
	return &out, nil
}

type attestationVerificationRow struct {
	ID         uuid.UUID
	BuildID    uuid.UUID
	EvidenceID uuid.UUID
	VerifiedBy uuid.UUID
	Verdict    model.AttestationVerdict
	Details    map[string]interface{}
	CreatedAt  time.Time
}

func (s *v2Store) createAttestationVerification(ctx context.Context, row attestationVerificationRow) (*attestationVerificationRow, error) {
	const q = `
INSERT INTO attestation_verifications (build_id, evidence_id, verified_by, verdict, details)
VALUES ($1,$2,$3,$4,$5)
RETURNING id, build_id, evidence_id, verified_by, verdict, details, created_at
`
	detailsRaw, err := json.Marshal(row.Details)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verification details: %w", err)
	}

	var out attestationVerificationRow
	var storedDetailsRaw []byte
	if err := s.db.QueryRow(ctx, q,
		row.BuildID,
		row.EvidenceID,
		row.VerifiedBy,
		string(row.Verdict),
		detailsRaw,
	).Scan(
		&out.ID,
		&out.BuildID,
		&out.EvidenceID,
		&out.VerifiedBy,
		&out.Verdict,
		&storedDetailsRaw,
		&out.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to create attestation verification: %w", err)
	}
	out.Details = map[string]interface{}{}
	_ = json.Unmarshal(storedDetailsRaw, &out.Details)
	return &out, nil
}

func (s *v2Store) getLatestAttestationVerification(ctx context.Context, buildID uuid.UUID) (*attestationVerificationRow, error) {
	const q = `
SELECT id, build_id, evidence_id, verified_by, verdict, details, created_at
FROM attestation_verifications
WHERE build_id = $1
ORDER BY created_at DESC
LIMIT 1
`
	var out attestationVerificationRow
	var detailsRaw []byte
	if err := s.db.QueryRow(ctx, q, buildID).Scan(
		&out.ID,
		&out.BuildID,
		&out.EvidenceID,
		&out.VerifiedBy,
		&out.Verdict,
		&detailsRaw,
		&out.CreatedAt,
	); err != nil {
		return nil, err
	}
	out.Details = map[string]interface{}{}
	_ = json.Unmarshal(detailsRaw, &out.Details)
	return &out, nil
}

func (s *v2Store) countAttestationEvidenceByBuildID(ctx context.Context, buildID uuid.UUID) (int64, error) {
	const q = `SELECT COUNT(*) FROM attestation_evidence WHERE build_id = $1`

	var count int64
	if err := s.db.QueryRow(ctx, q, buildID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count attestation evidence: %w", err)
	}
	return count, nil
}

func (s *v2Store) updateBuildAttestationState(ctx context.Context, buildID uuid.UUID, state model.AttestationState, verifiedAt *time.Time, verifiedBy *uuid.UUID) error {
	const q = `
UPDATE builds
SET attestation_state = $2,
	attestation_verified_at = $3,
	attestation_verified_by = $4
WHERE id = $1
`
	_, err := s.db.Exec(ctx, q, buildID, string(state), verifiedAt, verifiedBy)
	if err != nil {
		return fmt.Errorf("failed to update build attestation state: %w", err)
	}
	return nil
}

func (s *v2Store) getBuildAttestationState(ctx context.Context, buildID uuid.UUID) (model.AttestationState, *time.Time, *uuid.UUID, error) {
	const q = `SELECT attestation_state, attestation_verified_at, attestation_verified_by FROM builds WHERE id = $1`
	var state string
	var verifiedAtRaw pgtype.Timestamptz
	var verifiedByRaw pgtype.UUID
	if err := s.db.QueryRow(ctx, q, buildID).Scan(&state, &verifiedAtRaw, &verifiedByRaw); err != nil {
		return "", nil, nil, err
	}
	var verifiedAt *time.Time
	var verifiedBy *uuid.UUID
	if verifiedAtRaw.Valid {
		t := verifiedAtRaw.Time
		verifiedAt = &t
	}
	if verifiedByRaw.Valid {
		id := uuid.UUID(verifiedByRaw.Bytes)
		verifiedBy = &id
	}
	return model.AttestationState(state), verifiedAt, verifiedBy, nil
}
