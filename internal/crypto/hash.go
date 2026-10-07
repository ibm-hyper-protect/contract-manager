package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// SHA256Hex computes the SHA256 hash of data and returns it as a hex string.
func SHA256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SHA256HexString computes the SHA256 hash of a string.
func SHA256HexString(s string) string {
	return SHA256Hex([]byte(s))
}

// SHA256File computes the SHA256 hash of a file's contents.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeGenesisHash computes the deterministic genesis hash for a build's audit chain.
// Format: SHA256("IBM_CC:" + buildID)
func ComputeGenesisHash(buildID string) string {
	seed := fmt.Sprintf("IBM_CC:%s", buildID)
	return SHA256Hex([]byte(seed))
}

// ComputeEventHash computes the hash of an audit event using canonical JSON.
// The hash is computed as: SHA256(canonical_json(event_data) + previous_hash)
func ComputeEventHash(eventDataJSON []byte, previousHash string) string {
	// Canonicalize JSON to avoid representation drift (e.g., JSONB round-trips).
	// If canonicalization fails, fall back to raw bytes to preserve backward compatibility.
	canonical := eventDataJSON
	if normalized, err := canonicalizeJSONBytes(eventDataJSON); err == nil {
		canonical = normalized
	}

	// Concatenate canonical JSON with previous hash
	payload := append(canonical, []byte(previousHash)...)
	return SHA256Hex(payload)
}

func canonicalizeJSONBytes(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []byte("null"), nil
	}

	var v interface{}
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return nil, err
	}

	// encoding/json marshaling is deterministic for maps (sorted keys).
	return json.Marshal(v)
}

// CanonicalizeJSON converts JSON to RFC 8785 canonical form.
// For now, we use a simplified approach - proper RFC 8785 implementation
// would require a dedicated library or custom implementation.
// This is a placeholder that should be replaced with proper canonical JSON.
func CanonicalizeJSON(data map[string]interface{}) ([]byte, error) {
	// TODO: Implement proper RFC 8785 canonical JSON
	// For now, we'll use Go's standard JSON marshaling with sorted keys
	// This is NOT RFC 8785 compliant but provides deterministic output

	// Note: A proper implementation would use a library like:
	// github.com/gibson042/canonicaljson-go
	// or implement RFC 8785 spec directly

	return []byte(fmt.Sprintf("%v", data)), nil
}
