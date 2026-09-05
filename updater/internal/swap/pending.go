package swap

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/synssins/PersonaCore-Agent/updater/internal/manifest"
)

// PendingUpdate mirrors the JSON written by
// workstation_agent.updater_client.handoff.stage_pending.
type PendingUpdate struct {
	SchemaVersion int                       `json:"schema_version"`
	Verified      bool                      `json:"verified"`
	AgentPID      int                       `json:"agent_pid"`
	Manifest      manifest.UpdateManifest   `json:"manifest"`
	ManifestB64   string                    `json:"manifest_b64"`
	SignatureB64  string                    `json:"signature_b64"`
}

// LoadPending reads and parses pending_update.json.
func LoadPending(path string) (*PendingUpdate, []byte, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pending: read %s: %w", path, err)
	}
	var p PendingUpdate
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, nil, nil, fmt.Errorf("pending: parse %s: %w", path, err)
	}
	if p.SchemaVersion != 1 {
		return nil, nil, nil, fmt.Errorf("pending: unsupported schema_version %d", p.SchemaVersion)
	}
	manifestBytes, err := base64.StdEncoding.DecodeString(p.ManifestB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pending: manifest_b64: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(p.SignatureB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pending: signature_b64: %w", err)
	}
	return &p, manifestBytes, sigBytes, nil
}
