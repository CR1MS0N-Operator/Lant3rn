// Package snapshot owns the Lantern native snapshot schema: nodes.jsonl,
// edges.jsonl, and manifest.json. Per D-004 (S186 spec §2.10) these Go
// structs are the source of truth; JSONL readers and adapters must not
// diverge from them.
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SchemaVersion is the frozen manifest schema version (S186 §2.10).
// Additive fields (like sbom_ref) are minor-compatible and do not bump it;
// breaking changes require a major bump that import/readers hard-error on.
const SchemaVersion = "1.0"

// Manifest is the snapshot metadata file written alongside nodes.jsonl and
// edges.jsonl. Fields follow S186 §2.10 (generator, collected_at,
// source_host, redacted, tls, adapter_pins) plus the harness-consumed counts
// from the NightForge integration plan and sbom_ref (S186 GRC task).
//
// sbom_ref points at the CycloneDX SBOM artifact for the release binary,
// relative to the manifest's own directory. It is set by `lantern sbom`.
type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	Generator     string            `json:"generator,omitempty"`
	CollectedAt   *time.Time        `json:"collected_at,omitempty"`
	SourceHost    string            `json:"source_host,omitempty"`
	Redacted      bool              `json:"redacted,omitempty"`
	TLS           *TLSInfo          `json:"tls,omitempty"`
	AdapterPins   map[string]string `json:"adapter_pins,omitempty"`
	NodeCount     int               `json:"node_count,omitempty"`
	EdgeCount     int               `json:"edge_count,omitempty"`
	SBOMRef       string            `json:"sbom_ref,omitempty"`
}

// TLSInfo records transport security posture of a collection (S186 §2.9);
// Insecure=true marks a lab-only `--insecure` run.
type TLSInfo struct {
	Insecure bool `json:"insecure"`
}

// NewManifest returns a schema-conformant manifest with SchemaVersion set.
// generator identifies the producing tool, e.g. "aclguard/2.0.0" for the
// collector or "lantern-sbom/0.1.0" for the SBOM hook.
func NewManifest(generator string) *Manifest {
	return &Manifest{SchemaVersion: SchemaVersion, Generator: generator}
}

// LoadManifest reads and validates a manifest.json. A missing file is
// reported as an *os.PathError so callers can distinguish create-vs-update.
func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	if m.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("manifest %s: unsupported schema_version %q (supported: %s)",
			path, m.SchemaVersion, SchemaVersion)
	}
	return &m, nil
}

// Save writes the manifest as pretty-printed JSON (deterministic field
// order via encoding/json struct order).
func (m *Manifest) Save(path string) error {
	if m.SchemaVersion == "" {
		m.SchemaVersion = SchemaVersion
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
