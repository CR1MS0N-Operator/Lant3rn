package snapshot

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewManifestDefaults(t *testing.T) {
	m := NewManifest("lantern-sbom/0.1.0")
	if m.SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %q, want %q", m.SchemaVersion, SchemaVersion)
	}
	if m.Generator != "lantern-sbom/0.1.0" {
		t.Errorf("Generator = %q", m.Generator)
	}
	// sbom_ref is an additive field: schema stays 1.0, never bumps.
	if m.SBOMRef != "" {
		t.Errorf("fresh manifest must not carry SBOMRef")
	}
}

func TestManifestRoundTrip(t *testing.T) {
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	m := NewManifest("aclguard/2.0.0")
	m.CollectedAt = &at
	m.SourceHost = "dc01.corp.local"
	m.Redacted = true
	m.TLS = &TLSInfo{Insecure: true}
	m.AdapterPins = map[string]string{"bhce": "v9.x"}
	m.NodeCount = 42
	m.EdgeCount = 137
	m.SBOMRef = "out/sbom/aclguard.cdx.json"

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var got Manifest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != m.SchemaVersion ||
		got.Generator != m.Generator ||
		got.SourceHost != m.SourceHost ||
		got.Redacted != m.Redacted ||
		got.TLS == nil || got.TLS.Insecure != true ||
		got.AdapterPins["bhce"] != "v9.x" ||
		got.NodeCount != 42 || got.EdgeCount != 137 ||
		got.SBOMRef != m.SBOMRef {
		t.Errorf("round-trip mismatch:\n%s", b)
	}
	if got.CollectedAt == nil || !got.CollectedAt.Equal(at) {
		t.Errorf("CollectedAt = %v, want %v", got.CollectedAt, at)
	}
}

func TestManifestZeroValueOmitsOptionalFields(t *testing.T) {
	// Diff-friendly output (S186 §2.4): optional fields stay absent.
	b, err := json.Marshal(NewManifest("lantern-sbom/0.1.0"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"collected_at", "source_host", "tls", "adapter_pins", "sbom_ref"} {
		if _, ok := m[absent]; ok {
			t.Errorf("field %q present in zero-value manifest: %s", absent, b)
		}
	}
	if _, ok := m["schema_version"]; !ok {
		t.Errorf("schema_version missing: %s", b)
	}
}

func TestManifestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	m := NewManifest("lantern-sbom/0.1.0")
	m.SBOMRef = "aclguard.cdx.json"
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.SBOMRef != "aclguard.cdx.json" || got.SchemaVersion != "1.0" {
		t.Errorf("load mismatch: %+v", got)
	}
}

func TestLoadManifestMissingFile(t *testing.T) {
	_, err := LoadManifest(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("want os.ErrNotExist, got %v", err)
	}
}

func TestLoadManifestRejectsForeignSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"9.9"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("want error for unsupported schema_version")
	}
}
