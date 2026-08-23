// Package sbom implements the `lantern sbom` hook: scan a release binary
// with syft (CycloneDX SBOM) and grype (vulnerability report), persist both
// as artifacts, and record the CycloneDX path in the snapshot manifest via
// the sbom_ref field.
package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"lantern/internal/snapshot"
)

// Options configures a scan. Zero values are fine except Binary.
type Options struct {
	// Binary is the release binary to scan. Required.
	Binary string
	// OutDir is where artifacts are written (created if missing).
	// Default "out/sbom".
	OutDir string
	// Base is the artifact base name; default is the binary's file base
	// ("aclguard" → "aclguard.cdx.json", "aclguard.grype.json").
	Base string
	// Manifest is an optional manifest.json path to update with sbom_ref
	// (relative to the manifest's directory). Created if absent.
	Manifest string
	// Syft/Grype override the executables (default: resolved on PATH).
	Syft  string
	Grype string
	// Version is used in the manifest Generator field, e.g. "0.1.0".
	Version string
}

// Report summarizes a completed scan.
type Report struct {
	Binary             string
	CdxPath            string
	GrypePath          string
	ComponentCount     int
	VulnerabilityCount int
	ManifestPath       string
	ManifestUpdated    bool
	SBOMRef            string
}

// Run scans Binary with syft and grype, writes the CycloneDX and grype
// artifacts into OutDir, and (when Manifest is set) records sbom_ref.
func Run(ctx context.Context, opts Options) (*Report, error) {
	if opts.Binary == "" {
		return nil, errors.New("binary path required")
	}
	if _, err := os.Stat(opts.Binary); err != nil {
		return nil, fmt.Errorf("binary: %w", err)
	}
	if opts.OutDir == "" {
		opts.OutDir = "out/sbom"
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return nil, err
	}
	base := opts.Base
	if base == "" {
		base = filepath.Base(opts.Binary)
	}

	syft, err := resolveTool(opts.Syft, "syft", "https://github.com/anchore/syft")
	if err != nil {
		return nil, err
	}
	grype, err := resolveTool(opts.Grype, "grype", "https://github.com/anchore/grype")
	if err != nil {
		return nil, err
	}

	// syft → CycloneDX JSON (the report artifact).
	cdxPath := filepath.Join(opts.OutDir, base+".cdx.json")
	cdx, err := runTool(ctx, "syft", syft, "-q", opts.Binary, "-o", "cyclonedx-json")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cdxPath, cdx, 0o644); err != nil {
		return nil, err
	}

	// grype → JSON vulnerability report.
	grypePath := filepath.Join(opts.OutDir, base+".grype.json")
	grep, err := runTool(ctx, "grype", grype, "-q", opts.Binary, "-o", "json")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(grypePath, grep, 0o644); err != nil {
		return nil, err
	}

	rep := &Report{
		Binary:    opts.Binary,
		CdxPath:   cdxPath,
		GrypePath: grypePath,
	}
	rep.ComponentCount, err = cdxComponentCount(cdx)
	if err != nil {
		return nil, fmt.Errorf("syft output is not valid CycloneDX: %w", err)
	}
	rep.VulnerabilityCount, err = grypeMatchCount(grep)
	if err != nil {
		return nil, fmt.Errorf("grype output is not valid JSON: %w", err)
	}

	if opts.Manifest != "" {
		if err := updateManifest(opts.Manifest, cdxPath, opts.Version, rep); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

// resolveTool returns opts override or resolves name on PATH with an
// install hint when missing.
func resolveTool(override, name, installURL string) (string, error) {
	if override != "" {
		return override, nil
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH: install it (%s)", name, installURL)
	}
	return p, nil
}

// runTool executes tool with args, returning captured stdout; a non-zero
// exit yields an error carrying the stderr tail.
func runTool(ctx context.Context, name, tool string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, tool, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s: %w: %s", name, err, msg)
	}
	return stdout.Bytes(), nil
}

func cdxComponentCount(cdx []byte) (int, error) {
	var doc struct {
		Components []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(cdx, &doc); err != nil {
		return 0, err
	}
	return len(doc.Components), nil
}

func grypeMatchCount(grep []byte) (int, error) {
	var doc struct {
		Matches []json.RawMessage `json:"matches"`
	}
	if err := json.Unmarshal(grep, &doc); err != nil {
		return 0, err
	}
	return len(doc.Matches), nil
}

// updateManifest sets manifest.sbom_ref to cdxPath (relative to the
// manifest's directory). An existing manifest is loaded and preserved;
// a missing one is created with the schema version.
func updateManifest(manifestPath, cdxPath, version string, rep *Report) error {
	m, err := snapshot.LoadManifest(manifestPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("manifest: %w", err)
		}
		m = snapshot.NewManifest("lantern-sbom/" + version)
	}
	rel, err := filepath.Rel(filepath.Dir(manifestPath), cdxPath)
	if err != nil {
		rel = cdxPath
	}
	m.SBOMRef = rel
	if err := m.Save(manifestPath); err != nil {
		return err
	}
	rep.ManifestPath = manifestPath
	rep.ManifestUpdated = true
	rep.SBOMRef = rel
	return nil
}
