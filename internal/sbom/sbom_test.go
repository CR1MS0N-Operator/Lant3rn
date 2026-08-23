package sbom

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDir holds Go-built fake syft/grype executables, shared across tests.
var fakeDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lantern-sbom-fakes-")
	if err != nil {
		panic(err)
	}
	for name, src := range map[string]string{
		"syft":  "../../testdata/sbom/fake/syft.go",
		"grype": "../../testdata/sbom/fake/grype.go",
	} {
		out := filepath.Join(dir, name)
		cmd := exec.Command("go", "build", "-o", out, src)
		if b, err := cmd.CombinedOutput(); err != nil {
			os.RemoveAll(dir)
			panic("build " + name + ": " + err.Error() + "\n" + string(b))
		}
	}
	fakeDir = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// writeBinary creates a throwaway "release binary" for scans.
func writeBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "aclguard")
	if err := os.WriteFile(p, []byte("ELF not required for fakes"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunWritesArtifactsAndCounts(t *testing.T) {
	bin := writeBinary(t)
	out := filepath.Join(t.TempDir(), "out", "sbom")

	rep, err := Run(context.Background(), Options{
		Binary: bin,
		OutDir: out,
		Syft:   filepath.Join(fakeDir, "syft"),
		Grype:  filepath.Join(fakeDir, "grype"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ComponentCount != 2 {
		t.Errorf("ComponentCount = %d, want 2", rep.ComponentCount)
	}
	if rep.VulnerabilityCount != 1 {
		t.Errorf("VulnerabilityCount = %d, want 1", rep.VulnerabilityCount)
	}
	for _, f := range []string{"aclguard.cdx.json", "aclguard.grype.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing artifact %s: %v", f, err)
		}
	}
}

func TestRunUpdatesManifestSBOMRef(t *testing.T) {
	bin := writeBinary(t)
	out := filepath.Join(t.TempDir(), "out")
	manifest := filepath.Join(out, "manifest.json")

	rep, err := Run(context.Background(), Options{
		Binary:   bin,
		OutDir:   filepath.Join(out, "sbom"),
		Manifest: manifest,
		Syft:     filepath.Join(fakeDir, "syft"),
		Grype:    filepath.Join(fakeDir, "grype"),
		Version:  "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ManifestUpdated {
		t.Fatal("ManifestUpdated = false")
	}
	// sbom_ref is relative to the manifest's directory.
	if rep.SBOMRef != "sbom/aclguard.cdx.json" {
		t.Errorf("SBOMRef = %q, want %q", rep.SBOMRef, "sbom/aclguard.cdx.json")
	}
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if want := `"sbom_ref": "sbom/aclguard.cdx.json"`; !strings.Contains(string(b), want) {
		t.Errorf("manifest missing %s:\n%s", want, b)
	}
	if want := `"schema_version": "1.0"`; !strings.Contains(string(b), want) {
		t.Errorf("manifest missing %s:\n%s", want, b)
	}
	if want := `"generator": "lantern-sbom/0.1.0"`; !strings.Contains(string(b), want) {
		t.Errorf("manifest missing %s:\n%s", want, b)
	}
}

func TestRunPreservesExistingManifestFields(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	manifest := filepath.Join(out, "manifest.json")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := writeBinary(t)
	if err := os.WriteFile(manifest, []byte(
		`{"schema_version":"1.0","generator":"aclguard/2.0.0","redacted":true,"node_count":7}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), Options{
		Binary:   bin,
		OutDir:   filepath.Join(out, "sbom"),
		Manifest: manifest,
		Syft:     filepath.Join(fakeDir, "syft"),
		Grype:    filepath.Join(fakeDir, "grype"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SBOMRef != "sbom/aclguard.cdx.json" {
		t.Errorf("SBOMRef = %q", rep.SBOMRef)
	}
	b, _ := os.ReadFile(manifest)
	s := string(b)
	for _, want := range []string{`"redacted": true`, `"node_count": 7`, `"generator": "aclguard/2.0.0"`, `"sbom_ref"`} {
		if !strings.Contains(s, want) {
			t.Errorf("manifest lost %s:\n%s", want, s)
		}
	}
}

func TestRunErrorsOnMissingBinary(t *testing.T) {
	_, err := Run(context.Background(), Options{
		Binary: filepath.Join(t.TempDir(), "nope"),
		Syft:   filepath.Join(fakeDir, "syft"),
		Grype:  filepath.Join(fakeDir, "grype"),
	})
	if err == nil {
		t.Fatal("want error for missing binary")
	}
}

func TestRunErrorsWhenSyftFails(t *testing.T) {
	bin := writeBinary(t)
	_, err := Run(context.Background(), Options{
		Binary: bin,
		OutDir: t.TempDir(),
		Syft:   "/nonexistent/syft",
		Grype:  filepath.Join(fakeDir, "grype"),
	})
	if err == nil {
		t.Fatal("want error for failing syft")
	}
}

func TestRunPropagatesToolExitFailure(t *testing.T) {
	bin := writeBinary(t)
	t.Setenv("FAKE_SYFT_EXIT", "7")
	_, err := Run(context.Background(), Options{
		Binary: bin,
		OutDir: t.TempDir(),
		Syft:   filepath.Join(fakeDir, "syft"),
		Grype:  filepath.Join(fakeDir, "grype"),
	})
	if err == nil {
		t.Fatal("want error when syft exits non-zero")
	}
}
