package cargo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestDetect_WithCargoToml(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[package]\nname = \"test\"\n"), 0644)

	a := &CargoAnalyzer{}
	if !a.Detect(dir) {
		t.Error("expected Detect to return true with Cargo.toml")
	}
}

func TestDetect_WithoutCargoFiles(t *testing.T) {
	dir := t.TempDir()
	a := &CargoAnalyzer{}
	if a.Detect(dir) {
		t.Error("expected Detect to return false without cargo files")
	}
}

func TestCheckCargoLockfile_Missing(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[package]\nname = \"test\"\n"), 0644)

	findings := checkCargoLockfile(dir)
	if len(findings) == 0 {
		t.Fatal("expected finding for missing Cargo.lock")
	}
	if findings[0].CheckID != types.CheckLockfileIntegrity {
		t.Errorf("expected CheckID %s, got %s", types.CheckLockfileIntegrity, findings[0].CheckID)
	}
}

func TestParseCargoLock(t *testing.T) {
	dir := t.TempDir()
	lockContent := `[[package]]
name = "serde"
version = "1.0.200"

[[package]]
name = "tokio"
version = "1.37.0"
`
	lockPath := filepath.Join(dir, "Cargo.lock")
	os.WriteFile(lockPath, []byte(lockContent), 0644)

	deps := parseCargoLock(lockPath)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if deps[0].Name != "serde" || deps[0].Version != "1.0.200" {
		t.Errorf("unexpected first dep: %+v", deps[0])
	}
}
