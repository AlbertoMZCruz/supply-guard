package cargo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestCheckCargoVersionRanges_DefaultCaret(t *testing.T) {
	dir := t.TempDir()
	toml := `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0.200"
tokio = { version = "1.37", features = ["full"] }
exact-dep = "=0.5.0"
`
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	findings := checkCargoVersionRanges(dir, "conservative")

	found := map[string]bool{}
	for _, f := range findings {
		if f.CheckID != types.CheckVersionRange {
			t.Errorf("expected SG011, got %s", f.CheckID)
		}
		found[f.Package] = true
	}

	if !found["serde"] {
		t.Error("expected finding for serde (bare 1.0.200 = ^1.0.200)")
	}
	if !found["tokio"] {
		t.Error("expected finding for tokio (1.37 = ^1.37)")
	}
	if found["exact-dep"] {
		t.Error("exact-dep uses =0.5.0 which should NOT be flagged")
	}
}

func TestCheckCargoVersionRanges_WildcardDangerous(t *testing.T) {
	dir := t.TempDir()
	toml := `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
wild = "*"
unbounded = ">=1.0.0"
`
	os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(toml), 0644)

	findings := checkCargoVersionRanges(dir, "conservative")
	if len(findings) < 2 {
		t.Errorf("expected at least 2 dangerous findings, got %d", len(findings))
	}
}

func TestParseCargoDepLine(t *testing.T) {
	tests := []struct {
		line        string
		wantName    string
		wantVersion string
	}{
		{`serde = "1.0.200"`, "serde", "1.0.200"},
		{`tokio = { version = "1.37", features = ["full"] }`, "tokio", "1.37"},
		{`rand = "=0.8.5"`, "rand", "=0.8.5"},
		{`empty = {}`, "empty", ""},
		{`bad line without equals`, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			name, version := parseCargoDepLine(tt.line)
			if name != tt.wantName {
				t.Errorf("name: got %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version: got %q, want %q", version, tt.wantVersion)
			}
		})
	}
}
