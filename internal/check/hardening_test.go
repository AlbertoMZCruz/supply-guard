package check

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckNpmrcHardening_Missing(t *testing.T) {
	dir := t.TempDir()
	result := CheckNpmrcHardening(dir)
	if len(result.Missing) == 0 {
		t.Error("expected missing settings when .npmrc doesn't exist")
	}
}

func TestCheckNpmrcHardening_Hardened(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("ignore-scripts=true\n"), 0644)

	result := CheckNpmrcHardening(dir)
	if len(result.Missing) != 0 {
		t.Errorf("expected no missing settings, got: %v", result.Missing)
	}
}

func TestCheckNpmrcHardening_NotHardened(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("registry=https://registry.npmjs.org\n"), 0644)

	result := CheckNpmrcHardening(dir)
	if len(result.Missing) == 0 {
		t.Error("expected missing settings when ignore-scripts is not set")
	}
}

func TestCheckGitHubActionsPinning(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	workflow := `name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@0a44ba7841725637a19e28fa30b79a866c81b0a6
      - run: npm test
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644)

	issues := CheckGitHubActionsPinning(dir)
	if len(issues) != 1 {
		t.Errorf("expected 1 unpinned action, got %d", len(issues))
		for _, i := range issues {
			t.Logf("  action: %s at %s:%d", i.Action, i.File, i.Line)
		}
	}
}
