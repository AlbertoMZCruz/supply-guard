package check

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckCIInstallCommands_NpmInstall(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatal(err)
	}

	workflow := `name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
      - run: npm test
`
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	issues := CheckCIInstallCommands(dir)
	if len(issues) == 0 {
		t.Fatal("expected finding for 'npm install' in CI")
	}
	if issues[0].Command != "npm install" {
		t.Errorf("expected command 'npm install', got %q", issues[0].Command)
	}
}

func TestCheckCIInstallCommands_NpmCiIsSafe(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	workflow := `name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
      - run: npm test
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644)

	issues := CheckCIInstallCommands(dir)
	if len(issues) != 0 {
		t.Errorf("expected no issues for 'npm ci', got %d: %v", len(issues), issues)
	}
}

func TestCheckCIInstallCommands_PipWithoutHashes(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	workflow := `name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: pip install -r requirements.txt
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644)

	issues := CheckCIInstallCommands(dir)
	if len(issues) == 0 {
		t.Fatal("expected finding for pip install without --require-hashes")
	}
}

func TestCheckCIInstallCommands_NpmGlobalInstallIsSafe(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	workflow := `name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm install -g typescript
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644)

	issues := CheckCIInstallCommands(dir)
	if len(issues) != 0 {
		t.Errorf("expected no issues for global npm install, got %d", len(issues))
	}
}
