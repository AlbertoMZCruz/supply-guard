package check

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckNpmIntegrity_MissingHash(t *testing.T) {
	dir := t.TempDir()
	lock := `{
		"lockfileVersion": 3,
		"packages": {
			"": {},
			"node_modules/lodash": {
				"version": "4.17.21",
				"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
			},
			"node_modules/evil-pkg": {
				"version": "1.0.0",
				"resolved": "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz",
				"integrity": ""
			}
		}
	}`
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0644)

	issues := CheckNpmIntegrity(dir)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].IssueType != "missing_integrity" {
		t.Errorf("expected missing_integrity, got %s", issues[0].IssueType)
	}
	if issues[0].Package != "evil-pkg" {
		t.Errorf("expected evil-pkg, got %s", issues[0].Package)
	}
}

func TestCheckNpmIntegrity_GitSource(t *testing.T) {
	dir := t.TempDir()
	lock := `{
		"lockfileVersion": 3,
		"packages": {
			"": {},
			"node_modules/my-fork": {
				"version": "1.0.0",
				"resolved": "git+https://github.com/user/fork.git#abc123",
				"integrity": ""
			}
		}
	}`
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0644)

	issues := CheckNpmIntegrity(dir)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].IssueType != "git_source" {
		t.Errorf("expected git_source, got %s", issues[0].IssueType)
	}
}

func TestCheckNpmIntegrity_AllGood(t *testing.T) {
	dir := t.TempDir()
	lock := `{
		"lockfileVersion": 3,
		"packages": {
			"": {},
			"node_modules/lodash": {
				"version": "4.17.21",
				"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				"integrity": "sha512-abc123"
			}
		}
	}`
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0644)

	issues := CheckNpmIntegrity(dir)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues, got %d", len(issues))
	}
}

func TestCheckPipHashes_MixedHashes(t *testing.T) {
	dir := t.TempDir()
	req := `--require-hashes
requests==2.28.0 --hash=sha256:abc123
flask==2.3.0
`
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(req), 0644)

	issues := CheckPipHashes(dir)
	found := false
	for _, issue := range issues {
		if issue.Package == "flask" && issue.IssueType == "missing_integrity" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing_integrity for flask when --require-hashes is set")
	}
}

func TestCheckPipHashes_GitSource(t *testing.T) {
	dir := t.TempDir()
	req := `git+https://github.com/user/repo.git#egg=mypackage
requests==2.28.0
`
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(req), 0644)

	issues := CheckPipHashes(dir)
	found := false
	for _, issue := range issues {
		if issue.IssueType == "git_source" {
			found = true
		}
	}
	if !found {
		t.Error("expected git_source issue for git+ dependency")
	}
}

func TestCheckCargoChecksums_MissingChecksum(t *testing.T) {
	dir := t.TempDir()
	lock := `[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "evil-crate"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte(lock), 0644)

	issues := CheckCargoChecksums(dir)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].Package != "evil-crate" {
		t.Errorf("expected evil-crate, got %s", issues[0].Package)
	}
}

func TestCheckCargoChecksums_GitSource(t *testing.T) {
	dir := t.TempDir()
	lock := `[[package]]
name = "my-fork"
version = "0.1.0"
source = "git+https://github.com/user/fork#abc123"
`
	os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte(lock), 0644)

	issues := CheckCargoChecksums(dir)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].IssueType != "git_source" {
		t.Errorf("expected git_source, got %s", issues[0].IssueType)
	}
}

func TestCheckCargoChecksums_PathSourceIgnored(t *testing.T) {
	dir := t.TempDir()
	lock := `[[package]]
name = "my-local"
version = "0.1.0"
source = "path+file:///Users/me/local-crate"
`
	os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte(lock), 0644)

	issues := CheckCargoChecksums(dir)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for path source, got %d", len(issues))
	}
}

func TestCheckNuGetContentHash_Missing(t *testing.T) {
	dir := t.TempDir()
	lock := `{
		"version": 1,
		"dependencies": {
			"net8.0": {
				"Newtonsoft.Json": {
					"type": "Direct",
					"resolved": "13.0.3",
					"contentHash": "abc123"
				},
				"SomePackage": {
					"type": "Direct",
					"resolved": "1.0.0",
					"contentHash": ""
				}
			}
		}
	}`
	os.WriteFile(filepath.Join(dir, "packages.lock.json"), []byte(lock), 0644)

	issues := CheckNuGetContentHash(dir)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].Package != "SomePackage" {
		t.Errorf("expected SomePackage, got %s", issues[0].Package)
	}
}

func TestCheckCIProvenanceWorkflow_NoSLSA(t *testing.T) {
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
      - run: npm ci
`
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644)

	issue := CheckCIProvenanceWorkflow(dir)
	if issue == nil {
		t.Fatal("expected no_slsa_workflow issue")
	}
	if issue.IssueType != "no_slsa_workflow" {
		t.Errorf("expected no_slsa_workflow, got %s", issue.IssueType)
	}
}

func TestCheckCIProvenanceWorkflow_WithSLSA(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	workflow := `name: Release
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1
`
	os.WriteFile(filepath.Join(workflowDir, "release.yml"), []byte(workflow), 0644)

	issue := CheckCIProvenanceWorkflow(dir)
	if issue != nil {
		t.Error("expected no issue when SLSA is configured")
	}
}

func TestCheckCIProvenanceWorkflow_NoWorkflowDir(t *testing.T) {
	dir := t.TempDir()
	issue := CheckCIProvenanceWorkflow(dir)
	if issue != nil {
		t.Error("expected nil when no .github/workflows exists")
	}
}
