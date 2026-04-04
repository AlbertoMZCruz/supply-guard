package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/analyzer"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type stubAnalyzer struct {
	name      string
	ecosystem string
	detected  bool
	findings  []types.Finding
	err       error
}

func (s *stubAnalyzer) Name() string      { return s.name }
func (s *stubAnalyzer) Ecosystem() string  { return s.ecosystem }
func (s *stubAnalyzer) Detect(dir string) bool { return s.detected }
func (s *stubAnalyzer) Analyze(ctx context.Context, dir string, cfg *config.Config) ([]types.Finding, error) {
	return s.findings, s.err
}

func TestEngine_Scan_EmptyProject(t *testing.T) {
	analyzer.ResetForTesting()
	defer analyzer.ResetForTesting()

	analyzer.Register(&stubAnalyzer{
		name: "test-stub", ecosystem: "test", detected: true,
		findings: []types.Finding{},
	})

	dir := t.TempDir()
	cfg := defaultConfig()
	eng := New(cfg)
	result, err := eng.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestEngine_Scan_CollectsFindings(t *testing.T) {
	analyzer.ResetForTesting()
	defer analyzer.ResetForTesting()

	analyzer.Register(&stubAnalyzer{
		name: "test-findings", ecosystem: "test", detected: true,
		findings: []types.Finding{
			{CheckID: types.CheckIOCMatch, Severity: types.SeverityCritical, Title: "test finding"},
			{CheckID: types.CheckConfigHardening, Severity: types.SeverityMedium, Title: "test hardening"},
		},
	})

	dir := t.TempDir()
	cfg := defaultConfig()
	eng := New(cfg)
	result, err := eng.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", result.Summary.Critical)
	}
	if result.Summary.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", result.Summary.Medium)
	}
	if result.Summary.Total != 2 {
		t.Errorf("expected 2 total, got %d", result.Summary.Total)
	}
}

func TestEngine_Scan_SkipsUndetectedEcosystem(t *testing.T) {
	analyzer.ResetForTesting()
	defer analyzer.ResetForTesting()

	analyzer.Register(&stubAnalyzer{
		name: "not-detected", ecosystem: "test", detected: false,
		findings: []types.Finding{{Title: "should not appear"}},
	})

	dir := t.TempDir()
	cfg := defaultConfig()
	eng := New(cfg)
	result, err := eng.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for undetected ecosystem, got %d", len(result.Findings))
	}
}

func TestEngine_FilterIgnored(t *testing.T) {
	analyzer.ResetForTesting()
	defer analyzer.ResetForTesting()

	analyzer.Register(&stubAnalyzer{
		name: "ignore-test", ecosystem: "test", detected: true,
		findings: []types.Finding{
			{CheckID: types.CheckIOCMatch, Severity: types.SeverityCritical, Package: "safe-pkg", Title: "should appear"},
			{CheckID: types.CheckIOCMatch, Severity: types.SeverityCritical, Package: "ignored-pkg", Title: "should NOT appear"},
		},
	})

	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Ignore = []string{"ignored-pkg"}
	eng := New(cfg)
	result, err := eng.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary.Total != 1 {
		t.Errorf("expected 1 finding after ignore, got %d", result.Summary.Total)
	}
}

func TestEngine_Scan_GitHubActionsPinning(t *testing.T) {
	analyzer.ResetForTesting()
	defer analyzer.ResetForTesting()

	analyzer.Register(&stubAnalyzer{
		name: "action-test", ecosystem: "test", detected: true,
		findings: []types.Finding{},
	})

	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatal(err)
	}

	workflow := "name: CI\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	eng := New(cfg)
	result, err := eng.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == types.CheckActionsPinning {
			found = true
		}
	}
	if !found {
		t.Error("expected GitHub Actions pinning finding")
	}
}

func TestEngine_DisabledChecks(t *testing.T) {
	analyzer.ResetForTesting()
	defer analyzer.ResetForTesting()

	analyzer.Register(&stubAnalyzer{
		name: "disable-test", ecosystem: "test", detected: true,
		findings: []types.Finding{
			{CheckID: types.CheckIOCMatch, Severity: types.SeverityCritical, Package: "pkg1"},
			{CheckID: types.CheckInstallScripts, Severity: types.SeverityMedium, Package: "pkg2"},
			{CheckID: types.CheckConfigHardening, Severity: types.SeverityMedium, Package: ""},
		},
	})

	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Checks.Disabled = []string{"SG002", "SG008"}
	eng := New(cfg)
	result, err := eng.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary.Total != 1 {
		t.Errorf("expected 1 finding after disabling SG002+SG008, got %d", result.Summary.Total)
	}
	if result.Findings[0].CheckID != types.CheckIOCMatch {
		t.Errorf("expected remaining finding to be SG003, got %s", result.Findings[0].CheckID)
	}
}

func TestEngine_IgnoreRules(t *testing.T) {
	analyzer.ResetForTesting()
	defer analyzer.ResetForTesting()

	analyzer.Register(&stubAnalyzer{
		name: "rule-test", ecosystem: "test", detected: true,
		findings: []types.Finding{
			{CheckID: types.CheckInstallScripts, Severity: types.SeverityMedium, Package: "esbuild", File: "node_modules/esbuild/package.json"},
			{CheckID: types.CheckInstallScripts, Severity: types.SeverityMedium, Package: "malicious-pkg", File: "node_modules/malicious-pkg/package.json"},
			{CheckID: types.CheckIOCMatch, Severity: types.SeverityCritical, Package: "esbuild", File: "package-lock.json"},
		},
	})

	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.IgnoreRules = []config.IgnoreRule{
		{Check: "SG002", Package: "esbuild", Reason: "trusted"},
	}
	eng := New(cfg)
	result, err := eng.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// SG002 for esbuild should be suppressed, but SG003 for esbuild and SG002 for malicious-pkg should remain
	if result.Summary.Total != 2 {
		t.Errorf("expected 2 findings after ignore rule, got %d", result.Summary.Total)
	}
}

func TestEngine_IgnoreRuleByFile(t *testing.T) {
	analyzer.ResetForTesting()
	defer analyzer.ResetForTesting()

	analyzer.Register(&stubAnalyzer{
		name: "file-rule-test", ecosystem: "test", detected: true,
		findings: []types.Finding{},
	})

	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte("name: CI\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"), 0644)

	cfg := defaultConfig()
	cfg.IgnoreRules = []config.IgnoreRule{
		{Check: "SG009", File: ".github/workflows/ci.yml", Reason: "managed externally"},
	}
	eng := New(cfg)
	result, err := eng.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range result.Findings {
		if f.CheckID == types.CheckActionsPinning {
			t.Error("expected SG009 findings to be suppressed by file ignore rule")
		}
	}
}

func defaultConfig() *config.Config {
	return &config.Config{
		Output: "table",
		Ecosystems: config.EcosystemsConfig{
			Npm:    config.EcosystemToggle{Enabled: true},
			Pip:    config.EcosystemToggle{Enabled: true},
			Cargo:  config.EcosystemToggle{Enabled: true},
			Nuget:  config.EcosystemToggle{Enabled: true},
			Maven:  config.EcosystemToggle{Enabled: true},
			Gradle: config.EcosystemToggle{Enabled: true},
		},
		Checks: config.ChecksConfig{DependencyAgeDays: 7},
	}
}
