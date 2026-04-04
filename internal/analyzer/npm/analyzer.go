package npm

import (
	"context"
	"os"
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/analyzer"
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

var _ analyzer.Analyzer = (*NpmAnalyzer)(nil)

func init() {
	analyzer.Register(&NpmAnalyzer{})
}

type NpmAnalyzer struct{}

func (a *NpmAnalyzer) Name() string      { return "npm" }
func (a *NpmAnalyzer) Ecosystem() string  { return "npm" }

func (a *NpmAnalyzer) Detect(dir string) bool {
	candidates := []string{"package.json", "package-lock.json", "npm-shrinkwrap.json"}
	for _, f := range candidates {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

func (a *NpmAnalyzer) Analyze(ctx context.Context, dir string, cfg *config.Config) ([]types.Finding, error) {
	var findings []types.Finding

	// SG001: Lockfile integrity
	lockFindings := checkLockfile(dir)
	findings = append(findings, lockFindings...)

	// SG002: Install scripts detection
	scriptFindings := checkInstallScripts(dir)
	findings = append(findings, scriptFindings...)

	// SG003: IOC matching
	iocFindings := checkIOCs(dir)
	findings = append(findings, iocFindings...)

	// SG004: Dependency age (only if lockfile exists)
	ageFindings := checkDependencyAge(dir, cfg.Checks.DependencyAgeDays)
	findings = append(findings, ageFindings...)

	// SG005: Phantom dependencies
	phantomFindings := checkPhantomDeps(dir)
	findings = append(findings, phantomFindings...)

	// SG006: Typosquatting
	typoFindings := checkTyposquatting(dir)
	findings = append(findings, typoFindings...)

	// SG011: Version range permissiveness
	rangeFindings := checkVersionRanges(dir, cfg.Checks.VersionRangeStrictness)
	findings = append(findings, rangeFindings...)

	// SG003: Suspicious maintainer emails (IOC sub-check)
	maintainerFindings := checkMaintainerEmails(dir)
	findings = append(findings, maintainerFindings...)

	// SG007: Provenance - npm integrity hashes
	npmProvIssues := check.CheckNpmIntegrity(dir)
	for _, issue := range npmProvIssues {
		sev := types.SeverityMedium
		if issue.IssueType == "git_source" {
			sev = types.SeverityHigh
		}
		findings = append(findings, types.Finding{
			CheckID:     types.CheckProvenance,
			Severity:    sev,
			Ecosystem:   "npm",
			Package:     issue.Package,
			File:        issue.File,
			Title:       "Missing provenance: " + issue.Package,
			Description: issue.Description,
			Remediation: "Run 'npm install' to regenerate the lockfile with integrity hashes, or pin the dependency to a registry source.",
		})
	}

	// SG008: Config hardening
	hardeningResult := check.CheckNpmrcHardening(dir)
	for _, missing := range hardeningResult.Missing {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckConfigHardening,
			Severity:    types.SeverityMedium,
			Ecosystem:   "npm",
			File:        ".npmrc",
			Title:       "Missing security hardening in .npmrc",
			Description: "Setting " + missing + " is not configured. Install scripts are the #1 attack vector for npm malware.",
			Remediation: "Add '" + missing + "' to .npmrc or run 'supply-guard init'",
		})
	}

	return findings, nil
}
