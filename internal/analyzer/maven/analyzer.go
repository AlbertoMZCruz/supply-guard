package maven

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/analyzer"
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

var _ analyzer.Analyzer = (*MavenAnalyzer)(nil)

func init() {
	analyzer.Register(&MavenAnalyzer{})
}

type MavenAnalyzer struct{}

func (a *MavenAnalyzer) Name() string      { return "maven" }
func (a *MavenAnalyzer) Ecosystem() string  { return "maven" }

func (a *MavenAnalyzer) Detect(dir string) bool {
	candidates := []string{"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}
	for _, f := range candidates {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

func (a *MavenAnalyzer) Analyze(ctx context.Context, dir string, cfg *config.Config) ([]types.Finding, error) {
	var findings []types.Finding

	if _, err := os.Stat(filepath.Join(dir, "pom.xml")); err == nil {
		findings = append(findings, analyzeMaven(dir)...)
		findings = append(findings, checkMavenVersionRanges(dir, cfg.Checks.VersionRangeStrictness)...)
	}

	if isGradle(dir) {
		findings = append(findings, analyzeGradle(dir)...)
		findings = append(findings, checkGradleVersionRanges(dir, cfg.Checks.VersionRangeStrictness)...)
	}

	findings = append(findings, checkMavenNetworkCalls(dir)...)
	findings = append(findings, checkMavenTyposquatting(dir)...)

	return findings, nil
}

// Maven analysis

type pomFile struct {
	XMLName      xml.Name       `xml:"project"`
	Dependencies pomDependencies `xml:"dependencies"`
	Repositories []pomRepository `xml:"repositories>repository"`
}

type pomDependencies struct {
	Dependencies []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version   string `xml:"version"`
}

type pomRepository struct {
	ID  string `xml:"id"`
	URL string `xml:"url"`
}

func analyzeMaven(dir string) []types.Finding {
	var findings []types.Finding

	pomPath := filepath.Join(dir, "pom.xml")
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return findings
	}

	var pom pomFile
	if err := xml.Unmarshal(data, &pom); err != nil {
		return findings
	}

	// Check for dependency confusion: public repos mixed with private
	for _, repo := range pom.Repositories {
		if strings.Contains(repo.URL, "http://") {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckConfigHardening,
				Severity:    types.SeverityHigh,
				Ecosystem:   "maven",
				File:        "pom.xml",
				Title:       "Maven repository using HTTP",
				Description: fmt.Sprintf("Repository '%s' uses unencrypted HTTP (%s). Dependencies could be intercepted via MITM attack.", repo.ID, repo.URL),
				Remediation: "Change repository URL to use HTTPS",
			})
		}
	}

	// Check dependencies for IOCs
	for _, dep := range pom.Dependencies.Dependencies {
		fullName := dep.GroupID + ":" + dep.ArtifactID

		match, err := check.CheckPackageIOC("maven", fullName, dep.Version)
		if err != nil {
			continue
		}
		if match != nil {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckIOCMatch,
				Severity:    types.SeverityCritical,
				Ecosystem:   "maven",
				Package:     fullName,
				Version:     dep.Version,
				File:        "pom.xml",
				Title:       "Known malicious Maven artifact detected",
				Description: match.Reason,
				Remediation: "Remove this dependency immediately",
			})
		}
	}

	// Check for verification metadata
	verificationPath := filepath.Join(dir, "gradle", "verification-metadata.xml")
	mavenWrapperPath := filepath.Join(dir, ".mvn", "maven.config")
	if _, err := os.Stat(verificationPath); err != nil {
		if _, err := os.Stat(mavenWrapperPath); err != nil {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckConfigHardening,
				Severity:    types.SeverityLow,
				Ecosystem:   "maven",
				File:        "pom.xml",
				Title:       "No dependency verification configured",
				Description: "Neither Maven checksum verification nor Gradle verification-metadata.xml is configured.",
				Remediation: "Add checksum verification to your build process",
			})
		}
	}

	return findings
}

// Gradle analysis

func isGradle(dir string) bool {
	for _, f := range []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

func analyzeGradle(dir string) []types.Finding {
	var findings []types.Finding

	// Check for verification-metadata.xml
	verPath := filepath.Join(dir, "gradle", "verification-metadata.xml")
	if _, err := os.Stat(verPath); err != nil {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckConfigHardening,
			Severity:    types.SeverityMedium,
			Ecosystem:   "gradle",
			File:        "build.gradle",
			Title:       "Gradle verification-metadata.xml not found",
			Description: "Gradle's dependency verification is not configured. Without checksum verification, dependencies could be tampered with.",
			Remediation: "Run 'gradle --write-verification-metadata sha256' to generate verification-metadata.xml",
		})
	}

	// Check for dependency locking
	lockDir := filepath.Join(dir, "gradle", "dependency-locks")
	if _, err := os.Stat(lockDir); err != nil {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckLockfileIntegrity,
			Severity:    types.SeverityMedium,
			Ecosystem:   "gradle",
			File:        "build.gradle",
			Title:       "Gradle dependency locking not enabled",
			Description: "No dependency lock files found. Without locking, builds may use different dependency versions.",
			Remediation: "Enable dependency locking: add 'dependencyLocking { lockAllConfigurations() }' and run 'gradle dependencies --write-locks'",
		})
	}

	// Scan build files for HTTP repositories
	for _, buildFile := range []string{"build.gradle", "build.gradle.kts"} {
		buildPath := filepath.Join(dir, buildFile)
		data, err := os.ReadFile(buildPath)
		if err != nil {
			continue
		}

		content := string(data)
		if strings.Contains(content, "http://") && strings.Contains(content, "maven") {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckConfigHardening,
				Severity:    types.SeverityHigh,
				Ecosystem:   "gradle",
				File:        buildFile,
				Title:       "Gradle build uses HTTP repository",
				Description: "Build file references a Maven repository over unencrypted HTTP. Dependencies could be intercepted.",
				Remediation: "Change all repository URLs to HTTPS",
			})
		}
	}

	return findings
}
