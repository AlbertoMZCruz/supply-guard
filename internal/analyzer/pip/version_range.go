package pip

import (
	"fmt"
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkPipVersionRanges(dir string, strictness string) []types.Finding {
	var findings []types.Finding

	threshold := pipRiskThreshold(strictness)
	reqFiles := []string{"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}

	for _, f := range reqFiles {
		deps := parseRequirementsTxt(filepath.Join(dir, f))
		for _, dep := range deps {
			cl := check.ClassifyPipRange(dep.Version)
			if cl.Risk < threshold {
				continue
			}
			sev := pipRangeSeverity(cl.Risk)
			findings = append(findings, types.Finding{
				CheckID:   types.CheckVersionRange,
				Severity:  sev,
				Ecosystem: "pip",
				Package:   dep.Name,
				Version:   dep.Version,
				File:      f,
				Line:      dep.Line,
				Title:     fmt.Sprintf("Permissive version range (%s): %s", cl.Risk, dep.Name),
				Description: fmt.Sprintf(
					"Package '%s' uses '%s' (%s). Without exact pinning, pip may install a compromised newer version.",
					dep.Name, dep.Version, cl.Explanation,
				),
				Remediation: fmt.Sprintf("Pin to exact version: %s==<version>", dep.Name),
			})
		}
	}

	return findings
}

func pipRangeSeverity(risk check.VersionRisk) types.Severity {
	switch risk {
	case check.RiskDangerous:
		return types.SeverityHigh
	case check.RiskPermissive:
		return types.SeverityMedium
	case check.RiskConservative:
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

func pipRiskThreshold(strictness string) check.VersionRisk {
	switch strictness {
	case "exact":
		return check.RiskConservative
	case "permissive":
		return check.RiskDangerous
	default:
		return check.RiskPermissive
	}
}
