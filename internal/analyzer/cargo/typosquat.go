package cargo

import (
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

const defaultCargoMaxTypoDistance = 2

func checkCargoTyposquatting(dir string) []types.Finding {
	var findings []types.Finding

	lockPath := "Cargo.lock"
	deps := parseCargoLock(dir + "/" + lockPath)

	for _, dep := range deps {
		popular, dist, err := check.CheckTyposquatting("cargo", dep.Name, defaultCargoMaxTypoDistance)
		if err != nil || popular == "" {
			continue
		}

		severity := types.SeverityHigh
		if dist == 1 {
			severity = types.SeverityCritical
		}

		findings = append(findings, types.Finding{
			CheckID:   types.CheckTyposquatting,
			Severity:  severity,
			Ecosystem: "cargo",
			Package:   dep.Name,
			Version:   dep.Version,
			File:      lockPath,
			Title:     "Possible typosquatting: " + dep.Name + " (similar to " + popular + ")",
			Description: "Crate '" + dep.Name + "' has a Levenshtein distance of " +
				string(rune('0'+dist)) + " from popular crate '" + popular + "'. This may be a typosquatting attempt.",
			Remediation: "Verify you intended to use '" + dep.Name + "' and not '" + popular + "'.",
		})
	}

	return findings
}
