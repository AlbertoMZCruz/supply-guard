package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

const defaultMaxTypoDistance = 2

func checkTyposquatting(dir string) []types.Finding {
	var findings []types.Finding

	pkgPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return findings
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return findings
	}

	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	for name := range allDeps {
		similarTo, dist, err := check.CheckTyposquatting("npm", name, defaultMaxTypoDistance)
		if err != nil {
			continue
		}
		if similarTo != "" {
			severity := types.SeverityHigh
			if dist == 1 {
				severity = types.SeverityCritical
			}

			findings = append(findings, types.Finding{
				CheckID:   types.CheckTyposquatting,
				Severity:  severity,
				Ecosystem: "npm",
				Package:   name,
				File:      "package.json",
				Title:     fmt.Sprintf("Possible typosquatting: '%s' similar to '%s'", name, similarTo),
				Description: fmt.Sprintf(
					"Package '%s' has an edit distance of %d from popular package '%s'. "+
						"In February 2026, over 1,000 typosquatting packages were published with similar name patterns.",
					name, dist, similarTo,
				),
				Remediation: fmt.Sprintf("Verify you intended to install '%s' and not '%s'", name, similarTo),
			})
		}
	}

	return findings
}
