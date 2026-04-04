package npm

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkIOCs(dir string) []types.Finding {
	var findings []types.Finding

	lockPath := filepath.Join(dir, "package-lock.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return checkIOCsFromPackageJSON(dir)
	}

	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return findings
	}

	deps := extractLockDeps(&lock)
	for name, version := range deps {
		match, err := check.CheckPackageIOC("npm", name, version)
		if err != nil {
			continue
		}
		if match != nil {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckIOCMatch,
				Severity:    types.SeverityCritical,
				Ecosystem:   "npm",
				Package:     name,
				Version:     version,
				File:        "package-lock.json",
				Title:       "Known malicious package detected",
				Description: match.Reason,
				Remediation: "Remove this package immediately and audit your systems for compromise",
			})
		}
	}

	return findings
}

func checkIOCsFromPackageJSON(dir string) []types.Finding {
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

	for name, version := range allDeps {
		match, err := check.CheckPackageIOC("npm", name, version)
		if err != nil {
			continue
		}
		if match != nil {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckIOCMatch,
				Severity:    types.SeverityCritical,
				Ecosystem:   "npm",
				Package:     name,
				Version:     version,
				File:        "package.json",
				Title:       "Known malicious package detected",
				Description: match.Reason,
				Remediation: "Remove this package immediately and audit your systems for compromise",
			})
		}
	}

	return findings
}
