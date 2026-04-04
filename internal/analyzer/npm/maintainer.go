package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type packageMaintainerInfo struct {
	Name        string `json:"name"`
	Author      struct {
		Email string `json:"email"`
	} `json:"author"`
	Maintainers []struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"maintainers"`
}

func checkMaintainerEmails(dir string) []types.Finding {
	var findings []types.Finding

	nodeModules := filepath.Join(dir, "node_modules")
	if _, err := os.Stat(nodeModules); err != nil {
		return findings
	}

	entries, err := os.ReadDir(nodeModules)
	if err != nil {
		return findings
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		if strings.HasPrefix(entry.Name(), "@") {
			scopeEntries, err := os.ReadDir(filepath.Join(nodeModules, entry.Name()))
			if err != nil {
				continue
			}
			for _, scopeEntry := range scopeEntries {
				if !scopeEntry.IsDir() {
					continue
				}
				pkgName := entry.Name() + "/" + scopeEntry.Name()
				findings = append(findings, scanPackageMaintainers(dir, nodeModules, pkgName)...)
			}
			continue
		}

		findings = append(findings, scanPackageMaintainers(dir, nodeModules, entry.Name())...)
	}

	return findings
}

func scanPackageMaintainers(projectDir, nodeModules, pkgName string) []types.Finding {
	var findings []types.Finding

	pkgJSONPath := filepath.Join(nodeModules, pkgName, "package.json")
	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return findings
	}

	var pkg packageMaintainerInfo
	if err := json.Unmarshal(data, &pkg); err != nil {
		return findings
	}

	relPath, _ := filepath.Rel(projectDir, pkgJSONPath)
	if relPath == "" {
		relPath = pkgJSONPath
	}

	seen := make(map[string]bool)

	if pkg.Author.Email != "" {
		if suspicious, pattern := check.CheckMaintainerEmail(pkg.Author.Email); suspicious {
			key := pkg.Author.Email
			if !seen[key] {
				seen[key] = true
				findings = append(findings, types.Finding{
					CheckID:     types.CheckIOCMatch,
					Severity:    types.SeverityMedium,
					Ecosystem:   "npm",
					Package:     pkgName,
					File:        relPath,
					Title:       "Suspicious maintainer email for " + pkgName,
					Description: "Package '" + pkgName + "' has author email '" + pkg.Author.Email + "' matching suspicious pattern '" + pattern + "'. This may indicate a throwaway account used for malicious publishing.",
					Remediation: "Verify the package maintainer and source. Consider alternatives if unverified.",
				})
			}
		}
	}

	for _, m := range pkg.Maintainers {
		if m.Email == "" {
			continue
		}
		if suspicious, pattern := check.CheckMaintainerEmail(m.Email); suspicious {
			key := m.Email
			if !seen[key] {
				seen[key] = true
				findings = append(findings, types.Finding{
					CheckID:     types.CheckIOCMatch,
					Severity:    types.SeverityMedium,
					Ecosystem:   "npm",
					Package:     pkgName,
					File:        relPath,
					Title:       "Suspicious maintainer email for " + pkgName,
					Description: "Package '" + pkgName + "' has maintainer '" + m.Name + "' with email '" + m.Email + "' matching suspicious pattern '" + pattern + "'. This may indicate a throwaway account.",
					Remediation: "Verify the package maintainer and source. Consider alternatives if unverified.",
				})
			}
		}
	}

	return findings
}
