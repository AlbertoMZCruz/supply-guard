package nuget

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkNuGetNetworkCalls(dir string) []types.Finding {
	var findings []types.Finding

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "bin" || name == "obj" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		name := d.Name()
		if !strings.HasSuffix(name, ".targets") && !strings.HasSuffix(name, ".props") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		content := string(data)
		issues := check.ScanForNetworkCalls(content, "nuget")

		relPath, _ := filepath.Rel(dir, path)
		if relPath == "" {
			relPath = path
		}

		for _, issue := range issues {
			if issue.Category == "c2_domain" || issue.Category == "raw_ip" || issue.Category == "download_cmd" || issue.Category == "network_api" {
				sev := types.SeverityHigh
				if issue.Risk == "critical" {
					sev = types.SeverityCritical
				}
				findings = append(findings, types.Finding{
					CheckID:     types.CheckNetworkCalls,
					Severity:    sev,
					Ecosystem:   "nuget",
					File:        relPath,
					Title:       "Network pattern in build file: " + issue.Pattern,
					Description: relPath + " contains a " + issue.Category + " pattern (" + issue.Pattern + ") that may indicate download or exfiltration during build.",
					Remediation: "Review " + relPath + " and ensure no unauthorized network access occurs during build.",
				})
			}
		}

		return nil
	})

	return findings
}
