package pip

import (
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkPipProvenance(dir string) []types.Finding {
	var findings []types.Finding

	issues := check.CheckPipHashes(dir)
	for _, issue := range issues {
		sev := types.SeverityMedium
		if issue.IssueType == "git_source" {
			sev = types.SeverityHigh
		}
		findings = append(findings, types.Finding{
			CheckID:     types.CheckProvenance,
			Severity:    sev,
			Ecosystem:   "pip",
			Package:     issue.Package,
			File:        issue.File,
			Title:       "Missing provenance: " + issue.Package,
			Description: issue.Description,
			Remediation: "Add --hash entries for all packages or pin to a registry source.",
		})
	}

	return findings
}
