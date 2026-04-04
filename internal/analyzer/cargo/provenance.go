package cargo

import (
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkCargoProvenance(dir string) []types.Finding {
	var findings []types.Finding

	issues := check.CheckCargoChecksums(dir)
	for _, issue := range issues {
		sev := types.SeverityMedium
		if issue.IssueType == "git_source" {
			sev = types.SeverityHigh
		}
		findings = append(findings, types.Finding{
			CheckID:     types.CheckProvenance,
			Severity:    sev,
			Ecosystem:   "cargo",
			Package:     issue.Package,
			File:        issue.File,
			Title:       "Missing provenance: " + issue.Package,
			Description: issue.Description,
			Remediation: "Pin the crate to a registry source or verify the git source manually.",
		})
	}

	return findings
}
