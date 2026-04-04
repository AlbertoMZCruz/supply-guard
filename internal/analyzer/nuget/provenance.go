package nuget

import (
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkNuGetProvenance(dir string) []types.Finding {
	var findings []types.Finding

	issues := check.CheckNuGetContentHash(dir)
	for _, issue := range issues {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckProvenance,
			Severity:    types.SeverityMedium,
			Ecosystem:   "nuget",
			Package:     issue.Package,
			File:        issue.File,
			Title:       "Missing provenance: " + issue.Package,
			Description: issue.Description,
			Remediation: "Regenerate packages.lock.json with 'dotnet restore' to include content hashes.",
		})
	}

	return findings
}
