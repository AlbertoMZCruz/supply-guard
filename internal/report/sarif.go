package report

import (
	"encoding/json"
	"io"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
	"github.com/AlbertoMZCruz/supply-guard/internal/version"
)

type SARIFReporter struct{}

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifMessage     `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig  `json:"defaultConfiguration"`
	Properties       sarifRuleProps   `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func (r *SARIFReporter) Report(w io.Writer, result *types.ScanResult) error {
	rulesMap := map[types.CheckID]bool{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range result.Findings {
		if !rulesMap[f.CheckID] {
			rulesMap[f.CheckID] = true
			desc := types.CheckDescriptions[f.CheckID]
			if desc == "" {
				desc = string(f.CheckID)
			}
			rules = append(rules, sarifRule{
				ID:               string(f.CheckID),
				Name:             desc,
				ShortDescription: sarifMessage{Text: desc},
				DefaultConfig:    sarifRuleConfig{Level: sarifLevel(f.Severity)},
				Properties:       sarifRuleProps{Tags: []string{"security", "supply-chain"}},
			})
		}

		sr := sarifResult{
			RuleID:  string(f.CheckID),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Title + ": " + f.Description},
		}
		if f.File != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI:       f.File,
						URIBaseID: "%SRCROOT%",
					},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			sr.Locations = append(sr.Locations, loc)
		}
		results = append(results, sr)
	}

	doc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "supply-guard",
					Version:        version.Version,
					InformationURI: "https://github.com/AlbertoMZCruz/supply-guard",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s types.Severity) string {
	switch s {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	case types.SeverityLow, types.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

