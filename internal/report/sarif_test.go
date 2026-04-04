package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestSARIFReporter_ValidStructure(t *testing.T) {
	result := &types.ScanResult{
		ProjectDir: "/test",
		Timestamp:  time.Now(),
		Duration:   "5ms",
		Ecosystems: []string{"npm"},
		Findings: []types.Finding{
			{
				CheckID:     types.CheckIOCMatch,
				Severity:    types.SeverityCritical,
				Package:     "evil-pkg",
				File:        "package.json",
				Line:        10,
				Title:       "malicious",
				Description: "known bad package",
			},
			{
				CheckID:     types.CheckConfigHardening,
				Severity:    types.SeverityMedium,
				File:        ".npmrc",
				Title:       "hardening",
				Description: "missing config",
			},
		},
	}

	var buf bytes.Buffer
	r := &SARIFReporter{}
	if err := r.Report(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc sarifDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if doc.Runs[0].Tool.Driver.Name != "supply-guard" {
		t.Errorf("expected tool name 'supply-guard', got %s", doc.Runs[0].Tool.Driver.Name)
	}
	if len(doc.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(doc.Runs[0].Results))
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(doc.Runs[0].Tool.Driver.Rules))
	}

	// Check that critical maps to "error" level
	for _, r := range doc.Runs[0].Results {
		if r.RuleID == "SG003" && r.Level != "error" {
			t.Errorf("expected level 'error' for SG003, got %s", r.Level)
		}
		if r.RuleID == "SG008" && r.Level != "warning" {
			t.Errorf("expected level 'warning' for SG008, got %s", r.Level)
		}
	}
}

func TestSARIFReporter_EmptyFindings(t *testing.T) {
	result := &types.ScanResult{
		ProjectDir: "/test",
		Timestamp:  time.Now(),
		Findings:   []types.Finding{},
	}

	var buf bytes.Buffer
	r := &SARIFReporter{}
	if err := r.Report(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc sarifDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results for empty findings")
	}
}
