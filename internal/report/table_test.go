package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestTableReporter_NoFindings(t *testing.T) {
	result := &types.ScanResult{
		ProjectDir: "/test",
		Timestamp:  time.Now(),
		Duration:   "1ms",
		Ecosystems: []string{"npm"},
		Findings:   []types.Finding{},
	}

	var buf bytes.Buffer
	r := &TableReporter{}
	if err := r.Report(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No issues found") {
		t.Error("expected 'No issues found' in output")
	}
}

func TestTableReporter_WithFindings(t *testing.T) {
	result := &types.ScanResult{
		ProjectDir: "/test",
		Timestamp:  time.Now(),
		Duration:   "5ms",
		Ecosystems: []string{"npm"},
		Summary:    types.Summary{Total: 1, Critical: 1},
		Findings: []types.Finding{{
			CheckID:     types.CheckIOCMatch,
			Severity:    types.SeverityCritical,
			Package:     "evil-pkg",
			Version:     "1.0.0",
			File:        "package.json",
			Line:        5,
			Title:       "Known malicious package",
			Description: "this is bad",
			Remediation: "remove it",
		}},
	}

	var buf bytes.Buffer
	r := &TableReporter{}
	if err := r.Report(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "evil-pkg@1.0.0") {
		t.Error("expected 'evil-pkg@1.0.0' in output")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("expected 'CRITICAL' in output")
	}
	if !strings.Contains(out, "1 critical") {
		t.Error("expected summary with '1 critical'")
	}
}
