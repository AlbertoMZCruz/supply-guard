package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestJSONReporter_EmptyFindings(t *testing.T) {
	result := &types.ScanResult{
		ProjectDir: "/test",
		Timestamp:  time.Now(),
		Duration:   "1ms",
		Ecosystems: []string{"npm"},
		Findings:   []types.Finding{},
	}

	var buf bytes.Buffer
	r := &JSONReporter{}
	if err := r.Report(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed types.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if parsed.Summary.Total != 0 {
		t.Errorf("expected 0 total, got %d", parsed.Summary.Total)
	}
}

func TestJSONReporter_WithFindings(t *testing.T) {
	result := &types.ScanResult{
		ProjectDir: "/test",
		Timestamp:  time.Now(),
		Duration:   "5ms",
		Ecosystems: []string{"npm"},
		Summary:    types.Summary{Total: 1, Critical: 1},
		Findings: []types.Finding{{
			CheckID:  types.CheckIOCMatch,
			Severity: types.SeverityCritical,
			Package:  "evil-pkg",
			Title:    "malicious",
		}},
	}

	var buf bytes.Buffer
	r := &JSONReporter{}
	if err := r.Report(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed types.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(parsed.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].Package != "evil-pkg" {
		t.Errorf("expected package 'evil-pkg', got %q", parsed.Findings[0].Package)
	}
}
