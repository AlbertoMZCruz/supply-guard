package types

import "testing"

func TestSummaryAdd(t *testing.T) {
	var s Summary
	s.Add(SeverityCritical)
	s.Add(SeverityHigh)
	s.Add(SeverityHigh)
	s.Add(SeverityMedium)
	s.Add(SeverityLow)
	s.Add(SeverityInfo)

	if s.Total != 6 {
		t.Errorf("Total = %d, want 6", s.Total)
	}
	if s.Critical != 1 {
		t.Errorf("Critical = %d, want 1", s.Critical)
	}
	if s.High != 2 {
		t.Errorf("High = %d, want 2", s.High)
	}
}

func TestSummaryHasSeverity(t *testing.T) {
	s := Summary{Critical: 1, High: 0}

	if !s.HasSeverity(SeverityCritical) {
		t.Error("expected HasSeverity(critical) = true")
	}
	if s.HasSeverity(SeverityHigh) {
		t.Error("expected HasSeverity(high) = false")
	}
	if !s.HasSeverity(SeverityCritical, SeverityHigh) {
		t.Error("expected HasSeverity(critical, high) = true")
	}
}
