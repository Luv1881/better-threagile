package types

import (
	"strings"
	"testing"
	"time"
)

func date(value string) Date {
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		panic(err)
	}
	return Date{Time: parsed}
}

func datePtr(value string) *Date {
	d := date(value)
	return &d
}

func TestIsAcceptanceExpired(t *testing.T) {
	now := date("2026-06-12")

	tests := []struct {
		name     string
		tracking RiskTracking
		expired  bool
	}{
		{"accepted, expired yesterday", RiskTracking{Status: Accepted, AcceptedUntil: datePtr("2026-06-11")}, true},
		{"accepted, expires today", RiskTracking{Status: Accepted, AcceptedUntil: datePtr("2026-06-12")}, false},
		{"accepted, future expiry", RiskTracking{Status: Accepted, AcceptedUntil: datePtr("2027-01-01")}, false},
		{"accepted, no expiry", RiskTracking{Status: Accepted}, false},
		{"mitigated with stale expiry", RiskTracking{Status: Mitigated, AcceptedUntil: datePtr("2020-01-01")}, false},
		{"unchecked", RiskTracking{Status: Unchecked}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tracking.IsAcceptanceExpired(now); got != tc.expired {
				t.Errorf("IsAcceptanceExpired = %v, want %v", got, tc.expired)
			}
		})
	}
}

type recordingReporter struct {
	infos []string
	warns []string
}

func (r *recordingReporter) Info(a ...any)                  { r.infos = append(r.infos, joinAny(a)) }
func (r *recordingReporter) Warn(a ...any)                  { r.warns = append(r.warns, joinAny(a)) }
func (r *recordingReporter) Error(a ...any)                 {}
func (r *recordingReporter) Infof(format string, a ...any)  { r.infos = append(r.infos, format) }
func (r *recordingReporter) Warnf(format string, a ...any)  { r.warns = append(r.warns, format) }
func (r *recordingReporter) Errorf(format string, a ...any) {}

func joinAny(a []any) string {
	parts := make([]string, len(a))
	for i, v := range a {
		parts[i], _ = v.(string)
	}
	return strings.Join(parts, " ")
}

func expiryModel() *Model {
	return &Model{
		RiskTracking: map[string]*RiskTracking{
			"expired@a":   {SyntheticRiskId: "expired@a", Status: Accepted, AcceptedUntil: datePtr("2026-01-01"), AcceptedBy: "ciso"},
			"valid@b":     {SyntheticRiskId: "valid@b", Status: Accepted, AcceptedUntil: datePtr("2027-01-01")},
			"no-expiry@c": {SyntheticRiskId: "no-expiry@c", Status: Accepted},
			"mitigated@d": {SyntheticRiskId: "mitigated@d", Status: Mitigated},
		},
	}
}

func TestCheckAcceptanceExpiry_FailsOnExpired(t *testing.T) {
	model := expiryModel()
	reporter := &recordingReporter{}

	err := model.CheckAcceptanceExpiry(date("2026-06-12"), false, reporter)
	if err == nil {
		t.Fatal("expected error for expired acceptance")
	}
	if !strings.Contains(err.Error(), "expired@a") {
		t.Errorf("error should name the expired risk, got: %v", err)
	}
	if !strings.Contains(err.Error(), "ciso") {
		t.Errorf("error should include accepted_by, got: %v", err)
	}
	if strings.Contains(err.Error(), "valid@b") || strings.Contains(err.Error(), "no-expiry@c") {
		t.Errorf("error should only list expired entries, got: %v", err)
	}
}

func TestCheckAcceptanceExpiry_IgnoreFlagWarnsOnly(t *testing.T) {
	model := expiryModel()
	reporter := &recordingReporter{}

	if err := model.CheckAcceptanceExpiry(date("2026-06-12"), true, reporter); err != nil {
		t.Fatalf("expected nil error with ignore flag, got: %v", err)
	}
	if len(reporter.warns) != 1 {
		t.Errorf("expected 1 warning for the expired acceptance, got %d", len(reporter.warns))
	}
}

func TestCheckAcceptanceExpiry_CleanModel(t *testing.T) {
	model := &Model{RiskTracking: map[string]*RiskTracking{
		"valid@b": {SyntheticRiskId: "valid@b", Status: Accepted, AcceptedUntil: datePtr("2027-01-01")},
	}}
	reporter := &recordingReporter{}
	if err := model.CheckAcceptanceExpiry(date("2026-06-12"), false, reporter); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(reporter.warns) != 0 {
		t.Errorf("expected no warnings, got %v", reporter.warns)
	}
}
