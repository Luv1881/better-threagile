package gate

import (
	"errors"
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func risk(id string, sev types.RiskSeverity, status types.RiskStatus) *types.Risk {
	return &types.Risk{SyntheticId: id, Severity: sev, RiskStatus: status}
}

// riskMap keys by lower-cased synthetic ID, mirroring GeneratedRisksBySyntheticId.
func riskMap(rs ...*types.Risk) map[string]*types.Risk {
	m := make(map[string]*types.Risk, len(rs))
	for _, r := range rs {
		m[strings.ToLower(r.SyntheticId)] = r
	}
	return m
}

func hasViolation(r *Result, rule string) bool {
	for _, v := range r.Violations {
		if v.Rule == rule {
			return true
		}
	}
	return false
}

func TestEmptyPolicyPasses(t *testing.T) {
	in := Input{Risks: riskMap(
		risk("a", types.CriticalSeverity, types.Unchecked),
		risk("b", types.HighSeverity, types.Unchecked),
	)}
	r := Evaluate(&Policy{}, in)
	if !r.Passed() {
		t.Fatalf("empty policy should pass, got %v", r.Violations)
	}
	if r.AtRiskTotal != 2 {
		t.Fatalf("AtRiskTotal = %d, want 2", r.AtRiskTotal)
	}
}

func TestMinScore(t *testing.T) {
	floor := 75
	mk := func(score *int) *Result {
		return Evaluate(&Policy{MinScore: &floor}, Input{Score: score})
	}
	// below floor -> violation
	low := 60
	if r := mk(&low); r.Passed() {
		t.Errorf("score %d below floor %d should fail", low, floor)
	}
	// at/above floor -> pass
	ok := 80
	if r := mk(&ok); !r.Passed() {
		t.Errorf("score %d at/above floor %d should pass, got %v", ok, floor, r.Violations)
	}
	// missing score with the rule set -> loud violation, not silent pass
	if r := mk(nil); r.Passed() {
		t.Error("min_score rule with no score supplied should fail loudly")
	}
	// no rule -> score ignored
	if r := Evaluate(&Policy{}, Input{Score: &low}); !r.Passed() {
		t.Error("min_score not set should ignore the score")
	}
}

func TestMaxSeverityCounts(t *testing.T) {
	in := Input{Risks: riskMap(
		risk("a", types.CriticalSeverity, types.Unchecked),
		risk("b", types.HighSeverity, types.Unchecked),
		risk("c", types.HighSeverity, types.Unchecked),
		// mitigated -> not at risk, should not count
		risk("d", types.CriticalSeverity, types.Mitigated),
	)}
	p := &Policy{MaxSeverityCounts: map[string]int{"critical": 0, "high": 1}}
	r := Evaluate(p, in)
	if r.Passed() {
		t.Fatal("expected violations")
	}
	// 1 critical at risk > 0, and 2 high > 1 => two violations
	if len(r.Violations) != 2 {
		t.Fatalf("want 2 violations, got %d: %v", len(r.Violations), r.Violations)
	}
	if r.AtRiskBySeverity["critical"] != 1 {
		t.Fatalf("critical at-risk count = %d, want 1 (mitigated excluded)", r.AtRiskBySeverity["critical"])
	}
}

// A policy written with a capitalised severity key (Critical) must be honoured,
// not silently ignored.
func TestMaxSeverityCountsCaseInsensitive(t *testing.T) {
	in := Input{Risks: riskMap(risk("a", types.CriticalSeverity, types.Unchecked))}
	p := &Policy{MaxSeverityCounts: map[string]int{"Critical": 0}}
	r := Evaluate(p, in)
	if !hasViolation(r, "max_severity_counts") {
		t.Fatalf("'Critical: 0' should be honoured (case-insensitive), got %v", r.Violations)
	}
}

func TestMaxSeverityCountsUnknownKey(t *testing.T) {
	p := &Policy{MaxSeverityCounts: map[string]int{"catastrophic": 0}}
	r := Evaluate(p, Input{Risks: riskMap()})
	if !hasViolation(r, "max_severity_counts") {
		t.Fatal("unknown severity key should produce a config violation")
	}
}

func TestMaxTotalAtRisk(t *testing.T) {
	n := 1
	in := Input{Risks: riskMap(
		risk("a", types.LowSeverity, types.Unchecked),
		risk("b", types.LowSeverity, types.Unchecked),
	)}
	r := Evaluate(&Policy{MaxTotalAtRisk: &n}, in)
	if !hasViolation(r, "max_total_at_risk") {
		t.Fatalf("expected max_total_at_risk violation, got %v", r.Violations)
	}
}

func TestRequireTracking(t *testing.T) {
	in := Input{Risks: riskMap(
		risk("a", types.HighSeverity, types.Unchecked),      // violates
		risk("b", types.ElevatedSeverity, types.InProgress), // tracked, ok
		risk("c", types.MediumSeverity, types.Unchecked),    // below threshold, ok
	)}
	r := Evaluate(&Policy{RequireTrackingAtOrAbove: "elevated"}, in)
	if !hasViolation(r, "require_tracking_at_or_above") {
		t.Fatalf("expected tracking violation, got %v", r.Violations)
	}
	msg := r.Violations[0].Message
	if !strings.Contains(msg, "a") || strings.Contains(msg, "\"c\"") {
		t.Fatalf("violation should mention 'a' only, got %q", msg)
	}
}

func TestRequireTrackingAllTracked(t *testing.T) {
	in := Input{Risks: riskMap(
		risk("a", types.HighSeverity, types.Accepted),
		risk("b", types.CriticalSeverity, types.InDiscussion),
	)}
	r := Evaluate(&Policy{RequireTrackingAtOrAbove: "high"}, in)
	if !r.Passed() {
		t.Fatalf("all findings tracked, should pass, got %v", r.Violations)
	}
}

func TestExpiredAcceptance(t *testing.T) {
	in := Input{
		Risks:                riskMap(risk("a", types.LowSeverity, types.Accepted)),
		ExpiredAcceptanceErr: errors.New("1 acceptance expired"),
	}
	// Disabled -> ignored.
	if r := Evaluate(&Policy{}, in); !r.Passed() {
		t.Fatalf("disabled rule should not fail, got %v", r.Violations)
	}
	// Enabled -> violation.
	if r := Evaluate(&Policy{FailOnExpiredAcceptance: true}, in); !hasViolation(r, "fail_on_expired_acceptance") {
		t.Fatal("expected expired-acceptance violation")
	}
}

func TestForbidNewWithBaseline(t *testing.T) {
	in := Input{
		Risks: riskMap(
			risk("old-high", types.HighSeverity, types.Unchecked),
			risk("new-high", types.HighSeverity, types.Unchecked),
			risk("new-medium", types.MediumSeverity, types.Unchecked),
		),
		Baseline: map[string]types.RiskSeverity{"old-high": types.HighSeverity},
	}
	r := Evaluate(&Policy{ForbidNewAtOrAbove: "high"}, in)
	if !hasViolation(r, "forbid_new_at_or_above") {
		t.Fatalf("expected forbid_new violation, got %v", r.Violations)
	}
	msg := r.Violations[0].Message
	if !strings.Contains(msg, "new-high") || strings.Contains(msg, "new-medium") || strings.Contains(msg, "old-high") {
		t.Fatalf("should flag new-high only, got %q", msg)
	}
}

// A finding present in the baseline at a lower severity, now escalated above the
// threshold, must be flagged as new/escalated.
func TestForbidNewCatchesEscalation(t *testing.T) {
	in := Input{
		Risks:    riskMap(risk("esc", types.HighSeverity, types.Unchecked)),
		Baseline: map[string]types.RiskSeverity{"esc": types.MediumSeverity},
	}
	r := Evaluate(&Policy{ForbidNewAtOrAbove: "high"}, in)
	if !hasViolation(r, "forbid_new_at_or_above") {
		t.Fatalf("severity escalation should violate, got %v", r.Violations)
	}
}

// A finding that was mitigated in the baseline (hence absent from the at-risk
// baseline set) and is now at risk again must count as new.
func TestForbidNewCatchesReopened(t *testing.T) {
	in := Input{
		Risks:    riskMap(risk("reopened", types.HighSeverity, types.Unchecked)),
		Baseline: map[string]types.RiskSeverity{}, // was mitigated -> not in at-risk set
	}
	r := Evaluate(&Policy{ForbidNewAtOrAbove: "high"}, in)
	if !hasViolation(r, "forbid_new_at_or_above") {
		t.Fatalf("reopened finding should violate, got %v", r.Violations)
	}
}

// A new finding that is already mitigated must NOT fail the gate.
func TestForbidNewIgnoresMitigatedCurrent(t *testing.T) {
	in := Input{
		Risks:    riskMap(risk("mit", types.CriticalSeverity, types.Mitigated)),
		Baseline: map[string]types.RiskSeverity{},
	}
	r := Evaluate(&Policy{ForbidNewAtOrAbove: "high"}, in)
	if !r.Passed() {
		t.Fatalf("a new but mitigated finding should not fail, got %v", r.Violations)
	}
}

func TestForbidNewWithoutBaselineFails(t *testing.T) {
	in := Input{Risks: riskMap(risk("a", types.HighSeverity, types.Unchecked))}
	r := Evaluate(&Policy{ForbidNewAtOrAbove: "high"}, in)
	if !hasViolation(r, "forbid_new_at_or_above") {
		t.Fatal("forbid_new without a baseline must fail loudly, not pass silently")
	}
}

func TestFrameworkCoverage(t *testing.T) {
	in := Input{
		Risks:            riskMap(),
		CoveragePercents: map[string]float64{"owasp_top10_2021": 60},
	}
	p := &Policy{FrameworkCoverage: []CoverageThreshold{{Framework: "owasp_top10_2021", MinPercent: 70}}}
	if r := Evaluate(p, in); !hasViolation(r, "framework_coverage") {
		t.Fatalf("60%% < 70%% should violate, got %v", r.Violations)
	}
	in.CoveragePercents["owasp_top10_2021"] = 80
	if r := Evaluate(p, in); !r.Passed() {
		t.Fatalf("80%% >= 70%% should pass, got %v", r.Violations)
	}
}

func TestFormatTextAndMarkdown(t *testing.T) {
	in := Input{Risks: riskMap(risk("a", types.CriticalSeverity, types.Unchecked))}
	r := Evaluate(&Policy{Name: "test", MaxSeverityCounts: map[string]int{"critical": 0}}, in)

	text := FormatText(r)
	if !strings.Contains(text, "FAIL") || !strings.Contains(text, "max_severity_counts") {
		t.Fatalf("text report missing content:\n%s", text)
	}
	md := FormatMarkdown(r)
	if !strings.Contains(md, "❌") || !strings.Contains(md, "| Rule | Detail |") {
		t.Fatalf("markdown report missing content:\n%s", md)
	}

	pass := Evaluate(&Policy{Name: "ok"}, Input{Risks: riskMap()})
	if !strings.Contains(FormatText(pass), "PASS") {
		t.Fatal("passing text report should say PASS")
	}
	if !strings.Contains(FormatMarkdown(pass), "✅") {
		t.Fatal("passing markdown report should show ✅")
	}
}

// A multiline violation message (acceptance-expiry errors embed newlines) must
// not break the Markdown table — newlines become <br>, not literal row breaks.
func TestFormatMarkdownMultilineMessage(t *testing.T) {
	r := &Result{
		PolicyName:       "p",
		AtRiskBySeverity: map[string]int{},
		Violations: []Violation{{
			Rule:    "fail_on_expired_acceptance",
			Message: "2 acceptances expired:\n  a\n  b",
		}},
	}
	md := FormatMarkdown(r)
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| `fail_on_expired_acceptance`") {
			if strings.Contains(line, "<br>") && strings.Count(line, "|") == 3 {
				return // single well-formed table row
			}
			t.Fatalf("table row malformed by multiline message: %q", line)
		}
	}
	t.Fatal("violation row not found in markdown")
}
