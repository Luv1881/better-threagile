package coverage

import (
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func makeCategory(id string, nist, owasp []string) *types.RiskCategory {
	return &types.RiskCategory{
		ID: id,
		Controls: &types.ControlMapping{
			NIST80053:  nist,
			OWASPTop10: owasp,
		},
	}
}

func TestAnalyze_basic(t *testing.T) {
	cats := []*types.RiskCategory{
		makeCategory("rule-a", []string{"SC-8", "SC-13"}, []string{"A02"}),
		makeCategory("rule-b", []string{"AC-3"}, []string{"A01", "A05"}),
		makeCategory("rule-c", nil, nil), // no controls
	}

	report, err := Analyze("nist_800_53", cats)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if report.Framework != "nist_800_53" {
		t.Errorf("expected framework nist_800_53, got %q", report.Framework)
	}
	if report.TotalRules != 3 {
		t.Errorf("expected 3 rules, got %d", report.TotalRules)
	}
	if report.CoveredCount != 3 {
		t.Errorf("expected 3 covered controls (SC-8, SC-13, AC-3), got %d", report.CoveredCount)
	}

	// SC-8 should be covered by rule-a
	var sc8 *ControlEntry
	for i := range report.Controls {
		if report.Controls[i].ControlID == "SC-8" {
			sc8 = &report.Controls[i]
		}
	}
	if sc8 == nil {
		t.Fatal("SC-8 not found in report")
	}
	if !sc8.Covered {
		t.Error("SC-8 should be covered")
	}
	if len(sc8.CoveringRules) != 1 || sc8.CoveringRules[0] != "rule-a" {
		t.Errorf("SC-8 covering rules: expected [rule-a], got %v", sc8.CoveringRules)
	}
}

func TestAnalyze_multipleRulesSameControl(t *testing.T) {
	cats := []*types.RiskCategory{
		makeCategory("rule-x", []string{"SC-28"}, nil),
		makeCategory("rule-y", []string{"SC-28", "SC-8"}, nil),
	}

	report, _ := Analyze("nist_800_53", cats)
	for _, e := range report.Controls {
		if e.ControlID == "SC-28" {
			if len(e.CoveringRules) != 2 {
				t.Errorf("expected 2 rules for SC-28, got %v", e.CoveringRules)
			}
		}
	}
}

func TestAnalyze_unknownFramework(t *testing.T) {
	_, err := Analyze("fantasy_framework", nil)
	if err == nil {
		t.Error("expected error for unknown framework")
	}
}

func TestAnalyze_emptyRules(t *testing.T) {
	report, err := Analyze("owasp_top10_2021", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Controls) != 0 {
		t.Errorf("expected 0 controls, got %d", len(report.Controls))
	}
}

func TestAnalyzeWithGaps(t *testing.T) {
	cats := []*types.RiskCategory{
		makeCategory("rule-a", []string{"SC-8"}, nil),
	}
	known := []string{"SC-8", "SC-13", "AC-3"}

	report, err := AnalyzeWithGaps("nist_800_53", cats, known)
	if err != nil {
		t.Fatalf("AnalyzeWithGaps failed: %v", err)
	}
	if report.CoveredCount != 1 {
		t.Errorf("expected 1 covered, got %d", report.CoveredCount)
	}
	if report.GapCount != 2 {
		t.Errorf("expected 2 gaps, got %d", report.GapCount)
	}
	if len(report.Controls) != 3 {
		t.Errorf("expected 3 total controls, got %d", len(report.Controls))
	}
}

func TestFormatTable(t *testing.T) {
	cats := []*types.RiskCategory{
		makeCategory("rule-a", []string{"SC-8"}, nil),
	}
	report, _ := Analyze("nist_800_53", cats)
	out := FormatTable(report)

	if !strings.Contains(out, "SC-8") {
		t.Error("output should contain SC-8")
	}
	if !strings.Contains(out, "COVERED") {
		t.Error("output should contain COVERED")
	}
	if !strings.Contains(out, "NIST SP 800-53") {
		t.Error("output should contain framework title")
	}
}

func TestFormatTable_noControls(t *testing.T) {
	cats := []*types.RiskCategory{
		{ID: "rule-a", Controls: nil},
	}
	report, _ := Analyze("nist_800_53", cats)
	out := FormatTable(report)
	if !strings.Contains(out, "No control mappings") {
		t.Error("output should indicate no controls found")
	}
}
