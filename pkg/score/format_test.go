package score

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func sampleReport() *Report {
	return Compute(modelWith([]*types.Risk{
		{Severity: types.HighSeverity, RiskStatus: types.Accepted, MostRelevantTechnicalAssetId: "api"},
		{Severity: types.MediumSeverity, RiskStatus: types.InProgress, MostRelevantTechnicalAssetId: "db"},
	}))
}

func TestFormatTextHasAllSections(t *testing.T) {
	out := FormatText(sampleReport())
	for _, want := range []string{"Threat-model score:", "completeness:", "Completeness checks:", "Risks:"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatMarkdownHasTable(t *testing.T) {
	out := FormatMarkdown(sampleReport())
	if !strings.Contains(out, "## Threat-model score") || !strings.Contains(out, "| Completeness check |") {
		t.Errorf("markdown missing header/table:\n%s", out)
	}
}

func TestFormatTextShowsNotesWhenCapped(t *testing.T) {
	// an un-triaged Critical caps the score and must surface a caveat note
	r := Compute(modelWith([]*types.Risk{
		{Severity: types.CriticalSeverity, RiskStatus: types.Unchecked, MostRelevantTechnicalAssetId: "api"},
	}))
	if !strings.Contains(FormatText(r), "!") {
		t.Errorf("capped report should print a caveat note:\n%s", FormatText(r))
	}
}

func TestBadgeColorAllGrades(t *testing.T) {
	cases := map[string]string{"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}
	for grade, want := range cases {
		if got := badgeColor(grade); got != want {
			t.Errorf("badgeColor(%q) = %q, want %q", grade, got, want)
		}
	}
}

func TestGradeBoundaries(t *testing.T) {
	cases := map[int]string{100: "A", 90: "A", 89: "B", 80: "B", 79: "C", 70: "C", 69: "D", 60: "D", 59: "F", 0: "F"}
	for overall, want := range cases {
		if got := grade(overall); got != want {
			t.Errorf("grade(%d) = %q, want %q", overall, got, want)
		}
	}
}

func TestWeightOfFallback(t *testing.T) {
	// a known severity uses its weight; an out-of-range one falls back to Medium.
	if weightOf(types.CriticalSeverity) != severityWeight[types.CriticalSeverity] {
		t.Error("known severity weight wrong")
	}
	if weightOf(types.RiskSeverity(99)) != severityWeight[types.MediumSeverity] {
		t.Error("unknown severity should fall back to Medium weight")
	}
}

func TestFormatShieldsValidForEachGrade(t *testing.T) {
	for _, st := range []types.RiskStatus{types.Mitigated, types.Unchecked} {
		r := Compute(modelWith([]*types.Risk{{Severity: types.LowSeverity, RiskStatus: st, MostRelevantTechnicalAssetId: "api"}}))
		out, err := FormatShields(r)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("shields not valid JSON: %v", err)
		}
	}
}
