package score

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func modelWith(risks []*types.Risk) *types.Model {
	return &types.Model{
		Title:  "Test",
		Author: &types.Author{Name: "Alice"},
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"api": {Id: "api", Owner: "team-a", DataAssetsProcessed: []string{"secret"},
				CommunicationLinks: []*types.CommunicationLink{{TargetId: "db", Protocol: types.HTTPS}}},
			"db": {Id: "db", Owner: "team-a", DataAssetsStored: []string{"secret"}},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"net": {Id: "net", TechnicalAssetsInside: []string{"api", "db"}},
		},
		DataAssets: map[string]*types.DataAsset{"secret": {Id: "secret"}},
		GeneratedRisksByCategory: map[string][]*types.Risk{
			"cat": risks,
		},
	}
}

func TestPerfectModelScoresHigh(t *testing.T) {
	// fully-modelled, all risks mitigated -> should be grade A.
	r := Compute(modelWith([]*types.Risk{
		{Severity: types.HighSeverity, RiskStatus: types.Mitigated, MostRelevantTechnicalAssetId: "api"},
		{Severity: types.CriticalSeverity, RiskStatus: types.Mitigated, MostRelevantTechnicalAssetId: "db"},
	}))
	if r.Grade != "A" {
		t.Errorf("expected grade A, got %s (overall %d, compl %.2f, posture %.2f)", r.Grade, r.Overall, r.Completeness, r.Posture)
	}
	if r.Posture != 1.0 {
		t.Errorf("all-mitigated posture should be 1.0, got %.2f", r.Posture)
	}
}

func TestUncheckedCriticalTanksPosture(t *testing.T) {
	r := Compute(modelWith([]*types.Risk{
		{Severity: types.CriticalSeverity, RiskStatus: types.Unchecked, MostRelevantTechnicalAssetId: "api"},
	}))
	if r.Posture != 0.0 {
		t.Errorf("a single unchecked Critical should give posture 0, got %.2f", r.Posture)
	}
	if r.Grade == "A" {
		t.Errorf("an un-triaged Critical should not be grade A, got %s", r.Grade)
	}
}

func TestSeverityWeightingFavorsFixingCriticals(t *testing.T) {
	// Same number of risks; fixing the Critical (vs the Low) yields higher posture.
	fixCrit := Compute(modelWith([]*types.Risk{
		{Severity: types.CriticalSeverity, RiskStatus: types.Mitigated},
		{Severity: types.LowSeverity, RiskStatus: types.Unchecked},
	}))
	fixLow := Compute(modelWith([]*types.Risk{
		{Severity: types.CriticalSeverity, RiskStatus: types.Unchecked},
		{Severity: types.LowSeverity, RiskStatus: types.Mitigated},
	}))
	if !(fixCrit.Posture > fixLow.Posture) {
		t.Errorf("fixing the Critical should beat fixing the Low: %.2f vs %.2f", fixCrit.Posture, fixLow.Posture)
	}
}

func TestIncompleteModelLowersCompleteness(t *testing.T) {
	m := modelWith([]*types.Risk{{Severity: types.LowSeverity, RiskStatus: types.Mitigated}})
	m.TechnicalAssets["api"].Owner = "" // drop an owner
	m.TechnicalAssets["api"].CommunicationLinks[0].Protocol = types.UnknownProtocol
	full := Compute(modelWith([]*types.Risk{{Severity: types.LowSeverity, RiskStatus: types.Mitigated}}))
	partial := Compute(m)
	if !(partial.Completeness < full.Completeness) {
		t.Errorf("missing owner+protocol should lower completeness: %.2f vs %.2f", partial.Completeness, full.Completeness)
	}
}

func TestEmptyModelScoresZeroNotPerfect(t *testing.T) {
	// Gaming guard: an empty (or title+author-only) model must NOT look perfect.
	r := Compute(&types.Model{Title: "Looks legit", Author: &types.Author{Name: "Eve"}})
	if r.Overall != 0 || r.Grade != "F" {
		t.Errorf("empty model should score 0/F, got %d/%s", r.Overall, r.Grade)
	}
	if !r.Insufficient || len(r.Notes) == 0 {
		t.Errorf("empty model should be flagged insufficient with a note, got %+v", r)
	}
}

func TestUntriagedCriticalCapsScore(t *testing.T) {
	// Gaming guard: piling up mitigated lows cannot mask an un-triaged Critical.
	risks := []*types.Risk{{Severity: types.CriticalSeverity, RiskStatus: types.Unchecked, MostRelevantTechnicalAssetId: "api"}}
	for i := 0; i < 20; i++ {
		risks = append(risks, &types.Risk{Severity: types.LowSeverity, RiskStatus: types.Mitigated})
	}
	r := Compute(modelWith(risks))
	if r.Overall > cappedCeiling {
		t.Errorf("an un-triaged Critical must cap the score at %d, got %d", cappedCeiling, r.Overall)
	}
	if r.Grade != "F" || !r.Capped {
		t.Errorf("expected capped grade F, got %s (capped=%v)", r.Grade, r.Capped)
	}
}

func TestTriagedCriticalIsNotCapped(t *testing.T) {
	// An accepted (consciously triaged) Critical does not trigger the hard cap.
	r := Compute(modelWith([]*types.Risk{
		{Severity: types.CriticalSeverity, RiskStatus: types.Accepted, MostRelevantTechnicalAssetId: "api"},
	}))
	if r.Capped {
		t.Errorf("a triaged (accepted) Critical should not hard-cap the score: %+v", r)
	}
}

func TestDeterministic(t *testing.T) {
	build := func() *Report {
		return Compute(modelWith([]*types.Risk{
			{Severity: types.HighSeverity, RiskStatus: types.Accepted},
			{Severity: types.MediumSeverity, RiskStatus: types.InProgress},
		}))
	}
	first, _ := FormatJSON(build())
	for i := 0; i < 10; i++ {
		got, _ := FormatJSON(build())
		if got != first {
			t.Fatal("non-deterministic score output")
		}
	}
}

func TestShieldsBadgeValid(t *testing.T) {
	r := Compute(modelWith([]*types.Risk{{Severity: types.LowSeverity, RiskStatus: types.Mitigated}}))
	out, err := FormatShields(r)
	if err != nil {
		t.Fatal(err)
	}
	var badge map[string]any
	if err := json.Unmarshal([]byte(out), &badge); err != nil {
		t.Fatalf("shields output is not valid JSON: %v", err)
	}
	if badge["schemaVersion"].(float64) != 1 {
		t.Errorf("shields schemaVersion should be 1, got %v", badge["schemaVersion"])
	}
	if !strings.Contains(badge["message"].(string), r.Grade) {
		t.Errorf("badge message %q should contain grade %s", badge["message"], r.Grade)
	}
}
