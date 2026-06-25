package prioritize

import (
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// internet client -> api -> db(strictly-confidential). api has a High risk; an
// out-of-band internal asset has a High risk too but is not internet-reachable.
func buildModel() *types.Model {
	link := func(t string) *types.CommunicationLink { return &types.CommunicationLink{TargetId: t} }
	return &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"client": {Id: "client", Title: "Client", Internet: true, CommunicationLinks: []*types.CommunicationLink{link("api")}},
			"api":    {Id: "api", Title: "API", Internet: true, CommunicationLinks: []*types.CommunicationLink{link("db")}, DataAssetsProcessed: []string{"secret"}},
			"db":     {Id: "db", Title: "DB", DataAssetsStored: []string{"secret"}},
			"batch":  {Id: "batch", Title: "Batch Job"},
		},
		DataAssets: map[string]*types.DataAsset{
			"secret": {Id: "secret", Confidentiality: types.StrictlyConfidential},
		},
		GeneratedRisksByCategory: map[string][]*types.Risk{
			"cat-a": {{SyntheticId: "cat-a@api", Title: "Exposed API", CategoryId: "cat-a", Severity: types.HighSeverity, RiskStatus: types.Unchecked, MostRelevantTechnicalAssetId: "api"}},
			"cat-b": {{SyntheticId: "cat-b@batch", Title: "Batch flaw", CategoryId: "cat-b", Severity: types.HighSeverity, RiskStatus: types.Unchecked, MostRelevantTechnicalAssetId: "batch"}},
			"cat-c": {{SyntheticId: "cat-c@db", Title: "Mitigated DB issue", CategoryId: "cat-c", Severity: types.CriticalSeverity, RiskStatus: types.Mitigated, MostRelevantTechnicalAssetId: "db"}},
		},
		BuiltInRiskCategories: types.RiskCategories{
			{ID: "cat-a", Action: "Add authentication", Mitigation: "Require auth on the API", CWE: 306},
		},
	}
}

func TestInternetExposedRanksAboveInternalSameSeverity(t *testing.T) {
	r := Analyze(buildModel())
	if r.TotalAtRisk != 2 {
		t.Fatalf("expected 2 still-at-risk (mitigated excluded), got %d", r.TotalAtRisk)
	}
	if len(r.Items) < 2 {
		t.Fatalf("expected ranked items, got %d", len(r.Items))
	}
	// the internet-facing, attack-path-reachable API finding must outrank the
	// internal batch finding of the same severity.
	if r.Items[0].SyntheticID != "cat-a@api" {
		t.Errorf("expected exposed API finding first, got %s (score %d) vs %s", r.Items[0].SyntheticID, r.Items[0].Score, r.Items[1].SyntheticID)
	}
	if r.Items[0].Score <= r.Items[1].Score {
		t.Errorf("exposed finding should score higher: %d vs %d", r.Items[0].Score, r.Items[1].Score)
	}
}

func TestRemediationIsAttached(t *testing.T) {
	r := Analyze(buildModel())
	var apiItem *Item
	for i := range r.Items {
		if r.Items[i].SyntheticID == "cat-a@api" {
			apiItem = &r.Items[i]
		}
	}
	if apiItem == nil {
		t.Fatal("api item missing")
	}
	if apiItem.Remediation.Action != "Add authentication" || apiItem.Remediation.CWE != 306 {
		t.Errorf("remediation not surfaced: %+v", apiItem.Remediation)
	}
}

func TestMitigatedExcluded(t *testing.T) {
	r := Analyze(buildModel())
	for _, it := range r.Items {
		if it.SyntheticID == "cat-c@db" {
			t.Error("mitigated finding should not be ranked")
		}
	}
}

func TestAdditiveScoreNeverZeroForRealFinding(t *testing.T) {
	// An internal, low-sensitivity finding still gets a non-zero score (additive,
	// not multiplicative) so it isn't hidden entirely.
	r := Analyze(buildModel())
	for _, it := range r.Items {
		if it.Score <= 0 {
			t.Errorf("finding %s scored 0 — additive model should avoid that", it.SyntheticID)
		}
	}
}

func TestDeterministic(t *testing.T) {
	first, _ := FormatJSON(Analyze(buildModel()).Items, 2)
	for i := 0; i < 10; i++ {
		got, _ := FormatJSON(Analyze(buildModel()).Items, 2)
		if got != first {
			t.Fatal("non-deterministic prioritize output")
		}
	}
}

func TestFormatTextShowsFix(t *testing.T) {
	r := Analyze(buildModel())
	txt := FormatText(r.Top(5), r.TotalAtRisk)
	if !strings.Contains(txt, "fix:") || !strings.Contains(txt, "Add authentication") {
		t.Errorf("text output should show the fix:\n%s", txt)
	}
}
