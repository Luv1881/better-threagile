package requirements

import (
	"strings"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func model() *types.Model {
	return &types.Model{
		Title: "App",
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"api": {Id: "api", Title: "API"},
			"web": {Id: "web", Title: "Web"},
		},
		GeneratedRisksByCategory: map[string][]*types.Risk{
			"missing-authentication": {
				{SyntheticId: "missing-authentication@api", CategoryId: "missing-authentication", Severity: types.HighSeverity, RiskStatus: types.Unchecked, MostRelevantTechnicalAssetId: "api"},
				{SyntheticId: "missing-authentication@web", CategoryId: "missing-authentication", Severity: types.ElevatedSeverity, RiskStatus: types.Unchecked, MostRelevantTechnicalAssetId: "web"},
			},
			"resolved-thing": {
				{SyntheticId: "resolved-thing@api", CategoryId: "resolved-thing", Severity: types.CriticalSeverity, RiskStatus: types.Mitigated, MostRelevantTechnicalAssetId: "api"},
			},
		},
		BuiltInRiskCategories: types.RiskCategories{
			{ID: "missing-authentication", Title: "Missing Authentication", Action: "Authenticate incoming requests", Check: "Is auth enforced?", CWE: 306},
		},
	}
}

func TestBuildDedupesByCategoryAndExcludesResolved(t *testing.T) {
	reqs := Build(model())
	if len(reqs) != 1 {
		t.Fatalf("expected 1 requirement (deduped; resolved excluded), got %d: %+v", len(reqs), reqs)
	}
	r := reqs[0]
	if r.CategoryID != "missing-authentication" {
		t.Fatalf("wrong category: %s", r.CategoryID)
	}
	if r.FindingCount != 2 {
		t.Errorf("finding count = %d, want 2", r.FindingCount)
	}
	if r.Severity != "high" {
		t.Errorf("severity should be the highest (high), got %s", r.Severity)
	}
	if r.Statement != "Authenticate incoming requests" || r.CWE != 306 || r.Verification != "Is auth enforced?" {
		t.Errorf("requirement content wrong: %+v", r)
	}
	if len(r.AffectedAssets) != 2 {
		t.Errorf("expected both affected assets, got %v", r.AffectedAssets)
	}
}

func TestFormatsProduceContent(t *testing.T) {
	reqs := Build(model())
	md := FormatMarkdown(reqs)
	if !strings.Contains(md, "- [ ] **Missing Authentication**") || !strings.Contains(md, "CWE-306") || !strings.Contains(md, "Verify:") {
		t.Errorf("markdown missing content:\n%s", md)
	}
	g := FormatGherkin("App", reqs)
	if !strings.Contains(g, "Feature: App security requirements") || !strings.Contains(g, "Scenario: Missing Authentication") || !strings.Contains(g, "Then Authenticate incoming requests") {
		t.Errorf("gherkin missing content:\n%s", g)
	}
}

func TestEmptyWhenAllResolved(t *testing.T) {
	m := model()
	for _, rs := range m.GeneratedRisksByCategory["missing-authentication"] {
		rs.RiskStatus = types.Mitigated
	}
	reqs := Build(m)
	if len(reqs) != 0 {
		t.Errorf("no still-at-risk -> no requirements, got %d", len(reqs))
	}
	if !strings.Contains(FormatMarkdown(reqs), "nothing to require") {
		t.Error("empty markdown should say nothing to require")
	}
}

func TestDeterministic(t *testing.T) {
	first, _ := FormatJSON(Build(model()))
	for i := 0; i < 10; i++ {
		got, _ := FormatJSON(Build(model()))
		if got != first {
			t.Fatal("non-deterministic requirements output")
		}
	}
}
