package oscal

import (
	"encoding/json"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func sampleModel() *types.Model {
	return &types.Model{
		Title: "VaultNote",
		GeneratedRisksByCategory: map[string][]*types.Risk{
			"missing-authentication": {
				{SyntheticId: "missing-authentication@web", Title: "Missing Auth on web", CategoryId: "missing-authentication", Severity: types.HighSeverity, RiskStatus: types.Unchecked},
			},
			"unencrypted-asset": {
				{SyntheticId: "unencrypted-asset@db", Title: "Unencrypted db", CategoryId: "unencrypted-asset", Severity: types.ElevatedSeverity, RiskStatus: types.Mitigated},
			},
		},
	}
}

func TestBuildShapeAndStatuses(t *testing.T) {
	doc := Build(sampleModel(), sampleModel().AllRisks(), "", "")
	ar := doc.AssessmentResults
	if ar.UUID == "" || ar.Metadata.OSCALVersion != oscalVersion {
		t.Fatalf("bad metadata: %+v", ar.Metadata)
	}
	if ar.ImportAP.Href == "" {
		t.Error("import-ap href is required by OSCAL")
	}
	if len(ar.Results) != 1 || len(ar.Results[0].Findings) != 2 {
		t.Fatalf("expected 1 result with 2 findings, got %+v", ar.Results)
	}
	// findings are sorted by synthetic id: missing-authentication before unencrypted
	f := ar.Results[0].Findings
	if f[0].Target.Status.State != "not-satisfied" {
		t.Errorf("unchecked High should be not-satisfied, got %s", f[0].Target.Status.State)
	}
	if f[1].Target.Status.State != "satisfied" {
		t.Errorf("mitigated risk should be satisfied, got %s", f[1].Target.Status.State)
	}
	if f[0].Target.TargetID != "missing-authentication" {
		t.Errorf("target-id should be the category, got %s", f[0].Target.TargetID)
	}
}

func TestDeterministicAndValidJSON(t *testing.T) {
	first, err := json.Marshal(Build(sampleModel(), sampleModel().AllRisks(), "", ""))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		got, _ := json.Marshal(Build(sampleModel(), sampleModel().AllRisks(), "", ""))
		if string(got) != string(first) {
			t.Fatal("non-deterministic OSCAL output")
		}
	}
	// round-trips as JSON
	var v map[string]any
	if err := json.Unmarshal(first, &v); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, ok := v["assessment-results"]; !ok {
		t.Error("missing top-level assessment-results")
	}
}

func TestBuildRecordsProvenance(t *testing.T) {
	doc := Build(sampleModel(), sampleModel().AllRisks(), "1.2.3", "abc123")
	props := doc.AssessmentResults.Metadata.Props
	got := map[string]string{}
	for _, p := range props {
		got[p.Name] = p.Value
	}
	if got["threagile-version"] != "1.2.3" || got["model-sha256"] != "abc123" {
		t.Fatalf("expected provenance props, got %+v", props)
	}
	// empty provenance must be omitted, not emitted as empty props
	if Build(sampleModel(), sampleModel().AllRisks(), "", "").AssessmentResults.Metadata.Props != nil {
		t.Error("expected no props when version/hash are empty")
	}
}

func TestEmptyModelProducesValidDocument(t *testing.T) {
	doc := Build(&types.Model{Title: "Empty"}, nil, "", "")
	if len(doc.AssessmentResults.Results) != 1 {
		t.Errorf("should still emit one result entry, got %d", len(doc.AssessmentResults.Results))
	}
	if len(doc.AssessmentResults.Results[0].Findings) != 0 {
		t.Errorf("no risks -> no findings")
	}
}
