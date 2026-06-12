package quant

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func writeEstimates(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "estimates.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write estimates: %v", err)
	}
	return path
}

func TestLoadEstimates_Valid(t *testing.T) {
	path := writeEstimates(t, `
default_iterations: 500
estimates:
  some-category:
    loss_event_frequency: {min: 0.1, most_likely: 0.5, max: 2.0}
    loss_magnitude: {min: 1000, most_likely: 25000, max: 500000}
    confidence: 0.7
`)
	estimates, err := LoadEstimates(path)
	if err != nil {
		t.Fatalf("LoadEstimates: %v", err)
	}
	if estimates.DefaultIterations != 500 {
		t.Errorf("expected default_iterations 500, got %d", estimates.DefaultIterations)
	}
	if len(estimates.Estimates) != 1 {
		t.Fatalf("expected 1 estimate, got %d", len(estimates.Estimates))
	}
	if estimates.Estimates["some-category"].LossMagnitude.Max != 500000 {
		t.Error("loss_magnitude.max not parsed")
	}
}

func TestLoadEstimates_Errors(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"empty", `estimates: {}`},
		{"missing magnitude", `
estimates:
  x:
    loss_event_frequency: {min: 0.1, most_likely: 0.5, max: 2.0}
`},
		{"min greater than mode", `
estimates:
  x:
    loss_event_frequency: {min: 1.0, most_likely: 0.5, max: 2.0}
    loss_magnitude: {min: 1000, most_likely: 25000, max: 500000}
`},
		{"negative min", `
estimates:
  x:
    loss_event_frequency: {min: 0.1, most_likely: 0.5, max: 2.0}
    loss_magnitude: {min: -5, most_likely: 25000, max: 500000}
`},
		{"not yaml", `{{{{`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadEstimates(writeEstimates(t, tc.content)); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestLoadEstimates_MissingFile(t *testing.T) {
	if _, err := LoadEstimates(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}

func quantifyFixtureModel() *types.Model {
	return &types.Model{
		GeneratedRisksByCategory: map[string][]*types.Risk{
			"cat-a": {
				{SyntheticId: "cat-a@asset-1", Severity: types.HighSeverity},
				{SyntheticId: "cat-a@asset-2", Severity: types.MediumSeverity},
			},
			"cat-b": {
				{SyntheticId: "cat-b@asset-1", Severity: types.CriticalSeverity},
			},
			"cat-c": {
				{SyntheticId: "cat-c@asset-1", Severity: types.LowSeverity},
			},
		},
		RiskTracking: map[string]*types.RiskTracking{
			"cat-a@asset-2": {SyntheticRiskId: "cat-a@asset-2", Status: types.Accepted},
		},
	}
}

func testEstimates() *EstimatesFile {
	lef := &types.LossDistribution{Min: 0.1, MostLikely: 0.5, Max: 2.0}
	lm := &types.LossDistribution{Min: 1000, MostLikely: 25000, Max: 500000}
	bigLM := &types.LossDistribution{Min: 100000, MostLikely: 500000, Max: 5000000}
	return &EstimatesFile{
		Estimates: map[string]*types.FairEstimate{
			"cat-a":         {LossEventFrequency: lef, LossMagnitude: lm},
			"cat-b@asset-1": {LossEventFrequency: lef, LossMagnitude: bigLM},
		},
	}
}

func TestQuantify(t *testing.T) {
	parsedModel := quantifyFixtureModel()
	result := Quantify(parsedModel, testEstimates(), 2000)

	if result.Iterations != 2000 {
		t.Errorf("expected 2000 iterations, got %d", result.Iterations)
	}
	if result.Portfolio.TotalRisks != 4 {
		t.Errorf("expected 4 total risks, got %d", result.Portfolio.TotalRisks)
	}
	if result.Portfolio.QuantifiedRisks != 3 {
		t.Fatalf("expected 3 quantified risks (cat-c has no estimate), got %d", result.Portfolio.QuantifiedRisks)
	}

	// cat-b@asset-1 has the much larger loss magnitude, so it must sort first.
	if result.Risks[0].SyntheticId != "cat-b@asset-1" {
		t.Errorf("expected cat-b@asset-1 to have the highest median ALE, got %q first", result.Risks[0].SyntheticId)
	}
	if result.Risks[0].MatchedBy != "cat-b@asset-1" {
		t.Errorf("expected exact synthetic-ID match, got matched_by %q", result.Risks[0].MatchedBy)
	}

	for _, riskResult := range result.Risks {
		if riskResult.Result.ALE_P10 > riskResult.Result.ALE_P50 || riskResult.Result.ALE_P50 > riskResult.Result.ALE_P90 {
			t.Errorf("%s: percentiles not monotonic: %v", riskResult.SyntheticId, riskResult.Result)
		}
		if riskResult.SyntheticId != "cat-b@asset-1" && riskResult.MatchedBy != "cat-a" {
			t.Errorf("%s: expected category fallback match, got %q", riskResult.SyntheticId, riskResult.MatchedBy)
		}
	}

	// tracking status applied
	for _, riskResult := range result.Risks {
		if riskResult.SyntheticId == "cat-a@asset-2" && riskResult.Status != types.Accepted.String() {
			t.Errorf("expected tracking status accepted for cat-a@asset-2, got %q", riskResult.Status)
		}
	}

	sum := result.Risks[0].Result.ALE_P50 + result.Risks[1].Result.ALE_P50 + result.Risks[2].Result.ALE_P50
	if diff := result.Portfolio.SumALEP50 - sum; diff > 0.001 || diff < -0.001 {
		t.Errorf("portfolio P50 sum mismatch: %f vs %f", result.Portfolio.SumALEP50, sum)
	}
}

func TestQuantify_Deterministic(t *testing.T) {
	parsedModel := quantifyFixtureModel()
	first := Quantify(parsedModel, testEstimates(), 1000)
	second := Quantify(parsedModel, testEstimates(), 1000)

	if len(first.Risks) != len(second.Risks) {
		t.Fatalf("risk count differs across runs: %d vs %d", len(first.Risks), len(second.Risks))
	}
	for i := range first.Risks {
		a, b := first.Risks[i], second.Risks[i]
		if a.SyntheticId != b.SyntheticId || *a.Result != *b.Result {
			t.Errorf("run results differ at %d: %+v vs %+v", i, a, b)
		}
	}
}

func TestQuantify_DefaultIterations(t *testing.T) {
	parsedModel := quantifyFixtureModel()

	estimates := testEstimates()
	estimates.DefaultIterations = 100
	if got := Quantify(parsedModel, estimates, 0).Iterations; got != 100 {
		t.Errorf("expected estimates-file default of 100 iterations, got %d", got)
	}

	estimates.DefaultIterations = 0
	if got := Quantify(parsedModel, estimates, 0).Iterations; got != DefaultIterations {
		t.Errorf("expected package default %d iterations, got %d", DefaultIterations, got)
	}
}
