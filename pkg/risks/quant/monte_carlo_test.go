package quant

import (
	"math"
	"math/rand"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func TestRunMonteCarlo_nil_estimate_returns_nil(t *testing.T) {
	result := RunMonteCarlo("test@asset", nil, DefaultIterations)
	if result != nil {
		t.Error("expected nil for nil estimate")
	}
}

func TestRunMonteCarlo_returns_ordered_percentiles(t *testing.T) {
	estimate := &types.FairEstimate{
		LossEventFrequency: &types.LossDistribution{Min: 0.1, MostLikely: 1.0, Max: 10.0},
		LossMagnitude:      &types.LossDistribution{Min: 10_000, MostLikely: 100_000, Max: 1_000_000},
	}

	result := RunMonteCarlo("sql-injection@api-server", estimate, DefaultIterations)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.ALE_P10 > result.ALE_P50 {
		t.Errorf("P10 (%f) > P50 (%f)", result.ALE_P10, result.ALE_P50)
	}
	if result.ALE_P50 > result.ALE_P90 {
		t.Errorf("P50 (%f) > P90 (%f)", result.ALE_P50, result.ALE_P90)
	}
	if result.ALE_P90 <= 0 {
		t.Error("P90 should be positive")
	}
}

func TestRunMonteCarlo_is_deterministic(t *testing.T) {
	estimate := &types.FairEstimate{
		LossEventFrequency: &types.LossDistribution{Min: 0.5, MostLikely: 2.0, Max: 8.0},
		LossMagnitude:      &types.LossDistribution{Min: 5_000, MostLikely: 50_000, Max: 500_000},
	}
	r1 := RunMonteCarlo("same-id@asset", estimate, 1000)
	r2 := RunMonteCarlo("same-id@asset", estimate, 1000)

	if math.Abs(r1.ALE_P50-r2.ALE_P50) > 1e-9 {
		t.Errorf("results differ across runs: %f vs %f", r1.ALE_P50, r2.ALE_P50)
	}
}

func TestRunMonteCarlo_different_ids_differ(t *testing.T) {
	estimate := &types.FairEstimate{
		LossEventFrequency: &types.LossDistribution{Min: 1, MostLikely: 5, Max: 20},
		LossMagnitude:      &types.LossDistribution{Min: 1_000, MostLikely: 10_000, Max: 100_000},
	}
	r1 := RunMonteCarlo("rule-a@asset-x", estimate, 1000)
	r2 := RunMonteCarlo("rule-b@asset-y", estimate, 1000)
	if r1.ALE_P50 == r2.ALE_P50 {
		t.Error("expected different P50 for different synthetic IDs")
	}
}

func TestPERTSample_stays_in_bounds(t *testing.T) {
	rng := rand.New(rand.NewSource(42)) //nolint:gosec
	for i := 0; i < 10_000; i++ {
		v := PERTSample(rng, 1.0, 5.0, 10.0)
		if v < 1.0 || v > 10.0 {
			t.Fatalf("PERTSample out of bounds: %f", v)
		}
	}
}
