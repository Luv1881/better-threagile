// Package quant provides quantitative risk functions for FAIR-style ALE calculations.
package quant

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/rand"
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

const DefaultIterations = 10_000

// PERTSample draws one sample from a modified PERT distribution defined by (min, mode, max).
// The modified PERT uses lambda=4 (equal weighting to min and max as in classic PERT).
// rng must be a pre-seeded source; callers own the seed for reproducibility.
func PERTSample(rng *rand.Rand, min, mode, max float64) float64 {
	if min >= max {
		return min
	}

	// Map to Beta distribution parameters.
	// alpha = 1 + lambda*(mode-min)/(max-min)
	// beta  = 1 + lambda*(max-mode)/(max-min)
	const lambda = 4.0
	alpha := 1.0 + lambda*(mode-min)/(max-min)
	beta := 1.0 + lambda*(max-mode)/(max-min)

	// Draw from Beta(alpha, beta) using the Johnk method.
	sample := betaSample(rng, alpha, beta)
	return min + sample*(max-min)
}

// betaSample draws one sample from Beta(alpha, beta) using Cheng's BB algorithm
// for large parameters and Johnk's method for small ones.
func betaSample(rng *rand.Rand, alpha, beta float64) float64 {
	if alpha <= 0 || beta <= 0 {
		return 0
	}
	if alpha == 1 && beta == 1 {
		return rng.Float64()
	}

	// Use log-gamma approach via gamma ratio for robustness across all parameter ranges.
	x := gammaSample(rng, alpha)
	y := gammaSample(rng, beta)
	if x+y == 0 {
		return 0.5
	}
	return x / (x + y)
}

// gammaSample draws from Gamma(shape, 1) using Marsaglia–Tsang method.
func gammaSample(rng *rand.Rand, shape float64) float64 {
	if shape < 1 {
		return gammaSample(rng, shape+1) * math.Pow(rng.Float64(), 1.0/shape)
	}

	d := shape - 1.0/3.0
	c := 1.0 / math.Sqrt(9.0*d)

	for {
		x := rng.NormFloat64()
		v := 1.0 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := rng.Float64()
		if u < 1.0-0.0331*(x*x)*(x*x) {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1.0-v+math.Log(v)) {
			return d * v
		}
	}
}

// modelSeedFromID derives a deterministic uint64 seed from a synthetic risk ID
// so results are reproducible across runs for the same model state.
func modelSeedFromID(syntheticID string) int64 {
	h := sha256.Sum256([]byte(syntheticID))
	return int64(binary.LittleEndian.Uint64(h[:8]))
}

// RunMonteCarlo simulates ALE for a single finding given its FAIR estimate.
// syntheticID is used to seed the RNG deterministically.
// Returns nil if the estimate has no LossEventFrequency or LossMagnitude.
func RunMonteCarlo(syntheticID string, estimate *types.FairEstimate, iterations int) *types.MonteCarloResult {
	if estimate == nil || estimate.LossEventFrequency == nil || estimate.LossMagnitude == nil {
		return nil
	}

	if iterations <= 0 {
		iterations = DefaultIterations
	}

	lef := estimate.LossEventFrequency
	lm := estimate.LossMagnitude

	rng := rand.New(rand.NewSource(modelSeedFromID(syntheticID))) //nolint:gosec
	ales := make([]float64, iterations)

	for i := 0; i < iterations; i++ {
		freq := PERTSample(rng, lef.Min, lef.MostLikely, lef.Max)
		mag := PERTSample(rng, lm.Min, lm.MostLikely, lm.Max)
		if freq < 0 {
			freq = 0
		}
		if mag < 0 {
			mag = 0
		}
		ales[i] = freq * mag
	}

	sort.Float64s(ales)

	p10 := ales[int(math.Floor(float64(iterations)*0.10))]
	p50 := ales[int(math.Floor(float64(iterations)*0.50))]
	p90 := ales[int(math.Floor(float64(iterations)*0.90))]

	return &types.MonteCarloResult{
		ALE_P10:    p10,
		ALE_P50:    p50,
		ALE_P90:    p90,
		Iterations: iterations,
	}
}
