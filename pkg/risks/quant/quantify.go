package quant

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/threagile/threagile/pkg/types"
)

// EstimatesFile is the YAML document passed to `threagile quantify --estimates`.
// Estimate keys are matched against each generated risk's synthetic ID first
// (exact match wins), then against its category ID (applies to every risk of
// that category).
type EstimatesFile struct {
	// DefaultIterations overrides the Monte-Carlo iteration count (optional).
	DefaultIterations int `yaml:"default_iterations,omitempty" json:"default_iterations,omitempty"`
	// Estimates maps a synthetic risk ID or risk-category ID to its FAIR estimate.
	Estimates map[string]*types.FairEstimate `yaml:"estimates" json:"estimates"`
}

// LoadEstimates reads and validates an estimates YAML file.
func LoadEstimates(filename string) (*EstimatesFile, error) {
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("read estimates file: %w", err)
	}
	var file EstimatesFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse estimates file %q: %w", filename, err)
	}
	if len(file.Estimates) == 0 {
		return nil, fmt.Errorf("estimates file %q contains no estimates", filename)
	}
	for key, estimate := range file.Estimates {
		if estimate == nil || estimate.LossEventFrequency == nil || estimate.LossMagnitude == nil {
			return nil, fmt.Errorf("estimate %q must define both loss_event_frequency and loss_magnitude", key)
		}
		for name, dist := range map[string]*types.LossDistribution{
			"loss_event_frequency": estimate.LossEventFrequency,
			"loss_magnitude":       estimate.LossMagnitude,
		} {
			if dist.Min < 0 || dist.MostLikely < dist.Min || dist.Max < dist.MostLikely {
				return nil, fmt.Errorf("estimate %q: %s must satisfy 0 <= min <= most_likely <= max", key, name)
			}
		}
	}
	return &file, nil
}

// RiskQuantification is the simulation result for one generated risk.
type RiskQuantification struct {
	SyntheticId string                  `yaml:"synthetic_id" json:"synthetic_id"`
	CategoryId  string                  `yaml:"category" json:"category"`
	Severity    string                  `yaml:"severity" json:"severity"`
	Status      string                  `yaml:"status" json:"status"`
	MatchedBy   string                  `yaml:"matched_by" json:"matched_by"` // estimate key that supplied the FAIR parameters
	Result      *types.MonteCarloResult `yaml:"result" json:"result"`
}

// PortfolioResult aggregates per-risk ALE percentiles. The sums are an
// approximation (summing percentiles, not jointly simulating) and bound the
// true portfolio percentiles from above for p90 / below for p10.
type PortfolioResult struct {
	QuantifiedRisks int     `yaml:"quantified_risks" json:"quantified_risks"`
	TotalRisks      int     `yaml:"total_risks" json:"total_risks"`
	SumALEP10       float64 `yaml:"sum_ale_p10" json:"sum_ale_p10"`
	SumALEP50       float64 `yaml:"sum_ale_p50" json:"sum_ale_p50"`
	SumALEP90       float64 `yaml:"sum_ale_p90" json:"sum_ale_p90"`
}

// QuantifyResult is the full output of a quantify run.
type QuantifyResult struct {
	Iterations int                  `yaml:"iterations" json:"iterations"`
	Portfolio  PortfolioResult      `yaml:"portfolio" json:"portfolio"`
	Risks      []RiskQuantification `yaml:"risks" json:"risks"`
}

// Quantify runs the Monte-Carlo ALE simulation for every generated risk that
// has a matching FAIR estimate (by synthetic ID, falling back to category ID).
// Results are deterministic per synthetic ID and sorted by ALE p50 descending.
func Quantify(parsedModel *types.Model, estimates *EstimatesFile, iterations int) *QuantifyResult {
	if iterations <= 0 {
		iterations = estimates.DefaultIterations
	}
	if iterations <= 0 {
		iterations = DefaultIterations
	}

	result := &QuantifyResult{Iterations: iterations, Risks: make([]RiskQuantification, 0)}

	categoryIDs := make([]string, 0, len(parsedModel.GeneratedRisksByCategory))
	for categoryID := range parsedModel.GeneratedRisksByCategory {
		categoryIDs = append(categoryIDs, categoryID)
	}
	sort.Strings(categoryIDs)

	for _, categoryID := range categoryIDs {
		for _, risk := range parsedModel.GeneratedRisksByCategory[categoryID] {
			result.Portfolio.TotalRisks++

			matchedBy := ""
			var estimate *types.FairEstimate
			if e, ok := estimates.Estimates[risk.SyntheticId]; ok {
				estimate, matchedBy = e, risk.SyntheticId
			} else if e, ok := estimates.Estimates[categoryID]; ok {
				estimate, matchedBy = e, categoryID
			} else {
				continue
			}

			mc := RunMonteCarlo(risk.SyntheticId, estimate, iterations)
			if mc == nil {
				continue
			}

			status := risk.RiskStatus
			if tracking, ok := parsedModel.RiskTracking[risk.SyntheticId]; ok {
				status = tracking.Status
			}

			result.Risks = append(result.Risks, RiskQuantification{
				SyntheticId: risk.SyntheticId,
				CategoryId:  categoryID,
				Severity:    risk.Severity.String(),
				Status:      status.String(),
				MatchedBy:   matchedBy,
				Result:      mc,
			})
			result.Portfolio.QuantifiedRisks++
			result.Portfolio.SumALEP10 += mc.ALE_P10
			result.Portfolio.SumALEP50 += mc.ALE_P50
			result.Portfolio.SumALEP90 += mc.ALE_P90
		}
	}

	sort.Slice(result.Risks, func(i, j int) bool {
		if result.Risks[i].Result.ALE_P50 == result.Risks[j].Result.ALE_P50 {
			return result.Risks[i].SyntheticId < result.Risks[j].SyntheticId
		}
		return result.Risks[i].Result.ALE_P50 > result.Risks[j].Result.ALE_P50
	})

	return result
}
