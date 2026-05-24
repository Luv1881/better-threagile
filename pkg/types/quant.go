package types

// LossDistribution holds the three-point PERT estimate for a FAIR loss parameter.
// All values are in USD per year (for LEF) or USD per event (for LM).
type LossDistribution struct {
	Min        float64 `yaml:"min" json:"min"`
	MostLikely float64 `yaml:"most_likely" json:"most_likely"`
	Max        float64 `yaml:"max" json:"max"`
}

// FairEstimate is the optional FAIR quantitative block a rule or finding may carry.
// Both fields use a modified-PERT distribution; nil means "not specified".
type FairEstimate struct {
	// LossEventFrequency: expected number of times per year the threat materialises.
	LossEventFrequency *LossDistribution `yaml:"loss_event_frequency,omitempty" json:"loss_event_frequency,omitempty"`
	// LossMagnitude: expected USD loss per event.
	LossMagnitude *LossDistribution `yaml:"loss_magnitude,omitempty" json:"loss_magnitude,omitempty"`
	// Confidence 0–1 in the estimates themselves (distinct from finding confidence).
	Confidence float64 `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

// MonteCarloResult holds the output of a Monte Carlo ALE simulation for one finding.
type MonteCarloResult struct {
	// Annualized Loss Expectancy percentiles (USD/year).
	ALE_P10 float64 `yaml:"ale_p10" json:"ale_p10"`
	ALE_P50 float64 `yaml:"ale_p50" json:"ale_p50"`
	ALE_P90 float64 `yaml:"ale_p90" json:"ale_p90"`
	// Number of Monte Carlo iterations used.
	Iterations int `yaml:"iterations" json:"iterations"`
}
