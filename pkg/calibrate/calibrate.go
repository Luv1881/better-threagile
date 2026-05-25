// Package calibrate provides a Bayesian calibration harness for rule likelihood priors.
// It reads a labelled corpus of past findings (did this finding materialise into an incident?)
// and fits a Beta posterior for each rule, producing a calibration.yaml that can be passed
// to threagile via --calibration to adjust likelihood priors.
package calibrate

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Finding is one labelled row in the ground-truth corpus.
type Finding struct {
	RuleID    string `json:"rule_id"    yaml:"rule_id"`
	FindingID string `json:"finding_id" yaml:"finding_id"`
	Exploited bool   `json:"exploited"  yaml:"exploited"` // true = threat materialised
	Severity  string `json:"severity,omitempty"  yaml:"severity,omitempty"`
}

// RuleStats holds the calibrated posterior for a single rule.
type RuleStats struct {
	RuleID       string  `yaml:"rule_id"          json:"rule_id"`
	Observations int     `yaml:"observations"     json:"observations"`
	Positives    int     `yaml:"positives"        json:"positives"`
	// LikelihoodPrior: Bayesian posterior mean P(exploited | rule fires)
	// = (1 + positives) / (2 + total_observations)  [Beta(1,1) prior → Beta(1+pos, 1+neg)]
	LikelihoodPrior float64 `yaml:"likelihood_prior" json:"likelihood_prior"`
	// BrierScore: mean squared error between LikelihoodPrior and actual outcomes; lower is better.
	BrierScore float64 `yaml:"brier_score" json:"brier_score"`
}

// Calibration is the full output of a calibration run.
type Calibration struct {
	GeneratedAt  time.Time              `yaml:"generated_at"  json:"generated_at"`
	CorpusSize   int                    `yaml:"corpus_size"   json:"corpus_size"`
	OverallBrier float64                `yaml:"overall_brier" json:"overall_brier"`
	Rules        map[string]*RuleStats  `yaml:"rules"         json:"rules"`
}

// Analyze fits Bayesian posteriors for each rule in the corpus and returns a Calibration.
func Analyze(findings []Finding) *Calibration {
	type acc struct {
		total int
		pos   int
	}
	counts := make(map[string]*acc)
	for _, f := range findings {
		if _, ok := counts[f.RuleID]; !ok {
			counts[f.RuleID] = &acc{}
		}
		counts[f.RuleID].total++
		if f.Exploited {
			counts[f.RuleID].pos++
		}
	}

	rules := make(map[string]*RuleStats, len(counts))
	for id, c := range counts {
		posterior := (1.0 + float64(c.pos)) / (2.0 + float64(c.total))
		brier := brierScore(posterior, findings, id)
		rules[id] = &RuleStats{
			RuleID:          id,
			Observations:    c.total,
			Positives:       c.pos,
			LikelihoodPrior: posterior,
			BrierScore:      brier,
		}
	}

	overallBrier := overallBrierScore(rules, findings)

	return &Calibration{
		GeneratedAt:  time.Now().UTC(),
		CorpusSize:   len(findings),
		OverallBrier: overallBrier,
		Rules:        rules,
	}
}

// brierScore computes the Brier score for a single rule given its posterior estimate.
func brierScore(posterior float64, findings []Finding, ruleID string) float64 {
	var sum float64
	var n int
	for _, f := range findings {
		if f.RuleID != ruleID {
			continue
		}
		outcome := 0.0
		if f.Exploited {
			outcome = 1.0
		}
		diff := posterior - outcome
		sum += diff * diff
		n++
	}
	if n == 0 {
		return 0
	}
	return math.Round(sum/float64(n)*10000) / 10000
}

// overallBrierScore computes the mean Brier score across all findings.
func overallBrierScore(rules map[string]*RuleStats, findings []Finding) float64 {
	var sum float64
	for _, f := range findings {
		r, ok := rules[f.RuleID]
		if !ok {
			continue
		}
		outcome := 0.0
		if f.Exploited {
			outcome = 1.0
		}
		diff := r.LikelihoodPrior - outcome
		sum += diff * diff
	}
	if len(findings) == 0 {
		return 0
	}
	return math.Round(sum/float64(len(findings))*10000) / 10000
}

// LoadCorpus reads a JSON corpus file (array of Finding).
func LoadCorpus(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("calibrate: read corpus %s: %w", path, err)
	}
	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("calibrate: parse corpus %s: %w", path, err)
	}
	return findings, nil
}

// SaveCalibration writes a Calibration to a YAML file.
func SaveCalibration(path string, cal *Calibration) error {
	data, err := yaml.Marshal(cal)
	if err != nil {
		return fmt.Errorf("calibrate: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("calibrate: write %s: %w", path, err)
	}
	return nil
}

// LoadCalibration reads a calibration YAML produced by Analyze.
func LoadCalibration(path string) (*Calibration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("calibrate: read %s: %w", path, err)
	}
	var cal Calibration
	if err := yaml.Unmarshal(data, &cal); err != nil {
		return nil, fmt.Errorf("calibrate: parse %s: %w", path, err)
	}
	return &cal, nil
}

// FormatReport returns a human-readable calibration report table.
func FormatReport(cal *Calibration) string {
	// Sort rules by Brier score ascending (best first)
	type row struct {
		id     string
		stats  *RuleStats
	}
	rows := make([]row, 0, len(cal.Rules))
	for id, s := range cal.Rules {
		rows = append(rows, row{id, s})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].stats.BrierScore < rows[j].stats.BrierScore })

	out := fmt.Sprintf("Calibration Report  (corpus: %d findings, overall Brier: %.4f)\n\n",
		cal.CorpusSize, cal.OverallBrier)
	out += fmt.Sprintf("%-50s  %8s  %9s  %12s  %10s\n",
		"Rule ID", "Obs", "Positives", "P(exploit)", "Brier")
	out += fmt.Sprintf("%-50s  %8s  %9s  %12s  %10s\n",
		repeat("-", 50), repeat("-", 8), repeat("-", 9), repeat("-", 12), repeat("-", 10))
	for _, r := range rows {
		out += fmt.Sprintf("%-50s  %8d  %9d  %12.4f  %10.4f\n",
			r.id, r.stats.Observations, r.stats.Positives, r.stats.LikelihoodPrior, r.stats.BrierScore)
	}
	return out
}

func repeat(s string, n int) string {
	result := ""
	for range n {
		result += s
	}
	return result
}
