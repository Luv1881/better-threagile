package calibrate_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/pkg/calibrate"
)

func TestAnalyze_EmptyCorpus(t *testing.T) {
	cal := calibrate.Analyze(nil)
	if cal.CorpusSize != 0 {
		t.Errorf("expected 0, got %d", cal.CorpusSize)
	}
	if len(cal.Rules) != 0 {
		t.Errorf("expected no rules, got %d", len(cal.Rules))
	}
}

func TestAnalyze_PerfectPredictor(t *testing.T) {
	// Rule fires only when exploited — perfect predictor
	findings := []calibrate.Finding{
		{RuleID: "sql-injection", FindingID: "f1", Exploited: true},
		{RuleID: "sql-injection", FindingID: "f2", Exploited: true},
		{RuleID: "sql-injection", FindingID: "f3", Exploited: true},
	}
	cal := calibrate.Analyze(findings)
	r := cal.Rules["sql-injection"]
	if r == nil {
		t.Fatal("no rule stats for sql-injection")
	}
	if r.Observations != 3 {
		t.Errorf("observations: want 3, got %d", r.Observations)
	}
	if r.Positives != 3 {
		t.Errorf("positives: want 3, got %d", r.Positives)
	}
	// posterior = (1+3)/(2+3) = 0.8
	want := 4.0 / 5.0
	if abs(r.LikelihoodPrior-want) > 0.001 {
		t.Errorf("posterior: want %.4f, got %.4f", want, r.LikelihoodPrior)
	}
}

func TestAnalyze_NeverExploited(t *testing.T) {
	findings := []calibrate.Finding{
		{RuleID: "info-disclosure", FindingID: "x1", Exploited: false},
		{RuleID: "info-disclosure", FindingID: "x2", Exploited: false},
	}
	cal := calibrate.Analyze(findings)
	r := cal.Rules["info-disclosure"]
	if r == nil {
		t.Fatal("missing rule")
	}
	// posterior = (1+0)/(2+2) = 0.25
	want := 1.0 / 4.0
	if abs(r.LikelihoodPrior-want) > 0.001 {
		t.Errorf("posterior: want %.4f, got %.4f", want, r.LikelihoodPrior)
	}
}

func TestAnalyze_MultipleRules(t *testing.T) {
	findings := []calibrate.Finding{
		{RuleID: "ruleA", Exploited: true},
		{RuleID: "ruleA", Exploited: false},
		{RuleID: "ruleB", Exploited: true},
		{RuleID: "ruleB", Exploited: true},
	}
	cal := calibrate.Analyze(findings)
	if len(cal.Rules) != 2 {
		t.Errorf("want 2 rules, got %d", len(cal.Rules))
	}
	if cal.CorpusSize != 4 {
		t.Errorf("want corpus 4, got %d", cal.CorpusSize)
	}
}

func TestRoundTrip_SaveLoad(t *testing.T) {
	findings := []calibrate.Finding{
		{RuleID: "xss", FindingID: "a", Exploited: true},
		{RuleID: "xss", FindingID: "b", Exploited: false},
	}
	cal := calibrate.Analyze(findings)

	dir := t.TempDir()
	path := filepath.Join(dir, "cal.yaml")
	if err := calibrate.SaveCalibration(path, cal); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := calibrate.LoadCalibration(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.CorpusSize != cal.CorpusSize {
		t.Errorf("corpus size mismatch: %d != %d", loaded.CorpusSize, cal.CorpusSize)
	}
	if abs(loaded.OverallBrier-cal.OverallBrier) > 0.0001 {
		t.Errorf("brier mismatch: %.4f != %.4f", loaded.OverallBrier, cal.OverallBrier)
	}
}

func TestLoadCorpus(t *testing.T) {
	findings := []calibrate.Finding{
		{RuleID: "test-rule", FindingID: "f1", Exploited: true},
	}
	data, _ := json.Marshal(findings)
	path := filepath.Join(t.TempDir(), "corpus.json")
	os.WriteFile(path, data, 0o644) //nolint:errcheck
	loaded, err := calibrate.LoadCorpus(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 1 || loaded[0].RuleID != "test-rule" {
		t.Errorf("unexpected findings: %+v", loaded)
	}
}

func TestFormatReport_Smoke(t *testing.T) {
	findings := []calibrate.Finding{{RuleID: "r1", Exploited: true}}
	cal := calibrate.Analyze(findings)
	report := calibrate.FormatReport(cal)
	if report == "" {
		t.Error("empty report")
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
