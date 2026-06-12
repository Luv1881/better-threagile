package report_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/pkg/report"
)

func TestBuildSarif_Golden(t *testing.T) {
	parsedModel := loadFixtureModel(t)

	sarifBytes, err := report.BuildSarif(parsedModel, "threagile.yaml", "test")
	if err != nil {
		t.Fatalf("BuildSarif: %v", err)
	}

	goldenCompare(t, filepath.Join("testdata", "golden_risks.sarif"), sarifBytes)
}

func TestBuildSarif_ValidStructure(t *testing.T) {
	parsedModel := loadFixtureModel(t)

	sarifBytes, err := report.BuildSarif(parsedModel, "threagile.yaml", "1.2.3")
	if err != nil {
		t.Fatalf("BuildSarif: %v", err)
	}

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if unmarshalErr := json.Unmarshal(sarifBytes, &log); unmarshalErr != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", unmarshalErr)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "Threagile" {
		t.Errorf("expected driver name Threagile, got %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("expected driver version 1.2.3, got %q", run.Tool.Driver.Version)
	}
	if len(run.Results) == 0 {
		t.Fatal("expected at least one result for the demo model")
	}

	totalRisks := 0
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		totalRisks += len(risks)
	}
	if len(run.Results) != totalRisks {
		t.Errorf("expected %d results (one per risk), got %d", totalRisks, len(run.Results))
	}

	ruleIDs := make(map[string]int)
	for i, rule := range run.Tool.Driver.Rules {
		ruleIDs[rule.ID] = i
	}
	validLevels := map[string]bool{"error": true, "warning": true, "note": true}
	for _, result := range run.Results {
		idx, ok := ruleIDs[result.RuleID]
		if !ok {
			t.Errorf("result references unknown rule %q", result.RuleID)
		} else if idx != result.RuleIndex {
			t.Errorf("result ruleIndex %d does not match rules array position %d for %q", result.RuleIndex, idx, result.RuleID)
		}
		if !validLevels[result.Level] {
			t.Errorf("invalid SARIF level %q", result.Level)
		}
		if result.Message.Text == "" {
			t.Error("result with empty message text")
		}
		if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "threagile.yaml" {
			t.Errorf("result location should point at the model file, got %+v", result.Locations)
		}
		if result.PartialFingerprints["threagileSyntheticId"] == "" {
			t.Error("result missing threagileSyntheticId fingerprint")
		}
	}
}

func TestWriteRisksSARIF(t *testing.T) {
	parsedModel := loadFixtureModel(t)

	outPath := filepath.Join(t.TempDir(), "risks.sarif")
	if err := report.WriteRisksSARIF(parsedModel, "threagile.yaml", "test", outPath); err != nil {
		t.Fatalf("WriteRisksSARIF: %v", err)
	}

	written, readErr := os.ReadFile(outPath) //nolint:gosec // path is under t.TempDir()
	if readErr != nil {
		t.Fatalf("read written SARIF: %v", readErr)
	}
	if !json.Valid(written) {
		t.Fatal("written SARIF file is not valid JSON")
	}
}
