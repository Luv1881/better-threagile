package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// minimalParsedModel returns a model with two generated risks sufficient to
// exercise the JSON report functions without loading a real YAML model file.
func minimalParsedModel() *types.Model {
	m := &types.Model{
		Title:                       "Test Model",
		TechnicalAssets:             make(map[string]*types.TechnicalAsset),
		GeneratedRisksByCategory:    make(map[string][]*types.Risk),
		GeneratedRisksBySyntheticId: make(map[string]*types.Risk),
	}

	r1 := &types.Risk{
		SyntheticId: "risk-001",
		CategoryId:  "missing-authentication",
		Title:       "Missing Authentication",
		Severity:    types.HighSeverity,
		RiskStatus:  types.Unchecked,
	}
	r2 := &types.Risk{
		SyntheticId: "risk-002",
		CategoryId:  "sql-injection",
		Title:       "SQL Injection",
		Severity:    types.CriticalSeverity,
		RiskStatus:  types.Accepted,
	}

	m.GeneratedRisksByCategory["missing-authentication"] = []*types.Risk{r1}
	m.GeneratedRisksByCategory["sql-injection"] = []*types.Risk{r2}
	m.GeneratedRisksBySyntheticId["risk-001"] = r1
	m.GeneratedRisksBySyntheticId["risk-002"] = r2
	return m
}

// --- WriteRisksJSON ---------------------------------------------------------

func TestWriteRisksJSON_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "risks.json")

	if err := WriteRisksJSON(minimalParsedModel(), path); err != nil {
		t.Fatalf("WriteRisksJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("risks.json is empty")
	}

	// Must be valid JSON
	var out interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("risks.json is not valid JSON: %v", err)
	}
}

func TestWriteRisksJSON_ContainsRisks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "risks.json")
	m := minimalParsedModel()

	if err := WriteRisksJSON(m, path); err != nil {
		t.Fatalf("WriteRisksJSON: %v", err)
	}

	data, _ := os.ReadFile(path)
	var risks []*types.Risk
	if err := json.Unmarshal(data, &risks); err != nil {
		t.Fatalf("unmarshal risks: %v", err)
	}
	if len(risks) != len(m.AllRisks()) {
		t.Errorf("len(risks) = %d, want %d", len(risks), len(m.AllRisks()))
	}
}

// --- WriteTechnicalAssetsJSON -----------------------------------------------

func TestWriteTechnicalAssetsJSON_EmptyModel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assets.json")
	m := &types.Model{TechnicalAssets: make(map[string]*types.TechnicalAsset)}

	if err := WriteTechnicalAssetsJSON(m, path); err != nil {
		t.Fatalf("WriteTechnicalAssetsJSON: %v", err)
	}

	data, _ := os.ReadFile(path)
	var out interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("assets.json is not valid JSON: %v", err)
	}
}

// --- WriteStatsJSON ---------------------------------------------------------

func TestWriteStatsJSON_CorrectCounts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	m := minimalParsedModel()

	if err := WriteStatsJSON(m, path); err != nil {
		t.Fatalf("WriteStatsJSON: %v", err)
	}

	data, _ := os.ReadFile(path)
	var stats riskStatistics
	if err := json.Unmarshal(data, &stats); err != nil {
		t.Fatalf("unmarshal stats: %v", err)
	}

	// high unchecked: 1
	if stats.Risks[types.HighSeverity.String()][types.Unchecked.String()] != 1 {
		t.Errorf("high/unchecked = %d, want 1",
			stats.Risks[types.HighSeverity.String()][types.Unchecked.String()])
	}
	// critical accepted: 1
	if stats.Risks[types.CriticalSeverity.String()][types.Accepted.String()] != 1 {
		t.Errorf("critical/accepted = %d, want 1",
			stats.Risks[types.CriticalSeverity.String()][types.Accepted.String()])
	}
}

// --- golden file test -------------------------------------------------------
// Captures the JSON risks output of a known model as a golden file.
// On first run (no golden file): writes it. On subsequent runs: asserts no change.
// This guards Phase 5 refactoring: if the output changes, the test fails.

func TestWriteRisksJSON_GoldenFile(t *testing.T) {
	m := minimalParsedModel()
	goldenPath := filepath.Join("testdata", "golden_risks.json")

	// Generate current output
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "risks.json")
	if err := WriteRisksJSON(m, outPath); err != nil {
		t.Fatalf("WriteRisksJSON: %v", err)
	}
	current, _ := os.ReadFile(outPath)

	// If no golden file yet: create it
	if _, err := os.Stat(goldenPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o750); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, current, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("golden file created at %s (first run)", goldenPath)
		return
	}

	golden, _ := os.ReadFile(goldenPath)
	if string(current) != string(golden) {
		t.Errorf("WriteRisksJSON output changed from golden.\nGolden: %s\nCurrent: %s",
			string(golden), string(current))
	}
}
