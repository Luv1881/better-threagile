package threagile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeQuantifyEstimates(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "estimates.yaml")
	content := `
default_iterations: 1000
estimates:
  unencrypted-communication:
    loss_event_frequency: {min: 0.1, most_likely: 0.5, max: 2.0}
    loss_magnitude: {min: 1000, most_likely: 25000, max: 500000}
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestQuantifyCommand_Runs(t *testing.T) {
	estimates := writeQuantifyEstimates(t)
	outputJSON := filepath.Join(t.TempDir(), "quantify.json")

	args := []string{"quantify", "--model", demoModelPath(t), "--estimates", estimates, "--output-json", outputJSON}
	app := newTestAppWithArgs(args...)
	out, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, out, "FAIR Monte-Carlo ALE simulation (1000 iterations per risk)")
	assert.Contains(t, out, "Portfolio")

	data, readErr := os.ReadFile(outputJSON) //nolint:gosec // path under t.TempDir()
	require.NoError(t, readErr)

	var result struct {
		Iterations int `json:"iterations"`
		Portfolio  struct {
			QuantifiedRisks int     `json:"quantified_risks"`
			TotalRisks      int     `json:"total_risks"`
			SumALEP50       float64 `json:"sum_ale_p50"`
		} `json:"portfolio"`
		Risks []struct {
			SyntheticId string `json:"synthetic_id"`
			MatchedBy   string `json:"matched_by"`
		} `json:"risks"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	assert.Equal(t, 1000, result.Iterations)
	assert.Greater(t, result.Portfolio.QuantifiedRisks, 0, "demo model should generate unencrypted-communication risks")
	assert.Greater(t, result.Portfolio.SumALEP50, 0.0)
	for _, riskResult := range result.Risks {
		assert.Equal(t, "unencrypted-communication", riskResult.MatchedBy)
	}
}

func TestQuantifyCommand_NoMatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "estimates.yaml")
	content := `
estimates:
  category-that-does-not-exist:
    loss_event_frequency: {min: 0.1, most_likely: 0.5, max: 2.0}
    loss_magnitude: {min: 1000, most_likely: 25000, max: 500000}
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	args := []string{"quantify", "--model", demoModelPath(t), "--estimates", path}
	app := newTestAppWithArgs(args...)
	out, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, out, "No generated risks matched any estimate key")
}

func TestQuantifyCommand_BadEstimatesFile(t *testing.T) {
	args := []string{"quantify", "--model", demoModelPath(t), "--estimates", filepath.Join(t.TempDir(), "missing.yaml")}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}
