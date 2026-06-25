package threagile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOSCALCommand_WritesValidAssessmentResults(t *testing.T) {
	modelPath := demoModelPath(t)
	out := filepath.Join(t.TempDir(), "oscal.json")
	args := []string{"oscal", "--model", modelPath, "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)

	var doc struct {
		AssessmentResults struct {
			UUID     string `json:"uuid"`
			Metadata struct {
				OSCALVersion string `json:"oscal-version"`
			} `json:"metadata"`
			Results []struct {
				Findings []struct {
					Target struct {
						Status struct {
							State string `json:"state"`
						} `json:"status"`
					} `json:"target"`
				} `json:"findings"`
			} `json:"results"`
		} `json:"assessment-results"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.NotEmpty(t, doc.AssessmentResults.UUID)
	assert.Equal(t, "1.1.2", doc.AssessmentResults.Metadata.OSCALVersion)
	require.Len(t, doc.AssessmentResults.Results, 1)
	assert.NotEmpty(t, doc.AssessmentResults.Results[0].Findings, "demo model should yield findings")
}
