package threagile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttackTreeCommand_Formats(t *testing.T) {
	modelPath := demoModelPath(t)
	for _, format := range []string{"text", "json", "dot", "markdown"} {
		out := filepath.Join(t.TempDir(), "tree."+format)
		args := []string{"attack-tree", "--model", modelPath, "--format", format, "--output", out}
		app := newTestAppWithArgs(args...)
		_, err := executeCmd(app, args...)
		require.NoError(t, err, "format %s", format)
		data, readErr := os.ReadFile(out)
		require.NoError(t, readErr)
		assert.NotEmpty(t, data)
		if format == "json" {
			var v map[string]any
			require.NoError(t, json.Unmarshal(data, &v), "json must be valid")
		}
		if format == "dot" {
			assert.True(t, strings.HasPrefix(string(data), "digraph attack_trees {"))
		}
	}
}

func TestAttackTreeCommand_RejectsUnknownTo(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"attack-tree", "--model", modelPath, "--to", "no-such-thing"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}

func TestD3FENDCommand(t *testing.T) {
	modelPath := demoModelPath(t)
	out := filepath.Join(t.TempDir(), "d3.json")
	args := []string{"d3fend", "--model", modelPath, "--format", "json", "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	var report struct {
		Recommendations []struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			URL         string   `json:"url"`
			Addresses   []string `json:"addresses_categories"`
			FindingHits int      `json:"finding_count"`
		} `json:"recommendations"`
	}
	require.NoError(t, json.Unmarshal(data, &report))
	require.NotEmpty(t, report.Recommendations, "demo should map to D3FEND countermeasures")
	// sorted by coverage desc
	for i := 1; i < len(report.Recommendations); i++ {
		assert.GreaterOrEqual(t, report.Recommendations[i-1].FindingHits, report.Recommendations[i].FindingHits)
	}
	for _, rec := range report.Recommendations {
		assert.True(t, strings.HasPrefix(rec.ID, "D3-"))
		assert.NotEmpty(t, rec.Name)
		assert.Contains(t, rec.URL, "d3fend.mitre.org")
		assert.Positive(t, rec.FindingHits)
	}
}
