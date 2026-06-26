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

func TestSummaryCommand_Markdown(t *testing.T) {
	modelPath := demoModelPath(t)
	out := filepath.Join(t.TempDir(), "summary.md")
	args := []string{"summary", "--model", modelPath, "--top", "3", "--output", out}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, stdout, "# Threat-model summary")
	assert.Contains(t, stdout, "Score:")
	assert.Contains(t, stdout, "Fix these first")
	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	assert.NotEmpty(t, data)
}

func TestSummaryCommand_JSON(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"summary", "--model", modelPath, "--format", "json", "--top", "5"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	var v struct {
		Score       int   `json:"score"`
		StillAtRisk int   `json:"still_at_risk"`
		Top         []any `json:"top_findings"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &v))
	assert.GreaterOrEqual(t, v.Score, 0)
	assert.LessOrEqual(t, len(v.Top), 5)
}

func TestSummaryCommand_RejectsBadFormat(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"summary", "--model", modelPath, "--format", "pdf"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}

func TestSummaryCommand_TextHasScoreAndFindings(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"summary", "--model", modelPath, "--format", "text", "--top", "2"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.True(t, strings.Contains(stdout, "Score:") && strings.Contains(stdout, "fix:"))
}
