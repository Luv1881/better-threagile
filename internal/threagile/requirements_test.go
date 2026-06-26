package threagile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirementsCommand_Formats(t *testing.T) {
	modelPath := demoModelPath(t)
	for _, format := range []string{"markdown", "gherkin", "json"} {
		args := []string{"requirements", "--model", modelPath, "--format", format}
		app := newTestAppWithArgs(args...)
		stdout, err := executeCmd(app, args...)
		require.NoError(t, err, "format %s", format)
		assert.NotEmpty(t, stdout)
		switch format {
		case "markdown":
			assert.Contains(t, stdout, "# Security requirements")
			assert.Contains(t, stdout, "- [ ]")
		case "gherkin":
			assert.Contains(t, stdout, "Feature:")
			assert.Contains(t, stdout, "Scenario:")
		case "json":
			var v []map[string]any
			require.NoError(t, json.Unmarshal([]byte(stdout), &v))
			assert.NotEmpty(t, v)
		}
	}
}

func TestRequirementsCommand_RejectsBadFormat(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"requirements", "--model", modelPath, "--format", "csv"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}

func TestRequirementsCommand_SortedBySeverity(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"requirements", "--model", modelPath, "--format", "json"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	var v []struct {
		Severity string `json:"severity"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &v))
	require.NotEmpty(t, v)
	// first entry should be a top severity (high/critical) for the demo
	assert.Contains(t, []string{"high", "critical", "elevated"}, strings.ToLower(v[0].Severity))
}
