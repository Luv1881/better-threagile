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

func TestPrioritizeCommand_Formats(t *testing.T) {
	modelPath := demoModelPath(t)
	for _, format := range []string{"text", "markdown", "json"} {
		out := filepath.Join(t.TempDir(), "p."+format)
		args := []string{"prioritize", "--model", modelPath, "--format", format, "--output", out, "--top", "5"}
		app := newTestAppWithArgs(args...)
		stdout, err := executeCmd(app, args...)
		require.NoError(t, err, "format %s", format)
		assert.NotEmpty(t, stdout)
		data, readErr := os.ReadFile(out)
		require.NoError(t, readErr)
		if format == "json" {
			var v map[string]any
			require.NoError(t, json.Unmarshal(data, &v))
			items, _ := v["items"].([]any)
			assert.LessOrEqual(t, len(items), 5, "--top should cap the list")
		}
	}
}

func TestPrioritizeCommand_MinSeverityFilters(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"prioritize", "--model", modelPath, "--min-severity", "high", "--format", "json", "--top", "0"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	var v struct {
		Items []struct {
			Severity string `json:"severity"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &v))
	for _, it := range v.Items {
		assert.Contains(t, []string{"high", "critical"}, strings.ToLower(it.Severity), "only High+ should remain")
	}
}

func TestPrioritizeCommand_RejectsBadSeverity(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"prioritize", "--model", modelPath, "--min-severity", "spicy"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}
