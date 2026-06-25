package threagile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScoreCommand_Formats(t *testing.T) {
	modelPath := demoModelPath(t)
	for _, format := range []string{"text", "markdown", "json", "shields"} {
		out := filepath.Join(t.TempDir(), "score."+format)
		args := []string{"score", "--model", modelPath, "--format", format, "--output", out}
		app := newTestAppWithArgs(args...)
		_, err := executeCmd(app, args...)
		require.NoError(t, err, "format %s", format)
		data, readErr := os.ReadFile(out)
		require.NoError(t, readErr)
		assert.NotEmpty(t, data)
		if format == "json" || format == "shields" {
			var v map[string]any
			require.NoError(t, json.Unmarshal(data, &v), "%s must be valid JSON", format)
		}
	}
}

func TestScoreCommand_MinGateFails(t *testing.T) {
	modelPath := demoModelPath(t)
	// An impossibly-high floor must fail with the gate exit code (3).
	args := []string{"score", "--model", modelPath, "--min", "100"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
	var ec *exitCodeError
	require.ErrorAs(t, err, &ec)
	assert.Equal(t, 3, ec.ExitCode())
}

func TestScoreCommand_MinGatePasses(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"score", "--model", modelPath, "--min", "0"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)
}

func TestScoreCommand_RejectsUnknownFormat(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"score", "--model", modelPath, "--format", "pdf"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}
