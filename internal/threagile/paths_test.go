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

func TestPathsCommand_TextAndJSON(t *testing.T) {
	modelPath := demoModelPath(t)
	out := filepath.Join(t.TempDir(), "paths.json")

	args := []string{"paths", "--model", modelPath, "--format", "json", "--output", out, "--max-paths", "10"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)

	var result struct {
		Paths []struct {
			Assets []string `json:"assets"`
			Hops   int      `json:"hops"`
		} `json:"paths"`
		EntryPoints  []string `json:"entry_points"`
		TargetAssets []string `json:"target_assets"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	require.NotEmpty(t, result.EntryPoints, "demo has internet-facing assets")
	require.NotEmpty(t, result.TargetAssets, "demo has crown-jewel assets")
	require.NotEmpty(t, result.Paths, "demo should have at least one attack path")
	assert.LessOrEqual(t, len(result.Paths), 10, "max-paths cap respected")
	// shortest-first
	for i := 1; i < len(result.Paths); i++ {
		assert.LessOrEqual(t, result.Paths[i-1].Hops, result.Paths[i].Hops)
	}
}

func TestPathsCommand_RejectsUnknownFrom(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"paths", "--model", modelPath, "--from", "no-such-asset"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err, "unknown --from must error, not silently return no paths")
}

func TestPathsCommand_RejectsUnknownTo(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"paths", "--model", modelPath, "--to", "no-such-target"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err, "unknown --to must error")
}

func TestPathsCommand_Markdown(t *testing.T) {
	modelPath := demoModelPath(t)
	out := filepath.Join(t.TempDir(), "paths.md")
	args := []string{"paths", "--model", modelPath, "--format", "markdown", "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)
	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	assert.True(t, strings.Contains(string(data), "## Attack-path analysis"))
}
