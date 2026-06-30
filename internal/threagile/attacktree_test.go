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
