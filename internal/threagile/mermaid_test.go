package threagile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMermaidCommand_Flowchart(t *testing.T) {
	modelPath := demoModelPath(t)
	out := filepath.Join(t.TempDir(), "diagram.mmd")
	args := []string{"mermaid", "--model", modelPath, "--output", out}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	content := string(data)
	assert.True(t, strings.HasPrefix(content, "flowchart TB\n"), "should start with a flowchart header")
	assert.Contains(t, content, "subgraph tb_", "demo model has trust boundaries")
	assert.Contains(t, stdout, "flowchart TB", "diagram is also written to stdout")
}

func TestMermaidCommand_MarkdownFenced(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"mermaid", "--model", modelPath, "--format", "markdown"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(stdout, "```mermaid\n"), "markdown format wraps in a fenced block")
	assert.Contains(t, stdout, "flowchart TB")
	assert.True(t, strings.HasSuffix(strings.TrimRight(stdout, "\n"), "```"), "fence should be closed")
}

func TestMermaidCommand_RejectsUnknownFormat(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"mermaid", "--model", modelPath, "--format", "svg"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}
