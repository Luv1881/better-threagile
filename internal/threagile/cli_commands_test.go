package threagile

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func demoModelPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "demo", "example", "threagile.yaml"))
	require.NoError(t, err)
	return path
}

func TestValidateCommand_ValidModel(t *testing.T) {
	app := newTestAppWithArgs(ValidateCommand, "--model", demoModelPath(t))
	out, err := executeCmd(app, ValidateCommand, "--model", demoModelPath(t))
	require.NoError(t, err)
	assert.Contains(t, out, "Model is valid")
}

func TestLintCommand_Runs(t *testing.T) {
	app := newTestAppWithArgs(LintCommand, "--model", demoModelPath(t))
	out, err := executeCmd(app, LintCommand, "--model", demoModelPath(t))
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestLintCommand_JSONOutput(t *testing.T) {
	app := newTestAppWithArgs(LintCommand, "--model", demoModelPath(t), "--json")
	out, err := executeCmd(app, LintCommand, "--model", demoModelPath(t), "--json")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(strings.TrimSpace(out), "[") || strings.TrimSpace(out) == "null")
}

func TestExplainRulesCommand_Runs(t *testing.T) {
	app := newTestApp()
	out, err := executeCmd(app, ExplainCommand, RulesItem)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestExplainMacrosCommand_Runs(t *testing.T) {
	app := newTestApp()
	out, err := executeCmd(app, ExplainCommand, MacrosItem)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestExplainTypesCommand_Runs(t *testing.T) {
	app := newTestApp()
	out, err := executeCmd(app, ExplainCommand, TypesItem)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}
