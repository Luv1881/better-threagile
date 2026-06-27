package threagile

import (
	"os"
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

func TestValidateCommand_JSONOutput(t *testing.T) {
	app := newTestAppWithArgs(ValidateCommand, "--model", demoModelPath(t), "--json")
	out, err := executeCmd(app, ValidateCommand, "--model", demoModelPath(t), "--json")
	require.NoError(t, err)
	assert.Contains(t, out, `"valid": true`)
}

// A model that loads but has dangling references across multiple (map-keyed)
// assets exercises the deterministic ordering of validation errors.
func TestValidateCommand_DeterministicErrorOrder(t *testing.T) {
	model := `title: Determinism Test
technical_assets:
  Zeta Asset:
    id: zeta-asset
    data_assets_processed:
      - missing-data
  Alpha Asset:
    id: alpha-asset
    data_assets_processed:
      - missing-data
`
	path := filepath.Join(t.TempDir(), "threagile.yaml")
	require.NoError(t, os.WriteFile(path, []byte(model), 0600))

	app := newTestAppWithArgs(ValidateCommand, "--model", path, "--json")
	out, err := executeCmd(app, ValidateCommand, "--model", path, "--json")
	require.Error(t, err) // invalid model -> non-zero exit
	assert.Contains(t, out, `"valid": false`)
	// Errors are sorted, so "Alpha Asset" must appear before "Zeta Asset".
	assert.Less(t, strings.Index(out, "Alpha Asset"), strings.Index(out, "Zeta Asset"))
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

func TestLintCommand_DeterministicOrder(t *testing.T) {
	model := `title: Determinism Test
technical_assets:
  Zeta Asset:
    id: zeta-asset
  Alpha Asset:
    id: alpha-asset
`
	path := filepath.Join(t.TempDir(), "threagile.yaml")
	require.NoError(t, os.WriteFile(path, []byte(model), 0600))

	app := newTestAppWithArgs(LintCommand, "--model", path, "--json")
	out, err := executeCmd(app, LintCommand, "--model", path, "--json")
	require.NoError(t, err)
	// Findings are sorted by asset, so "Alpha Asset" must precede "Zeta Asset".
	assert.Less(t, strings.Index(out, "Alpha Asset"), strings.Index(out, "Zeta Asset"))
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
