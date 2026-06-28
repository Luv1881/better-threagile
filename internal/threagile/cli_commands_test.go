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
	// Each error points at the offending asset's source line.
	assert.Contains(t, out, "(line ")
}

// Diagnostics must resolve the source file:line for entities pulled in via the
// fork's includes: directive, not just the top-level model file.
func TestValidateCommand_ResolvesIncludeLocation(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "feature.yaml"),
		[]byte("technical_assets:\n  Split Asset:\n    id: split\n    data_assets_processed:\n      - missing\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "threagile.yaml"),
		[]byte("title: Split Model\nincludes:\n  - feature.yaml\n"), 0600))

	path := filepath.Join(dir, "threagile.yaml")
	app := newTestAppWithArgs(ValidateCommand, "--model", path, "--json")
	out, err := executeCmd(app, ValidateCommand, "--model", path, "--json")
	require.Error(t, err)
	assert.Contains(t, out, "feature.yaml:") // file:line, not just line
}

func TestPrioritizeCommand_JSONHasSourceLine(t *testing.T) {
	args := []string{"prioritize", "--model", demoModelPath(t),
		"--ignore-orphaned-risk-tracking", "--format", "json"}
	app := newTestAppWithArgs(args...)
	out, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, out, "source_line") // findings carry their asset's source line
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
	// Asset findings carry their source line.
	assert.Contains(t, out, `"line"`)
}

func TestDefaultProjectConfig_AutoLoaded(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, defaultProjectConfigFile),
		[]byte("InputFile: from-project-config.yaml\n"), 0600))
	t.Chdir(dir)

	app := newTestApp() // Init() runs processArgs, which auto-loads the config
	assert.Equal(t, "from-project-config.yaml", app.config.GetInputFile())
}

func TestDefaultProjectConfig_FlagOverrides(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, defaultProjectConfigFile),
		[]byte("InputFile: from-project-config.yaml\n"), 0600))
	t.Chdir(dir)

	// An explicit --model on the command line must win over the project config.
	app := newTestAppWithArgs("--model", "from-flag.yaml")
	assert.Contains(t, app.config.GetInputFile(), "from-flag.yaml")
}

func TestDriftCommand_FailOnNewHighExits3(t *testing.T) {
	// Empty baseline vs the demo model => demo's high/critical findings are all
	// "new" => the gate must fail with the standard gate exit code 3.
	baseline := filepath.Join(t.TempDir(), "baseline.yaml")
	require.NoError(t, os.WriteFile(baseline, []byte("title: Empty Baseline\nbusiness_criticality: important\n"), 0600))
	args := []string{"drift", "--baseline", baseline, "--current", demoModelPath(t),
		"--fail-on-new-high", "--ignore-orphaned-risk-tracking"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
	var ece *exitCodeError
	require.ErrorAs(t, err, &ece)
	assert.Equal(t, 3, ece.code)
}

func TestDriftCommand_NoDriftExitsZero(t *testing.T) {
	args := []string{"drift", "--baseline", demoModelPath(t), "--current", demoModelPath(t),
		"--fail-on-new-high", "--ignore-orphaned-risk-tracking"}
	app := newTestAppWithArgs(args...)
	out, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, out, "No risk drift detected")
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
