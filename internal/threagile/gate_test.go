package threagile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func writeGatePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func TestGateCommand_Passes(t *testing.T) {
	policy := writeGatePolicy(t, "name: lenient\nmax_severity_counts:\n  critical: 100\n")
	model := demoModelPath(t)
	app := newTestAppWithArgs("gate", "--model", model, "--policy", policy)
	out, err := executeCmd(app, "gate", "--model", model, "--policy", policy)
	require.NoError(t, err)
	assert.Contains(t, out, "PASS")
}

func TestGateCommand_FailsWithExitCode3(t *testing.T) {
	// demo model has findings; require zero of every severity -> guaranteed failure.
	policy := writeGatePolicy(t, "name: strict\nmax_total_at_risk: 0\n")
	model := demoModelPath(t)
	app := newTestAppWithArgs("gate", "--model", model, "--policy", policy)
	out, err := executeCmd(app, "gate", "--model", model, "--policy", policy)
	require.Error(t, err)
	var ec *exitCodeError
	require.True(t, errors.As(err, &ec), "expected exitCodeError, got %T", err)
	assert.Equal(t, 3, ec.ExitCode())
	assert.Contains(t, out, "FAIL")
}

func TestLoadBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risks.json")
	// unchecked (omitempty -> no risk_status), accepted, mitigated, false-positive.
	content := `[
	  {"synthetic_id":"a@x","severity":"high"},
	  {"synthetic_id":"b@y","severity":"critical","risk_status":"accepted"},
	  {"synthetic_id":"c@z","severity":"high","risk_status":"mitigated"},
	  {"synthetic_id":"d@w","severity":"elevated","risk_status":"false-positive"}
	]`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	baseline, err := loadBaseline(path)
	require.NoError(t, err)
	// Only still-at-risk findings (a unchecked, b accepted) are kept.
	assert.Len(t, baseline, 2)
	assert.Equal(t, types.HighSeverity, baseline["a@x"])
	assert.Equal(t, types.CriticalSeverity, baseline["b@y"])
	_, hasMitigated := baseline["c@z"]
	assert.False(t, hasMitigated, "mitigated baseline finding must be excluded")
}

func TestLoadBaseline_RejectsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risks.json")
	// Entry with empty synthetic_id (truncated/corrupt file).
	require.NoError(t, os.WriteFile(path, []byte(`[{"severity":"high"}]`), 0600))
	_, err := loadBaseline(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "synthetic_id")
}

func TestGateCommand_MarkdownFormat(t *testing.T) {
	policy := writeGatePolicy(t, "name: md\nmax_severity_counts:\n  critical: 100\n")
	model := demoModelPath(t)
	app := newTestAppWithArgs("gate", "--model", model, "--policy", policy, "--format", "markdown")
	out, err := executeCmd(app, "gate", "--model", model, "--policy", policy, "--format", "markdown")
	require.NoError(t, err)
	assert.Contains(t, out, "## Threat-model gate")
	assert.True(t, strings.Contains(out, "✅"))
}
