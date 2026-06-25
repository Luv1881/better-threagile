package threagile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/gate"
)

func TestPolicyInit_WritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "policy.yaml")
	args := []string{"policy", "init", "--profile", "strict", "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "Strict gate")
	// the written file must load through the real gate policy loader
	_, loadErr := gate.LoadPolicy(out)
	require.NoError(t, loadErr)
}

func TestPolicyInit_RefusesOverwriteWithoutForce(t *testing.T) {
	out := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(out, []byte("name: existing\n"), 0600))
	args := []string{"policy", "init", "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// --force overwrites
	args = []string{"policy", "init", "--output", out, "--force"}
	app = newTestAppWithArgs(args...)
	_, err = executeCmd(app, args...)
	require.NoError(t, err)
}

func TestPolicyInit_StdoutAndUnknownProfile(t *testing.T) {
	args := []string{"policy", "init", "--profile", "balanced", "--output", "-"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Balanced gate")

	args = []string{"policy", "init", "--profile", "bogus"}
	app = newTestAppWithArgs(args...)
	_, err = executeCmd(app, args...)
	require.Error(t, err)
}

func TestPolicyList(t *testing.T) {
	args := []string{"policy", "list"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	for _, name := range gate.ProfileNames() {
		assert.True(t, strings.Contains(stdout, name), "list should mention %q", name)
	}
}
