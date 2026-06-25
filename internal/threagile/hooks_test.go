package threagile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderHookScript_PreCommit(t *testing.T) {
	s := renderHookScript("pre-commit", "/usr/local/bin/threagile", "threagile.yaml")
	assert.True(t, strings.HasPrefix(s, "#!/bin/sh\n"), "needs a shebang")
	assert.Contains(t, s, "validate --model")
	assert.Contains(t, s, "lint --model")
	assert.NotContains(t, s, "gate --model", "pre-commit stays fast, no gate")
	assert.Contains(t, s, `THREAGILE='/usr/local/bin/threagile'`)
	assert.Contains(t, s, `[ -f "$MODEL" ] || exit 0`, "must no-op when no model present")
}

func TestRenderHookScript_PrePushRunsGate(t *testing.T) {
	s := renderHookScript("pre-push", "/bin/threagile", "model.yaml")
	assert.Contains(t, s, "validate --model")
	assert.Contains(t, s, "gate --model")
	assert.Contains(t, s, "policy.yaml")
}

func TestShQuoteEscapesSingleQuotes(t *testing.T) {
	assert.Equal(t, `'a'\''b'`, shQuote("a'b"))
	assert.Equal(t, `'/path with spaces/threagile'`, shQuote("/path with spaces/threagile"))
}

func TestHooksInstall_WritesExecutableHooks(t *testing.T) {
	dir := t.TempDir()
	args := []string{"hooks", "install", "--dir", dir}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)

	for _, h := range []string{"pre-commit", "pre-push"} {
		path := filepath.Join(dir, h)
		info, statErr := os.Stat(path)
		require.NoError(t, statErr, "%s should be installed", h)
		assert.NotZero(t, info.Mode()&0100, "%s must be executable", h)
	}
}

func TestHooksInstall_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "pre-commit")
	require.NoError(t, os.WriteFile(existing, []byte("#!/bin/sh\necho keep\n"), 0600))

	args := []string{"hooks", "install", "--hook", "pre-commit", "--dir", dir}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	args = []string{"hooks", "install", "--hook", "pre-commit", "--dir", dir, "--force"}
	app = newTestAppWithArgs(args...)
	_, err = executeCmd(app, args...)
	require.NoError(t, err)
	data, _ := os.ReadFile(existing)
	assert.Contains(t, string(data), "validate --model", "force should replace with the generated hook")
}

func TestHooksInstall_ForceResetsInsecurePerms(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "pre-commit")
	require.NoError(t, os.WriteFile(existing, []byte("#!/bin/sh\n"), 0600))
	require.NoError(t, os.Chmod(existing, 0666)) //nolint:gosec // intentionally insecure: verifies the installer resets it

	args := []string{"hooks", "install", "--hook", "pre-commit", "--dir", dir, "--force"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)

	info, statErr := os.Stat(existing)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm(), "force overwrite must reset hook perms to 0700")
}

func TestHooksInstall_EmbedsAbsoluteModelPath(t *testing.T) {
	dir := t.TempDir()
	args := []string{"hooks", "install", "--hook", "pre-commit", "--dir", dir}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)
	data, readErr := os.ReadFile(filepath.Join(dir, "pre-commit"))
	require.NoError(t, readErr)
	// MODEL='...' must be an absolute path so the hook works from the repo root.
	assert.Contains(t, string(data), "MODEL='/", "model path embedded in the hook should be absolute")
}

func TestHooksInstall_PrintDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	args := []string{"hooks", "install", "--dir", dir, "--print"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, stdout, "pre-commit")
	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries, "--print must not write any files")
}

func TestHooksInstall_RejectsUnknownHook(t *testing.T) {
	args := []string{"hooks", "install", "--hook", "post-merge", "--dir", t.TempDir()}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}
