package threagile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bootstrapCompose = `services:
  web:
    image: nginx
    ports: ["80:80"]
  db:
    image: postgres
`

func TestBootstrapCommand_GeneratesModelAndPolicy(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(bootstrapCompose), 0600))
	modelPath := filepath.Join(dir, "threagile.yaml")
	policyPath := filepath.Join(dir, "policy.yaml")

	// run with cwd = dir so policy.yaml lands there
	wd, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(wd) }()

	args := []string{"bootstrap", "--output", "threagile.yaml"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Wrote starter model")
	assert.Contains(t, stdout, "Next steps")

	mdata, err := os.ReadFile(modelPath)
	require.NoError(t, err)
	assert.NotEmpty(t, mdata)
	_, err = os.Stat(policyPath)
	require.NoError(t, err, "policy.yaml should be scaffolded")
}

func TestBootstrapCommand_NoInfraIsGraceful(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("# nothing"), 0600))

	args := []string{"bootstrap", "--dir", dir, "--output", filepath.Join(dir, "threagile.yaml")}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err) // graceful, not an error
	assert.Contains(t, stdout, "No importable infrastructure found")
	_, statErr := os.Stat(filepath.Join(dir, "threagile.yaml"))
	assert.True(t, os.IsNotExist(statErr), "should not write an empty model")
}

func TestBootstrapCommand_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(bootstrapCompose), 0600))
	model := filepath.Join(dir, "threagile.yaml")
	require.NoError(t, os.WriteFile(model, []byte("title: existing\n"), 0600))

	args := []string{"bootstrap", "--dir", dir, "--output", model, "--policy-profile", ""}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestBootstrapCommand_DryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(bootstrapCompose), 0600))

	wd, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(wd) }()

	args := []string{"bootstrap", "--dry-run"}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Would write starter model")
	assert.Contains(t, stdout, "Would write gate policy")
	assert.Contains(t, stdout, "dry run")
	assert.NotContains(t, stdout, "Next steps", "no next steps for a preview that wrote nothing")

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Len(t, entries, 1, "--dry-run must not write anything (only the compose fixture remains)")
	_, statErr := os.Stat(filepath.Join(dir, "threagile.yaml"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestBootstrapCommand_DryRunMirrorsOverwriteRefusal(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(bootstrapCompose), 0600))
	existing := filepath.Join(dir, "threagile.yaml")
	require.NoError(t, os.WriteFile(existing, []byte("title: existing\n"), 0600))

	args := []string{"bootstrap", "--dir", dir, "--dry-run", "--output", existing}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err, "dry-run must fail exactly like the real run when the model exists without --force")
	assert.Contains(t, err.Error(), "already exists")

	data, readErr := os.ReadFile(existing)
	require.NoError(t, readErr)
	assert.Equal(t, "title: existing\n", string(data), "existing model must stay untouched")
}

func TestBootstrapCommand_DryRunForceShowsDiffAndDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(bootstrapCompose), 0600))
	existing := filepath.Join(dir, "threagile.yaml")
	original := "# old hand-written model\ntitle: old\n"
	require.NoError(t, os.WriteFile(existing, []byte(original), 0600))

	args := []string{"bootstrap", "--dir", dir, "--dry-run", "--force", "--output", existing}
	app := newTestAppWithArgs(args...)
	stdout, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Would overwrite starter model")
	assert.Contains(t, stdout, "-title: old", "the preview must diff the file it would replace")

	data, readErr := os.ReadFile(existing)
	require.NoError(t, readErr)
	assert.Equal(t, original, string(data), "--force dry-run must not overwrite")
}
