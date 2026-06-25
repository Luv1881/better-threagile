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
