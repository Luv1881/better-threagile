package threagile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGitHubPAT is assembled from parts so gosec G101 doesn't flag this test file.
var fakeGitHubPAT = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"

var modelWithSecret = `threagile_version: "1.0.0"
title: Secret Test
author:
  name: Tester
technical_assets:
  Web:
    id: web
    description: "deploy key ` + fakeGitHubPAT + `"
    type: process
    usage: business
data_assets: {}
`

func TestValidate_WarnsOnSecretButPassesByDefault(t *testing.T) {
	dir := t.TempDir()
	model := filepath.Join(dir, "m.yaml")
	require.NoError(t, os.WriteFile(model, []byte(modelWithSecret), 0600))

	args := []string{"validate", "--model", model}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err, "a secret is a warning by default, not a failure")
}

func TestValidate_FailOnSecretsExits3(t *testing.T) {
	dir := t.TempDir()
	model := filepath.Join(dir, "m.yaml")
	require.NoError(t, os.WriteFile(model, []byte(modelWithSecret), 0600))

	args := []string{"validate", "--model", model, "--fail-on-secrets"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
	var ec *exitCodeError
	require.ErrorAs(t, err, &ec)
	assert.Equal(t, 3, ec.ExitCode())
}

func TestValidate_DemoModelHasNoSecretFalsePositives(t *testing.T) {
	findings := scanModelForSecrets(demoModelPath(t))
	if len(findings) != 0 {
		var b strings.Builder
		for _, f := range findings {
			b.WriteString(f.Rule + " ")
		}
		t.Errorf("demo model should not trip the secret scanner, got: %s", b.String())
	}
}
