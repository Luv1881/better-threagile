package threagile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end CLI tests for the import subcommands: stdout, --output, --diff, and
// error paths. These guard the importer→converter→YAML wiring (and would have
// caught the previously-advertised but nonexistent --apply flag).

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0600))
	return p
}

func TestImportComposeCLI_OutputAndAnalyzable(t *testing.T) {
	compose := writeTemp(t, "docker-compose.yml", `
services:
  web:
    image: nginx:alpine
    ports: ["443:443"]
    depends_on: [db]
  db:
    image: postgres:16
`)
	out := filepath.Join(t.TempDir(), "fragment.yaml")
	args := []string{"import", "compose", "--compose", compose, "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	body := string(data)
	assert.Contains(t, body, "technical_assets:")
	assert.Contains(t, body, "business_criticality:") // converter-supplied required field
}

func TestImportComposeCLI_Diff(t *testing.T) {
	compose := writeTemp(t, "docker-compose.yml", "services:\n  a:\n    image: redis:7\n")
	args := []string{"import", "compose", "--compose", compose, "--diff"}
	app := newTestAppWithArgs(args...)
	out, err := executeCmd(app, args...)
	require.NoError(t, err)
	assert.Contains(t, out, "Model fragment summary")
}

func TestImportKubernetesCLI_Output(t *testing.T) {
	manifests := writeTemp(t, "k8s.yaml", `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop, labels: {app: web}}
spec:
  template:
    metadata: {labels: {app: web}}
    spec: {containers: [{name: web, image: nginx:1.25}]}
`)
	out := filepath.Join(t.TempDir(), "fragment.yaml")
	args := []string{"import", "kubernetes", "--manifests", manifests, "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)
	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "shop-web-k8s")
}

func TestImportCompose_ErrorOnBadFile(t *testing.T) {
	args := []string{"import", "compose", "--compose", "/no/such/compose.yml"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}

func TestImportHelpDoesNotAdvertiseApply(t *testing.T) {
	// Regression: the parent help previously claimed an --apply flag that never existed.
	app := newTestApp()
	out, _ := executeCmd(app, "import", "--help")
	assert.NotContains(t, strings.ToLower(out), "--apply")
}
