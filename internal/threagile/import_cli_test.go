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

func TestImportThreatDragonCLI(t *testing.T) {
	td := writeTemp(t, "model.json", `{
	  "version":"2.0","summary":{"title":"T"},
	  "detail":{"diagrams":[{"id":0,"cells":[
	    {"shape":"actor","id":"u","position":{"x":0,"y":0},"size":{"width":80,"height":40},"data":{"type":"tm.Actor","name":"User"}},
	    {"shape":"process","id":"p","position":{"x":0,"y":100},"size":{"width":80,"height":40},"data":{"type":"tm.Process","name":"App"}},
	    {"shape":"flow","id":"f","source":{"cell":"u"},"target":{"cell":"p"},"data":{"type":"tm.Flow","name":"HTTP"}}
	  ]}]}
	}`)
	out := filepath.Join(t.TempDir(), "fragment.yaml")
	args := []string{"import", "threat-dragon", "--tdmodel", td, "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)
	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "u-td")
	assert.Contains(t, string(data), "business_criticality:")
}

func TestImportDrawioCLI(t *testing.T) {
	dio := writeTemp(t, "d.drawio", `<mxfile><diagram><mxGraphModel><root>
	  <mxCell id="0"/><mxCell id="1" parent="0"/>
	  <mxCell id="u" value="User" style="shape=actor;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="40" height="80" as="geometry"/></mxCell>
	  <mxCell id="p" value="Service" style="rounded=1;" vertex="1" parent="1"><mxGeometry x="0" y="120" width="80" height="40" as="geometry"/></mxCell>
	  <mxCell id="e" edge="1" parent="1" source="u" target="p"><mxGeometry as="geometry"/></mxCell>
	</root></mxGraphModel></diagram></mxfile>`)
	out := filepath.Join(t.TempDir(), "fragment.yaml")
	args := []string{"import", "drawio", "--diagram", dio, "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)
	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "u-drawio")
	assert.Contains(t, string(data), "review-drawio")
}

func TestImportHelpDoesNotAdvertiseApply(t *testing.T) {
	// Regression: the parent help previously claimed an --apply flag that never existed.
	app := newTestApp()
	out, _ := executeCmd(app, "import", "--help")
	assert.NotContains(t, strings.ToLower(out), "--apply")
}
