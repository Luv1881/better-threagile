package threagile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8simport "github.com/threagile/threagile/pkg/import/kubernetes"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
	"gopkg.in/yaml.v3"
)

const k8sManifests = `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop, labels: {app: web}}
spec:
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: web, image: nginx:1.25, ports: [{containerPort: 80}]}]
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec: {type: LoadBalancer, selector: {app: web}, ports: [{port: 443}]}
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: db, namespace: shop, labels: {app: db}}
spec:
  template:
    metadata: {labels: {app: db}}
    spec:
      containers: [{name: db, image: postgres:16}]
---
apiVersion: v1
kind: Secret
metadata: {name: db-creds, namespace: shop}
`

// TestImporterOutputIsAnalyzable is the regression test for the importer
// round-trip bug: importer output marshalled the internal types.Model, which the
// model parser cannot read back. modelToInput now converts to the authoring
// format, so the emitted YAML must parse AND analyze.
func TestImporterOutputIsAnalyzable(t *testing.T) {
	model, err := k8simport.Import([]byte(k8sManifests), k8simport.ImportOptions{})
	require.NoError(t, err)

	in := modelToInput(model)
	// model-level required fields are populated by the converter.
	assert.NotEmpty(t, in.BusinessCriticality)
	// every used tag must be declared
	assert.Contains(t, in.TagsAvailable, "credential")

	dir := t.TempDir()
	modelPath := filepath.Join(dir, "model.yaml")

	// Render via the same conversion the CLI uses, then analyze it end-to-end.
	yamlBytes, marshalErr := yaml.Marshal(in)
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(modelPath, yamlBytes, 0600))

	out := filepath.Join(dir, "out")
	// Root-persistent flags (the --skip-* set) only reach config via os.Args at
	// Init() time, so they must be passed through newTestAppWithArgs as well.
	analyzeArgs := []string{"analyze-model", "--model", modelPath, "--output", out,
		"--skip-report-pdf", "--skip-report-adoc", "--skip-risks-excel", "--skip-tags-excel",
		"--skip-data-flow-diagram", "--skip-data-asset-diagram",
		"--skip-technical-assets-json", "--skip-stats-json", "--skip-risks-sarif"}
	app := newTestAppWithArgs(analyzeArgs...)
	_, err = executeCmd(app, analyzeArgs...)
	require.NoError(t, err, "importer output must analyze cleanly")

	risks, readErr := os.ReadFile(filepath.Join(out, "risks.json"))
	require.NoError(t, readErr, "analysis must produce risks.json")
	assert.Contains(t, string(risks), "synthetic_id", "expected at least one generated risk")
}

func TestModelToInputPreservesPiiAndAuthStrength(t *testing.T) {
	// HasPii is derived by the parser from pii_categories, so a HasPii-only data
	// asset (e.g. openapi's heuristic) must emit a category to survive re-parse.
	m := &types.Model{
		ThreagileVersion: "1.0.0",
		DataAssets: map[string]*types.DataAsset{
			"d1": {Id: "d1", Title: "User Data", HasPii: true},
		},
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"a1": {Id: "a1", Title: "API", RequiresAuthenticationStrength: "two-factor"},
		},
	}
	in := modelToInput(m)

	var da input.DataAsset
	for _, v := range in.DataAssets {
		da = v
	}
	if len(da.PiiCategories) == 0 {
		t.Error("HasPii data asset must emit a pii category so HasPii survives re-parse")
	}

	var ta input.TechnicalAsset
	for _, v := range in.TechnicalAssets {
		ta = v
	}
	if ta.RequiresAuthenticationStrength != "two-factor" {
		t.Errorf("requires_authentication_strength dropped: %q", ta.RequiresAuthenticationStrength)
	}
}

func TestModelToInputNestsLinksAndStringEnums(t *testing.T) {
	model, err := k8simport.Import([]byte(k8sManifests), k8simport.ImportOptions{})
	require.NoError(t, err)
	in := modelToInput(model)

	// Technical assets are keyed by title, carry string enums, and an id.
	var webKey string
	for k, ta := range in.TechnicalAssets {
		if ta.ID == "shop-web-k8s" {
			webKey = k
		}
	}
	require.NotEmpty(t, webKey, "web asset not found by id")
	web := in.TechnicalAssets[webKey]
	assert.Equal(t, "process", web.Type)
	assert.Equal(t, "container", web.Machine)
	assert.NotEmpty(t, web.Size)

	// The internet client's link must be nested under it and target by id.
	var clientHasLink bool
	for _, ta := range in.TechnicalAssets {
		for _, l := range ta.CommunicationLinks {
			if l.Target == "shop-web-k8s" {
				clientHasLink = true
				assert.Equal(t, "https", l.Protocol)
			}
		}
	}
	assert.True(t, clientHasLink, "expected nested communication link targeting web by id")
}
