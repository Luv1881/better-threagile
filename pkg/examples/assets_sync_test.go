package examples

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAssetsSyncedWithRepoFiles guards against drift between the embedded
// assets and the canonical repo files they were copied from. If this test
// fails, re-copy the canonical file into pkg/examples/assets/.
func TestAssetsSyncedWithRepoFiles(t *testing.T) {
	canonicalFiles := map[string]string{
		"threagile-example-model.yaml": filepath.Join("..", "..", "demo", "example", "threagile.yaml"),
		"threagile-stub-model.yaml":    filepath.Join("..", "..", "demo", "stub", "threagile.yaml"),
		"schema.json":                  filepath.Join("..", "..", "support", "schema.json"),
		"live-templates.txt":           filepath.Join("..", "..", "support", "live-templates.txt"),
		"openapi.yaml":                 filepath.Join("..", "..", "support", "openapi.yaml"),
	}

	for assetName, canonicalPath := range canonicalFiles {
		assetName, canonicalPath := assetName, canonicalPath
		t.Run(assetName, func(t *testing.T) {
			embedded, readError := assetsFS.ReadFile("assets/" + assetName)
			require.NoError(t, readError, "embedded asset %q must exist", assetName)

			canonical, readError := os.ReadFile(canonicalPath)
			require.NoError(t, readError, "canonical repo file %q must exist", canonicalPath)

			assert.Equal(t, string(canonical), string(embedded),
				"embedded asset pkg/examples/assets/%s has drifted from the canonical repo file %s — re-copy the canonical file into pkg/examples/assets/", assetName, canonicalPath)
		})
	}

	// reverse check: no extra files in the embedded assets dir that have no
	// canonical repo counterpart
	assetEntries, readError := assetsFS.ReadDir("assets")
	require.NoError(t, readError)
	for _, entry := range assetEntries {
		assert.Contains(t, canonicalFiles, entry.Name(),
			"embedded asset pkg/examples/assets/%s has no canonical repo file — add it to the drift guard or remove the file", entry.Name())
	}
}
