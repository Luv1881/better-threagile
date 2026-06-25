package threagile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSTIXCommand(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle.json")
	modelPath := demoModelPath(t)
	args := []string{"stix", "--model", modelPath, "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)

	var bundle struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		Objects []struct {
			Type        string `json:"type"`
			SpecVersion string `json:"spec_version"`
			ID          string `json:"id"`
		} `json:"objects"`
	}
	require.NoError(t, json.Unmarshal(data, &bundle), "STIX bundle must be valid JSON")
	assert.Equal(t, "bundle", bundle.Type)
	assert.True(t, strings.HasPrefix(bundle.ID, "bundle--"))
	require.NotEmpty(t, bundle.Objects)

	kinds := map[string]int{}
	for _, o := range bundle.Objects {
		kinds[o.Type]++
		assert.Equal(t, "2.1", o.SpecVersion)
	}
	assert.Equal(t, 1, kinds["identity"])
	assert.Positive(t, kinds["vulnerability"])
	assert.Positive(t, kinds["attack-pattern"])
	assert.Positive(t, kinds["relationship"])
}

func TestSTIXCommand_StdoutIsValidJSON(t *testing.T) {
	modelPath := demoModelPath(t)
	args := []string{"stix", "--model", modelPath}
	app := newTestAppWithArgs(args...)
	out, err := executeCmd(app, args...)
	require.NoError(t, err)
	// executeCmd shares one buffer for stdout+stderr; the JSON object must be present.
	assert.Contains(t, out, `"type": "bundle"`)
}
