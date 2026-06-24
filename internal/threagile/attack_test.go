package threagile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttackNavigatorCommand(t *testing.T) {
	out := filepath.Join(t.TempDir(), "layer.json")
	modelPath := demoModelPath(t)
	app := newTestAppWithArgs("attack-navigator", "--model", modelPath, "--output", out)
	stdout, err := executeCmd(app, "attack-navigator", "--model", modelPath, "--output", out)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Navigator layer written")

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)

	var layer struct {
		Domain     string `json:"domain"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Score       int    `json:"score"`
			Enabled     bool   `json:"enabled"`
		} `json:"techniques"`
	}
	require.NoError(t, json.Unmarshal(data, &layer), "layer must be valid JSON")
	assert.Equal(t, "enterprise-attack", layer.Domain)
	require.NotEmpty(t, layer.Techniques, "demo model should map to ATT&CK techniques")

	// T1190 (Exploit Public-Facing Application) is the dominant technique for the
	// demo model's injection findings.
	var foundT1190 bool
	for _, tech := range layer.Techniques {
		assert.True(t, tech.Enabled)
		assert.Positive(t, tech.Score)
		if tech.TechniqueID == "T1190" {
			foundT1190 = true
		}
	}
	assert.True(t, foundT1190, "expected T1190 in the demo model layer")
}
