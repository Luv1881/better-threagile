package threagile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cliSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [{"type":"library","name":"lodash","version":"4.17.20","bom-ref":"r1"}],
  "vulnerabilities": [
    {"id":"CVE-2021-23337","ratings":[{"score":7.2,"severity":"high"}],"affects":[{"ref":"r1"}]},
    {"id":"CVE-2020-0001","ratings":[{"score":5.0,"severity":"medium"}],"analysis":{"state":"not_affected"}}
  ]
}`

// TestSBOMCommand_OfflineJSON runs the command with an empty cache dir (no KEV,
// no network) and asserts it parses and correlates without error.
func TestSBOMCommand_OfflineJSON(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	require.NoError(t, os.WriteFile(sbomPath, []byte(cliSBOM), 0600))
	out := filepath.Join(dir, "out.json")

	args := []string{"sbom", "--sbom", sbomPath, "--cache-dir", dir, "--format", "json", "--output", out}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	var result struct {
		Findings        []map[string]any `json:"findings"`
		TotalVulns      int              `json:"total_vulns"`
		SuppressedCount int              `json:"suppressed_count"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	assert.Equal(t, 2, result.TotalVulns)
	assert.Equal(t, 1, result.SuppressedCount, "not_affected vuln must be suppressed")
	assert.Len(t, result.Findings, 1, "only the non-suppressed vuln is reported by default")
}

func TestSBOMCommand_MissingFile(t *testing.T) {
	args := []string{"sbom", "--sbom", "/no/such/sbom.json"}
	app := newTestAppWithArgs(args...)
	_, err := executeCmd(app, args...)
	require.Error(t, err)
}
