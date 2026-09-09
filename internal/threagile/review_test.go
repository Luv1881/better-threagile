package threagile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeReviewModel builds a syntactically-minimal model that exercises
// scanReviewTags/formatReviewMarkdown; it is loaded via input.Model.Load
// only (as `review` does), not the full risk-analysis pipeline.
func writeReviewModel(t *testing.T) string {
	t.Helper()
	model := `title: Review Test
technical_assets:
  API Server:
    id: api-mermaid
    tags:
      - review-mermaid
    communication_links:
      To DB:
        target: db-mermaid
        tags:
          - review-mermaid
  DB:
    id: db-mermaid
    tags: []
data_assets:
  Stub Payload:
    id: stub-payload
    tags:
      - stub-data-asset
trust_boundaries:
  DMZ:
    id: boundary-dmz
    tags:
      - review-mermaid
`
	path := filepath.Join(t.TempDir(), "threagile.yaml")
	require.NoError(t, os.WriteFile(path, []byte(model), 0600))
	return path
}

// writeReviewableDemoModel copies the full demo model (which passes complete
// risk analysis) and tags one technical asset and one data asset for review,
// so `gate --policy fail_on_unreviewed` has a realistic, fully-analyzable
// fixture to fail against.
func writeReviewableDemoModel(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(demoModelPath(t))
	require.NoError(t, err)

	content := string(data)

	tagsMarker := "tags_available:\n"
	require.Contains(t, content, tagsMarker)
	content = strings.Replace(content, tagsMarker,
		tagsMarker+"  - review-mermaid\n  - stub-data-asset\n", 1)

	taMarker := "  Customer Web Client:\n    id: customer-client\n    description: Customer Web Client\n    type: external-entity # values: external-entity, process, datastore\n    usage: business # values: business, devops\n    used_as_client_by_human: true\n    out_of_scope: true\n    justification_out_of_scope: Owned and managed by end-user customer\n    size: component # values: system, service, application, component\n    technology: browser # values: see help\n    tags:\n"
	require.Contains(t, content, taMarker, "demo model layout changed; update the fixture marker")
	content = strings.Replace(content, taMarker,
		strings.Replace(taMarker, "    tags:\n", "    tags:\n      - review-mermaid\n", 1), 1)

	daMarker := "data_assets:\n"
	require.Contains(t, content, daMarker)
	stubAsset := "  Stub Payload:\n" +
		"    id: stub-payload\n" +
		"    usage: business\n" +
		"    quantity: few\n" +
		"    confidentiality: internal\n" +
		"    integrity: operational\n" +
		"    availability: operational\n" +
		"    tags:\n" +
		"      - stub-data-asset\n"
	content = strings.Replace(content, daMarker, daMarker+stubAsset, 1)

	path := filepath.Join(t.TempDir(), "threagile.yaml")
	// #nosec G703 -- path is derived from t.TempDir(), never attacker-controlled
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func TestIsReviewTag(t *testing.T) {
	assert.True(t, isReviewTag("review-drawio"))
	assert.True(t, isReviewTag("review-mermaid"))
	assert.True(t, isReviewTag("review-otm"))
	assert.True(t, isReviewTag("stub-data-asset"))
	assert.False(t, isReviewTag("reviewed"))
	assert.False(t, isReviewTag("prod"))
	assert.False(t, isReviewTag(""))
}

func TestReviewModel_FindsAllKinds(t *testing.T) {
	path := writeReviewModel(t)
	items, err := reviewModel(path)
	require.NoError(t, err)
	require.Len(t, items, 4) // technical_asset, communication_link, data_asset, trust_boundary

	kinds := map[string]bool{}
	for _, it := range items {
		kinds[it.Kind] = true
	}
	assert.True(t, kinds["technical_asset"])
	assert.True(t, kinds["communication_link"])
	assert.True(t, kinds["data_asset"])
	assert.True(t, kinds["trust_boundary"])

	// DB carries no review tag and must not appear.
	for _, it := range items {
		assert.NotEqual(t, "DB", it.Name)
	}
}

func TestFormatReviewMarkdown_Empty(t *testing.T) {
	out := formatReviewMarkdown(nil)
	assert.Contains(t, out, "No elements are flagged")
}

func TestFormatReviewMarkdown_ListsSections(t *testing.T) {
	path := writeReviewModel(t)
	items, err := reviewModel(path)
	require.NoError(t, err)
	out := formatReviewMarkdown(items)
	assert.Contains(t, out, "Technical assets")
	assert.Contains(t, out, "Communication links")
	assert.Contains(t, out, "Data assets")
	assert.Contains(t, out, "Trust boundaries")
	assert.Contains(t, out, "API Server")
	assert.Contains(t, out, "stub-data-asset")
}

func TestReviewCommand_MarkdownDefault(t *testing.T) {
	path := writeReviewModel(t)
	app := newTestAppWithArgs("review", "--model", path)
	out, err := executeCmd(app, "review", "--model", path)
	require.NoError(t, err)
	assert.Contains(t, out, "# Threagile review")
	assert.Contains(t, out, "review-mermaid")
}

func TestReviewCommand_JSONFormat(t *testing.T) {
	path := writeReviewModel(t)
	app := newTestAppWithArgs("review", "--model", path, "--format", "json")
	out, err := executeCmd(app, "review", "--model", path, "--format", "json")
	require.NoError(t, err)
	var items []ReviewItem
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	assert.Len(t, items, 4)
}

func TestReviewCommand_NoFindingsOnCleanModel(t *testing.T) {
	app := newTestAppWithArgs("review", "--model", demoModelPath(t))
	out, err := executeCmd(app, "review", "--model", demoModelPath(t))
	require.NoError(t, err)
	assert.Contains(t, out, "No elements are flagged")
}

func TestReviewCommand_FailOnUnreviewedExitsThree(t *testing.T) {
	path := writeReviewModel(t)
	app := newTestAppWithArgs("review", "--model", path, "--fail-on-unreviewed")
	_, err := executeCmd(app, "review", "--model", path, "--fail-on-unreviewed")
	require.Error(t, err)
	var ec *exitCodeError
	require.True(t, errors.As(err, &ec), "expected exitCodeError, got %T", err)
	assert.Equal(t, 3, ec.ExitCode())
}

func TestReviewCommand_FailOnUnreviewedPassesWhenClean(t *testing.T) {
	app := newTestAppWithArgs("review", "--model", demoModelPath(t), "--fail-on-unreviewed")
	_, err := executeCmd(app, "review", "--model", demoModelPath(t), "--fail-on-unreviewed")
	require.NoError(t, err)
}

func TestReviewCommand_UnknownFormat(t *testing.T) {
	path := writeReviewModel(t)
	app := newTestAppWithArgs("review", "--model", path, "--format", "yaml")
	_, err := executeCmd(app, "review", "--model", path, "--format", "yaml")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "unknown --format"))
}

// --- gate integration ---------------------------------------------------

func TestGateCommand_FailOnUnreviewed(t *testing.T) {
	model := writeReviewableDemoModel(t)
	policy := writeGatePolicy(t, "name: unreviewed\nfail_on_unreviewed: true\n")
	app := newTestAppWithArgs("gate", "--model", model, "--policy", policy)
	out, err := executeCmd(app, "gate", "--model", model, "--policy", policy)
	require.Error(t, err)
	var ec *exitCodeError
	require.True(t, errors.As(err, &ec))
	assert.Equal(t, 3, ec.ExitCode())
	assert.Contains(t, out, "fail_on_unreviewed")
}

func TestGateCommand_FailOnUnreviewedPassesWhenClean(t *testing.T) {
	model := demoModelPath(t)
	policy := writeGatePolicy(t, "name: unreviewed\nfail_on_unreviewed: true\nmax_severity_counts:\n  critical: 100\n")
	app := newTestAppWithArgs("gate", "--model", model, "--policy", policy)
	out, err := executeCmd(app, "gate", "--model", model, "--policy", policy)
	require.NoError(t, err)
	assert.Contains(t, out, "PASS")
}
