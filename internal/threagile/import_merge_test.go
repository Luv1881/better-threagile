package threagile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

// diagramModel builds a tiny synthetic "fresh diagram import" result: one
// technical asset carrying the review-drawio tag, mimicking what
// drawio.Import produces before P7 merge runs.
func diagramModel(techType string) *types.Model {
	api := &types.TechnicalAsset{
		Id:              "web-api-drawio",
		Title:           "Web Api",
		Type:            types.Process,
		Technologies:    types.TechnologyList{&types.Technology{Name: types.WebServer}},
		Machine:         types.Virtual,
		Confidentiality: types.Confidential,
		Integrity:       types.Critical,
		Availability:    types.Critical,
		Tags:            []string{"review-drawio"},
	}
	if techType != "" {
		api.Technologies = types.TechnologyList{&types.Technology{Name: techType}}
	}
	return &types.Model{
		ThreagileVersion:   "1.0.0",
		Title:              "Imported from draw.io",
		TechnicalAssets:    map[string]*types.TechnicalAsset{"web-api-drawio": api},
		DataAssets:         map[string]*types.DataAsset{},
		TrustBoundaries:    map[string]*types.TrustBoundary{},
		CommunicationLinks: map[string]*types.CommunicationLink{},
		TagsAvailable:      []string{"review-drawio"},
	}
}

func writeTestModelFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

const baseModelYAML = `threagile_version: "1.0.0"
title: Hand-edited model
business_criticality: important
tags_available:
  - review-drawio
technical_assets:
  Web Api:
    id: web-api-drawio
    type: process
    technology: web-server
    machine: virtual
    confidentiality: confidential
    integrity: critical
    availability: critical
    tags:
      - review-drawio
`

func TestMergeFreshImportIntoEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTestModelFile(t, dir, "model.yaml", "threagile_version: \"1.0.0\"\ntitle: Empty\nbusiness_criticality: important\n")

	outcome, err := mergeDiagramImport(diagramModel(""), "drawio", path)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.NewElements)
	assert.Equal(t, 0, outcome.UpdatedElements)
	assert.Equal(t, 0, outcome.ConflictElements)
	assert.Contains(t, outcome.ChangedFiles, path)
	assert.Len(t, outcome.Warnings, 1, "empty file has no review tags at all, so it must warn")

	m := outcome.ChangedFiles[path]
	found := false
	for _, ta := range m.TechnicalAssets {
		if ta.ID == "web-api-drawio" {
			found = true
		}
	}
	assert.True(t, found)
}

func TestMergeReimportUnchangedIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := writeTestModelFile(t, dir, "model.yaml", baseModelYAML)

	outcome, err := mergeDiagramImport(diagramModel(""), "drawio", path)
	require.NoError(t, err)
	assert.Equal(t, 0, outcome.NewElements)
	assert.Equal(t, 1, outcome.UpdatedElements, "still importer-owned, so it is refreshed even though content is identical")
	assert.Equal(t, 0, outcome.ConflictElements)
	assert.Equal(t, 0, outcome.AbsentElements)
}

func TestMergeChangedDiagramReviewTagPresentOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := writeTestModelFile(t, dir, "model.yaml", baseModelYAML)

	outcome, err := mergeDiagramImport(diagramModel(types.Database), "drawio", path)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.UpdatedElements)
	assert.Equal(t, 0, outcome.ConflictElements)

	m := outcome.ChangedFiles[path]
	for _, ta := range m.TechnicalAssets {
		if ta.ID == "web-api-drawio" {
			assert.Equal(t, types.Database, ta.Technology)
		}
	}
}

func TestMergeChangedDiagramReviewTagRemovedFlagsConflict(t *testing.T) {
	dir := t.TempDir()
	userEdited := `threagile_version: "1.0.0"
title: Hand-edited model
business_criticality: important
technical_assets:
  Web Api:
    id: web-api-drawio
    type: process
    technology: web-server
    machine: virtual
    confidentiality: confidential
    integrity: critical
    availability: critical
`
	path := writeTestModelFile(t, dir, "model.yaml", userEdited)

	outcome, err := mergeDiagramImport(diagramModel(types.Database), "drawio", path)
	require.NoError(t, err)
	assert.Equal(t, 0, outcome.UpdatedElements, "review tag removed -> user-owned -> never overwritten")
	assert.Equal(t, 1, outcome.ConflictElements)

	m := outcome.ChangedFiles[path]
	for _, ta := range m.TechnicalAssets {
		if ta.ID == "web-api-drawio" {
			assert.Equal(t, "web-server", ta.Technology, "user-owned field must not be overwritten")
			assert.Contains(t, ta.Tags, "merge-conflict:technology")
		}
	}
}

func TestMergeNewElementAppendsToMainFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTestModelFile(t, dir, "model.yaml", baseModelYAML)

	fresh := diagramModel("")
	fresh.TechnicalAssets["db-drawio"] = &types.TechnicalAsset{
		Id: "db-drawio", Title: "Database", Type: types.Datastore,
		Technologies: types.TechnologyList{&types.Technology{Name: types.Database}},
		Tags:         []string{"review-drawio"},
	}

	outcome, err := mergeDiagramImport(fresh, "drawio", path)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.NewElements)

	m := outcome.ChangedFiles[path]
	assert.Len(t, m.TechnicalAssets, 2)
}

func TestMergeElementRemovedFromDiagramFlagsAbsent(t *testing.T) {
	dir := t.TempDir()
	path := writeTestModelFile(t, dir, "model.yaml", baseModelYAML)

	// Fresh diagram no longer contains any technical assets at all.
	fresh := &types.Model{
		ThreagileVersion:   "1.0.0",
		TechnicalAssets:    map[string]*types.TechnicalAsset{},
		DataAssets:         map[string]*types.DataAsset{},
		TrustBoundaries:    map[string]*types.TrustBoundary{},
		CommunicationLinks: map[string]*types.CommunicationLink{},
	}

	outcome, err := mergeDiagramImport(fresh, "drawio", path)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.AbsentElements)

	m := outcome.ChangedFiles[path]
	for _, ta := range m.TechnicalAssets {
		assert.Contains(t, ta.Tags, mergeAbsentTag)
	}
}

func TestMergeIncludesScenario(t *testing.T) {
	dir := t.TempDir()
	includedContent := `threagile_version: "1.0.0"
title: Included
technical_assets:
  Web Api:
    id: web-api-drawio
    type: process
    technology: web-server
    machine: virtual
    confidentiality: confidential
    integrity: critical
    availability: critical
    tags:
      - review-drawio
`
	writeTestModelFile(t, dir, "included.yaml", includedContent)
	mainContent := `threagile_version: "1.0.0"
title: Main model
business_criticality: important
includes:
  - included.yaml
`
	mainPath := writeTestModelFile(t, dir, "main.yaml", mainContent)

	fresh := diagramModel(types.Database)
	fresh.TechnicalAssets["cache-drawio"] = &types.TechnicalAsset{
		Id: "cache-drawio", Title: "Cache", Type: types.Datastore,
		Technologies: types.TechnologyList{&types.Technology{Name: types.Database}},
		Tags:         []string{"review-drawio"},
	}

	outcome, err := mergeDiagramImport(fresh, "drawio", mainPath)
	require.NoError(t, err)

	includedPath := filepath.Join(dir, "included.yaml")
	require.Contains(t, outcome.ChangedFiles, includedPath, "existing element must be updated in the file it was found in")
	require.Contains(t, outcome.ChangedFiles, mainPath, "brand-new element must land in the main entry-point file")

	includedModel := outcome.ChangedFiles[includedPath]
	assert.Len(t, includedModel.TechnicalAssets, 1, "the new element must not be appended to the included file")
	for _, ta := range includedModel.TechnicalAssets {
		assert.Equal(t, types.Database, ta.Technology, "matched element updated in-place in its own file")
	}

	mainModel := outcome.ChangedFiles[mainPath]
	assert.Len(t, mainModel.TechnicalAssets, 1, "new element appended only to main file")
}

func TestWriteMergedFileOnlyAnnotatesOwnedElements(t *testing.T) {
	m := &input.Model{
		TechnicalAssets: map[string]input.TechnicalAsset{
			"Owned":    {ID: "owned", Type: "process", Tags: []string{"review-drawio"}},
			"NotOwned": {ID: "not-owned", Type: "process"},
		},
	}
	out, err := writeMergedFile(m)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "TODO(review)")
	// The annotation should not appear twice for the non-owned element: a
	// crude but effective check is that there is exactly one TODO comment
	// (the owned element has exactly one scaffolded field: "type").
	count := 0
	for i := 0; i+len("TODO(review)") <= len(s); i++ {
		if s[i:i+len("TODO(review)")] == "TODO(review)" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}
