package input

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestModel_Merge_BasicFields(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "include.yaml", `
title: Included Title
tags_available:
  - foo
  - bar
security_requirements:
  req1: must do foo
data_assets:
  Some Data:
    id: some-data
    description: included data asset
`)

	model := new(Model).Defaults()
	model.SecurityRequirements["req0"] = "must do bar"

	err := model.Merge(dir, "include.yaml")
	require.NoError(t, err)

	// Title was empty, so the included title is taken (singleton merge).
	assert.Equal(t, "Included Title", model.Title)
	assert.ElementsMatch(t, []string{"foo", "bar"}, model.TagsAvailable)
	assert.Equal(t, map[string]string{"req0": "must do bar", "req1": "must do foo"}, model.SecurityRequirements)
	assert.Contains(t, model.DataAssets, "Some Data")
}

func TestModel_Merge_TitleConflict(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "include.yaml", `
title: Other Title
`)

	model := new(Model).Defaults()
	model.Title = "Main Title"

	err := model.Merge(dir, "include.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "title")
}

func TestModel_Merge_DuplicateSecurityRequirement(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "include.yaml", `
security_requirements:
  req1: included value
`)

	model := new(Model).Defaults()
	model.SecurityRequirements["req1"] = "main value"

	err := model.Merge(dir, "include.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "security requirements")
}

func TestModel_Merge_AuthorMismatch(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "include.yaml", `
author:
  name: Someone Else
`)

	model := new(Model).Defaults()
	model.Author.Name = "Original Author"

	err := model.Merge(dir, "include.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "author")
}

func TestModel_Merge_FileNotFound(t *testing.T) {
	dir := t.TempDir()

	model := new(Model).Defaults()
	err := model.Merge(dir, "does-not-exist.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to read model file")
}

func TestModel_Merge_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "broken.yaml", "title: [this is not valid yaml")

	model := new(Model).Defaults()
	err := model.Merge(dir, "broken.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse model")
}

func TestModel_Merge_NestedIncludes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "nested/inner.yaml", `
tags_available:
  - inner-tag
`)
	writeFile(t, dir, "nested/outer.yaml", `
includes:
  - inner.yaml
tags_available:
  - outer-tag
`)

	model := new(Model).Defaults()
	err := model.Merge(dir, "nested/outer.yaml")
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"outer-tag", "inner-tag"}, model.TagsAvailable)
}

func TestModel_Merge_DiagramTweakSlicesDeduped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "include.yaml", `
diagram_tweak_same_rank_assets:
  - asset-b
  - asset-a
`)

	model := new(Model).Defaults()
	model.DiagramTweakSameRankAssets = []string{"asset-a", "asset-c"}

	err := model.Merge(dir, "include.yaml")
	require.NoError(t, err)

	assert.Equal(t, []string{"asset-a", "asset-b", "asset-c"}, model.DiagramTweakSameRankAssets)
}

func TestModel_Load_WithIncludes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "included.yaml", `
title: Included Title
tags_available:
  - included-tag
`)
	mainFile := writeFile(t, dir, "main.yaml", `
includes:
  - included.yaml
tags_available:
  - main-tag
`)

	model := new(Model).Defaults()
	err := model.Load(mainFile)
	require.NoError(t, err)

	assert.Equal(t, "Included Title", model.Title)
	assert.ElementsMatch(t, []string{"main-tag", "included-tag"}, model.TagsAvailable)
}

func TestModel_Load_WithFeatureIncludesGlob(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "features/a.yaml", `
tags_available:
  - feature-a
`)
	writeFile(t, dir, "features/b.yaml", `
tags_available:
  - feature-b
`)
	mainFile := writeFile(t, dir, "main.yaml", `
feature_includes:
  - features/*.yaml
tags_available:
  - main-tag
`)

	model := new(Model).Defaults()
	err := model.Load(mainFile)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"main-tag", "feature-a", "feature-b"}, model.TagsAvailable)
}

func TestModel_Load_FeatureIncludesNoMatch(t *testing.T) {
	dir := t.TempDir()
	mainFile := writeFile(t, dir, "main.yaml", `
feature_includes:
  - features/*.yaml
title: Main Title
`)

	model := new(Model).Defaults()
	err := model.Load(mainFile)
	require.NoError(t, err)

	// No matching files: model is otherwise unaffected, just a warning is logged.
	assert.Equal(t, "Main Title", model.Title)
}

func TestModel_AddTagToModelInput(t *testing.T) {
	model := new(Model).Defaults()

	var changes []string
	model.AddTagToModelInput("  Some-Tag  ", false, &changes)
	assert.Equal(t, []string{"some-tag"}, model.TagsAvailable)
	assert.Equal(t, []string{"adding tag: some-tag"}, changes)

	// Adding the same (normalized) tag again is a no-op.
	changes = nil
	model.AddTagToModelInput("some-tag", false, &changes)
	assert.Empty(t, changes)
	assert.Equal(t, []string{"some-tag"}, model.TagsAvailable)

	// Dry run does not mutate the model.
	changes = nil
	model.AddTagToModelInput("dry-run-tag", true, &changes)
	assert.Equal(t, []string{"adding tag: dry-run-tag"}, changes)
	assert.Equal(t, []string{"some-tag"}, model.TagsAvailable)
}

func TestNormalizeTag(t *testing.T) {
	assert.Equal(t, "some-tag", NormalizeTag("  Some-Tag  "))
}
