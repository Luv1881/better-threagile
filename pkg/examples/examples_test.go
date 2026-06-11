package examples

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateExampleModelFile(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(appFolder, "threagile-example-model.yaml"), []byte("title: example"), 0o600))

	err := CreateExampleModelFile(appFolder, outputDir, "input.yaml")
	require.NoError(t, err)

	content, readErr := os.ReadFile(filepath.Join(outputDir, "threagile-example-model.yaml"))
	require.NoError(t, readErr)
	assert.Equal(t, "title: example", string(content))
}

func TestCreateExampleModelFile_FallbackToInputFile(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(appFolder, "input.yaml"), []byte("title: fallback"), 0o600))

	err := CreateExampleModelFile(appFolder, outputDir, "input.yaml")
	require.NoError(t, err)

	content, readErr := os.ReadFile(filepath.Join(outputDir, "threagile-example-model.yaml"))
	require.NoError(t, readErr)
	assert.Equal(t, "title: fallback", string(content))
}

func TestCreateExampleModelFile_NoSourceFiles(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()

	err := CreateExampleModelFile(appFolder, outputDir, "input.yaml")
	assert.Error(t, err)
}

func TestCreateStubModelFile(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(appFolder, "threagile-stub-model.yaml"), []byte("title: stub"), 0o600))

	err := CreateStubModelFile(appFolder, outputDir, "input.yaml")
	require.NoError(t, err)

	content, readErr := os.ReadFile(filepath.Join(outputDir, "threagile-stub-model.yaml"))
	require.NoError(t, readErr)
	assert.Equal(t, "title: stub", string(content))
}

func TestCreateStubModelFile_FallbackToInputFile(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(appFolder, "input.yaml"), []byte("title: fallback"), 0o600))

	err := CreateStubModelFile(appFolder, outputDir, "input.yaml")
	require.NoError(t, err)

	content, readErr := os.ReadFile(filepath.Join(outputDir, "threagile-stub-model.yaml"))
	require.NoError(t, readErr)
	assert.Equal(t, "title: fallback", string(content))
}

func TestCreateEditingSupportFiles(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(appFolder, "schema.json"), []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(appFolder, "live-templates.txt"), []byte("templates"), 0o600))

	err := CreateEditingSupportFiles(appFolder, outputDir)
	require.NoError(t, err)

	schema, readErr := os.ReadFile(filepath.Join(outputDir, "schema.json"))
	require.NoError(t, readErr)
	assert.Equal(t, "{}", string(schema))

	templates, readErr := os.ReadFile(filepath.Join(outputDir, "live-templates.txt"))
	require.NoError(t, readErr)
	assert.Equal(t, "templates", string(templates))
}

func TestCreateEditingSupportFiles_MissingSchema(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()

	err := CreateEditingSupportFiles(appFolder, outputDir)
	assert.Error(t, err)
}
