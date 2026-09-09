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

func TestCreateExampleModelFile_AppFolderFileWinsOverEmbedded(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(appFolder, "threagile-example-model.yaml"), []byte("title: app folder wins"), 0o600))

	err := CreateExampleModelFile(appFolder, outputDir, "input.yaml")
	require.NoError(t, err)

	content, readErr := os.ReadFile(filepath.Join(outputDir, "threagile-example-model.yaml"))
	require.NoError(t, readErr)
	assert.Equal(t, "title: app folder wins", string(content))
}

func TestCreateExampleModelFile_EmbeddedFallback(t *testing.T) {
	appFolder := t.TempDir() // no app-folder file
	outputDir := t.TempDir()

	err := CreateExampleModelFile(appFolder, outputDir, "input.yaml")
	require.NoError(t, err)

	content, readErr := os.ReadFile(filepath.Join(outputDir, "threagile-example-model.yaml"))
	require.NoError(t, readErr)

	embedded, embedErr := assetsFS.ReadFile("assets/threagile-example-model.yaml")
	require.NoError(t, embedErr)
	assert.Equal(t, string(embedded), string(content))
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

func TestCreateStubModelFile_EmbeddedFallback(t *testing.T) {
	appFolder := t.TempDir() // no app-folder file
	outputDir := t.TempDir()

	err := CreateStubModelFile(appFolder, outputDir, "input.yaml")
	require.NoError(t, err)

	content, readErr := os.ReadFile(filepath.Join(outputDir, "threagile-stub-model.yaml"))
	require.NoError(t, readErr)

	embedded, embedErr := assetsFS.ReadFile("assets/threagile-stub-model.yaml")
	require.NoError(t, embedErr)
	assert.Equal(t, string(embedded), string(content))
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

func TestCreateEditingSupportFiles_AppFolderFileWinsOverEmbedded(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(appFolder, "schema.json"), []byte(`{"app":"wins"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(appFolder, "live-templates.txt"), []byte("app templates"), 0o600))

	err := CreateEditingSupportFiles(appFolder, outputDir)
	require.NoError(t, err)

	schema, readErr := os.ReadFile(filepath.Join(outputDir, "schema.json"))
	require.NoError(t, readErr)
	assert.Equal(t, `{"app":"wins"}`, string(schema))

	templates, readErr := os.ReadFile(filepath.Join(outputDir, "live-templates.txt"))
	require.NoError(t, readErr)
	assert.Equal(t, "app templates", string(templates))
}

func TestCreateEditingSupportFiles_EmbeddedFallback(t *testing.T) {
	appFolder := t.TempDir() // no app-folder files
	outputDir := t.TempDir()

	err := CreateEditingSupportFiles(appFolder, outputDir)
	require.NoError(t, err)

	schema, readErr := os.ReadFile(filepath.Join(outputDir, "schema.json"))
	require.NoError(t, readErr)

	embeddedSchema, embedErr := assetsFS.ReadFile("assets/schema.json")
	require.NoError(t, embedErr)
	assert.Equal(t, string(embeddedSchema), string(schema))

	templates, readErr := os.ReadFile(filepath.Join(outputDir, "live-templates.txt"))
	require.NoError(t, readErr)

	embeddedTemplates, embedErr := assetsFS.ReadFile("assets/live-templates.txt")
	require.NoError(t, embedErr)
	assert.Equal(t, string(embeddedTemplates), string(templates))
}

// CreateExampleModelFile fails if the output directory does not exist
// (the file is not created on demand) — this test pins that behavior.
func TestCreateExampleModelFile_MissingOutputDir(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := filepath.Join(t.TempDir(), "does", "not", "exist")

	err := CreateExampleModelFile(appFolder, outputDir, "input.yaml")
	assert.Error(t, err)
}

func TestCreateEditingSupportFiles_MissingOutputDir(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := filepath.Join(t.TempDir(), "does", "not", "exist")

	err := CreateEditingSupportFiles(appFolder, outputDir)
	assert.Error(t, err)
}
