package examples

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed assets
var assetsFS embed.FS

const (
	ExampleModelAssetName  = "threagile-example-model.yaml"
	StubModelAssetName     = "threagile-stub-model.yaml"
	SchemaAssetName        = "schema.json"
	LiveTemplatesAssetName = "live-templates.txt"
	OpenAPIAssetName       = "openapi.yaml"
)

// ReadAsset returns the named built-in asset: the file in appFolder wins if it
// exists (so Docker layouts and custom app folders keep working), otherwise
// the copy embedded into the binary is returned.
func ReadAsset(appFolder, assetName string) ([]byte, error) {
	appFile := filepath.Join(appFolder, assetName)
	if fileExists(appFile) {
		// #nosec G304 // app folder is operator-configured, reading assets from it is the documented behavior
		data, readError := os.ReadFile(appFile)
		if readError != nil {
			return nil, fmt.Errorf("error reading asset %q from app folder %q: %w", assetName, appFolder, readError)
		}
		return data, nil
	}

	data, readError := assetsFS.ReadFile("assets/" + assetName)
	if readError != nil {
		return nil, fmt.Errorf("asset %q found neither in app folder %q nor embedded in the binary: %w", assetName, appFolder, readError)
	}
	return data, nil
}

func CreateExampleModelFile(appFolder, outputDir, inputFile string) error {
	return writeAssetFile(appFolder, outputDir, ExampleModelAssetName)
}

func CreateStubModelFile(appFolder, outputDir, inputFile string) error {
	return writeAssetFile(appFolder, outputDir, StubModelAssetName)
}

func CreateEditingSupportFiles(appFolder, outputDir string) error {
	schemaError := writeAssetFile(appFolder, outputDir, SchemaAssetName)
	if schemaError != nil {
		return schemaError
	}

	templateError := writeAssetFile(appFolder, outputDir, LiveTemplatesAssetName)
	return templateError
}

// writeAssetFile copies the named asset into outputDir. The file in appFolder
// wins if it exists; otherwise the asset embedded into the binary is used.
func writeAssetFile(appFolder, outputDir, assetName string) error {
	destination := filepath.Join(outputDir, assetName)

	appFile := filepath.Join(appFolder, assetName)
	if fileExists(appFile) {
		return copyFile(appFile, destination)
	}

	source, openError := assetsFS.Open("assets/" + assetName)
	if openError != nil {
		return fmt.Errorf("asset %q found neither in app folder %q nor embedded in the binary: %w", assetName, appFolder, openError)
	}
	defer func() { _ = source.Close() }()

	return copyFromFS(source, destination)
}

func copyFromFS(source fs.File, destination string) error {
	data, readError := io.ReadAll(source)
	if readError != nil {
		return fmt.Errorf("error reading embedded asset: %w", readError)
	}

	// #nosec G306 -- schema/OpenAPI/example assets are published reference
	// files, world-readable by design (same 0644 as the repo and Docker copies)
	if writeError := os.WriteFile(destination, data, 0644); writeError != nil {
		return fmt.Errorf("error writing %q: %w", destination, writeError)
	}

	return nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func copyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	destination, err := os.Create(filepath.Clean(dst))
	if err != nil {
		return err
	}
	defer func() { _ = destination.Close() }()
	_, err = io.Copy(destination, source)
	return err
}
