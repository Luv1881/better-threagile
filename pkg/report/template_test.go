package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/types"
)

func TestResolveTemplateFilename_AppFolderWins(t *testing.T) {
	appFolder := t.TempDir()
	tempFolder := t.TempDir()

	customTemplate := []byte("%PDF-custom")
	require.NoError(t, os.WriteFile(filepath.Join(appFolder, defaultBackgroundTemplate), customTemplate, 0600))

	filename, cleanup, err := resolveTemplateFilename(appFolder, defaultBackgroundTemplate, tempFolder)
	require.NoError(t, err)
	defer cleanup()

	assert.Equal(t, filepath.Join(appFolder, defaultBackgroundTemplate), filename)

	// the app-folder file must not be removed by cleanup
	cleanup()
	assert.FileExists(t, filename)
}

func TestResolveTemplateFilename_EmbeddedFallbackExtractsAndCleansUp(t *testing.T) {
	appFolder := t.TempDir() // no background.pdf inside
	tempFolder := t.TempDir()

	filename, cleanup, err := resolveTemplateFilename(appFolder, defaultBackgroundTemplate, tempFolder)
	require.NoError(t, err)

	// extracted into the temp folder, not the app folder
	assert.Equal(t, tempFolder, filepath.Dir(filename))
	assert.FileExists(t, filename)

	// extracted content must equal the embedded default
	extracted, readErr := os.ReadFile(filename)
	require.NoError(t, readErr)
	embedded, embedErr := templateFS.ReadFile("template/" + defaultBackgroundTemplate)
	require.NoError(t, embedErr)
	assert.Equal(t, embedded, extracted)

	// cleanup removes the extracted file
	cleanup()
	_, statErr := os.Stat(filename)
	assert.True(t, os.IsNotExist(statErr), "cleanup must remove the extracted template file")
}

func TestResolveTemplateFilename_CustomTemplateMissingIsAnError(t *testing.T) {
	appFolder := t.TempDir()
	tempFolder := t.TempDir()

	_, _, err := resolveTemplateFilename(appFolder, "my-custom.pdf", tempFolder)
	assert.Error(t, err, "a missing custom template must not silently fall back to the embedded default")

	// nothing extracted
	entries, readErr := os.ReadDir(tempFolder)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
}

func TestResolveTemplateFilename_CustomNamedBackgroundStillErrors(t *testing.T) {
	appFolder := t.TempDir()
	tempFolder := t.TempDir()

	// a path that merely ends in background.pdf is not the built-in default
	_, _, err := resolveTemplateFilename(appFolder, filepath.Join("some", "dir", defaultBackgroundTemplate), tempFolder)
	assert.Error(t, err)

	entries, readErr := os.ReadDir(tempFolder)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
}

func TestResolveTemplateFilename_MissingTempFolderIsAnError(t *testing.T) {
	appFolder := t.TempDir()

	_, _, err := resolveTemplateFilename(appFolder, defaultBackgroundTemplate, filepath.Join(t.TempDir(), "does-not-exist"))
	assert.Error(t, err)
}

// TestWriteReportPDF_MissingDiagramsStillProducesReport covers the case where
// graphviz is unavailable and no diagram PNGs were rendered: the PDF report
// must still be written (with the diagram chapters noting the missing images).
func TestWriteReportPDF_MissingDiagramsStillProducesReport(t *testing.T) {
	modelPath, absErr := filepath.Abs(filepath.Join("..", "..", "demo", "example", "threagile.yaml"))
	if absErr != nil {
		t.Fatalf("resolve fixture model path: %v", absErr)
	}

	templatePath, absErr2 := filepath.Abs(filepath.Join("template", "background.pdf"))
	if absErr2 != nil {
		t.Fatalf("resolve background template path: %v", absErr2)
	}

	cfg := &pdfTestConfig{inputFile: modelPath}

	result, analyzeErr := model.ReadAndAnalyzeModel(cfg, smokeTestRiskRules(), quietProgressReporter{})
	if analyzeErr != nil {
		t.Fatalf("ReadAndAnalyzeModel: %v", analyzeErr)
	}

	tempFolder := t.TempDir()
	reportPath := filepath.Join(t.TempDir(), "report.pdf")

	reporter := newPdfReporter(nil)
	writeErr := reporter.WriteReportPDF(
		reportPath,
		templatePath,
		filepath.Join(tempFolder, "missing-data-flow-diagram.png"),
		filepath.Join(tempFolder, "missing-data-asset-diagram.png"),
		"model.yaml",
		nil,
		"TEST_BUILD",
		"TEST_VERSION",
		"TEST_HASH",
		result.IntroTextRAA,
		nil,
		tempFolder,
		result.ParsedModel,
		map[ChaptersToShowHide]bool{},
	)
	if writeErr != nil {
		t.Fatalf("WriteReportPDF with missing diagram PNGs: %v", writeErr)
	}

	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatalf("read report.pdf: %v", readErr)
	}
	if len(data) < 1024 {
		t.Fatalf("report.pdf is suspiciously small: %d bytes", len(data))
	}
	if string(data[:5]) != "%PDF-" {
		t.Fatalf("report.pdf does not start with PDF magic bytes: %q", data[:5])
	}
}

func TestWriteDefaultTheme_DefaultLogoMissingFallsBackToEmbedded(t *testing.T) {
	target := t.TempDir()
	adoc := adocReport{targetDirectory: target, imagesDir: filepath.Join(target, "images"), model: &types.Model{}}

	// go test runs with CWD set to the package dir, so the CWD-relative
	// default logo path never exists here — assert the precondition anyway
	_, statErr := os.Stat(DefaultReportLogoImagePath)
	require.True(t, os.IsNotExist(statErr), "precondition: default logo file must not exist at %q", DefaultReportLogoImagePath)

	require.NoError(t, adoc.writeDefaultTheme(DefaultReportLogoImagePath))

	embedded, readErr := templateFS.ReadFile("template/" + defaultLogoImageFilename)
	require.NoError(t, readErr)
	logoData, readErr := os.ReadFile(filepath.Join(target, "theme", "logo.png"))
	require.NoError(t, readErr, "theme should contain the embedded logo")
	assert.Equal(t, embedded, logoData)

	theme, readErr := os.ReadFile(filepath.Join(target, "theme", "pdf-theme.yml"))
	require.NoError(t, readErr)
	assert.Contains(t, string(theme), "logo:")
}

func TestWriteDefaultTheme_CustomLogoMissingKeepsThemeWithoutLogo(t *testing.T) {
	target := t.TempDir()
	adoc := adocReport{targetDirectory: target, imagesDir: filepath.Join(target, "images"), model: &types.Model{}}

	require.NoError(t, adoc.writeDefaultTheme("custom/does-not-exist.png"))

	_, statErr := os.Stat(filepath.Join(target, "theme", "logo.png"))
	assert.True(t, os.IsNotExist(statErr))

	theme, readErr := os.ReadFile(filepath.Join(target, "theme", "pdf-theme.yml"))
	require.NoError(t, readErr)
	assert.NotContains(t, string(theme), "logo:")
}

func TestWriteDefaultTheme_ExistingLogoWins(t *testing.T) {
	target := t.TempDir()
	logoSrc := filepath.Join(t.TempDir(), "custom-logo.svg")
	require.NoError(t, os.WriteFile(logoSrc, []byte("<svg/>"), 0600))
	adoc := adocReport{targetDirectory: target, imagesDir: filepath.Join(target, "images"), model: &types.Model{}}

	require.NoError(t, adoc.writeDefaultTheme(logoSrc))

	data, readErr := os.ReadFile(filepath.Join(target, "theme", "logo.svg"))
	require.NoError(t, readErr, "theme should contain the custom logo")
	assert.Equal(t, "<svg/>", string(data))
}
