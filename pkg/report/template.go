package report

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed template/background.pdf template/threagile-logo.png
var templateFS embed.FS

// defaultBackgroundTemplate is the built-in report background shipped inside
// the binary. It is only used as a fallback when no app-folder file with the
// exact same name exists, so explicitly configured custom templates keep
// failing loudly when they are missing instead of silently reverting.
const defaultBackgroundTemplate = "background.pdf"

// defaultLogoImageFilename is the built-in report logo embedded above.
const defaultLogoImageFilename = "threagile-logo.png"

// DefaultReportLogoImagePath is the CLI default for the report logo (relative
// to the working directory, unlike the app-folder-relative template). A file at
// this path wins; only when it is missing does the adoc theme fall back to the
// copy embedded into the binary.
const DefaultReportLogoImagePath = "report/" + defaultLogoImageFilename

// resolveTemplateFilename returns the PDF background template to use for report
// generation: a file named templateFilename in appFolder takes precedence (so
// custom templates and Docker's /app layout keep working); only when the
// requested template is exactly the built-in default and it is missing, the
// default is extracted to tempFolder and that path is returned.
// The returned cleanup function removes the extracted file again and must be
// called once the report has been written; it is a no-op for app-folder files.
func resolveTemplateFilename(appFolder, templateFilename, tempFolder string) (string, func(), error) {
	appTemplateFilename := filepath.Join(appFolder, templateFilename)
	if fileExists(appTemplateFilename) {
		return appTemplateFilename, func() {}, nil
	}

	if templateFilename != defaultBackgroundTemplate {
		return "", nil, fmt.Errorf("report template %q not found in app folder %q", templateFilename, appFolder)
	}

	templateBytes, readError := templateFS.ReadFile("template/" + defaultBackgroundTemplate)
	if readError != nil {
		return "", nil, fmt.Errorf("error reading embedded default report template: %w", readError)
	}

	tmpFile, createError := os.CreateTemp(tempFolder, "background-*.pdf")
	if createError != nil {
		return "", nil, fmt.Errorf("error creating temporary file for report template: %w", createError)
	}
	cleanup := func() { _ = os.Remove(tmpFile.Name()) }

	if _, writeError := tmpFile.Write(templateBytes); writeError != nil {
		_ = tmpFile.Close()
		cleanup()
		return "", nil, fmt.Errorf("error writing temporary report template file: %w", writeError)
	}
	if closeError := tmpFile.Close(); closeError != nil {
		cleanup()
		return "", nil, fmt.Errorf("error closing temporary report template file: %w", closeError)
	}

	return tmpFile.Name(), cleanup, nil
}
