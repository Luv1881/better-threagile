package report_test

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/threagile/threagile/pkg/report"
)

var generatedLineRE = regexp.MustCompile(`(?m)^\*\*Generated:\*\*.*$`)

// TestMarkdownReport_Golden characterizes the Markdown report for the
// canonical demo/example model. The "Generated:" timestamp line is
// normalized before comparison since it changes on every run.
func TestMarkdownReport_Golden(t *testing.T) {
	model := loadFixtureModel(t)

	out := report.MarkdownReport(model)
	out = generatedLineRE.ReplaceAllString(out, "**Generated:** <normalized>")

	goldenCompare(t, filepath.Join("testdata", "golden_report.md"), []byte(out))
}
