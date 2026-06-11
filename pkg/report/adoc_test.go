package report_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/types"
)

// TestAdocReport_Golden characterizes the AsciiDoc report output for the
// canonical demo/example model: the set of generated chapter files and the
// content of the main include file.
func TestAdocReport_Golden(t *testing.T) {
	model := loadFixtureModel(t)

	targetDir := t.TempDir()
	dataFlowPNG := writeFixturePNG(t, targetDir, "data-flow-diagram.png")
	dataAssetPNG := writeFixturePNG(t, targetDir, "data-asset-diagram.png")

	adoc := report.NewAdocReport(targetDir, types.RiskRules{}, false)
	writeErr := adoc.WriteReport(model,
		dataFlowPNG,
		dataAssetPNG,
		"model.yaml",
		nil,
		"TEST_BUILD",
		"TEST_VERSION",
		"TEST_HASH",
		"",
		types.RiskRules{},
		"",
		map[report.ChaptersToShowHide]bool{},
	)
	if writeErr != nil {
		t.Fatalf("WriteReport: %v", writeErr)
	}

	reportDir := filepath.Join(targetDir, "adocReport")
	entries, readErr := os.ReadDir(reportDir)
	if readErr != nil {
		t.Fatalf("ReadDir: %v", readErr)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var listing string
	for _, name := range names {
		listing += name + "\n"
	}
	goldenCompare(t, filepath.Join("testdata", "golden_adoc_files.txt"), []byte(listing))

	mainContent, readErr := os.ReadFile(filepath.Join(reportDir, "000_main.adoc"))
	if readErr != nil {
		t.Fatalf("read report.adoc: %v", readErr)
	}
	goldenCompare(t, filepath.Join("testdata", "golden_main.adoc"), mainContent)
}
