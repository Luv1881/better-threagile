package report_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// TestAdocReport_MissingDiagramsStillProducesReport covers the case where
// graphviz is unavailable and no diagram PNGs were rendered: the ADOC report
// must still be written, with the diagram chapters kept but noting the
// missing images.
func TestAdocReport_MissingDiagramsStillProducesReport(t *testing.T) {
	model := loadFixtureModel(t)

	targetDir := t.TempDir()
	missingDataFlowPNG := filepath.Join(targetDir, "missing-data-flow-diagram.png")
	missingDataAssetPNG := filepath.Join(targetDir, "missing-data-asset-diagram.png")

	adoc := report.NewAdocReport(targetDir, types.RiskRules{}, false)
	writeErr := adoc.WriteReport(model,
		missingDataFlowPNG,
		missingDataAssetPNG,
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
		t.Fatalf("WriteReport with missing diagram PNGs: %v", writeErr)
	}

	reportDir := filepath.Join(targetDir, "adocReport")

	// the diagram chapters must still exist...
	for _, chapter := range []string{"060_DataFlowDiagram.adoc", "130_DataRiskMapping.adoc"} {
		content, readErr := os.ReadFile(filepath.Join(reportDir, chapter))
		if readErr != nil {
			t.Fatalf("read %s: %v", chapter, readErr)
		}
		if !strings.Contains(string(content), "not available") {
			t.Fatalf("%s does not note the missing diagram", chapter)
		}
		if strings.Contains(string(content), "image::") {
			t.Fatalf("%s references an image even though the diagram is missing", chapter)
		}
	}

	// ...and the main include file must still reference them
	mainContent, readErr := os.ReadFile(filepath.Join(reportDir, "000_main.adoc"))
	if readErr != nil {
		t.Fatalf("read 000_main.adoc: %v", readErr)
	}
	if !strings.Contains(string(mainContent), "060_DataFlowDiagram.adoc") {
		t.Fatalf("000_main.adoc does not include the data flow diagram chapter")
	}
}
