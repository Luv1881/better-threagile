package report_test

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/threagile/threagile/internal/threagile"
	"github.com/threagile/threagile/pkg/report"
	"github.com/xuri/excelize/v2"
)

// TestWriteRisksExcelToFile_Golden characterizes the risks Excel report:
// sheet names and per-sheet row counts for the canonical demo/example model.
func TestWriteRisksExcelToFile_Golden(t *testing.T) {
	model := loadFixtureModel(t)
	cfg := new(threagile.Config).Defaults("test")

	path := filepath.Join(t.TempDir(), "risks.xlsx")
	if err := report.WriteRisksExcelToFile(model, path, cfg); err != nil {
		t.Fatalf("WriteRisksExcelToFile: %v", err)
	}

	goldenCompare(t, filepath.Join("testdata", "golden_risks_excel.txt"), []byte(summarizeExcel(t, path)))
}

// TestWriteTagsExcelToFile_Golden characterizes the tags Excel report.
func TestWriteTagsExcelToFile_Golden(t *testing.T) {
	model := loadFixtureModel(t)
	cfg := new(threagile.Config).Defaults("test")

	path := filepath.Join(t.TempDir(), "tags.xlsx")
	if err := report.WriteTagsExcelToFile(model, path, cfg); err != nil {
		t.Fatalf("WriteTagsExcelToFile: %v", err)
	}

	goldenCompare(t, filepath.Join("testdata", "golden_tags_excel.txt"), []byte(summarizeExcel(t, path)))
}

// summarizeExcel returns a stable, human-readable summary of an xlsx file's
// sheet names and row counts, suitable for golden-file comparison (the raw
// bytes of an xlsx are not stable across regenerations).
func summarizeExcel(t *testing.T, path string) string {
	t.Helper()

	f, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() { _ = f.Close() }()

	sheets := append([]string{}, f.GetSheetList()...)
	sort.Strings(sheets)

	var b strings.Builder
	for _, sheet := range sheets {
		rows, rowsErr := f.GetRows(sheet)
		if rowsErr != nil {
			t.Fatalf("GetRows(%s): %v", sheet, rowsErr)
		}
		cols := 0
		if len(rows) > 0 {
			cols = len(rows[0])
		}
		b.WriteString(sheet)
		b.WriteString(": rows=")
		b.WriteString(strconv.Itoa(len(rows)))
		b.WriteString(" headerCols=")
		b.WriteString(strconv.Itoa(cols))
		b.WriteString("\n")
		if len(rows) > 0 {
			b.WriteString("  header: ")
			b.WriteString(strings.Join(rows[0], " | "))
			b.WriteString("\n")
		}
	}
	return b.String()
}
