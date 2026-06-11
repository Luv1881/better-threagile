package report_test

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/internal/threagile"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/server"
	"github.com/threagile/threagile/pkg/types"
)

// loadFixtureModel parses and analyzes the canonical demo/example model,
// running the full risk-generation pipeline so report tests exercise
// realistic data (multiple assets, data assets, and generated risks).
func loadFixtureModel(t *testing.T) *types.Model {
	t.Helper()

	modelPath, err := filepath.Abs(filepath.Join("..", "..", "demo", "example", "threagile.yaml"))
	if err != nil {
		t.Fatalf("resolve fixture model path: %v", err)
	}

	cfg := new(threagile.Config).Defaults("test")
	cfg.SetInputFile(modelPath)
	cfg.SetOutputFolder(t.TempDir())
	cfg.SetTempFolder(t.TempDir())

	result, analyzeErr := model.ReadAndAnalyzeModel(cfg, risks.GetBuiltInRiskRules(), server.DefaultProgressReporter{})
	if analyzeErr != nil {
		t.Fatalf("ReadAndAnalyzeModel: %v", analyzeErr)
	}
	return result.ParsedModel
}

// writeFixturePNG writes a small valid PNG to dir/name and returns its path,
// for use as a stand-in data-flow / data-asset diagram image.
func writeFixturePNG(t *testing.T, dir, name string) string {
	t.Helper()

	img := image.NewRGBA(image.Rect(0, 0, 1600, 1200))
	for y := 0; y < 1200; y++ {
		for x := 0; x < 1600; x++ {
			img.Set(x, y, color.RGBA{R: 200, G: 200, B: 200, A: 255})
		}
	}

	path := filepath.Join(dir, name)
	f, createErr := os.Create(path)
	if createErr != nil {
		t.Fatalf("create png: %v", createErr)
	}
	defer func() { _ = f.Close() }()

	if encodeErr := png.Encode(f, img); encodeErr != nil {
		t.Fatalf("encode png: %v", encodeErr)
	}
	return path
}

// goldenCompare checks current against the golden file at goldenPath,
// creating the golden file on first run (or when UPDATE_GOLDEN=1 is set).
func goldenCompare(t *testing.T, goldenPath string, current []byte) {
	t.Helper()

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if mkdirErr := os.MkdirAll(filepath.Dir(goldenPath), 0o750); mkdirErr != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(goldenPath), mkdirErr)
		}
		if writeErr := os.WriteFile(goldenPath, current, 0o600); writeErr != nil {
			t.Fatalf("write golden %s: %v", goldenPath, writeErr)
		}
		t.Logf("golden file updated at %s", goldenPath)
		return
	}

	if _, statErr := os.Stat(goldenPath); os.IsNotExist(statErr) {
		if mkdirErr := os.MkdirAll(filepath.Dir(goldenPath), 0o750); mkdirErr != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(goldenPath), mkdirErr)
		}
		if writeErr := os.WriteFile(goldenPath, current, 0o600); writeErr != nil {
			t.Fatalf("write golden %s: %v", goldenPath, writeErr)
		}
		t.Logf("golden file created at %s (first run)", goldenPath)
		return
	}

	golden, readErr := os.ReadFile(goldenPath)
	if readErr != nil {
		t.Fatalf("read golden %s: %v", goldenPath, readErr)
	}

	if string(current) != string(golden) {
		t.Errorf("output for %s changed from golden.\nRun with UPDATE_GOLDEN=1 to accept the new output if intentional.", goldenPath)
	}
}
