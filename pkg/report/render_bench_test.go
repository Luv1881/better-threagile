package report_test

import (
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/internal/threagile"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/server"
	"github.com/threagile/threagile/pkg/types"
)

// loadSyntheticBenchModel runs the full analyze pipeline on a synthetic
// 200-asset model, for use by report-rendering benchmarks.
func loadSyntheticBenchModel(b *testing.B) (*types.Model, *threagile.Config) {
	b.Helper()

	modelInput := model.BuildSyntheticModelInput(200)
	cfg := new(threagile.Config).Defaults("bench")
	cfg.SetOutputFolder(b.TempDir())
	cfg.SetTempFolder(b.TempDir())

	result, err := model.AnalyzeModel(modelInput, cfg, risks.GetBuiltInRiskRules(), make(types.RiskRules), server.DefaultProgressReporter{})
	if err != nil {
		b.Fatal(err)
	}

	return result.ParsedModel, cfg
}

func BenchmarkMarkdownReport_200Assets(b *testing.B) {
	parsedModel, _ := loadSyntheticBenchModel(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = report.MarkdownReport(parsedModel)
	}
}

func BenchmarkRisksExcelReport_200Assets(b *testing.B) {
	parsedModel, cfg := loadSyntheticBenchModel(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filename := filepath.Join(b.TempDir(), "risks.xlsx")
		if err := report.WriteRisksExcelToFile(parsedModel, filename, cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTagsExcelReport_200Assets(b *testing.B) {
	parsedModel, cfg := loadSyntheticBenchModel(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filename := filepath.Join(b.TempDir(), "tags.xlsx")
		if err := report.WriteTagsExcelToFile(parsedModel, filename, cfg); err != nil {
			b.Fatal(err)
		}
	}
}
