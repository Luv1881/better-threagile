package model_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/threagile/threagile/internal/threagile"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/server"
	"github.com/threagile/threagile/pkg/types"
)

func benchConfig(tb testing.TB) *threagile.Config {
	cfg := new(threagile.Config).Defaults("bench")
	cfg.SetOutputFolder(tb.TempDir())
	cfg.SetTempFolder(tb.TempDir())
	return cfg
}

// BenchmarkAnalyzeModel_200Assets runs the full parse + risk-generation
// pipeline (default STRIDE methodology, all built-in rules) on a synthetic
// 200-asset model.
func BenchmarkAnalyzeModel_200Assets(b *testing.B) {
	modelInput := model.BuildSyntheticModelInput(200)
	cfg := benchConfig(b)
	rules := risks.GetBuiltInRiskRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := model.AnalyzeModel(modelInput, cfg, rules, make(types.RiskRules), server.DefaultProgressReporter{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAnalyzeModel_AllMethodologies runs risk generation for each of the
// 7 built-in methodologies plus the ai-ml and supply-chain rule packs, on the
// same synthetic 200-asset model.
func BenchmarkAnalyzeModel_AllMethodologies(b *testing.B) {
	modelInput := model.BuildSyntheticModelInput(200)
	builtin := risks.GetBuiltInRiskRules()

	for _, methodology := range []string{"stride", "linddun", "pasta", "vast", "octave", "trike", "cloud-native"} {
		b.Run(methodology, func(b *testing.B) {
			cfg := benchConfig(b)
			cfg.SetMethodology(methodology)
			for i := 0; i < b.N; i++ {
				_, err := model.AnalyzeModel(modelInput, cfg, builtin, make(types.RiskRules), server.DefaultProgressReporter{})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	for _, pack := range []string{"ai-ml", "supply-chain"} {
		b.Run(pack, func(b *testing.B) {
			packRules, err := risks.LoadRulePack(pack)
			if err != nil {
				b.Fatal(err)
			}
			merged := builtin.Merge(packRules)
			cfg := benchConfig(b)
			for i := 0; i < b.N; i++ {
				_, err := model.AnalyzeModel(modelInput, cfg, merged, make(types.RiskRules), server.DefaultProgressReporter{})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestAnalyzeModel_SyntheticLargeModel_Race exercises the parallel rule
// runner (pkg/model/read.go applyRiskGeneration) on a 200-asset model with
// all built-in rules, intended to be run with -race.
func TestAnalyzeModel_SyntheticLargeModel_Race(t *testing.T) {
	modelInput := model.BuildSyntheticModelInput(200)
	cfg := benchConfig(t)

	result, err := model.AnalyzeModel(modelInput, cfg, risks.GetBuiltInRiskRules(), make(types.RiskRules), server.DefaultProgressReporter{})
	require.NoError(t, err)
	require.NotEmpty(t, result.ParsedModel.GeneratedRisksByCategory)
}
