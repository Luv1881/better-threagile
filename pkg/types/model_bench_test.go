package types

import (
	"fmt"
	"testing"
)

// buildBenchModel creates a model with nCategories risk categories, each having
// nRisksPerCat risks. Half of each category's risks are still-at-risk.
// nTracked risks have tracking entries so GeneratedRisksByCategoryWithCurrentStatus
// must merge them.
const (
	benchCategories  = 50
	benchRisksPerCat = 20
)

func buildBenchModel(nTracked int) *Model {
	nCategories := benchCategories
	nRisksPerCat := benchRisksPerCat
	m := &Model{
		GeneratedRisksByCategory: make(map[string][]*Risk, nCategories),
		RiskTracking:             make(map[string]*RiskTracking, nTracked),
		BuiltInRiskCategories:    make(RiskCategories, 0, nCategories),
		TechnicalAssets:          make(map[string]*TechnicalAsset),
		DataAssets:               make(map[string]*DataAsset),
	}

	tracked := 0
	for c := 0; c < nCategories; c++ {
		catID := fmt.Sprintf("cat-%d", c)
		cat := &RiskCategory{ID: catID, Title: fmt.Sprintf("Category %d", c)}
		m.BuiltInRiskCategories = append(m.BuiltInRiskCategories, cat)

		risks := make([]*Risk, 0, nRisksPerCat)
		for r := 0; r < nRisksPerCat; r++ {
			synID := fmt.Sprintf("%s@asset-%d", catID, r)
			sev := RiskSeverity((r % 4) + 1) // Low..Critical cycling
			risk := &Risk{
				SyntheticId:            synID,
				CategoryId:             catID,
				Severity:               sev,
				ExploitationImpact:     MediumImpact,
				ExploitationLikelihood: Likely,
				Title:                  synID,
			}
			risks = append(risks, risk)
			if tracked < nTracked {
				m.RiskTracking[synID] = &RiskTracking{Status: Mitigated}
				tracked++
			}
		}
		m.GeneratedRisksByCategory[catID] = risks
	}
	return m
}

func BenchmarkSortedRiskCategories(b *testing.B) {
	m := buildBenchModel(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.SortedRiskCategories()
	}
}

func BenchmarkGeneratedRisksByCategoryWithCurrentStatus_FirstCall(b *testing.B) {
	for i := 0; i < b.N; i++ {
		m := buildBenchModel(100)
		b.StartTimer()
		_ = m.GeneratedRisksByCategoryWithCurrentStatus()
		b.StopTimer()
	}
}

func BenchmarkGeneratedRisksByCategoryWithCurrentStatus_SubsequentCalls(b *testing.B) {
	m := buildBenchModel(100)
	// warm up — first call applies tracking
	_ = m.GeneratedRisksByCategoryWithCurrentStatus()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.GeneratedRisksByCategoryWithCurrentStatus()
	}
}

func BenchmarkSortedRisksOfCategory(b *testing.B) {
	m := buildBenchModel(0)
	cats := m.SortedRiskCategories()
	cat := cats[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.SortedRisksOfCategory(cat)
	}
}

func BenchmarkIdentifiedDataBreachProbability(b *testing.B) {
	m := buildBenchModel(0)
	da := &DataAsset{Id: "da-0"}
	m.DataAssets["da-0"] = da
	// Wire a few risks to reference the data asset so the function has work to do
	for catID, risks := range m.GeneratedRisksByCategory {
		for i := range risks {
			if i%5 == 0 {
				assetID := fmt.Sprintf("ta-%s-%d", catID, i)
				m.TechnicalAssets[assetID] = &TechnicalAsset{
					Id:                   assetID,
					DataAssetsProcessed:  []string{"da-0"},
				}
				m.GeneratedRisksByCategory[catID][i].DataBreachTechnicalAssetIDs = []string{assetID}
				m.GeneratedRisksByCategory[catID][i].DataBreachProbability = Probable
			}
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.IdentifiedDataBreachProbability(da)
	}
}

func BenchmarkAllRisks(b *testing.B) {
	m := buildBenchModel(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.AllRisks()
	}
}
