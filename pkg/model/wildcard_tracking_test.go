package model_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/server"
	"github.com/threagile/threagile/pkg/types"
)

// Regression test: wildcard risk-tracking entries (rule-id@*) must be applied
// to the generated risks' status. This used to silently fail because the
// synthetic-ID map building in applyRiskGeneration triggered the one-shot
// status-application cache (statusApplied) BEFORE the wildcard tracking
// entries were expanded into model.RiskTracking.
func TestWildcardRiskTracking_StatusReachesRisks(t *testing.T) {
	modelInput := model.BuildSyntheticModelInput(5)

	cfg := benchConfig(t)
	result, err := model.AnalyzeModel(modelInput, cfg, risks.GetBuiltInRiskRules(), make(types.RiskRules), server.DefaultProgressReporter{})
	require.NoError(t, err)
	require.NotEmpty(t, result.ParsedModel.GeneratedRisksByCategory)

	// Pick whichever category fired and build a wildcard pattern for it.
	var categoryID string
	for id, generated := range result.ParsedModel.GeneratedRisksByCategory {
		if len(generated) > 0 {
			categoryID = id
			break
		}
	}
	require.NotEmpty(t, categoryID)

	modelInput.RiskTracking = map[string]input.RiskTracking{
		categoryID + "@*": {
			Status:        "accepted",
			Justification: "wildcard acceptance for regression test",
			Date:          "2026-06-12",
		},
	}

	result, err = model.AnalyzeModel(modelInput, cfg, risks.GetBuiltInRiskRules(), make(types.RiskRules), server.DefaultProgressReporter{})
	require.NoError(t, err)

	withStatus := result.ParsedModel.GeneratedRisksByCategoryWithCurrentStatus()
	require.NotEmpty(t, withStatus[categoryID])
	for _, risk := range withStatus[categoryID] {
		require.Equal(t, types.Accepted, risk.RiskStatus,
			"wildcard tracking entry %s@* must set the risk status of %s", categoryID, risk.SyntheticId)
	}
}
