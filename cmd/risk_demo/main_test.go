package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/threagile/threagile/pkg/types"
)

func TestCustomRiskRule_Category(t *testing.T) {
	rule := new(customRiskRule)
	category := rule.Category()

	assert.Equal(t, "demo", category.ID)
	assert.Equal(t, types.Development, category.Function)
	assert.Equal(t, types.Tampering, category.STRIDE)
}

func TestCustomRiskRule_SupportedTags(t *testing.T) {
	rule := new(customRiskRule)
	assert.Equal(t, []string{"demo tag"}, rule.SupportedTags())
}

func TestCustomRiskRule_GenerateRisks(t *testing.T) {
	parsedModel := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"asset-1": {Id: "asset-1", Title: "Asset One"},
			"asset-2": {Id: "asset-2", Title: "Asset Two"},
		},
	}

	rule := new(customRiskRule)
	risks, err := rule.GenerateRisks(parsedModel)
	require.NoError(t, err)
	require.Len(t, risks, 2)

	for _, risk := range risks {
		assert.Equal(t, "demo", risk.CategoryId)
		assert.Contains(t, risk.Title, "Demo")
		assert.NotEmpty(t, risk.MostRelevantTechnicalAssetId)
		assert.Equal(t, risk.CategoryId+"@"+risk.MostRelevantTechnicalAssetId, risk.SyntheticId)
	}
}

func TestCreateRisk(t *testing.T) {
	asset := &types.TechnicalAsset{Id: "asset-1", Title: "Asset One"}
	risk := createRisk(asset)

	assert.Equal(t, "demo@asset-1", risk.SyntheticId)
	assert.Equal(t, []string{"asset-1"}, risk.DataBreachTechnicalAssetIDs)
	assert.Contains(t, risk.Title, "Asset One")
}
