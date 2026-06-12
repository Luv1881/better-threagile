package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

func inputModelWithTracking(tracking map[string]input.RiskTracking) *input.Model {
	m := createInputModel(make(map[string]input.TechnicalAsset), make(map[string]input.DataAsset))
	m.RiskTracking = tracking
	return m
}

func TestParseRiskTracking_AcceptedUntil(t *testing.T) {
	parsedModel, err := ParseModel(&mockConfig{}, inputModelWithTracking(map[string]input.RiskTracking{
		"some-risk@asset": {
			Status:        "accepted",
			Justification: "compensating control in place",
			AcceptedUntil: "2027-03-31",
			AcceptedBy:    "ciso@example.com",
		},
	}), make(types.RiskRules), make(types.RiskRules))

	require.NoError(t, err)
	tracking := parsedModel.RiskTracking["some-risk@asset"]
	require.NotNil(t, tracking)
	assert.Equal(t, types.Accepted, tracking.Status)
	require.NotNil(t, tracking.AcceptedUntil)
	assert.Equal(t, "2027-03-31", tracking.AcceptedUntil.Format("2006-01-02"))
	assert.Equal(t, "ciso@example.com", tracking.AcceptedBy)
}

func TestParseRiskTracking_AcceptedUntilInvalidDate(t *testing.T) {
	_, err := ParseModel(&mockConfig{}, inputModelWithTracking(map[string]input.RiskTracking{
		"some-risk@asset": {Status: "accepted", AcceptedUntil: "not-a-date"},
	}), make(types.RiskRules), make(types.RiskRules))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepted_until")
}

func TestParseRiskTracking_AcceptedUntilWrongStatus(t *testing.T) {
	_, err := ParseModel(&mockConfig{}, inputModelWithTracking(map[string]input.RiskTracking{
		"some-risk@asset": {Status: "mitigated", AcceptedUntil: "2027-03-31"},
	}), make(types.RiskRules), make(types.RiskRules))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "only valid with status 'accepted'")
}

func TestParseRiskTracking_NoExpiryStillWorks(t *testing.T) {
	parsedModel, err := ParseModel(&mockConfig{}, inputModelWithTracking(map[string]input.RiskTracking{
		"some-risk@asset": {Status: "accepted", Justification: "ok"},
	}), make(types.RiskRules), make(types.RiskRules))

	require.NoError(t, err)
	tracking := parsedModel.RiskTracking["some-risk@asset"]
	require.NotNil(t, tracking)
	assert.Nil(t, tracking.AcceptedUntil)
}
