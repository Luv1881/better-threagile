package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type LateralMovementTransitiveAccessRule struct{}

func NewLateralMovementTransitiveAccessRule() *LateralMovementTransitiveAccessRule {
	return &LateralMovementTransitiveAccessRule{}
}

func (*LateralMovementTransitiveAccessRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "lateral-movement-transitive-access",
		Title: "Lateral Movement via Transitive Data Flow Across Trust Boundaries",
		Description: "An asset in a low-trust zone communicates to a bridging asset, which in turn " +
			"communicates to an asset in a high-trust zone. The bridging asset creates a transitive " +
			"path that can be abused for lateral movement without the attacker ever directly connecting " +
			"to the high-trust target.",
		Impact: "An attacker who compromises the bridging asset or injects malicious data into the " +
			"first hop can influence or extract data from the high-trust target.",
		ASVS:       "V1 - Architecture, Design and Threat Modelling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html",
		Action:     "Eliminate Unnecessary Bridging",
		Mitigation: "Remove unnecessary transitive paths. Introduce a DMZ or API gateway for unavoidable " +
			"bridging. Apply strict input validation and output encoding in the bridging component. " +
			"Log and alert on data flowing from low-trust sources that reaches high-trust destinations.",
		Check:          "Does any asset bridge traffic from low-trust to high-trust zones without validation or separation?",
		Function:       types.Architecture,
		STRIDE:         types.LateralMovement,
		DetectionLogic: "Assets that receive communication from a low-trust zone AND send communication to a high-trust zone (the bridging pattern), where the high-trust target is more sensitive than the low-trust source.",
		RiskAssessment: "High when the destination zone contains strictly-confidential or mission-critical assets.",
	}
}

func (*LateralMovementTransitiveAccessRule) SupportedTags() []string {
	return []string{}
}

func (r *LateralMovementTransitiveAccessRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	var risks []*types.Risk

	for _, bridge := range input.TechnicalAssets {
		if bridge.OutOfScope {
			continue
		}

		bridgeBoundary := input.GetTechnicalAssetTrustBoundaryId(bridge)

		// Low-trust sources that feed this bridge
		var lowTrustSources []*types.TechnicalAsset
		incomingLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[bridge.Id]
		for _, link := range incomingLinks {
			src, ok := input.TechnicalAssets[link.SourceId]
			if !ok || src.OutOfScope {
				continue
			}
			srcBoundary := input.GetTechnicalAssetTrustBoundaryId(src)
			if srcBoundary != bridgeBoundary {
				lowTrustSources = append(lowTrustSources, src)
			}
		}
		if len(lowTrustSources) == 0 {
			continue
		}

		// High-trust targets this bridge feeds
		for _, link := range bridge.CommunicationLinks {
			target, ok := input.TechnicalAssets[link.TargetId]
			if !ok || target.OutOfScope {
				continue
			}
			targetBoundary := input.GetTechnicalAssetTrustBoundaryId(target)
			if targetBoundary == bridgeBoundary {
				continue
			}
			// Only flag when target is more sensitive than bridge
			if target.HighestSensitivityScore() <= bridge.HighestSensitivityScore() {
				continue
			}

			impact := types.MediumImpact
			if target.Confidentiality >= types.StrictlyConfidential ||
				target.Integrity >= types.MissionCritical {
				impact = types.HighImpact
			}

			synID := r.Category().ID + "@" + bridge.Id + "@" + target.Id
			// deduplicate
			alreadyAdded := false
			for _, existing := range risks {
				if existing.SyntheticId == synID {
					alreadyAdded = true
					break
				}
			}
			if alreadyAdded {
				continue
			}

			risk := &types.Risk{
				CategoryId:                   r.Category().ID,
				Severity:                     types.CalculateSeverity(types.Unlikely, impact),
				ExploitationLikelihood:       types.Unlikely,
				ExploitationImpact:           impact,
				Title:                        "<b>Transitive Lateral Movement</b> via bridge <b>" + bridge.Title + "</b> → high-trust target <b>" + target.Title + "</b>",
				MostRelevantTechnicalAssetId: bridge.Id,
				DataBreachProbability:        types.Improbable,
				DataBreachTechnicalAssetIDs:  []string{target.Id},
			}
			risk.SyntheticId = synID
			risks = append(risks, risk)
		}
	}
	return risks, nil
}
