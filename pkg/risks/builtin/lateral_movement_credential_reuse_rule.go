package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type LateralMovementCredentialReuseRule struct{}

func NewLateralMovementCredentialReuseRule() *LateralMovementCredentialReuseRule {
	return &LateralMovementCredentialReuseRule{}
}

func (*LateralMovementCredentialReuseRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "lateral-movement-credential-reuse",
		Title: "Lateral Movement via Credential Reuse Across Trust Boundaries",
		Description: "Technical assets that authenticate via the same credential type (credentials, tokens) to " +
			"targets in multiple distinct trust zones enable lateral movement: compromise of one credential " +
			"grants access across zone boundaries without additional authentication.",
		Impact: "Stolen credentials can be replayed to access assets in higher-trust zones, bypassing " +
			"the intended trust boundary controls.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
		Action:     "Credential Isolation per Trust Zone",
		Mitigation: "Use distinct credentials / service accounts per trust zone. Apply credential rotation and " +
			"short-lived tokens (OIDC/mTLS) so that credential reuse across zones is impossible by design.",
		Check:          "Are separate credentials used for assets in each trust zone?",
		Function:       types.Architecture,
		STRIDE:         types.LateralMovement,
		DetectionLogic: "Outgoing communication links that use credentials-based authentication and target assets in at least two different trust boundaries from the same source asset.",
		RiskAssessment: "High when the target trust zones differ significantly in sensitivity. Medium otherwise.",
	}
}

func (*LateralMovementCredentialReuseRule) SupportedTags() []string {
	return []string{}
}

func (r *LateralMovementCredentialReuseRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	var risks []*types.Risk

	for _, asset := range input.TechnicalAssets {
		if asset.OutOfScope {
			continue
		}

		// Collect trust boundaries of assets this asset connects to with credential-based auth
		credentialTargetBoundaries := map[string][]string{} // boundaryID → []targetAssetID
		for _, link := range asset.CommunicationLinks {
			auth := link.Authentication
			if auth != types.Credentials && auth != types.ClientCertificate {
				continue
			}
			target, ok := input.TechnicalAssets[link.TargetId]
			if !ok || target.OutOfScope {
				continue
			}
			bID := input.GetTechnicalAssetTrustBoundaryId(target)
			if bID == "" {
				continue
			}
			credentialTargetBoundaries[bID] = append(credentialTargetBoundaries[bID], target.Id)
		}

		if len(credentialTargetBoundaries) < 2 {
			continue
		}

		// Find highest-sensitivity target zone
		var highestSensTarget *types.TechnicalAsset
		for _, targetIDs := range credentialTargetBoundaries {
			for _, tid := range targetIDs {
				t := input.TechnicalAssets[tid]
				if highestSensTarget == nil || t.HighestSensitivityScore() > highestSensTarget.HighestSensitivityScore() {
					highestSensTarget = t
				}
			}
		}
		if highestSensTarget == nil {
			continue
		}

		impact := types.MediumImpact
		if highestSensTarget.Confidentiality >= types.StrictlyConfidential ||
			highestSensTarget.Integrity >= types.MissionCritical {
			impact = types.HighImpact
		}

		risk := &types.Risk{
			CategoryId:                   r.Category().ID,
			Severity:                     types.CalculateSeverity(types.Likely, impact),
			ExploitationLikelihood:       types.Likely,
			ExploitationImpact:           impact,
			Title:                        "<b>Lateral Movement via Credential Reuse</b> from <b>" + asset.Title + "</b> authenticating across " + itoa(len(credentialTargetBoundaries)) + " trust zones",
			MostRelevantTechnicalAssetId: asset.Id,
			DataBreachProbability:        types.Possible,
			DataBreachTechnicalAssetIDs:  []string{highestSensTarget.Id},
		}
		risk.SyntheticId = risk.CategoryId + "@" + asset.Id
		risks = append(risks, risk)
	}
	return risks, nil
}
