package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type LateralMovementServiceAccountScopeCreepRule struct{}

func NewLateralMovementServiceAccountScopeCreepRule() *LateralMovementServiceAccountScopeCreepRule {
	return &LateralMovementServiceAccountScopeCreepRule{}
}

func (*LateralMovementServiceAccountScopeCreepRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "lateral-movement-service-account-scope-creep",
		Title: "Lateral Movement via Service Account Scope Creep",
		Description: "A vault, identity provider, or service-account issuer that serves assets in multiple " +
			"distinct trust zones creates a high-value pivot: compromising the identity provider grants " +
			"credentials that are valid across all served trust zones.",
		Impact: "Compromise of the identity provider or vault allows an attacker to impersonate any " +
			"service account, achieving lateral movement to every trust zone the vault serves.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
		Action:     "Vault / Identity Provider Scoping",
		Mitigation: "Use separate vault namespaces or separate identity providers per trust zone. " +
			"Apply least-privilege roles: a vault in zone A should not issue credentials valid for zone B. " +
			"Enable audit logging on the identity provider to detect cross-zone credential usage.",
		Check:          "Does the vault/identity provider only issue credentials scoped to a single trust zone?",
		Function:       types.Architecture,
		STRIDE:         types.LateralMovement,
		DetectionLogic: "Identity-provider or vault assets that have outgoing communication links to assets in at least two different trust boundaries.",
		RiskAssessment: "High when any served trust zone contains sensitive or mission-critical assets.",
	}
}

func (*LateralMovementServiceAccountScopeCreepRule) SupportedTags() []string {
	return []string{}
}

func (r *LateralMovementServiceAccountScopeCreepRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	var risks []*types.Risk

	for _, asset := range input.TechnicalAssets {
		if asset.OutOfScope {
			continue
		}

		// Only flag identity providers and vaults
		isIDP := asset.Technologies.GetAttribute(types.IdentityProvider) ||
			asset.Technologies.GetAttribute(types.IdentityStoreDatabase) ||
			asset.Technologies.GetAttribute(types.IdentityStoreLDAP) ||
			asset.Technologies.GetAttribute("vault")
		if !isIDP {
			continue
		}

		servedBoundaries := map[string]struct{}{}
		var highestSensTarget *types.TechnicalAsset
		for _, link := range asset.CommunicationLinks {
			target, ok := input.TechnicalAssets[link.TargetId]
			if !ok || target.OutOfScope {
				continue
			}
			bID := input.GetTechnicalAssetTrustBoundaryId(target)
			if bID != "" {
				servedBoundaries[bID] = struct{}{}
			}
			if highestSensTarget == nil ||
				target.HighestSensitivityScore() > highestSensTarget.HighestSensitivityScore() {
				highestSensTarget = target
			}
		}

		if len(servedBoundaries) < 2 {
			continue
		}

		impact := types.HighImpact
		if highestSensTarget != nil &&
			highestSensTarget.Confidentiality >= types.StrictlyConfidential {
			impact = types.HighImpact
		}

		risk := &types.Risk{
			CategoryId:                   r.Category().ID,
			Severity:                     types.CalculateSeverity(types.Likely, impact),
			ExploitationLikelihood:       types.Likely,
			ExploitationImpact:           impact,
			Title:                        "<b>Service Account Scope Creep</b> via <b>" + asset.Title + "</b> serving " + itoa(len(servedBoundaries)) + " trust zones",
			MostRelevantTechnicalAssetId: asset.Id,
			DataBreachProbability:        types.Probable,
			DataBreachTechnicalAssetIDs:  []string{asset.Id},
		}
		if highestSensTarget != nil {
			risk.DataBreachTechnicalAssetIDs = append(risk.DataBreachTechnicalAssetIDs, highestSensTarget.Id)
		}
		risk.SyntheticId = risk.CategoryId + "@" + asset.Id
		risks = append(risks, risk)
	}
	return risks, nil
}
