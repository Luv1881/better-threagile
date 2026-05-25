package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type LateralMovementSharedRuntimeRule struct{}

func NewLateralMovementSharedRuntimeRule() *LateralMovementSharedRuntimeRule {
	return &LateralMovementSharedRuntimeRule{}
}

func (*LateralMovementSharedRuntimeRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "lateral-movement-shared-runtime",
		Title: "Lateral Movement via Shared Runtime",
		Description: "Technical assets from different trust zones co-located on the same shared runtime (e.g. container " +
			"platform, VM host, shared Kubernetes namespace) create a lateral movement path: a compromised low-trust " +
			"asset on the runtime can escalate to high-trust neighbours without traversing a network boundary.",
		Impact: "An attacker who compromises any asset on the shared runtime may pivot to other " +
			"co-located assets, including those in higher trust zones.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
		Action:     "Runtime Isolation",
		Mitigation: "Separate assets from different trust zones onto dedicated runtimes (separate node pools, " +
			"dedicated VMs, distinct container namespaces with NetworkPolicy). Apply seccomp/AppArmor profiles " +
			"and disable privilege escalation.",
		Check:          "Are high-trust and low-trust assets co-located on the same shared runtime?",
		Function:       types.Architecture,
		STRIDE:         types.LateralMovement,
		DetectionLogic: "Shared runtimes that host technical assets belonging to at least two distinct trust boundaries are flagged.",
		RiskAssessment: "Severity depends on the sensitivity gap between the least and most sensitive co-located assets.",
	}
}

func (*LateralMovementSharedRuntimeRule) SupportedTags() []string {
	return []string{}
}

func (r *LateralMovementSharedRuntimeRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	var risks []*types.Risk

	for _, runtime := range input.SharedRuntimes {
		if len(runtime.TechnicalAssetsRunning) < 2 {
			continue
		}

		// Collect distinct trust boundary IDs for all assets on this runtime
		boundaryIDs := map[string]struct{}{}
		assets := map[string]*types.TechnicalAsset{}
		for _, assetID := range runtime.TechnicalAssetsRunning {
			asset, ok := input.TechnicalAssets[assetID]
			if !ok || asset.OutOfScope {
				continue
			}
			assets[assetID] = asset
			bID := input.GetTechnicalAssetTrustBoundaryId(asset)
			if bID != "" {
				boundaryIDs[bID] = struct{}{}
			}
		}

		if len(boundaryIDs) < 2 {
			continue
		}

		// Find the least and most sensitive asset to calibrate impact
		var minSens, maxSens float64
		var mostSensitiveAsset *types.TechnicalAsset
		for _, asset := range assets {
			s := asset.HighestSensitivityScore()
			if s < minSens || mostSensitiveAsset == nil {
				minSens = s
			}
			if s > maxSens || mostSensitiveAsset == nil {
				maxSens = s
				mostSensitiveAsset = asset
			}
		}
		if mostSensitiveAsset == nil {
			continue
		}

		impact := types.MediumImpact
		if maxSens >= 2*minSens+0.5 {
			impact = types.HighImpact
		}
		if mostSensitiveAsset.Confidentiality >= types.StrictlyConfidential ||
			mostSensitiveAsset.Integrity >= types.MissionCritical {
			impact = types.HighImpact
		}

		risk := &types.Risk{
			CategoryId:                   r.Category().ID,
			Severity:                     types.CalculateSeverity(types.Likely, impact),
			ExploitationLikelihood:       types.Likely,
			ExploitationImpact:           impact,
			Title:                        "<b>Lateral Movement via Shared Runtime</b> on <b>" + runtime.Title + "</b>: assets from " + itoa(len(boundaryIDs)) + " trust zones co-located",
			MostRelevantTechnicalAssetId: mostSensitiveAsset.Id,
			DataBreachProbability:        types.Possible,
			DataBreachTechnicalAssetIDs:  []string{mostSensitiveAsset.Id},
		}
		risk.SyntheticId = risk.CategoryId + "@" + runtime.Id
		risks = append(risks, risk)
	}
	return risks, nil
}

func itoa(n int) string {
	switch n {
	case 2:
		return "2"
	case 3:
		return "3"
	case 4:
		return "4"
	case 5:
		return "5"
	default:
		return "multiple"
	}
}
