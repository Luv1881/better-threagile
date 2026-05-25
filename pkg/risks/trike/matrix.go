// Package trike provides a Trike methodology matrix engine for better-threagile.
// Trike models risk as a (subject × action × object) matrix where each cell has
// an "acceptable risk" decision from the organisation's perspective.
// An unacceptable or undeclared cell synthesises a finding.
package trike

import (
	"fmt"

	"github.com/threagile/threagile/pkg/types"
)

// MatrixEngine evaluates a Trike action matrix against the model and generates findings.
type MatrixEngine struct{}

// NewMatrixEngine creates a new Trike matrix engine instance.
func NewMatrixEngine() *MatrixEngine { return &MatrixEngine{} }

// GenerateRisks creates Trike risk findings from the model's TrikeActors and TrikeMatrix.
// It returns risks for:
//  1. Matrix cells where AcceptableRisk is false (explicitly rejected access pattern)
//  2. Actor × high-value-asset × action combinations that are not in the matrix at all
func (e *MatrixEngine) GenerateRisks(model *types.Model) ([]*types.Risk, error) {
	if len(model.TrikeActors) == 0 {
		return nil, nil
	}

	// Index declared matrix cells for fast lookup
	type cellKey struct {
		actorID string
		assetID string
		action  types.TrikeAction
	}
	declared := make(map[cellKey]*types.TrikeMatrixCell, len(model.TrikeMatrix))
	for _, cell := range model.TrikeMatrix {
		k := cellKey{cell.ActorId, cell.AssetId, cell.Action}
		declared[k] = cell
	}

	var risks []*types.Risk

	for _, actor := range model.TrikeActors {
		for _, asset := range model.TechnicalAssets {
			if asset.OutOfScope {
				continue
			}

			// Only analyse high-value targets (datastores or high-sensitivity assets)
			isHighValue := asset.Type == types.Datastore ||
				asset.Confidentiality >= types.Confidential ||
				asset.Integrity >= types.Critical

			if !isHighValue {
				continue
			}

			for _, action := range types.TrikeActions() {
				k := cellKey{actor.Id, asset.Id, action}
				cell, exists := declared[k]

				if !exists {
					// Undeclared cell for a high-value asset — flag as gap
					r := makeRisk(
						"trike-undeclared-access@"+actor.Id+"@"+asset.Id+"@"+string(action),
						fmt.Sprintf("<b>Undeclared Trike Access</b>: actor <b>%s</b> %s on <b>%s</b> — not in action matrix",
							actor.Title, action, asset.Title),
						actor, asset, types.MediumImpact,
					)
					risks = append(risks, r)
					continue
				}

				if !cell.AcceptableRisk {
					// Explicitly rejected access pattern
					r := makeRisk(
						"trike-unacceptable-access@"+actor.Id+"@"+asset.Id+"@"+string(action),
						fmt.Sprintf("<b>Unacceptable Trike Access</b>: actor <b>%s</b> %s on <b>%s</b> is explicitly disallowed (justification: %s)",
							actor.Title, action, asset.Title, cell.Justification),
						actor, asset, types.HighImpact,
					)
					risks = append(risks, r)
				}
			}
		}
	}

	return risks, nil
}

func makeRisk(synID, title string, actor *types.TrikeActor, asset *types.TechnicalAsset, impact types.RiskExploitationImpact) *types.Risk {
	likelihood := types.Unlikely
	if actor.TrustScore() == 0 {
		likelihood = types.Likely
	}

	r := &types.Risk{
		CategoryId:                   "trike-matrix",
		SyntheticId:                  synID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: asset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{asset.Id},
	}
	return r
}
