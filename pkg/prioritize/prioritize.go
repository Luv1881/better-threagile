// Package prioritize answers the question a developer actually asks — "of all
// these findings, which few should I fix first, and how?" — by ranking the
// still-at-risk findings on a composite exploitability score and attaching the
// remediation guidance the rule already carries.
//
// The score is additive over normalized [0,1] factors (so a single zero factor
// can't collapse it), and the reachability factor uses the real attack-path
// graph rather than self-declared metadata, so it is hard to game. Deterministic,
// no AI.
package prioritize

import (
	"sort"

	"github.com/threagile/threagile/pkg/attackpath"
	"github.com/threagile/threagile/pkg/types"
)

// factor weights (sum to 1.0). KEV/EPSS would add weight when an SBOM is
// correlated; that is a separate input, so the model-only score renormalizes
// over what it can compute here.
const (
	wSeverity     = 0.35
	wExposure     = 0.20
	wReachability = 0.20
	wDataSens     = 0.15
	wConfidence   = 0.10
)

// Factor is one named contribution to an item's score.
type Factor struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`  // normalized 0–1
	Weight float64 `json:"weight"` // contribution weight
}

// Remediation is the fix guidance carried by the finding's risk category.
type Remediation struct {
	Action     string `json:"action,omitempty"`
	Mitigation string `json:"mitigation,omitempty"`
	CheatSheet string `json:"cheat_sheet,omitempty"`
	CWE        int    `json:"cwe,omitempty"`
}

// Item is one ranked finding.
type Item struct {
	SyntheticID string      `json:"synthetic_id"`
	Title       string      `json:"title"`
	Severity    string      `json:"severity"`
	Status      string      `json:"status"`
	AssetID     string      `json:"asset_id,omitempty"`
	AssetTitle  string      `json:"asset_title,omitempty"`
	SourceFile  string      `json:"source_file,omitempty"` // model file the asset is defined in (via includes:)
	SourceLine  int         `json:"source_line,omitempty"` // line of the asset definition
	Score       int         `json:"score"`                 // 0–100
	Factors     []Factor    `json:"factors"`
	Remediation Remediation `json:"remediation"`
}

// Result is the ranked list, highest exploitability first.
type Result struct {
	Items       []Item `json:"items"`
	TotalAtRisk int    `json:"total_at_risk"`
}

// Analyze ranks the model's still-at-risk findings.
func Analyze(model *types.Model) *Result {
	reachable := reachableAssets(model)

	result := &Result{}
	for _, risk := range model.AllRisks() {
		if !risk.RiskStatus.IsStillAtRisk() {
			continue
		}
		result.TotalAtRisk++

		assetID := risk.MostRelevantTechnicalAssetId
		asset := model.TechnicalAssets[assetID]

		sev := (float64(risk.Severity) + 1) / 5 // Low..Critical -> 0.2..1.0
		exposure := 0.0
		dataSens := 0.0
		assetTitle := ""
		if asset != nil {
			assetTitle = asset.Title
			if asset.Internet {
				exposure = 1.0
			}
			dataSens = assetDataSensitivity(model, asset)
		}
		reach := 0.0
		if reachable[assetID] {
			reach = 1.0
		}
		conf := risk.Confidence
		if conf <= 0 {
			conf = 1.0 // unset confidence -> assume a true positive
		}

		factors := []Factor{
			{"severity", sev, wSeverity},
			{"internet-exposure", exposure, wExposure},
			{"attack-path-reachable", reach, wReachability},
			{"data-sensitivity", dataSens, wDataSens},
			{"confidence", conf, wConfidence},
		}
		score := 0.0
		for _, f := range factors {
			score += f.Value * f.Weight
		}

		result.Items = append(result.Items, Item{
			SyntheticID: risk.SyntheticId,
			Title:       risk.Title,
			Severity:    risk.Severity.String(),
			Status:      risk.RiskStatus.String(),
			AssetID:     assetID,
			AssetTitle:  assetTitle,
			Score:       int(score*100 + 0.5),
			Factors:     factors,
			Remediation: remediationFor(model, risk.CategoryId),
		})
	}

	sort.SliceStable(result.Items, func(i, j int) bool {
		if result.Items[i].Score != result.Items[j].Score {
			return result.Items[i].Score > result.Items[j].Score
		}
		return result.Items[i].SyntheticID < result.Items[j].SyntheticID
	})
	return result
}

// reachableAssets returns the set of technical-asset IDs that lie on any attack
// path from an internet-facing asset to crown-jewel data.
func reachableAssets(model *types.Model) map[string]bool {
	set := map[string]bool{}
	res := attackpath.Analyze(model, attackpath.Options{})
	for _, p := range res.Paths {
		for _, a := range p.Assets {
			set[a] = true
		}
	}
	return set
}

func assetDataSensitivity(model *types.Model, asset *types.TechnicalAsset) float64 {
	highest := types.Public
	consider := func(ids []string) {
		for _, id := range ids {
			if da := model.DataAssets[id]; da != nil && da.Confidentiality > highest {
				highest = da.Confidentiality
			}
		}
	}
	consider(asset.DataAssetsProcessed)
	consider(asset.DataAssetsStored)
	return float64(highest) / float64(types.StrictlyConfidential)
}

func remediationFor(model *types.Model, categoryID string) Remediation {
	return RemediationFromCategory(model.GetRiskCategory(categoryID))
}

// RemediationFromCategory extracts the fix guidance from a risk category (nil
// yields an empty Remediation). Shared with the diff PR-comment renderer.
func RemediationFromCategory(cat *types.RiskCategory) Remediation {
	if cat == nil {
		return Remediation{}
	}
	return Remediation{
		Action:     cat.Action,
		Mitigation: cat.Mitigation,
		CheatSheet: cat.CheatSheet,
		CWE:        cat.CWE,
	}
}

// FixLine is the public one-line "how to fix" rendering of a Remediation.
func FixLine(r Remediation) string { return fixLine(r) }

// Top returns at most n items (n <= 0 means all).
func (r *Result) Top(n int) []Item {
	if n <= 0 || n >= len(r.Items) {
		return r.Items
	}
	return r.Items[:n]
}
