// Package requirements turns a threat model into actionable, testable security
// requirements: one deduplicated requirement per still-at-risk finding category,
// derived from the rule's own remediation (action), verification (check), CWE and
// the affected assets. The output is a security backlog / acceptance-criteria
// checklist (or Gherkin test stubs) a team can drop into their tracker, so
// threats become work items instead of a report nobody reads. Deterministic, no AI.
package requirements

import (
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

// Requirement is one testable security requirement covering a finding category.
type Requirement struct {
	CategoryID     string   `json:"category_id"`
	Title          string   `json:"title"`
	Statement      string   `json:"statement"`              // "the system must ..."
	Verification   string   `json:"verification,omitempty"` // how to check it's satisfied
	CWE            int      `json:"cwe,omitempty"`
	Severity       string   `json:"severity"` // highest severity among the covered findings
	FindingCount   int      `json:"finding_count"`
	AffectedAssets []string `json:"affected_assets,omitempty"`
}

// Build returns the security requirements for the model's still-at-risk findings,
// sorted highest-severity first then by category for stable output.
func Build(model *types.Model) []Requirement {
	type acc struct {
		highest types.RiskSeverity
		count   int
		assets  map[string]bool
	}
	byCat := map[string]*acc{}

	for _, risk := range model.AllRisks() {
		if !risk.RiskStatus.IsStillAtRisk() {
			continue
		}
		a := byCat[risk.CategoryId]
		if a == nil {
			a = &acc{assets: map[string]bool{}}
			byCat[risk.CategoryId] = a
		}
		a.count++
		if risk.Severity > a.highest {
			a.highest = risk.Severity
		}
		if id := risk.MostRelevantTechnicalAssetId; id != "" {
			if ta := model.TechnicalAssets[id]; ta != nil {
				a.assets[ta.Title] = true
			} else {
				a.assets[id] = true
			}
		}
	}

	out := make([]Requirement, 0, len(byCat))
	for catID, a := range byCat {
		cat := model.GetRiskCategory(catID)
		title, statement, verification, cwe := catID, "", "", 0
		if cat != nil {
			title = cat.Title
			statement = requirementStatement(cat)
			verification = cat.Check
			cwe = cat.CWE
		}
		out = append(out, Requirement{
			CategoryID:     catID,
			Title:          title,
			Statement:      statement,
			Verification:   verification,
			CWE:            cwe,
			Severity:       a.highest.String(),
			FindingCount:   a.count,
			AffectedAssets: sortedKeys(a.assets),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		si, _ := types.ParseRiskSeverity(out[i].Severity)
		sj, _ := types.ParseRiskSeverity(out[j].Severity)
		if si != sj {
			return si > sj
		}
		return out[i].CategoryID < out[j].CategoryID
	})
	return out
}

// requirementStatement phrases the category's remediation as a "must" statement.
func requirementStatement(cat *types.RiskCategory) string {
	if cat.Action != "" {
		return cat.Action
	}
	return cat.Mitigation
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
