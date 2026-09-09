package types

import (
	"cmp"
	"slices"
)

func ReduceToOnlyStillAtRisk(risks []*Risk) []*Risk {
	filteredRisks := make([]*Risk, 0, len(risks))
	for _, risk := range risks {
		if risk.RiskStatus.IsStillAtRisk() {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func HighestSeverityStillAtRisk(risks []*Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result && risk.RiskStatus.IsStillAtRisk() {
			result = risk.Severity
		}
	}
	return result
}

func SortByRiskSeverity(risks []*Risk) {
	slices.SortFunc(risks, func(a, b *Risk) int {
		if n := cmp.Compare(b.Severity, a.Severity); n != 0 {
			return n
		}
		if n := cmp.Compare(a.RiskStatus, b.RiskStatus); n != 0 {
			return n
		}
		if n := cmp.Compare(b.ExploitationImpact, a.ExploitationImpact); n != 0 {
			return n
		}
		if n := cmp.Compare(b.ExploitationLikelihood, a.ExploitationLikelihood); n != 0 {
			return n
		}
		return cmp.Compare(a.Title, b.Title)
	})
}

type ByRiskCategoryTitleSort []*RiskCategory

func (what ByRiskCategoryTitleSort) Len() int { return len(what) }
func (what ByRiskCategoryTitleSort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}
func (what ByRiskCategoryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
