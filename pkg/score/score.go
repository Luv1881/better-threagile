// Package score computes a deterministic, no-AI "threat-model health" score:
// a single 0–100 number (plus an A–F grade) that a team can track every sprint,
// gate on, and surface as a badge.
//
// It blends two things that matter to the two adoption goals:
//
//   - Completeness — is the model well-formed enough to trust its findings?
//     (owners assigned, assets inside trust boundaries, links have protocols,
//     data assets actually used, basic metadata present)
//   - Posture — how much of the identified risk has actually been dealt with?
//     (still-at-risk findings weighted by severity, credited by tracking status)
//
// Both are pure functions of the analyzed model, so the score is reproducible
// and diffable in CI.
package score

import (
	"fmt"
	"math"

	"github.com/threagile/threagile/pkg/types"
)

// statusCredit is how much "handled" credit each tracking status earns, from
// fully resolved (1.0) to completely un-triaged (0.0).
var statusCredit = map[types.RiskStatus]float64{
	types.Mitigated:     1.0,
	types.FalsePositive: 1.0,
	types.Accepted:      0.7,
	types.InProgress:    0.5,
	types.InDiscussion:  0.3,
	types.Unchecked:     0.0,
}

// severityWeight makes a Critical count for much more than a Low when measuring
// posture, so resolving the scary findings moves the needle most.
var severityWeight = map[types.RiskSeverity]float64{
	types.LowSeverity:      1,
	types.MediumSeverity:   2,
	types.ElevatedSeverity: 3,
	types.HighSeverity:     5,
	types.CriticalSeverity: 8,
}

const (
	completenessWeight = 0.4
	postureWeight      = 0.6
)

// Check is one completeness dimension: how many applicable items satisfied it.
type Check struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Satisfied   int     `json:"satisfied"`
	Total       int     `json:"total"`
	Ratio       float64 `json:"ratio"`
}

// Report is the full deterministic scoring result.
type Report struct {
	Overall            int            `json:"overall"`      // 0–100
	Grade              string         `json:"grade"`        // A–F
	Completeness       float64        `json:"completeness"` // 0–1
	Posture            float64        `json:"posture"`      // 0–1
	CompletenessChecks []Check        `json:"completeness_checks"`
	RisksByStatus      map[string]int `json:"risks_by_status"`
	TotalRisks         int            `json:"total_risks"`
	StillAtRisk        int            `json:"still_at_risk"`
	// Capped is true when an un-triaged High/Critical forced the score down.
	Capped bool `json:"capped"`
	// Insufficient is true when the model is too empty to score meaningfully.
	Insufficient bool `json:"insufficient"`
	// Notes are human-readable caveats so a number can never mislead on its own.
	Notes []string `json:"notes,omitempty"`
}

// cappedCeiling is the highest score allowed while an un-triaged High/Critical
// finding remains: such a model is, by definition, not "healthy" yet.
const cappedCeiling = 59

// Compute produces the score Report for an analyzed model.
func Compute(model *types.Model) *Report {
	checks := completenessChecks(model)
	completeness := averageRatio(checks)
	posture, byStatus, total, atRisk := computePosture(model)

	report := &Report{
		Completeness:       completeness,
		Posture:            posture,
		CompletenessChecks: checks,
		RisksByStatus:      byStatus,
		TotalRisks:         total,
		StillAtRisk:        atRisk,
	}

	// Guard against the "empty model looks perfect" trap: a model with no
	// in-scope technical assets has modelled nothing, so it scores 0, not 100.
	if countInScope(model) == 0 {
		report.Overall = 0
		report.Grade = "F"
		report.Insufficient = true
		report.Notes = append(report.Notes, "no in-scope technical assets — the model is empty or unanalysable, so it cannot be considered healthy")
		return report
	}

	overall := int(math.Round(100 * (completenessWeight*completeness + postureWeight*posture)))
	if overall > 100 {
		overall = 100
	}
	if overall < 0 {
		overall = 0
	}

	// Hard cap: an un-triaged High/Critical finding (one nobody has even looked
	// at) cannot be masked by mitigating many low-severity findings.
	if n := untriagedSerious(model); n > 0 {
		if overall > cappedCeiling {
			overall = cappedCeiling
		}
		report.Capped = true
		report.Notes = append(report.Notes, fmt.Sprintf("%d un-triaged High/Critical finding(s) cap the score until they are reviewed", n))
	}

	report.Overall = overall
	report.Grade = grade(overall)
	return report
}

// countInScope returns the number of technical assets that are in scope.
func countInScope(model *types.Model) int {
	n := 0
	for _, ta := range model.TechnicalAssets {
		if !ta.OutOfScope {
			n++
		}
	}
	return n
}

// untriagedSerious counts still-at-risk findings of High+ severity that nobody
// has triaged yet (status unchecked).
func untriagedSerious(model *types.Model) int {
	n := 0
	for _, risk := range model.AllRisks() {
		if risk.RiskStatus == types.Unchecked && risk.Severity >= types.HighSeverity {
			n++
		}
	}
	return n
}

// weightOf returns the severity weight, defaulting unknown severities to the
// Medium weight so a finding can never be silently dropped from the posture.
func weightOf(sev types.RiskSeverity) float64 {
	if w, ok := severityWeight[sev]; ok {
		return w
	}
	return severityWeight[types.MediumSeverity]
}

func completenessChecks(model *types.Model) []Check {
	var inScope []*types.TechnicalAsset
	for _, ta := range model.TechnicalAssets {
		if !ta.OutOfScope {
			inScope = append(inScope, ta)
		}
	}

	// 1. Owners assigned.
	owners := Check{ID: "owners", Description: "in-scope assets with an owner"}
	for _, ta := range inScope {
		owners.Total++
		if ta.Owner != "" {
			owners.Satisfied++
		}
	}

	// 2. Assets inside a trust boundary.
	inBoundary := map[string]bool{}
	for _, tb := range model.TrustBoundaries {
		for _, id := range tb.TechnicalAssetsInside {
			inBoundary[id] = true
		}
	}
	boundaries := Check{ID: "trust_boundaries", Description: "in-scope assets inside a trust boundary"}
	for _, ta := range inScope {
		boundaries.Total++
		if inBoundary[ta.Id] {
			boundaries.Satisfied++
		}
	}

	// 3. Communication links declare a known protocol.
	protocols := Check{ID: "link_protocols", Description: "communication links with a known protocol"}
	for _, ta := range model.TechnicalAssets {
		for _, cl := range ta.CommunicationLinks {
			protocols.Total++
			if cl.Protocol != types.UnknownProtocol {
				protocols.Satisfied++
			}
		}
	}

	// 4. Data assets are actually referenced by an asset or link.
	referenced := referencedDataAssets(model)
	dataUse := Check{ID: "data_assets_used", Description: "data assets processed/stored/transmitted somewhere"}
	for id := range model.DataAssets {
		dataUse.Total++
		if referenced[id] {
			dataUse.Satisfied++
		}
	}

	// 5. Basic metadata present (title + author).
	meta := Check{ID: "metadata", Description: "model has a title and an author", Total: 2}
	if model.Title != "" {
		meta.Satisfied++
	}
	if model.Author != nil && model.Author.Name != "" {
		meta.Satisfied++
	}

	checks := []Check{owners, boundaries, protocols, dataUse, meta}
	for i := range checks {
		checks[i].Ratio = ratio(checks[i].Satisfied, checks[i].Total)
	}
	return checks
}

func referencedDataAssets(model *types.Model) map[string]bool {
	ref := map[string]bool{}
	for _, ta := range model.TechnicalAssets {
		for _, id := range ta.DataAssetsProcessed {
			ref[id] = true
		}
		for _, id := range ta.DataAssetsStored {
			ref[id] = true
		}
		for _, cl := range ta.CommunicationLinks {
			for _, id := range cl.DataAssetsSent {
				ref[id] = true
			}
			for _, id := range cl.DataAssetsReceived {
				ref[id] = true
			}
		}
	}
	return ref
}

// computePosture returns the severity-weighted, status-credited risk posture in
// [0,1], plus a status histogram and counts.
func computePosture(model *types.Model) (float64, map[string]int, int, int) {
	byStatus := map[string]int{}
	var weighted, credited float64
	total, atRisk := 0, 0

	for _, risk := range model.AllRisks() {
		total++
		byStatus[risk.RiskStatus.String()]++
		if risk.RiskStatus.IsStillAtRisk() {
			atRisk++
		}
		w := weightOf(risk.Severity)
		weighted += w
		credited += w * statusCredit[risk.RiskStatus]
	}

	if weighted == 0 {
		// No risks at all → nothing outstanding to handle.
		return 1.0, byStatus, total, atRisk
	}
	return credited / weighted, byStatus, total, atRisk
}

// averageRatio averages the applicable checks (Total > 0). An empty model with
// no applicable checks scores a neutral 1.0 on completeness.
func averageRatio(checks []Check) float64 {
	var sum float64
	n := 0
	for _, c := range checks {
		if c.Total > 0 {
			sum += c.Ratio
			n++
		}
	}
	if n == 0 {
		return 1.0
	}
	return sum / float64(n)
}

func ratio(sat, total int) float64 {
	if total == 0 {
		return 1.0
	}
	return float64(sat) / float64(total)
}

func grade(overall int) string {
	switch {
	case overall >= 90:
		return "A"
	case overall >= 80:
		return "B"
	case overall >= 70:
		return "C"
	case overall >= 60:
		return "D"
	default:
		return "F"
	}
}
