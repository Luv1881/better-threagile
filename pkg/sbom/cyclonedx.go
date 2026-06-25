// Package sbom ingests a CycloneDX SBOM (the format Trivy/Grype/Syft emit),
// extracts its components and any embedded vulnerabilities, and correlates the
// vulnerabilities against live threat intelligence (CISA KEV + FIRST EPSS) so a
// dependency inventory becomes prioritized, exploitability-aware signal.
//
// VEX is honoured: a vulnerability whose CycloneDX analysis.state marks it
// not_affected / false_positive / resolved is suppressed by default.
package sbom

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// BOM is the subset of a CycloneDX document we model.
type BOM struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	Components      []Component     `json:"components"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	BOMRef  string `json:"bom-ref"`
}

type Vulnerability struct {
	ID       string        `json:"id"` // typically a CVE ID
	Source   *VulnSource   `json:"source"`
	Ratings  []Rating      `json:"ratings"`
	Affects  []Affect      `json:"affects"`
	Analysis *VulnAnalysis `json:"analysis"`
}

type VulnSource struct {
	Name string `json:"name"`
}

type Rating struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"` // critical/high/medium/low/none/unknown
	Method   string  `json:"method"`
}

type Affect struct {
	Ref string `json:"ref"` // references a component bom-ref
}

type VulnAnalysis struct {
	State string `json:"state"` // resolved/exploitable/in_triage/false_positive/not_affected
}

// Parse decodes a CycloneDX JSON SBOM.
func Parse(data []byte) (*BOM, error) {
	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("sbom: failed to parse JSON: %w", err)
	}
	// Require an explicit CycloneDX bomFormat. Tolerate its (non-spec) omission
	// only when the document otherwise looks like CycloneDX (a specVersion plus
	// components or vulnerabilities) — but never accept a different format
	// (e.g. bomFormat: "SPDX") that merely happens to carry a components array.
	isCycloneDX := strings.EqualFold(bom.BOMFormat, "CycloneDX")
	looksCycloneDX := bom.BOMFormat == "" && bom.SpecVersion != "" &&
		(len(bom.Components) > 0 || len(bom.Vulnerabilities) > 0)
	if !isCycloneDX && !looksCycloneDX {
		return nil, fmt.Errorf("sbom: not a CycloneDX document (bomFormat=%q); convert with your scanner's CycloneDX output", bom.BOMFormat)
	}
	return &bom, nil
}

// suppressedStates are the VEX analysis states that hide a vulnerability by default.
var suppressedStates = map[string]bool{
	"not_affected":   true,
	"false_positive": true,
	"resolved":       true,
}

// IsSuppressed reports whether the vulnerability's VEX analysis state suppresses it.
func (v Vulnerability) IsSuppressed() bool {
	if v.Analysis == nil {
		return false
	}
	return suppressedStates[strings.ToLower(strings.TrimSpace(v.Analysis.State))]
}

var severityRank = map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// HighestSeverity returns a representative severity label and the highest CVSS
// score across all ratings. It is robust to mixed ratings: it takes the maximum
// numeric score, and the severity label from the highest-ranked severity present
// (so severity-only ratings, empty-severity high-score ratings, and all-zero
// scores still produce a sensible label rather than "unknown").
func (v Vulnerability) HighestSeverity() (string, float64) {
	var score float64
	bestRank := -1
	label := ""
	for _, r := range v.Ratings {
		if r.Score > score {
			score = r.Score
		}
		sev := strings.ToLower(strings.TrimSpace(r.Severity))
		if rank, ok := severityRank[sev]; ok && rank > bestRank {
			bestRank = rank
			label = sev
		}
	}
	if label == "" {
		label = "unknown"
	}
	return label, score
}

// componentIndex maps a component bom-ref (and purl) to a human label.
func (b *BOM) componentIndex() map[string]string {
	idx := map[string]string{}
	for _, c := range b.Components {
		label := c.Name
		if c.Version != "" {
			label = c.Name + "@" + c.Version
		}
		if c.BOMRef != "" {
			idx[c.BOMRef] = label
		}
		if c.PURL != "" {
			idx[c.PURL] = label
		}
	}
	return idx
}

// AffectedComponentLabels returns sorted human labels for the components a
// vulnerability affects, resolving refs via the component index where possible.
func (b *BOM) AffectedComponentLabels(v Vulnerability) []string {
	idx := b.componentIndex()
	seen := map[string]bool{}
	var out []string
	for _, a := range v.Affects {
		label := a.Ref
		if l, ok := idx[a.Ref]; ok {
			label = l
		}
		if label != "" && !seen[label] {
			seen[label] = true
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}
