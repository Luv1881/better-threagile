package attack

import (
	"fmt"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// Layer is a MITRE ATT&CK Navigator layer (schema 4.5), the JSON format the
// online Navigator (https://mitre-attack.github.io/attack-navigator/) imports to
// highlight techniques on the ATT&CK matrix.
type Layer struct {
	Name        string         `json:"name"`
	Versions    LayerVersions  `json:"versions"`
	Domain      string         `json:"domain"`
	Description string         `json:"description"`
	Techniques  []TechniqueRef `json:"techniques"`
	Gradient    Gradient       `json:"gradient"`
	LegendItems []LegendItem   `json:"legendItems,omitempty"`
}

type LayerVersions struct {
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

type TechniqueRef struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Color       string `json:"color,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Enabled     bool   `json:"enabled"`
}

type Gradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

type LegendItem struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

// BuildResult is the outcome of mapping a model's risks onto ATT&CK techniques.
type BuildResult struct {
	Layer Layer
	// UnmappedCategories lists risk-category IDs that produced findings but have
	// no ATT&CK mapping yet, so coverage gaps are visible rather than silent.
	UnmappedCategories []string
}

// techniqueAggregate accumulates per-technique evidence while scanning risks.
type techniqueAggregate struct {
	count      int
	categories map[string]bool
	maxSev     types.RiskSeverity
}

// BuildLayer maps the supplied risks onto ATT&CK techniques and returns a
// Navigator layer plus the set of categories with no mapping. Score is the
// number of findings touching a technique; the comment lists the contributing
// categories and the highest severity among them.
func BuildLayer(modelName string, risks []*types.Risk) BuildResult {
	agg := map[string]*techniqueAggregate{}
	unmapped := map[string]bool{}

	for _, r := range risks {
		if r == nil {
			continue
		}
		techniques, ok := CategoryTechniques[r.CategoryId]
		if !ok || len(techniques) == 0 {
			unmapped[r.CategoryId] = true
			continue
		}
		for _, tid := range techniques {
			a := agg[tid]
			if a == nil {
				a = &techniqueAggregate{categories: map[string]bool{}}
				agg[tid] = a
			}
			a.count++
			a.categories[r.CategoryId] = true
			if r.Severity > a.maxSev {
				a.maxSev = r.Severity
			}
		}
	}

	techniques := make([]TechniqueRef, 0, len(agg))
	maxScore := 1
	for tid, a := range agg {
		if a.count > maxScore {
			maxScore = a.count
		}
		cats := sortedKeys(a.categories)
		name := TechniqueName(tid)
		comment := fmt.Sprintf("%d finding(s) (max severity %s) from: %s",
			a.count, a.maxSev.String(), strings.Join(cats, ", "))
		if name != "" {
			comment = name + " — " + comment
		}
		techniques = append(techniques, TechniqueRef{
			TechniqueID: tid,
			Score:       a.count,
			Color:       severityColor(a.maxSev),
			Comment:     comment,
			Enabled:     true,
		})
	}
	sort.Slice(techniques, func(i, j int) bool { return techniques[i].TechniqueID < techniques[j].TechniqueID })

	name := "Threagile: " + modelName
	if strings.TrimSpace(modelName) == "" {
		name = "Threagile threat model"
	}

	return BuildResult{
		Layer: Layer{
			Name:        name,
			Versions:    LayerVersions{Attack: "16", Navigator: "4.9.1", Layer: "4.5"},
			Domain:      "enterprise-attack",
			Description: "ATT&CK techniques derived from Threagile risk findings. Score = number of findings; color = highest severity.",
			Techniques:  techniques,
			Gradient:    Gradient{Colors: []string{"#ffe766", "#ff6666"}, MinValue: 0, MaxValue: maxScore},
			LegendItems: []LegendItem{
				{Label: "Critical/High", Color: severityColor(types.HighSeverity)},
				{Label: "Elevated", Color: severityColor(types.ElevatedSeverity)},
				{Label: "Medium/Low", Color: severityColor(types.MediumSeverity)},
			},
		},
		UnmappedCategories: sortedKeys(unmapped),
	}
}

// severityColor returns a hex color bucket for a severity (Navigator per-technique color).
func severityColor(sev types.RiskSeverity) string {
	switch sev {
	case types.CriticalSeverity, types.HighSeverity:
		return "#e60000"
	case types.ElevatedSeverity:
		return "#ff8c00"
	default:
		return "#ffd966"
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
