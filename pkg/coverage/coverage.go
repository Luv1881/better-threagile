// Package coverage computes compliance-framework control coverage from a set of risk rules.
// For a given framework (e.g. "nist_800_53"), it determines which control IDs are covered
// by at least one loaded risk rule and which controls are gaps.
package coverage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// ControlEntry describes the coverage state of one control.
type ControlEntry struct {
	ControlID    string   // e.g. "SC-8" or "A10"
	CoveringRules []string // rule IDs that cover this control
	Covered      bool
}

// Report is the output of a coverage analysis for one framework.
type Report struct {
	Framework  string          // framework key (e.g. "nist_800_53")
	Title      string          // human-readable title
	Controls   []ControlEntry  // sorted by control ID
	TotalRules int             // total rules checked
	CoveredCount int
	GapCount     int
}

// CoveragePercent returns the coverage percentage (0–100).
func (r *Report) CoveragePercent() float64 {
	total := r.CoveredCount + r.GapCount
	if total == 0 {
		return 0
	}
	return float64(r.CoveredCount) / float64(total) * 100
}

// Analyze computes control coverage for the given framework over the provided rule categories.
// It returns a report that can be rendered in any format.
// If the framework is not one of types.SupportedFrameworks the function returns an error.
func Analyze(framework string, categories []*types.RiskCategory) (*Report, error) {
	framework = strings.ToLower(strings.TrimSpace(framework))

	found := false
	for _, f := range types.SupportedFrameworks {
		if f == framework {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("unknown framework %q (supported: %s)", framework,
			strings.Join(types.SupportedFrameworks, ", "))
	}

	// Build: controlID → list of covering rule IDs
	coverageMap := make(map[string][]string)

	for _, cat := range categories {
		if cat.Controls == nil {
			continue
		}
		controls := cat.Controls.ControlsFor(framework)
		for _, ctrl := range controls {
			ctrl = strings.TrimSpace(ctrl)
			if ctrl == "" {
				continue
			}
			coverageMap[ctrl] = appendUnique(coverageMap[ctrl], cat.ID)
		}
	}

	// Build sorted entries
	sortedControls := make([]string, 0, len(coverageMap))
	for ctrl := range coverageMap {
		sortedControls = append(sortedControls, ctrl)
	}
	sort.Strings(sortedControls)

	entries := make([]ControlEntry, 0, len(sortedControls))
	covered := 0
	for _, ctrl := range sortedControls {
		rules := coverageMap[ctrl]
		entry := ControlEntry{
			ControlID:     ctrl,
			CoveringRules: rules,
			Covered:       len(rules) > 0,
		}
		entries = append(entries, entry)
		if entry.Covered {
			covered++
		}
	}

	return &Report{
		Framework:    framework,
		Title:        types.FrameworkTitle(framework),
		Controls:     entries,
		TotalRules:   len(categories),
		CoveredCount: covered,
		GapCount:     0, // no known-gap list: only covered controls are reported
	}, nil
}

// AnalyzeWithGaps is like Analyze but also includes a known control list for the framework,
// so it can report GAP entries for controls not covered by any rule.
// knownControls is a sorted list of all control IDs in the framework (e.g. from a built-in catalog).
func AnalyzeWithGaps(framework string, categories []*types.RiskCategory, knownControls []string) (*Report, error) {
	report, err := Analyze(framework, categories)
	if err != nil {
		return nil, err
	}

	// Index existing covered entries
	coveredSet := make(map[string][]string)
	for _, e := range report.Controls {
		coveredSet[e.ControlID] = e.CoveringRules
	}

	// Rebuild entries including gaps
	all := make([]ControlEntry, 0, len(knownControls))
	covered := 0
	gaps := 0
	for _, ctrl := range knownControls {
		rules := coveredSet[ctrl]
		isCovered := len(rules) > 0
		all = append(all, ControlEntry{
			ControlID:     ctrl,
			CoveringRules: rules,
			Covered:       isCovered,
		})
		if isCovered {
			covered++
		} else {
			gaps++
		}
	}

	report.Controls = all
	report.CoveredCount = covered
	report.GapCount = gaps
	return report, nil
}

// FormatTable renders a coverage report as a plain-text table string.
func FormatTable(r *Report) string {
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "Coverage report: %s\n", r.Title)
	fmt.Fprintf(sb, "Rules analyzed: %d\n", r.TotalRules)
	fmt.Fprintf(sb, "Controls covered: %d", r.CoveredCount)
	if r.GapCount > 0 {
		fmt.Fprintf(sb, " / %d (%.0f%%)", r.CoveredCount+r.GapCount, r.CoveragePercent())
	}
	sb.WriteString("\n\n")

	if len(r.Controls) == 0 {
		sb.WriteString("No control mappings found for this framework in the loaded rules.\n")
		sb.WriteString("Add 'controls:" + r.Framework + ": [...]' to rule YAML files to populate coverage.\n")
		return sb.String()
	}

	// Column widths
	maxCtrl := len("Control")
	maxRules := len("Rules")
	for _, e := range r.Controls {
		if len(e.ControlID) > maxCtrl {
			maxCtrl = len(e.ControlID)
		}
		ruleStr := strings.Join(e.CoveringRules, ", ")
		if len(ruleStr) > maxRules {
			maxRules = len(ruleStr)
		}
	}
	if maxRules > 80 {
		maxRules = 80
	}

	headerFmt := fmt.Sprintf("%%-%ds  %%-%ds  %%s\n", maxCtrl, maxRules)
	rowFmt := fmt.Sprintf("%%-%ds  %%-%ds  %%s\n", maxCtrl, maxRules)

	fmt.Fprintf(sb, headerFmt, "Control", "Rules", "Status")
	fmt.Fprintf(sb, "%s  %s  %s\n",
		strings.Repeat("-", maxCtrl),
		strings.Repeat("-", maxRules),
		"-------")

	for _, e := range r.Controls {
		status := "COVERED"
		if !e.Covered {
			status = "GAP"
		}
		ruleStr := strings.Join(e.CoveringRules, ", ")
		if len(ruleStr) > 80 {
			ruleStr = ruleStr[:77] + "..."
		}
		fmt.Fprintf(sb, rowFmt, e.ControlID, ruleStr, status)
	}

	return sb.String()
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
