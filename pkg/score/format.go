package score

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// FormatText renders a human-readable score summary.
func FormatText(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Threat-model score: %d/100 (grade %s)\n", r.Overall, r.Grade)
	fmt.Fprintf(&b, "  completeness: %3.0f%%   posture: %3.0f%%\n", r.Completeness*100, r.Posture*100)
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "  ! %s\n", n)
	}
	b.WriteString("\n")

	b.WriteString("Completeness checks:\n")
	for _, c := range r.CompletenessChecks {
		if c.Total == 0 {
			fmt.Fprintf(&b, "  %-20s   n/a    %s\n", c.ID, c.Description)
			continue
		}
		fmt.Fprintf(&b, "  %-20s %4.0f%%  (%d/%d) %s\n", c.ID, c.Ratio*100, c.Satisfied, c.Total, c.Description)
	}

	fmt.Fprintf(&b, "\nRisks: %d total, %d still at risk\n", r.TotalRisks, r.StillAtRisk)
	for _, st := range sortedStatuses(r.RisksByStatus) {
		fmt.Fprintf(&b, "  %-14s %d\n", st, r.RisksByStatus[st])
	}
	return b.String()
}

// FormatMarkdown renders a PR-friendly score summary.
func FormatMarkdown(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Threat-model score: %d/100 — grade %s\n\n", r.Overall, r.Grade)
	fmt.Fprintf(&b, "- **Completeness:** %.0f%%\n- **Posture:** %.0f%%\n- **Risks:** %d total, %d still at risk\n",
		r.Completeness*100, r.Posture*100, r.TotalRisks, r.StillAtRisk)
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "- ⚠️ %s\n", n)
	}
	b.WriteString("\n")
	b.WriteString("| Completeness check | Score | |\n|---|---:|---|\n")
	for _, c := range r.CompletenessChecks {
		if c.Total == 0 {
			fmt.Fprintf(&b, "| %s | n/a | %s |\n", c.ID, c.Description)
			continue
		}
		fmt.Fprintf(&b, "| %s | %.0f%% | %d/%d %s |\n", c.ID, c.Ratio*100, c.Satisfied, c.Total, c.Description)
	}
	return b.String()
}

// FormatJSON renders the full report as indented JSON.
func FormatJSON(r *Report) (string, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}

// FormatShields renders a shields.io endpoint-badge JSON document, so a repo can
// show a live threat-model badge via https://shields.io/endpoint.
func FormatShields(r *Report) (string, error) {
	badge := struct {
		SchemaVersion int    `json:"schemaVersion"`
		Label         string `json:"label"`
		Message       string `json:"message"`
		Color         string `json:"color"`
	}{
		SchemaVersion: 1,
		Label:         "threat model",
		Message:       fmt.Sprintf("%s (%d)", r.Grade, r.Overall),
		Color:         badgeColor(r.Grade),
	}
	out, err := json.MarshalIndent(badge, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}

func badgeColor(grade string) string {
	switch grade {
	case "A":
		return "brightgreen"
	case "B":
		return "green"
	case "C":
		return "yellow"
	case "D":
		return "orange"
	default:
		return "red"
	}
}

func sortedStatuses(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
