package gate

import (
	"fmt"
	"strings"
)

// FormatText renders a human-readable gate report for terminal/CI logs.
func FormatText(r *Result) string {
	var sb strings.Builder
	name := r.PolicyName
	if name == "" {
		name = "policy"
	}
	fmt.Fprintf(&sb, "Threat-model gate: %s\n", name)
	fmt.Fprintf(&sb, "Findings still at risk: %d (%s)\n", r.AtRiskTotal, severitySummary(r.AtRiskBySeverity))
	sb.WriteString("\n")
	if r.Passed() {
		sb.WriteString("PASS — all policy rules satisfied.\n")
		return sb.String()
	}
	fmt.Fprintf(&sb, "FAIL — %d policy violation(s):\n", len(r.Violations))
	for _, v := range r.Violations {
		fmt.Fprintf(&sb, "  ✗ [%s] %s\n", v.Rule, v.Message)
	}
	return sb.String()
}

// FormatMarkdown renders the report as a Markdown snippet suitable for posting
// as a pull-request comment.
func FormatMarkdown(r *Result) string {
	var sb strings.Builder
	name := r.PolicyName
	if name == "" {
		name = "policy"
	}
	status := "✅ **PASS**"
	if !r.Passed() {
		status = "❌ **FAIL**"
	}
	fmt.Fprintf(&sb, "## Threat-model gate — %s\n\n", status)
	fmt.Fprintf(&sb, "_Policy: %s_\n\n", name)
	fmt.Fprintf(&sb, "Findings still at risk: **%d** (%s)\n\n", r.AtRiskTotal, severitySummary(r.AtRiskBySeverity))
	if r.Passed() {
		sb.WriteString("All policy rules satisfied.\n")
		return sb.String()
	}
	fmt.Fprintf(&sb, "### %d policy violation(s)\n\n", len(r.Violations))
	sb.WriteString("| Rule | Detail |\n|------|--------|\n")
	for _, v := range r.Violations {
		fmt.Fprintf(&sb, "| `%s` | %s |\n", v.Rule, escapeCell(v.Message))
	}
	return sb.String()
}

func severitySummary(bySeverity map[string]int) string {
	if len(bySeverity) == 0 {
		return "none"
	}
	// Fixed severity order, highest first.
	order := []string{"critical", "high", "elevated", "medium", "low"}
	var parts []string
	for _, sev := range order {
		if n, ok := bySeverity[sev]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// escapeCell makes a violation message safe inside a single Markdown table
// cell: pipes are escaped and newlines (acceptance-expiry messages embed them)
// become <br> so they don't break the table layout in a PR comment.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", "<br>")
	return s
}
