package prioritize

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// htmlTag strips the simple HTML markup (<b>, <u>, ...) that threagile stores in
// risk titles, so CLI / PR output reads cleanly.
var htmlTag = regexp.MustCompile(`</?[a-zA-Z][^>]*>`)

func plain(s string) string {
	return strings.TrimSpace(htmlTag.ReplaceAllString(s, ""))
}

// Plain strips threagile's simple HTML markup from a string for clean CLI output.
func Plain(s string) string { return plain(s) }

// FormatText renders the ranked items as a readable "fix these first" list.
func FormatText(items []Item, totalAtRisk int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Top %d findings to fix first (of %d still at risk):\n\n", len(items), totalAtRisk)
	for i, it := range items {
		fmt.Fprintf(&b, "  %d. [%3d] %-9s %s\n", i+1, it.Score, strings.ToUpper(it.Severity), plain(it.Title))
		if it.AssetTitle != "" {
			fmt.Fprintf(&b, "        asset: %s (%s)\n", it.AssetTitle, it.AssetID)
		}
		fmt.Fprintf(&b, "        why:   %s\n", whyLine(it.Factors))
		if fix := fixLine(it.Remediation); fix != "" {
			fmt.Fprintf(&b, "        fix:   %s\n", fix)
		}
	}
	return b.String()
}

// FormatMarkdown renders a PR-friendly ranked table plus remediation.
func FormatMarkdown(items []Item, totalAtRisk int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Fix these first — top %d of %d still-at-risk findings\n\n", len(items), totalAtRisk)
	b.WriteString("| # | Score | Severity | Finding | Asset |\n|--:|--:|---|---|---|\n")
	for i, it := range items {
		fmt.Fprintf(&b, "| %d | %d | %s | %s | %s |\n", i+1, it.Score, it.Severity, mdEscape(plain(it.Title)), mdEscape(it.AssetTitle))
	}
	b.WriteString("\n")
	for i, it := range items {
		if fix := fixLine(it.Remediation); fix != "" {
			fmt.Fprintf(&b, "%d. **%s** — %s\n", i+1, mdEscape(plain(it.Title)), mdEscape(fix))
		}
	}
	return b.String()
}

// FormatJSON renders the full ranked result (already top-N-sliced by the caller).
func FormatJSON(items []Item, totalAtRisk int) (string, error) {
	out, err := json.MarshalIndent(map[string]any{"items": items, "total_at_risk": totalAtRisk}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}

func whyLine(factors []Factor) string {
	parts := make([]string, 0, len(factors))
	for _, f := range factors {
		parts = append(parts, fmt.Sprintf("%s %.0f%%", f.Name, f.Value*100))
	}
	return strings.Join(parts, ", ")
}

func fixLine(r Remediation) string {
	var parts []string
	if r.Action != "" {
		parts = append(parts, strings.TrimSpace(r.Action))
	} else if r.Mitigation != "" {
		parts = append(parts, strings.TrimSpace(r.Mitigation))
	}
	var suffix []string
	if r.CWE > 0 {
		suffix = append(suffix, fmt.Sprintf("CWE-%d", r.CWE))
	}
	if r.CheatSheet != "" {
		suffix = append(suffix, "cheatsheet: "+strings.TrimSpace(r.CheatSheet))
	}
	line := strings.Join(parts, " ")
	if len(suffix) > 0 {
		if line != "" {
			line += " "
		}
		line += "(" + strings.Join(suffix, ", ") + ")"
	}
	return line
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
