package attackpath

import (
	"fmt"
	"strings"
)

// FormatText renders a human-readable attack-path report.
func FormatText(r *Result) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Attack-path analysis: %d entry point(s) → %d crown-jewel target(s)\n",
		len(r.EntryPoints), len(r.TargetAssets))
	if len(r.Paths) == 0 {
		sb.WriteString("\nNo attack paths found from the selected entry points to the targets.\n")
		return sb.String()
	}
	fmt.Fprintf(&sb, "\n%d path(s) (shortest first):\n\n", len(r.Paths))
	for _, p := range r.Paths {
		fmt.Fprintf(&sb, "  [%d hop(s)] %s\n", p.Hops, renderChain(p))
		if len(p.TargetDataAssets) > 0 {
			fmt.Fprintf(&sb, "            exposes: %s\n", strings.Join(p.TargetDataAssets, ", "))
		}
	}
	return sb.String()
}

// FormatMarkdown renders the report as a PR-comment-ready Markdown snippet.
func FormatMarkdown(r *Result) string {
	var sb strings.Builder
	sb.WriteString("## Attack-path analysis\n\n")
	fmt.Fprintf(&sb, "%d entry point(s) → %d crown-jewel target(s).\n\n", len(r.EntryPoints), len(r.TargetAssets))
	if len(r.Paths) == 0 {
		sb.WriteString("No attack paths found. ✅\n")
		return sb.String()
	}
	fmt.Fprintf(&sb, "Found **%d path(s)** (shortest first):\n\n", len(r.Paths))
	sb.WriteString("| Hops | Path | Exposes |\n|------|------|---------|\n")
	for _, p := range r.Paths {
		exposes := strings.Join(p.TargetDataAssets, ", ")
		fmt.Fprintf(&sb, "| %d | %s | %s |\n", p.Hops, escapeCell(renderChain(p)), escapeCell(exposes))
	}
	return sb.String()
}

// renderChain renders "a --(link)--> b --(link)--> c".
func renderChain(p Path) string {
	if len(p.Assets) == 1 {
		return p.Assets[0] + " (directly internet-facing)"
	}
	var sb strings.Builder
	for i, a := range p.Assets {
		sb.WriteString(a)
		if i < len(p.Links) {
			fmt.Fprintf(&sb, " --(%s)--> ", p.Links[i])
		}
	}
	return sb.String()
}

func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
