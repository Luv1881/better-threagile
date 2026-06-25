package sbom

import (
	"fmt"
	"strings"
)

// FormatText renders a human-readable correlation report.
func FormatText(r *Result) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "SBOM intel correlation: %d component(s), %d vulnerability(ies), %d KEV-listed\n",
		r.TotalComponents, r.TotalVulns, r.KEVCount)
	if r.SuppressedCount > 0 {
		fmt.Fprintf(&sb, "(%d VEX-suppressed)\n", r.SuppressedCount)
	}
	if len(r.Findings) == 0 {
		sb.WriteString("\nNo vulnerabilities to report.\n")
		return sb.String()
	}
	sb.WriteString("\n")
	for _, f := range r.Findings {
		flags := []string{}
		if f.KEV {
			flags = append(flags, "KEV")
		}
		if f.HasEPSS {
			flags = append(flags, fmt.Sprintf("EPSS %.0f%%", f.EPSS*100))
		}
		if f.Suppressed {
			flags = append(flags, "suppressed:"+f.SuppressionState)
		}
		marker := "  "
		if f.KEV {
			marker = "‼ "
		}
		fmt.Fprintf(&sb, "%s%-18s [%-8s cvss %.1f] %s\n", marker, f.CVE, f.Severity, f.CVSS, strings.Join(flags, " "))
		if len(f.AffectedComponents) > 0 {
			fmt.Fprintf(&sb, "    affects: %s\n", strings.Join(f.AffectedComponents, ", "))
		}
	}
	return sb.String()
}

// FormatMarkdown renders a PR-comment-ready report.
func FormatMarkdown(r *Result) string {
	var sb strings.Builder
	sb.WriteString("## SBOM intel correlation\n\n")
	fmt.Fprintf(&sb, "%d component(s), %d vulnerability(ies), **%d KEV-listed**", r.TotalComponents, r.TotalVulns, r.KEVCount)
	if r.SuppressedCount > 0 {
		fmt.Fprintf(&sb, ", %d VEX-suppressed", r.SuppressedCount)
	}
	sb.WriteString(".\n\n")
	if len(r.Findings) == 0 {
		sb.WriteString("No vulnerabilities to report. ✅\n")
		return sb.String()
	}
	sb.WriteString("| CVE | Severity | CVSS | KEV | EPSS | Affects |\n")
	sb.WriteString("|-----|----------|------|-----|------|---------|\n")
	for _, f := range r.Findings {
		kev := ""
		if f.KEV {
			kev = "‼️"
		}
		epss := ""
		if f.HasEPSS {
			epss = fmt.Sprintf("%.0f%%", f.EPSS*100)
		}
		cve := f.CVE
		if f.Suppressed {
			cve = "~~" + cve + "~~"
		}
		fmt.Fprintf(&sb, "| %s | %s | %.1f | %s | %s | %s |\n",
			cve, f.Severity, f.CVSS, kev, epss, escapeCell(strings.Join(f.AffectedComponents, ", ")))
	}
	return sb.String()
}

func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
