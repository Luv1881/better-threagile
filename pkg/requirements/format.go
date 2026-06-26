package requirements

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var htmlTag = regexp.MustCompile(`</?[a-zA-Z][^>]*>`)

func plain(s string) string { return strings.TrimSpace(htmlTag.ReplaceAllString(s, "")) }

// FormatMarkdown renders a backlog-ready checklist of security requirements.
func FormatMarkdown(reqs []Requirement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security requirements (%d)\n\n", len(reqs))
	if len(reqs) == 0 {
		b.WriteString("No still-at-risk findings — nothing to require. ✅\n")
		return b.String()
	}
	for _, r := range reqs {
		meta := strings.ToUpper(r.Severity)
		if r.CWE > 0 {
			meta += fmt.Sprintf(", CWE-%d", r.CWE)
		}
		if r.FindingCount > 1 {
			meta += fmt.Sprintf(", %d findings", r.FindingCount)
		}
		fmt.Fprintf(&b, "- [ ] **%s** — %s _(%s)_\n", plain(r.Title), plain(r.Statement), meta)
		if len(r.AffectedAssets) > 0 {
			fmt.Fprintf(&b, "      Affects: %s\n", strings.Join(r.AffectedAssets, ", "))
		}
		if r.Verification != "" {
			fmt.Fprintf(&b, "      Verify: %s\n", plain(r.Verification))
		}
	}
	return b.String()
}

// FormatGherkin renders the requirements as Gherkin scenario stubs, a starting
// point for security acceptance tests.
func FormatGherkin(title string, reqs []Requirement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Feature: %s security requirements\n\n", plain(title))
	for _, r := range reqs {
		fmt.Fprintf(&b, "  Scenario: %s\n", plain(r.Title))
		meta := strings.ToUpper(r.Severity)
		if r.CWE > 0 {
			meta += fmt.Sprintf(", CWE-%d", r.CWE)
		}
		fmt.Fprintf(&b, "    # %s\n", meta)
		if len(r.AffectedAssets) > 0 {
			fmt.Fprintf(&b, "    Given the affected assets %s are deployed\n", strings.Join(r.AffectedAssets, ", "))
		} else {
			b.WriteString("    Given the system is deployed\n")
		}
		if r.Statement != "" {
			fmt.Fprintf(&b, "    Then %s\n", plain(r.Statement))
		}
		if r.Verification != "" {
			fmt.Fprintf(&b, "    And it can be verified that %s\n", plain(r.Verification))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// FormatJSON renders the requirements as JSON.
func FormatJSON(reqs []Requirement) (string, error) {
	out, err := json.MarshalIndent(reqs, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}
