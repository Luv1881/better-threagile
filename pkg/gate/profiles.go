package gate

import (
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed templates/*.yaml
var templatesFS embed.FS

// profileDescriptions documents each bundled secure-by-default policy profile,
// from loosest to strictest. The order here is the order `policy list` prints.
var profileOrder = []string{"prototype", "balanced", "strict", "regulated"}

var profileDescriptions = map[string]string{
	"prototype": "Loosest — early spikes / pre-production. Blocks only still-at-risk Criticals + expired acceptances.",
	"balanced":  "Recommended default — no Critical/High at risk; Elevated must be triaged. Works with zero extra files.",
	"strict":    "Internet-facing / high-value — also no Elevated at risk; triage required down to Medium.",
	"regulated": "Audit scope — strict thresholds, every finding triaged, plus a framework-coverage template.",
}

// ProfileNames returns the bundled policy-profile names, loosest-to-strictest.
func ProfileNames() []string {
	out := make([]string, len(profileOrder))
	copy(out, profileOrder)
	return out
}

// ProfileDescription returns the one-line description for a profile, or "".
func ProfileDescription(name string) string {
	return profileDescriptions[strings.ToLower(strings.TrimSpace(name))]
}

// ProfileTemplate returns the raw YAML for a bundled secure-by-default policy
// profile. Unknown names return an error listing the valid choices.
func ProfileTemplate(name string) ([]byte, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if _, ok := profileDescriptions[key]; !ok {
		return nil, fmt.Errorf("unknown policy profile %q (choose one of: %s)", name, strings.Join(ProfileNames(), ", "))
	}
	data, err := templatesFS.ReadFile("templates/" + key + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("read bundled profile %q: %w", name, err)
	}
	return data, nil
}

// allProfileFiles lists the embedded template filenames (used by tests to keep
// the templates and the profile registry in sync).
func allProfileFiles() []string {
	entries, _ := templatesFS.ReadDir("templates")
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}
