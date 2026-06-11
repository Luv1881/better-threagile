package risks

import (
	"embed"
	"fmt"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

//go:embed methodologies/ai-ml methodologies/cloud-native methodologies/linddun methodologies/octave methodologies/pasta methodologies/supply-chain methodologies/trike methodologies/vast
var embeddedPacks embed.FS

// AvailableBuiltinPacks lists the methodology pack names shipped with the binary.
var AvailableBuiltinPacks = []string{"linddun", "pasta", "vast", "cloud-native", "supply-chain", "ai-ml", "octave", "trike"}

// LoadRulePack loads a named built-in methodology rule pack directly from the
// embedded filesystem. No temp directory or extraction is required.
func LoadRulePack(name string) (types.RiskRules, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	packDir := fmt.Sprintf("methodologies/%s", name)

	entries, err := embeddedPacks.ReadDir(packDir)
	if err != nil {
		return nil, fmt.Errorf("built-in rule pack %q not found (available: %s)",
			name, strings.Join(AvailableBuiltinPacks, ", "))
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("built-in rule pack %q is empty", name)
	}

	rules, loadErr := LoadRulePackFromFS(embeddedPacks, packDir)
	if loadErr != nil {
		return nil, fmt.Errorf("failed to load rules from pack %q: %w", name, loadErr)
	}

	return rules, nil
}
