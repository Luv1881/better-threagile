package risks

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

//go:embed methodologies/*.tar.gz
var embeddedPacks embed.FS

// AvailableBuiltinPacks lists the methodology pack names shipped with the binary.
var AvailableBuiltinPacks = []string{"linddun", "pasta", "vast"}

// LoadRulePack loads a named built-in methodology rule pack by name (e.g., "linddun").
// It extracts the embedded tar.gz into a temporary directory and loads its YAML risk rules.
func LoadRulePack(name string) (types.RiskRules, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	packPath := fmt.Sprintf("methodologies/%s.tar.gz", name)

	data, readErr := embeddedPacks.ReadFile(packPath)
	if readErr != nil {
		return nil, fmt.Errorf("built-in rule pack %q not found (available: %s)",
			name, strings.Join(AvailableBuiltinPacks, ", "))
	}

	tmpDir, tmpErr := os.MkdirTemp("", "threagile-pack-"+name+"-*")
	if tmpErr != nil {
		return nil, fmt.Errorf("failed to create temp dir for rule pack %q: %w", name, tmpErr)
	}

	if err := extractTarGz(bytes.NewReader(data), tmpDir); err != nil {
		return nil, fmt.Errorf("failed to extract rule pack %q: %w", name, err)
	}

	// The tar was created with 'tar -czf linddun.tar.gz -C methodologies linddun/'
	// so after extraction the rules live at tmpDir/linddun/
	rulesDir := filepath.Join(tmpDir, name)
	if _, statErr := os.Stat(rulesDir); os.IsNotExist(statErr) {
		// fall back to scanning tmpDir itself if no sub-directory exists
		rulesDir = tmpDir
	}

	rules, loadErr := LoadExternalScriptRiskRules(rulesDir)
	if loadErr != nil {
		return nil, fmt.Errorf("failed to load rules from pack %q: %w", name, loadErr)
	}

	return rules, nil
}
