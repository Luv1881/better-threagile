package macros

import (
	"fmt"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

// DiscoverAttackSurface is a PASTA Stage III macro that walks the model and
// seeds entry_point_type declarations on internet-exposed assets and generates
// a starter threat_scenarios block.
type DiscoverAttackSurface struct {
	questionsAnswered []string
}

func NewDiscoverAttackSurface() *DiscoverAttackSurface {
	return &DiscoverAttackSurface{}
}

func (what *DiscoverAttackSurface) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "discover-attack-surface",
		Title:       "Discover Attack Surface (PASTA)",
		Description: "PASTA Stage III helper: walks the model to identify internet-exposed assets lacking entry_point_type declarations and generates a starter threat_scenarios block for each discovered entry point.",
	}
}

func (what *DiscoverAttackSurface) GetNextQuestion(_ *types.Model) (MacroQuestion, error) {
	return NoMoreQuestions(), nil
}

func (what *DiscoverAttackSurface) ApplyAnswer(_ string, _ ...string) (string, bool, error) {
	return "No questions to answer", true, nil
}

func (what *DiscoverAttackSurface) GoBack() (string, bool, error) {
	return "Cannot go back", false, nil
}

func (what *DiscoverAttackSurface) GetFinalChangeImpact(modelInput *input.Model, model *types.Model) ([]string, string, bool, error) {
	changes := what.collectChanges(model)
	if len(changes) == 0 {
		return changes, "All internet-exposed assets already have entry_point_type declared. No changes needed.", true, nil
	}
	return changes, fmt.Sprintf("Will annotate %d assets and generate threat scenario stubs.", len(changes)), true, nil
}

func (what *DiscoverAttackSurface) Execute(modelInput *input.Model, model *types.Model) (string, bool, error) {
	count := 0
	for id, asset := range model.TechnicalAssets {
		if asset.OutOfScope || !asset.Internet {
			continue
		}
		inputAsset, exists := modelInput.TechnicalAssets[asset.Title]
		if !exists {
			continue
		}
		if inputAsset.EntryPointType == "" {
			// Infer from technology
			entryType := inferEntryPointType(asset)
			inputAsset.EntryPointType = entryType
			modelInput.TechnicalAssets[asset.Title] = inputAsset
			count++
		}
		// Seed a threat scenario if none references this asset
		if !scenarioCovered(modelInput, id) {
			scenarioID := "threat-scenario-" + id
			modelInput.ThreatScenarios[scenarioID] = input.ThreatScenario{
				ID:                scenarioID,
				Title:             "Threat Scenario for " + asset.Title,
				Description:       "Auto-generated stub. Populate actor_capabilities, kill_chain_steps, and mitigated_by.",
				ActorCapabilities: "script-kiddie",
				EntryAssets:       []string{id},
				KillChainSteps:    []string{"reconnaissance", "initial-access"},
				MitigatedBy:       []string{},
				AttackVector:      "internet",
			}
		}
	}

	return fmt.Sprintf("Annotated %d internet-exposed assets with entry_point_type and generated threat scenario stubs.", count), true, nil
}

func (what *DiscoverAttackSurface) collectChanges(model *types.Model) []string {
	var changes []string
	for _, asset := range model.TechnicalAssets {
		if !asset.OutOfScope && asset.Internet && asset.EntryPointType == "" {
			changes = append(changes, fmt.Sprintf("  add entry_point_type to: %s", asset.Title))
		}
	}
	return changes
}

func inferEntryPointType(asset *types.TechnicalAsset) string {
	for _, tech := range asset.Technologies {
		name := strings.ToLower(tech.Name)
		switch {
		case strings.Contains(name, "reverse-proxy") || strings.Contains(name, "load-balancer"):
			return "api"
		case strings.Contains(name, "web-service") || strings.Contains(name, "rest") || strings.Contains(name, "graphql"):
			return "api"
		case strings.Contains(name, "browser") || strings.Contains(name, "web-application"):
			return "web_ui"
		case strings.Contains(name, "file"):
			return "file_upload"
		}
	}
	if asset.UsedAsClientByHuman {
		return "web_ui"
	}
	return "api"
}

func scenarioCovered(modelInput *input.Model, assetID string) bool {
	for _, scenario := range modelInput.ThreatScenarios {
		for _, entry := range scenario.EntryAssets {
			if entry == assetID {
				return true
			}
		}
	}
	return false
}
