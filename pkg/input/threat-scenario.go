package input

import "fmt"

type ThreatScenario struct {
	ID                string   `yaml:"id,omitempty" json:"id,omitempty"`
	Title             string   `yaml:"title,omitempty" json:"title,omitempty"`
	Description       string   `yaml:"description,omitempty" json:"description,omitempty"`
	ActorCapabilities string   `yaml:"actor_capabilities,omitempty" json:"actor_capabilities,omitempty"`
	EntryAssets       []string `yaml:"entry_assets,omitempty" json:"entry_assets,omitempty"`
	KillChainSteps    []string `yaml:"kill_chain_steps,omitempty" json:"kill_chain_steps,omitempty"`
	MitigatedBy       []string `yaml:"mitigated_by,omitempty" json:"mitigated_by,omitempty"`
	AttackVector      string   `yaml:"attack_vector,omitempty" json:"attack_vector,omitempty"`
}

func (what *ThreatScenario) Merge(other ThreatScenario) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %w", mergeError)
	}

	what.Title, mergeError = new(Strings).MergeSingleton(what.Title, other.Title)
	if mergeError != nil {
		return fmt.Errorf("failed to merge title: %w", mergeError)
	}

	what.Description = new(Strings).MergeMultiline(what.Description, other.Description)
	what.EntryAssets = new(Strings).MergeUniqueSlice(what.EntryAssets, other.EntryAssets)
	what.KillChainSteps = new(Strings).MergeUniqueSlice(what.KillChainSteps, other.KillChainSteps)
	what.MitigatedBy = new(Strings).MergeUniqueSlice(what.MitigatedBy, other.MitigatedBy)

	what.ActorCapabilities, mergeError = new(Strings).MergeSingleton(what.ActorCapabilities, other.ActorCapabilities)
	if mergeError != nil {
		return fmt.Errorf("failed to merge actor_capabilities: %w", mergeError)
	}

	what.AttackVector, mergeError = new(Strings).MergeSingleton(what.AttackVector, other.AttackVector)
	if mergeError != nil {
		return fmt.Errorf("failed to merge attack_vector: %w", mergeError)
	}

	return nil
}

func (what *ThreatScenario) MergeMap(first map[string]ThreatScenario, second map[string]ThreatScenario) (map[string]ThreatScenario, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge threat scenario %q: %w", mapKey, mergeError)
			}
			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}
	return first, nil
}
