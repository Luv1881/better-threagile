package input

import "fmt"

type BusinessProcess struct {
	ID                         string   `yaml:"id,omitempty" json:"id,omitempty"`
	Title                      string   `yaml:"title,omitempty" json:"title,omitempty"`
	Description                string   `yaml:"description,omitempty" json:"description,omitempty"`
	Criticality                string   `yaml:"criticality,omitempty" json:"criticality,omitempty"`
	Owner                      string   `yaml:"owner,omitempty" json:"owner,omitempty"`
	SupportedByTechnicalAssets []string `yaml:"supported_by_technical_assets,omitempty" json:"supported_by_technical_assets,omitempty"`
	DataAssetsInFlight         []string `yaml:"data_assets_in_flight,omitempty" json:"data_assets_in_flight,omitempty"`
}

func (what *BusinessProcess) Merge(other BusinessProcess) error {
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

	what.Criticality, mergeError = new(Strings).MergeSingleton(what.Criticality, other.Criticality)
	if mergeError != nil {
		return fmt.Errorf("failed to merge criticality: %w", mergeError)
	}

	what.Owner, mergeError = new(Strings).MergeSingleton(what.Owner, other.Owner)
	if mergeError != nil {
		return fmt.Errorf("failed to merge owner: %w", mergeError)
	}

	what.SupportedByTechnicalAssets = new(Strings).MergeUniqueSlice(what.SupportedByTechnicalAssets, other.SupportedByTechnicalAssets)
	what.DataAssetsInFlight = new(Strings).MergeUniqueSlice(what.DataAssetsInFlight, other.DataAssetsInFlight)

	return nil
}

func (what *BusinessProcess) MergeMap(first map[string]BusinessProcess, second map[string]BusinessProcess) (map[string]BusinessProcess, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			if err := mapItem.Merge(mapValue); err != nil {
				return first, fmt.Errorf("failed to merge business process %q: %w", mapKey, err)
			}
			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}
	return first, nil
}
