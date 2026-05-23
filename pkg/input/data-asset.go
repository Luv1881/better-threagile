package input

import "fmt"

type DataAsset struct {
	ID                     string   `yaml:"id,omitempty" json:"id,omitempty"`
	Description            string   `yaml:"description,omitempty" json:"description,omitempty"`
	Usage                  string   `yaml:"usage,omitempty" json:"usage,omitempty"`
	Tags                   []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Origin                 string   `yaml:"origin,omitempty" json:"origin,omitempty"`
	Owner                  string   `yaml:"owner,omitempty" json:"owner,omitempty"`
	Quantity               string   `yaml:"quantity,omitempty" json:"quantity,omitempty"`
	Confidentiality        string   `yaml:"confidentiality,omitempty" json:"confidentiality,omitempty"`
	Integrity              string   `yaml:"integrity,omitempty" json:"integrity,omitempty"`
	Availability           string   `yaml:"availability,omitempty" json:"availability,omitempty"`
	JustificationCiaRating string   `yaml:"justification_cia_rating,omitempty" json:"justification_cia_rating,omitempty"`
	// LINDDUN privacy fields (all optional — existing models work unchanged)
	PiiCategories        []string `yaml:"pii_categories,omitempty" json:"pii_categories,omitempty"`
	DataSubjectCategory  string   `yaml:"data_subject_category,omitempty" json:"data_subject_category,omitempty"`
	LawfulBasis          string   `yaml:"lawful_basis,omitempty" json:"lawful_basis,omitempty"`
	RetentionPeriod      string   `yaml:"retention_period,omitempty" json:"retention_period,omitempty"`
	ProcessingPurpose    string   `yaml:"processing_purpose,omitempty" json:"processing_purpose,omitempty"`
	CrossBorderTransfer  bool     `yaml:"cross_border_transfer,omitempty" json:"cross_border_transfer,omitempty"`
}

func (what *DataAsset) Merge(other DataAsset) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Usage, mergeError = new(Strings).MergeSingleton(what.Usage, other.Usage)
	if mergeError != nil {
		return fmt.Errorf("failed to merge usage: %w", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	what.Origin, mergeError = new(Strings).MergeSingleton(what.Origin, other.Origin)
	if mergeError != nil {
		return fmt.Errorf("failed to merge origin: %w", mergeError)
	}

	what.Owner, mergeError = new(Strings).MergeSingleton(what.Owner, other.Owner)
	if mergeError != nil {
		return fmt.Errorf("failed to merge owner: %w", mergeError)
	}

	what.Quantity, mergeError = new(Strings).MergeSingleton(what.Quantity, other.Quantity)
	if mergeError != nil {
		return fmt.Errorf("failed to merge quantity: %w", mergeError)
	}

	what.Confidentiality, mergeError = new(Strings).MergeSingleton(what.Confidentiality, other.Confidentiality)
	if mergeError != nil {
		return fmt.Errorf("failed to merge confidentiality: %w", mergeError)
	}

	what.Integrity, mergeError = new(Strings).MergeSingleton(what.Integrity, other.Integrity)
	if mergeError != nil {
		return fmt.Errorf("failed to merge integrity: %w", mergeError)
	}

	what.Availability, mergeError = new(Strings).MergeSingleton(what.Availability, other.Availability)
	if mergeError != nil {
		return fmt.Errorf("failed to merge availability: %w", mergeError)
	}

	what.JustificationCiaRating = new(Strings).MergeMultiline(what.JustificationCiaRating, other.JustificationCiaRating)

	what.PiiCategories = new(Strings).MergeUniqueSlice(what.PiiCategories, other.PiiCategories)

	what.DataSubjectCategory, mergeError = new(Strings).MergeSingleton(what.DataSubjectCategory, other.DataSubjectCategory)
	if mergeError != nil {
		return fmt.Errorf("failed to merge data_subject_category: %w", mergeError)
	}

	what.LawfulBasis, mergeError = new(Strings).MergeSingleton(what.LawfulBasis, other.LawfulBasis)
	if mergeError != nil {
		return fmt.Errorf("failed to merge lawful_basis: %w", mergeError)
	}

	what.RetentionPeriod, mergeError = new(Strings).MergeSingleton(what.RetentionPeriod, other.RetentionPeriod)
	if mergeError != nil {
		return fmt.Errorf("failed to merge retention_period: %w", mergeError)
	}

	what.ProcessingPurpose, mergeError = new(Strings).MergeSingleton(what.ProcessingPurpose, other.ProcessingPurpose)
	if mergeError != nil {
		return fmt.Errorf("failed to merge processing_purpose: %w", mergeError)
	}

	if !what.CrossBorderTransfer {
		what.CrossBorderTransfer = other.CrossBorderTransfer
	}

	return nil
}

func (what *DataAsset) MergeMap(first map[string]DataAsset, second map[string]DataAsset) (map[string]DataAsset, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge data asset %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
