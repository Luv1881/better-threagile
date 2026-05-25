/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

type DataAsset struct {
	Id                     string          `yaml:"id,omitempty" json:"id,omitempty"`
	Title                  string          `yaml:"title,omitempty" json:"title,omitempty"`
	Description            string          `yaml:"description,omitempty" json:"description,omitempty"`
	Usage                  Usage           `yaml:"usage,omitempty" json:"usage,omitempty"`
	Tags                   []string        `yaml:"tags,omitempty" json:"tags,omitempty"`
	Origin                 string          `yaml:"origin,omitempty" json:"origin,omitempty"`
	Owner                  string          `yaml:"owner,omitempty" json:"owner,omitempty"`
	Quantity               Quantity        `yaml:"quantity,omitempty" json:"quantity,omitempty"`
	Confidentiality        Confidentiality `yaml:"confidentiality,omitempty" json:"confidentiality,omitempty"`
	Integrity              Criticality     `yaml:"integrity,omitempty" json:"integrity,omitempty"`
	Availability           Criticality     `yaml:"availability,omitempty" json:"availability,omitempty"`
	JustificationCiaRating string          `yaml:"justification_cia_rating,omitempty" json:"justification_cia_rating,omitempty"`
	// LINDDUN privacy fields (all optional)
	PiiCategories       []string `yaml:"pii_categories,omitempty" json:"pii_categories,omitempty"`
	DataSubjectCategory string   `yaml:"data_subject_category,omitempty" json:"data_subject_category,omitempty"`
	LawfulBasis         string   `yaml:"lawful_basis,omitempty" json:"lawful_basis,omitempty"`
	RetentionPeriod     string   `yaml:"retention_period,omitempty" json:"retention_period,omitempty"`
	ProcessingPurpose   string   `yaml:"processing_purpose,omitempty" json:"processing_purpose,omitempty"`
	CrossBorderTransfer bool     `yaml:"cross_border_transfer,omitempty" json:"cross_border_transfer,omitempty"`
	// Computed for rule engine: true when len(PiiCategories) > 0
	HasPii            bool   `yaml:"has_pii,omitempty" json:"has_pii,omitempty"`
	HasLawfulBasisSet bool   `yaml:"has_lawful_basis_set,omitempty" json:"has_lawful_basis_set,omitempty"`
	// AI/ML fields (all optional, Phase B.5)
	IsTrainingData    bool `yaml:"is_training_data,omitempty"    json:"is_training_data,omitempty"`
	IsModelWeights    bool `yaml:"is_model_weights,omitempty"    json:"is_model_weights,omitempty"`
	IsEmbeddingVector bool `yaml:"is_embedding_vector,omitempty" json:"is_embedding_vector,omitempty"`
}

// HasPII returns true when the data asset has at least one declared PII category.
func (what DataAsset) HasPII() bool {
	return len(what.PiiCategories) > 0
}

// HasLawfulBasis returns true when a GDPR lawful basis has been declared.
func (what DataAsset) HasLawfulBasis() bool {
	return what.LawfulBasis != ""
}

func (what DataAsset) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

type ByDataAssetTitleSort []*DataAsset

func (what ByDataAssetTitleSort) Len() int      { return len(what) }
func (what ByDataAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
