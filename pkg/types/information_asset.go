package types

// InformationAsset is an organisation-level information asset used by OCTAVE Allegro methodology.
// Unlike TechnicalAsset (which describes a component), an InformationAsset describes a
// logical body of information that may reside in or flow through multiple technical assets.
type InformationAsset struct {
	Id          string `yaml:"id,omitempty"          json:"id,omitempty"`
	Title       string `yaml:"title,omitempty"       json:"title,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Owner       string `yaml:"owner,omitempty"       json:"owner,omitempty"`
	// Containers lists the TechnicalAsset IDs that hold, transmit, or process this information asset.
	Containers []string `yaml:"containers,omitempty" json:"containers,omitempty"`
	// AreasOfConcern are free-form threat descriptions relevant to this information asset.
	AreasOfConcern []string `yaml:"areas_of_concern,omitempty" json:"areas_of_concern,omitempty"`
	// Requirements lists CIA + privacy + regulatory requirements for this information asset.
	Requirements []string `yaml:"requirements,omitempty" json:"requirements,omitempty"`
	// Criticality of the information asset (low/medium/high/very-high/mission-critical).
	Criticality string `yaml:"criticality,omitempty" json:"criticality,omitempty"`
	// Confidentiality classification (public/restricted/confidential/strictly-confidential).
	Confidentiality string `yaml:"confidentiality,omitempty" json:"confidentiality,omitempty"`
	Tags            []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

func (what InformationAsset) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

// IsCritical returns true if the criticality is high, very-high, or mission-critical.
func (what InformationAsset) IsCritical() bool {
	switch what.Criticality {
	case "high", "very-high", "mission-critical":
		return true
	}
	return false
}
