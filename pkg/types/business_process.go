package types

// BusinessProcess represents a VAST business process — a logical unit of
// business functionality supported by technical assets.
type BusinessProcess struct {
	Id                          string      `json:"id,omitempty" yaml:"id,omitempty"`
	Title                       string      `json:"title,omitempty" yaml:"title,omitempty"`
	Description                 string      `json:"description,omitempty" yaml:"description,omitempty"`
	Criticality                 Criticality `json:"criticality,omitempty" yaml:"criticality,omitempty"`
	Owner                       string      `json:"owner,omitempty" yaml:"owner,omitempty"`
	SupportedByTechnicalAssets  []string    `json:"supported_by_technical_assets,omitempty" yaml:"supported_by_technical_assets,omitempty"`
	DataAssetsInFlight          []string    `json:"data_assets_in_flight,omitempty" yaml:"data_assets_in_flight,omitempty"`
}
