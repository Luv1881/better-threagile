package types

import (
	"sort"
)

type TechnicalAsset struct {
	Id                      string                `json:"id,omitempty" yaml:"id,omitempty"`
	Title                   string                `json:"title,omitempty" yaml:"title,omitempty"`
	Description             string                `json:"description,omitempty" yaml:"description,omitempty"`
	Usage                   Usage                 `json:"usage,omitempty" yaml:"usage,omitempty"`
	Type                    TechnicalAssetType    `json:"type,omitempty" yaml:"type,omitempty"`
	Size                    TechnicalAssetSize    `json:"size,omitempty" yaml:"size,omitempty"`
	Technologies            TechnologyList        `json:"technologies,omitempty" yaml:"technologies,omitempty"`
	Machine                 TechnicalAssetMachine `json:"machine,omitempty" yaml:"machine,omitempty"`
	Internet                bool                  `json:"internet,omitempty" yaml:"internet,omitempty"`
	MultiTenant             bool                  `json:"multi_tenant,omitempty" yaml:"multi_tenant,omitempty"`
	Redundant               bool                  `json:"redundant,omitempty" yaml:"redundant,omitempty"`
	CustomDevelopedParts    bool                  `json:"custom_developed_parts,omitempty" yaml:"custom_developed_parts,omitempty"`
	OutOfScope              bool                  `json:"out_of_scope,omitempty" yaml:"out_of_scope,omitempty"`
	UsedAsClientByHuman     bool                  `json:"used_as_client_by_human,omitempty" yaml:"used_as_client_by_human,omitempty"`
	Encryption              EncryptionStyle       `json:"encryption,omitempty" yaml:"encryption"`
	JustificationOutOfScope string                `json:"justification_out_of_scope,omitempty" yaml:"justification_out_of_scope,omitempty"`
	Owner                   string                `json:"owner,omitempty" yaml:"owner,omitempty"`
	Confidentiality         Confidentiality       `json:"confidentiality,omitempty" yaml:"confidentiality,omitempty"`
	Integrity               Criticality           `json:"integrity,omitempty" yaml:"integrity,omitempty"`
	Availability            Criticality           `json:"availability,omitempty" yaml:"availability,omitempty"`
	JustificationCiaRating  string                `json:"justification_cia_rating,omitempty" yaml:"justification_cia_rating,omitempty"`
	Tags                    []string              `json:"tags,omitempty" yaml:"tags,omitempty"`
	DataAssetsProcessed     []string              `json:"data_assets_processed,omitempty" yaml:"data_assets_processed,omitempty"`
	DataAssetsStored        []string              `json:"data_assets_stored,omitempty" yaml:"data_assets_stored,omitempty"`
	DataFormatsAccepted     []DataFormat          `json:"data_formats_accepted,omitempty" yaml:"data_formats_accepted,omitempty"`
	CommunicationLinks      []*CommunicationLink  `json:"communication_links,omitempty" yaml:"communication_links,omitempty"`
	DiagramTweakOrder       int                   `json:"diagram_tweak_order,omitempty" yaml:"diagram_tweak_order,omitempty"`
	RAA                     float64               `json:"raa,omitempty" yaml:"raa,omitempty"` // will be set by separate calculation step
	// LINDDUN privacy fields (all optional)
	IsPiiProcessor   bool `json:"is_pii_processor,omitempty" yaml:"is_pii_processor,omitempty"`
	IsPiiController  bool `json:"is_pii_controller,omitempty" yaml:"is_pii_controller,omitempty"`
	DataMinimisation bool `json:"data_minimisation,omitempty" yaml:"data_minimisation,omitempty"`
	// PASTA attack-surface fields (all optional)
	EntryPointType                 string `json:"entry_point_type,omitempty" yaml:"entry_point_type,omitempty"`
	AttackSurfaceExposure          string `json:"attack_surface_exposure,omitempty" yaml:"attack_surface_exposure,omitempty"`
	RequiresAuthenticationStrength string `json:"requires_authentication_strength,omitempty" yaml:"requires_authentication_strength,omitempty"`
	// VAST business-process fields (all optional)
	SupportedBusinessProcesses []string `json:"supported_business_processes,omitempty" yaml:"supported_business_processes,omitempty"`
	// AI/ML fields (all optional, Phase B.5)
	IsLLMInference    bool     `json:"is_llm_inference,omitempty"      yaml:"is_llm_inference,omitempty"`
	IsVectorStore     bool     `json:"is_vector_store,omitempty"       yaml:"is_vector_store,omitempty"`
	RAGContextSources []string `json:"rag_context_sources,omitempty"   yaml:"rag_context_sources,omitempty"`
}

func (what TechnicalAsset) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what TechnicalAsset) HighestSensitivityScore() float64 {
	return what.Confidentiality.AttackerAttractivenessForAsset() +
		what.Integrity.AttackerAttractivenessForAsset() +
		what.Availability.AttackerAttractivenessForAsset()
}

func (what TechnicalAsset) DataFormatsAcceptedSorted() []DataFormat {
	result := make([]DataFormat, 0)
	result = append(result, what.DataFormatsAccepted...)
	sort.Sort(ByDataFormatAcceptedSort(result))
	return result
}

func (what TechnicalAsset) CommunicationLinksSorted() []*CommunicationLink {
	result := make([]*CommunicationLink, 0)
	result = append(result, what.CommunicationLinks...)
	sort.Sort(ByTechnicalCommunicationLinkTitleSort(result))
	return result
}

type ByTechnicalAssetRAAAndTitleSort []*TechnicalAsset

func (what ByTechnicalAssetRAAAndTitleSort) Len() int      { return len(what) }
func (what ByTechnicalAssetRAAAndTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalAssetRAAAndTitleSort) Less(i, j int) bool {
	raaLeft := what[i].RAA
	raaRight := what[j].RAA
	if raaLeft == raaRight {
		return what[i].Title < what[j].Title
	}
	return raaLeft > raaRight
}

type ByTechnicalAssetTitleSort []*TechnicalAsset

func (what ByTechnicalAssetTitleSort) Len() int      { return len(what) }
func (what ByTechnicalAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type ByOrderAndIdSort []*TechnicalAsset

func (what ByOrderAndIdSort) Len() int      { return len(what) }
func (what ByOrderAndIdSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByOrderAndIdSort) Less(i, j int) bool {
	if what[i].DiagramTweakOrder == what[j].DiagramTweakOrder {
		return what[i].Id > what[j].Id
	}
	return what[i].DiagramTweakOrder < what[j].DiagramTweakOrder
}
