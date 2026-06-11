package types

type RiskRule interface {
	Category() *RiskCategory
	SupportedTags() []string
	GenerateRisks(*Model) ([]*Risk, error)
}

// ModelMapRiskRule is an optional interface for risk rules that can generate
// risks from a pre-converted model map, avoiding a redundant marshal/unmarshal
// of the whole model when many rules are evaluated against the same model.
type ModelMapRiskRule interface {
	RiskRule
	GenerateRisksFromMap(modelMap map[string]any) ([]*Risk, error)
}

type RiskRules map[string]RiskRule

func (what RiskRules) Merge(rules RiskRules) RiskRules {
	for key, value := range rules {
		what[key] = value
	}

	return what
}
