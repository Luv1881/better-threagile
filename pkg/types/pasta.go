package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// PASTA represents the seven stages of the Process for Attack Simulation and Threat Analysis methodology.
type PASTA int

const (
	StageObjectives    PASTA = iota // Stage I: Define Objectives
	StageScope                      // Stage II: Define Technical Scope
	StageDecomposition              // Stage III: Application Decomposition
	StageThreatAnalysis             // Stage IV: Threat Analysis
	StageVulnAnalysis               // Stage V: Weakness and Vulnerability Analysis
	StageAttackModeling             // Stage VI: Attack Modeling and Simulation
	StageRiskAnalysis               // Stage VII: Risk Analysis and Management
)

func PASTAValues() []TypeEnum {
	return []TypeEnum{
		StageObjectives,
		StageScope,
		StageDecomposition,
		StageThreatAnalysis,
		StageVulnAnalysis,
		StageAttackModeling,
		StageRiskAnalysis,
	}
}

var PastaTypeDescription = [...]TypeDescription{
	{"stage-objectives", "Stage I: Define Business and Security Objectives"},
	{"stage-scope", "Stage II: Define Technical Scope"},
	{"stage-decomposition", "Stage III: Application Decomposition and Analysis"},
	{"stage-threat-analysis", "Stage IV: Threat Analysis"},
	{"stage-vuln-analysis", "Stage V: Weakness and Vulnerability Analysis"},
	{"stage-attack-modeling", "Stage VI: Attack Modeling and Simulation"},
	{"stage-risk-analysis", "Stage VII: Risk Analysis and Management"},
}

func ParsePASTA(value string) (PASTA, error) {
	value = strings.TrimSpace(value)
	for _, candidate := range PASTAValues() {
		if candidate.String() == value {
			return candidate.(PASTA), nil
		}
	}
	return StageObjectives, fmt.Errorf("unable to parse PASTA stage value %q", value)
}

func (what PASTA) String() string {
	return PastaTypeDescription[what].Name
}

func (what PASTA) Explain() string {
	return PastaTypeDescription[what].Description
}

func (what PASTA) Title() string {
	return [...]string{
		"Stage I: Objectives",
		"Stage II: Scope",
		"Stage III: Decomposition",
		"Stage IV: Threat Analysis",
		"Stage V: Vuln Analysis",
		"Stage VI: Attack Modeling",
		"Stage VII: Risk Analysis",
	}[what]
}

func (what PASTA) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *PASTA) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	value, err := what.find(text)
	if err != nil {
		return err
	}
	*what = value
	return nil
}

func (what PASTA) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *PASTA) UnmarshalYAML(node *yaml.Node) error {
	value, err := what.find(node.Value)
	if err != nil {
		return err
	}
	*what = value
	return nil
}

func (what PASTA) find(value string) (PASTA, error) {
	for index, description := range PastaTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return PASTA(index), nil
		}
	}
	return PASTA(0), fmt.Errorf("unknown PASTA stage value %q", value)
}
