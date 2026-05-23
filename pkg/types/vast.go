package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// VAST splits threats into two categories: Application and Operational.
type VAST int

const (
	ApplicationThreat VAST = iota // Threat to an application or service
	OperationalThreat             // Threat at the infrastructure/operational level
)

func VASTValues() []TypeEnum {
	return []TypeEnum{
		ApplicationThreat,
		OperationalThreat,
	}
}

var VastTypeDescription = [...]TypeDescription{
	{"application-threat", "Application Threat - threats targeting application logic, code, or data flows"},
	{"operational-threat", "Operational Threat - threats targeting infrastructure, deployment, and operations"},
}

func ParseVAST(value string) (VAST, error) {
	value = strings.TrimSpace(value)
	for _, candidate := range VASTValues() {
		if candidate.String() == value {
			return candidate.(VAST), nil
		}
	}
	return ApplicationThreat, fmt.Errorf("unable to parse VAST value %q", value)
}

func (what VAST) String() string {
	return VastTypeDescription[what].Name
}

func (what VAST) Explain() string {
	return VastTypeDescription[what].Description
}

func (what VAST) Title() string {
	return [...]string{"Application Threat", "Operational Threat"}[what]
}

func (what VAST) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *VAST) UnmarshalJSON(data []byte) error {
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

func (what VAST) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *VAST) UnmarshalYAML(node *yaml.Node) error {
	value, err := what.find(node.Value)
	if err != nil {
		return err
	}
	*what = value
	return nil
}

func (what VAST) find(value string) (VAST, error) {
	for index, description := range VastTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return VAST(index), nil
		}
	}
	return VAST(0), fmt.Errorf("unknown VAST value %q", value)
}
