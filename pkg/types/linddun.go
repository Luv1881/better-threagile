package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// LINDDUN is a privacy threat modeling methodology with seven threat categories.
type LINDDUN int

const (
	Linking           LINDDUN = iota // Linkability - linking items of interest without knowing their identity
	Identifying                      // Identifiability - identifying a person from data
	NonRepudiationL                  // Non-repudiation - inability to deny actions
	Detecting                        // Detectability - deducing whether something exists
	DataDisclosure                   // Disclosure of information - exposing data to unauthorized parties
	Unawareness                      // Unawareness - individuals unaware of data processing
	NonCompliance                    // Non-compliance - failure to comply with data protection rules
)

func LINDDUNValues() []TypeEnum {
	return []TypeEnum{
		Linking,
		Identifying,
		NonRepudiationL,
		Detecting,
		DataDisclosure,
		Unawareness,
		NonCompliance,
	}
}

var LinddunTypeDescription = [...]TypeDescription{
	{"linking", "Linkability - ability to link two items of interest without knowing the identity"},
	{"identifying", "Identifiability - ability to identify a natural person"},
	{"non-repudiation", "Non-repudiation - inability to deny having performed an action"},
	{"detecting", "Detectability - ability to detect whether a data item exists"},
	{"data-disclosure", "Disclosure of information - exposing data to someone not authorized"},
	{"unawareness", "Unawareness - individuals unaware of collection or processing of personal data"},
	{"non-compliance", "Non-compliance - failure to comply with data protection legislation or policies"},
}

func ParseLINDDUN(value string) (LINDDUN, error) {
	value = strings.TrimSpace(value)
	for _, candidate := range LINDDUNValues() {
		if candidate.String() == value {
			return candidate.(LINDDUN), nil
		}
	}
	return Linking, fmt.Errorf("unable to parse LINDDUN value %q", value)
}

func (what LINDDUN) String() string {
	return LinddunTypeDescription[what].Name
}

func (what LINDDUN) Explain() string {
	return LinddunTypeDescription[what].Description
}

func (what LINDDUN) Title() string {
	return [...]string{"Linking", "Identifying", "Non-Repudiation", "Detecting", "Data Disclosure", "Unawareness", "Non-Compliance"}[what]
}

func (what LINDDUN) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *LINDDUN) UnmarshalJSON(data []byte) error {
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

func (what LINDDUN) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *LINDDUN) UnmarshalYAML(node *yaml.Node) error {
	value, err := what.find(node.Value)
	if err != nil {
		return err
	}
	*what = value
	return nil
}

func (what LINDDUN) find(value string) (LINDDUN, error) {
	for index, description := range LinddunTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return LINDDUN(index), nil
		}
	}
	return LINDDUN(0), fmt.Errorf("unknown LINDDUN value %q", value)
}
