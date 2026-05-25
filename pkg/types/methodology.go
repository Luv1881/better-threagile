package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Methodology int

const (
	StrideMethodology    Methodology = iota
	LinddunMethodology
	PastaMethodology
	VastMethodology
	OctaveMethodology
	TrikeMethodology
	CloudNativeMethodology
)

func MethodologyValues() []TypeEnum {
	return []TypeEnum{
		StrideMethodology,
		LinddunMethodology,
		PastaMethodology,
		VastMethodology,
		OctaveMethodology,
		TrikeMethodology,
		CloudNativeMethodology,
	}
}

var MethodologyDescription = [...]TypeDescription{
	{"stride", "STRIDE - Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege"},
	{"linddun", "LINDDUN - Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of information, Unawareness, Non-compliance"},
	{"pasta", "PASTA - Process for Attack Simulation and Threat Analysis"},
	{"vast", "VAST - Visual, Agile and Simple Threat modeling"},
	{"octave", "OCTAVE - Operationally Critical Threat, Asset, and Vulnerability Evaluation"},
	{"trike", "Trike - Risk-based security auditing framework"},
	{"cloud-native", "Cloud-Native Security - IAM, network, data, container and serverless risk rules for cloud-hosted architectures"},
}

func ParseMethodology(value string) (Methodology, error) {
	value = strings.TrimSpace(value)
	for _, candidate := range MethodologyValues() {
		if candidate.String() == value {
			return candidate.(Methodology), nil
		}
	}
	return StrideMethodology, fmt.Errorf("unable to parse methodology %q (valid values: stride, linddun, pasta, vast, octave, trike, cloud-native)", value)
}

func (what Methodology) String() string {
	return MethodologyDescription[what].Name
}

func (what Methodology) Explain() string {
	return MethodologyDescription[what].Description
}

func (what Methodology) Title() string {
	return [...]string{"STRIDE", "LINDDUN", "PASTA", "VAST", "OCTAVE", "Trike", "Cloud-Native"}[what]
}

func (what Methodology) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Methodology) UnmarshalJSON(data []byte) error {
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

func (what Methodology) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *Methodology) UnmarshalYAML(node *yaml.Node) error {
	value, err := what.find(node.Value)
	if err != nil {
		return err
	}
	*what = value
	return nil
}

func (what Methodology) find(value string) (Methodology, error) {
	for index, description := range MethodologyDescription {
		if strings.EqualFold(value, description.Name) {
			return Methodology(index), nil
		}
	}
	return Methodology(0), fmt.Errorf("unknown methodology value %q", value)
}
