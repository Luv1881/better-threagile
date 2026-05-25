package types

// ControlMapping holds optional compliance control identifiers for a risk rule.
// Fields are keyed by framework name (YAML and JSON).
// A rule with no controls block simply has a nil pointer in RiskCategory.Controls.
type ControlMapping struct {
	NIST80053   []string `yaml:"nist_800_53,omitempty" json:"nist_800_53,omitempty"`
	ISO27001    []string `yaml:"iso_27001,omitempty" json:"iso_27001,omitempty"`
	SOC2CC      []string `yaml:"soc2_cc,omitempty" json:"soc2_cc,omitempty"`
	PCIDSS4     []string `yaml:"pci_dss_4,omitempty" json:"pci_dss_4,omitempty"`
	HIPAA       []string `yaml:"hipaa,omitempty" json:"hipaa,omitempty"`
	NIS2        []string `yaml:"nis2,omitempty" json:"nis2,omitempty"`
	CMMC        []string `yaml:"cmmc,omitempty" json:"cmmc,omitempty"`
	OWASPTop10  []string `yaml:"owasp_top10_2021,omitempty" json:"owasp_top10_2021,omitempty"`
	ASVS4       []string `yaml:"asvs_4,omitempty" json:"asvs_4,omitempty"`
	MITREAttack []string `yaml:"mitre_attack,omitempty" json:"mitre_attack,omitempty"`
}

// SupportedFrameworks lists all framework keys accepted by the coverage command.
var SupportedFrameworks = []string{
	"nist_800_53",
	"iso_27001",
	"soc2_cc",
	"pci_dss_4",
	"hipaa",
	"nis2",
	"cmmc",
	"owasp_top10_2021",
	"asvs_4",
	"mitre_attack",
}

// ControlsFor returns the control IDs for the named framework, or nil if the framework
// is unknown or no mapping exists for this framework on this control set.
func (c *ControlMapping) ControlsFor(framework string) []string {
	if c == nil {
		return nil
	}
	switch framework {
	case "nist_800_53":
		return c.NIST80053
	case "iso_27001":
		return c.ISO27001
	case "soc2_cc":
		return c.SOC2CC
	case "pci_dss_4":
		return c.PCIDSS4
	case "hipaa":
		return c.HIPAA
	case "nis2":
		return c.NIS2
	case "cmmc":
		return c.CMMC
	case "owasp_top10_2021":
		return c.OWASPTop10
	case "asvs_4":
		return c.ASVS4
	case "mitre_attack":
		return c.MITREAttack
	}
	return nil
}

// FrameworkTitle returns the human-readable title of a framework key.
func FrameworkTitle(key string) string {
	switch key {
	case "nist_800_53":
		return "NIST SP 800-53 Rev 5"
	case "iso_27001":
		return "ISO/IEC 27001:2022"
	case "soc2_cc":
		return "SOC 2 Trust Services Criteria"
	case "pci_dss_4":
		return "PCI-DSS v4.0"
	case "hipaa":
		return "HIPAA Security Rule"
	case "nis2":
		return "NIS2 Directive"
	case "cmmc":
		return "CMMC Level 2"
	case "owasp_top10_2021":
		return "OWASP Top 10 (2021)"
	case "asvs_4":
		return "OWASP ASVS v4.0"
	case "mitre_attack":
		return "MITRE ATT&CK Enterprise"
	}
	return key
}
