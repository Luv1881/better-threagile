package types

// TrikeActor represents a subject in the Trike threat-modeling methodology.
// Trike models risk as (subject × action × object) cells in an action matrix;
// each cell has an "acceptable risk" value from the organisation's perspective.
type TrikeActor struct {
	Id          string `yaml:"id,omitempty"          json:"id,omitempty"`
	Title       string `yaml:"title,omitempty"       json:"title,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Type: human | system | external-partner | regulator
	Type string `yaml:"type,omitempty" json:"type,omitempty"`
	// TrustLevel: untrusted | low | medium | high | admin
	TrustLevel string   `yaml:"trust_level,omitempty" json:"trust_level,omitempty"`
	Tags       []string `yaml:"tags,omitempty"        json:"tags,omitempty"`
}

// TrustScore returns an integer trust level (0 = untrusted, 4 = admin)
// used for impact calculation in the Trike matrix engine.
func (a *TrikeActor) TrustScore() int {
	switch a.TrustLevel {
	case "untrusted":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "admin":
		return 4
	}
	return 0
}
