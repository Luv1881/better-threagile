package types

// ThreatScenario represents a PASTA attack scenario documenting a specific threat actor,
// their capabilities, the entry points they use, and the kill chain they would follow.
type ThreatScenario struct {
	Id                 string   `json:"id,omitempty" yaml:"id,omitempty"`
	Title              string   `json:"title,omitempty" yaml:"title,omitempty"`
	Description        string   `json:"description,omitempty" yaml:"description,omitempty"`
	// script-kiddie, insider, nation-state, opportunist, competitor, hacktivist
	ActorCapabilities  string   `json:"actor_capabilities,omitempty" yaml:"actor_capabilities,omitempty"`
	EntryAssets        []string `json:"entry_assets,omitempty" yaml:"entry_assets,omitempty"`
	KillChainSteps     []string `json:"kill_chain_steps,omitempty" yaml:"kill_chain_steps,omitempty"`
	MitigatedBy        []string `json:"mitigated_by,omitempty" yaml:"mitigated_by,omitempty"`
	// internet, partner-vpn, internal-lan, air-gapped
	AttackVector       string   `json:"attack_vector,omitempty" yaml:"attack_vector,omitempty"`
}
