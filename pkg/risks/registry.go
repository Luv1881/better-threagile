package risks

import (
	"fmt"
	"sort"
)

// RulePackEntry describes a curated rule pack in the registry.
type RulePackEntry struct {
	Name        string
	Description string
	URL         string // canonical fetch URL, may include #sha256= and #ttl= fragments
	Methodology string // primary methodology this pack targets
	Embedded    bool   // true if shipped inside the threagile binary
	Source      string // upstream homepage / repo URL
}

// DefaultRegistry is the curated rule pack registry. It includes the embedded packs
// shipped with the binary and known remote packs.
//
// Operators can override entries by providing their own registry file via the
// --rule-pack-registry flag (future work).
var DefaultRegistry = []RulePackEntry{
	{
		Name:        "linddun",
		Description: "LINDDUN privacy threat modeling — 8 rules covering Linkability, Identifiability, Non-repudiation, Detectability, Data Disclosure, Unawareness, and Non-compliance",
		URL:         "embedded://linddun.tar.gz",
		Methodology: "linddun",
		Embedded:    true,
		Source:      "github.com/threagile/threagile/pkg/risks/methodologies/linddun",
	},
	{
		Name:        "pasta",
		Description: "PASTA attack-centric threat modeling — 9 rules covering the seven PASTA stages from Objectives to Risk Analysis",
		URL:         "embedded://pasta.tar.gz",
		Methodology: "pasta",
		Embedded:    true,
		Source:      "github.com/threagile/threagile/pkg/risks/methodologies/pasta",
	},
	{
		Name:        "vast",
		Description: "VAST threat modeling — 8 rules covering Application and Operational threats with business-process criticality weighting",
		URL:         "embedded://vast.tar.gz",
		Methodology: "vast",
		Embedded:    true,
		Source:      "github.com/threagile/threagile/pkg/risks/methodologies/vast",
	},
	{
		Name:        "cloud-native",
		Description: "Cloud-Native Security — 17 rules covering IAM, object storage, managed databases, serverless, containers, and API gateways in cloud-hosted architectures",
		URL:         "embedded://cloud-native.tar.gz",
		Methodology: "cloud-native",
		Embedded:    true,
		Source:      "github.com/threagile/threagile/pkg/risks/methodologies/cloud-native",
	},
	{
		Name:        "supply-chain",
		Description: "Software Supply Chain Security — 10 rules covering SBOM, dependency scanning, build provenance, image signing, branch protection, and SAST (SLSA/CRA aligned)",
		URL:         "embedded://supply-chain.tar.gz",
		Methodology: "stride",
		Embedded:    true,
		Source:      "github.com/threagile/threagile/pkg/risks/methodologies/supply-chain",
	},
	{
		Name:        "ai-ml",
		Description: "AI/ML Security (MITRE ATLAS aligned) — 18 rules covering LLM inference, RAG pipelines, vector stores, training data, model weights, prompt injection, and multi-tenant inference isolation",
		URL:         "embedded://ai-ml.tar.gz",
		Methodology: "stride",
		Embedded:    true,
		Source:      "github.com/threagile/threagile/pkg/risks/methodologies/ai-ml",
	},
	{
		Name:        "octave",
		Description: "OCTAVE Allegro — 8 rules covering information asset containers: access control, backup, logging, transport encryption, third-party exposure, insider threat, recovery, and cross-zone storage",
		URL:         "embedded://octave.tar.gz",
		Methodology: "octave",
		Embedded:    true,
		Source:      "github.com/threagile/threagile/pkg/risks/methodologies/octave",
	},
	{
		Name:        "trike",
		Description: "Trike rights-based threat modeling — 8 rules covering actor trust levels, action matrix coverage, unauthorised read/write, high-trust actor monitoring, privilege accumulation, and residual risk acceptance",
		URL:         "embedded://trike.tar.gz",
		Methodology: "trike",
		Embedded:    true,
		Source:      "github.com/threagile/threagile/pkg/risks/methodologies/trike",
	},
}

// LookupRulePack returns the registry entry for a given pack name, or nil if not found.
func LookupRulePack(name string) *RulePackEntry {
	for i := range DefaultRegistry {
		if DefaultRegistry[i].Name == name {
			return &DefaultRegistry[i]
		}
	}
	return nil
}

// ListRulePacks returns all registered packs sorted by name.
func ListRulePacks() []RulePackEntry {
	out := make([]RulePackEntry, len(DefaultRegistry))
	copy(out, DefaultRegistry)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DescribeRulePack returns a multi-line human-readable description of a pack.
func DescribeRulePack(name string) (string, error) {
	entry := LookupRulePack(name)
	if entry == nil {
		return "", fmt.Errorf("unknown rule pack %q (use `threagile rule-pack list` to see available packs)", name)
	}
	return fmt.Sprintf(
		"Name:        %s\n"+
			"Methodology: %s\n"+
			"Source:      %s\n"+
			"URL:         %s\n"+
			"Embedded:    %v\n\n"+
			"%s",
		entry.Name, entry.Methodology, entry.Source, entry.URL, entry.Embedded, entry.Description,
	), nil
}
