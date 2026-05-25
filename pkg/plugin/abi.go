// Package plugin defines the interfaces for the threagile plugin SDK (Phase J.1).
// Third-party plugins implement one or more of these interfaces and register them
// at init() time or via explicit registration, depending on the plugin ABI used.
//
// # Available plugin types
//
//   - RulePackPlugin:      Custom risk rule packs (compiled-Go alternative to YAML packs)
//   - ImportPlugin:        Custom IaC / spec import adapters
//   - ReportPlugin:        Custom report renderers
//   - SeverityCalculator:  Custom severity scoring logic
//
// # Plugin loading (future work)
//
// Plugins will be loaded as:
//   - Go native: `--plugin-dir /path/to/so` (Linux shared object built with -buildmode=plugin)
//   - WASM:       `--plugin-wasm /path/to/plugin.wasm` (requires WASI runtime)
//
// Both ABIs must implement the same interface set defined in this file.
package plugin

import "github.com/threagile/threagile/pkg/types"

// RulePackPlugin is the interface for custom compiled-Go rule packs.
// Implements the same contract as types.RiskRule but declares a pack-level ID.
type RulePackPlugin interface {
	// PackID returns the unique pack identifier (e.g. "my-org-custom-rules").
	PackID() string
	// Rules returns all RiskRules provided by this plugin.
	Rules() types.RiskRules
}

// ImportPlugin is the interface for custom IaC / API specification import adapters.
type ImportPlugin interface {
	// SourceType returns the source type string (e.g. "cloudformation", "pulumi").
	SourceType() string
	// Import parses raw source data and returns a partial model for merging.
	// The returned model contains only newly discovered assets/links/boundaries;
	// it is merged (not replaced) into the existing model by the import engine.
	Import(data []byte, opts ImportOptions) (*types.Model, error)
}

// ImportOptions carries common options passed to all import adapters.
type ImportOptions struct {
	// Label is a human-readable prefix applied to generated asset titles.
	Label string
	// StrictMode causes the import to fail on unknown resource types (default: warn).
	StrictMode bool
}

// ReportPlugin is the interface for custom report renderers.
type ReportPlugin interface {
	// Format returns the output format identifier (e.g. "confluence", "docx").
	Format() string
	// Render takes the analysed model and produces output bytes.
	Render(model *types.Model, opts RenderOptions) ([]byte, error)
}

// RenderOptions carries rendering options for report plugins.
type RenderOptions struct {
	// OutputPath is the target file path (empty = return bytes only).
	OutputPath string
	// Audience constrains the output: exec | engineer | auditor | all
	Audience string
}

// SeverityCalculator is the interface for custom severity-scoring logic.
// When registered, replaces the default (likelihood × impact) matrix with the
// plugin's calculation. Receives the full model for context.
type SeverityCalculator interface {
	// CalculateSeverity returns an adjusted severity for a risk, given the full model.
	CalculateSeverity(risk *types.Risk, model *types.Model) types.RiskSeverity
}

// Registry holds all registered plugin instances. There is one global Registry
// per binary run; plugins register themselves at init() time.
type Registry struct {
	RulePacks   []RulePackPlugin
	Importers   []ImportPlugin
	Reporters   []ReportPlugin
	Calculators []SeverityCalculator
}

// DefaultRegistry is the global plugin registry.
var DefaultRegistry = &Registry{}

// RegisterRulePack registers a compiled rule pack plugin.
func RegisterRulePack(p RulePackPlugin) {
	DefaultRegistry.RulePacks = append(DefaultRegistry.RulePacks, p)
}

// RegisterImporter registers an import adapter plugin.
func RegisterImporter(p ImportPlugin) {
	DefaultRegistry.Importers = append(DefaultRegistry.Importers, p)
}

// RegisterReporter registers a report renderer plugin.
func RegisterReporter(p ReportPlugin) {
	DefaultRegistry.Reporters = append(DefaultRegistry.Reporters, p)
}

// RegisterSeverityCalculator registers a custom severity calculator.
// Only the first registered calculator is used; subsequent registrations are ignored.
func RegisterSeverityCalculator(p SeverityCalculator) {
	if len(DefaultRegistry.Calculators) == 0 {
		DefaultRegistry.Calculators = append(DefaultRegistry.Calculators, p)
	}
}

// MergeRulePacks returns all rules from registered rule pack plugins,
// merged into the provided base rule set. Plugin rules override base rules with the same ID.
func (r *Registry) MergeRulePacks(base types.RiskRules) types.RiskRules {
	out := make(types.RiskRules, len(base))
	for k, v := range base {
		out[k] = v
	}
	for _, pack := range r.RulePacks {
		for id, rule := range pack.Rules() {
			out[id] = rule
		}
	}
	return out
}
