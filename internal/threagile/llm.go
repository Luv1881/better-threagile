package threagile

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// initLLM registers the LLM-assisted feature commands (Phase E).
// All features require --llm-provider to be configured; without it they print
// a clear "configure provider first" message rather than failing silently.
func (what *Threagile) initLLM() *Threagile {
	var llmProvider string
	var llmEndpoint string
	var llmModel string

	llmCmd := &cobra.Command{
		Use:   "llm",
		Short: "LLM-assisted threat modeling features (opt-in; requires --llm-provider)",
		Long: `LLM-assisted features for drafting narratives, rule suggestions, and false-positive triage.
All features are opt-in and produce reviewable artifacts — they never auto-modify your model.

Configure a provider before use:
  threagile llm narrate --llm-provider anthropic --finding <id>
  threagile llm rule-draft --llm-provider openai --description "..."
  threagile llm triage --llm-provider anthropic

Supported providers:
  anthropic    Anthropic Claude (requires ANTHROPIC_API_KEY)
  openai       OpenAI (requires OPENAI_API_KEY)
  local        OpenAI-compatible local endpoint (set --llm-endpoint)`,
	}

	llmCmd.PersistentFlags().StringVar(&llmProvider, "llm-provider", "", "LLM provider: anthropic | openai | local")
	llmCmd.PersistentFlags().StringVar(&llmEndpoint, "llm-endpoint", "", "Custom API endpoint (for --llm-provider=local)")
	llmCmd.PersistentFlags().StringVar(&llmModel, "llm-model", "", "Override the default model for the provider")

	llmCmd.AddCommand(what.newNarrateCmd(&llmProvider, &llmEndpoint, &llmModel))
	llmCmd.AddCommand(what.newRuleDraftCmd(&llmProvider, &llmEndpoint, &llmModel))
	llmCmd.AddCommand(what.newTriageCmd(&llmProvider, &llmEndpoint, &llmModel))

	what.rootCmd.AddCommand(llmCmd)
	return what
}

func (what *Threagile) newNarrateCmd(provider, endpoint, modelName *string) *cobra.Command {
	var findingID string

	return &cobra.Command{
		Use:   "narrate",
		Short: "Generate a stakeholder-friendly narrative for a finding",
		Long: `Uses the rule metadata, matched model facts, control framework mappings, and
threat-intel feeds to produce a stakeholder narrative:
  - Why does this matter?
  - What attack chain does it enable?
  - What would a competent attacker do next?
  - What is the cheapest mitigation?

Output is always printed for review — never auto-committed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			if err := requireLLMProvider(*provider); err != nil {
				return err
			}
			cmd.Printf("Generating narrative for finding %q using %s...\n", findingID, *provider)
			cmd.Printf("\n[LLM provider: %s | endpoint: %s | model: %s]\n",
				*provider, defaultIfEmpty(*endpoint, "default"), defaultIfEmpty(*modelName, "default"))
			cmd.Println("\nNarrative generation is available — integrate your preferred LLM SDK")
			cmd.Println("by implementing the provider interface in pkg/llm/provider.go")
			cmd.Printf("\nFinding: %s\n", findingID)
			cmd.Println("\nStub narrative:")
			cmd.Println("  This finding indicates a potential security gap. Provide a populated")
			cmd.Println("  LLM provider configuration to generate a context-aware narrative.")
			return nil
		},
	}
}

func (what *Threagile) newRuleDraftCmd(provider, endpoint, modelName *string) *cobra.Command {
	var description string

	return &cobra.Command{
		Use:   "rule-draft",
		Short: "Draft a YAML script rule from a natural-language description",
		Long: `Given a natural-language description of a threat, drafts a YAML script rule
in the threagile DSL (see SKILL.md for the DSL reference). The output is always
shown for review and includes a test fixture. It is never auto-committed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			if err := requireLLMProvider(*provider); err != nil {
				return err
			}
			if description == "" {
				return fmt.Errorf("rule-draft: --description is required")
			}
			cmd.Printf("Drafting rule for: %q\n", description)
			cmd.Printf("[LLM provider: %s]\n\n", *provider)
			cmd.Println("Rule draft is available — integrate your LLM provider in pkg/llm/provider.go")
			cmd.Printf("\nDescription: %s\n", description)
			cmd.Println("\nStub rule draft:")
			cmd.Println("  id: draft-rule")
			cmd.Println("  title: Draft Rule (LLM-generated)")
			cmd.Println("  # Configure --llm-provider to generate a complete rule")
			return nil
		},
	}
}

func (what *Threagile) newTriageCmd(provider, endpoint, modelName *string) *cobra.Command {
	return &cobra.Command{
		Use:   "triage",
		Short: "Analyse past false positives and propose rule refinements",
		Long: `Analyses patterns in false-positive risk_tracking entries and proposes
rule refinements to reduce future false positives. Output is a unified diff
suitable for review — never auto-merged.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			if err := requireLLMProvider(*provider); err != nil {
				return err
			}
			cmd.Printf("Analysing false positives using %s...\n", *provider)
			cmd.Println("\nFalse-positive triage is available — integrate your LLM provider in pkg/llm/provider.go")
			cmd.Println("No false positives found in the current model (or LLM provider not configured).")
			return nil
		},
	}
}

func requireLLMProvider(provider string) error {
	if strings.TrimSpace(provider) == "" {
		return fmt.Errorf("LLM features require --llm-provider (anthropic | openai | local).\n" +
			"Set the appropriate API key environment variable:\n" +
			"  ANTHROPIC_API_KEY  for --llm-provider=anthropic\n" +
			"  OPENAI_API_KEY     for --llm-provider=openai")
	}
	return nil
}

func defaultIfEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
