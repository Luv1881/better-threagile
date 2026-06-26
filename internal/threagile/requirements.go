package threagile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/requirements"
)

func (what *Threagile) initRequirements() *Threagile {
	var format string
	var outputFile string

	cmd := &cobra.Command{
		Use:   "requirements",
		Short: "Generate testable security requirements from the model's findings",
		Long: `Turn the threat model into an actionable security backlog: one deduplicated,
testable requirement per still-at-risk finding category, derived from the rule's
own remediation, verification check, CWE and the affected assets. Output a
Markdown checklist for your tracker, Gherkin scenario stubs for acceptance tests,
or JSON. Deterministic, no AI.

Examples:
  threagile requirements --model threagile.yaml
  threagile requirements --model threagile.yaml --format gherkin --output security.feature
  threagile requirements --model threagile.yaml --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("requirements: failed to read and analyze model: %w", err)
			}

			reqs := requirements.Build(r.ParsedModel)

			var rendered string
			switch strings.ToLower(format) {
			case "", "markdown", "md":
				rendered = requirements.FormatMarkdown(reqs)
			case "gherkin", "feature":
				rendered = requirements.FormatGherkin(r.ParsedModel.Title, reqs)
			case "json":
				rendered, err = requirements.FormatJSON(reqs)
			default:
				return fmt.Errorf("requirements: unknown --format %q (want markdown, gherkin, or json)", format)
			}
			if err != nil {
				return fmt.Errorf("requirements: render: %w", err)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(filepath.Clean(outputFile), []byte(rendered), 0600); writeErr != nil { // #nosec G304 -- operator-supplied --output path
					return fmt.Errorf("requirements: write %q: %w", outputFile, writeErr)
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "markdown", "output format: markdown, gherkin, or json")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the requirements to this file")

	what.rootCmd.AddCommand(cmd)
	return what
}
