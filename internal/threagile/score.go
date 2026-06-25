package threagile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/score"
)

func (what *Threagile) initScore() *Threagile {
	var format string
	var outputFile string
	var minScore int

	cmd := &cobra.Command{
		Use:   "score",
		Short: "Compute a 0-100 threat-model health score (completeness + risk posture)",
		Long: `Reduce the model to a single, trackable 0-100 score (and an A-F grade) that a
team can watch every sprint, gate on, and show as a badge. No AI.

It blends two deterministic measures:
  completeness — is the model trustworthy? (owners, trust boundaries, link
                 protocols, data-asset usage, basic metadata)
  posture      — how much identified risk is actually handled? (still-at-risk
                 findings weighted by severity, credited by tracking status)

Use --min to fail CI (exit 3) when the score drops below a floor, so a team can
ratchet quality up over time.

Examples:
  threagile score --model threagile.yaml
  threagile score --model threagile.yaml --format markdown --output score.md
  threagile score --model threagile.yaml --format shields > badge.json
  threagile score --model threagile.yaml --min 70`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("score: failed to read and analyze model: %w", err)
			}

			report := score.Compute(r.ParsedModel)

			var rendered string
			switch strings.ToLower(format) {
			case "", "text":
				rendered = score.FormatText(report)
			case "markdown", "md":
				rendered = score.FormatMarkdown(report)
			case "json":
				rendered, err = score.FormatJSON(report)
			case "shields", "badge":
				rendered, err = score.FormatShields(report)
			default:
				return fmt.Errorf("score: unknown --format %q (want text, markdown, json, or shields)", format)
			}
			if err != nil {
				return fmt.Errorf("score: render: %w", err)
			}

			if outputFile != "" {
				clean := filepath.Clean(outputFile)
				if writeErr := os.WriteFile(clean, []byte(rendered), 0600); writeErr != nil { // #nosec G304 -- operator-supplied --output path
					return fmt.Errorf("score: write %q: %w", clean, writeErr)
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)

			if cmd.Flags().Changed("min") && report.Overall < minScore {
				return &exitCodeError{code: 3, msg: fmt.Sprintf("score %d is below the required minimum of %d", report.Overall, minScore)}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "text", "output format: text, markdown, json, or shields")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the rendered report to this file")
	cmd.Flags().IntVar(&minScore, "min", 0, "fail (exit 3) if the score is below this floor")

	what.rootCmd.AddCommand(cmd)
	return what
}
