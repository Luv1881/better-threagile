package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/prioritize"
	"github.com/threagile/threagile/pkg/score"
)

func (what *Threagile) initSummary() *Threagile {
	var format string
	var outputFile string
	var top int

	cmd := &cobra.Command{
		Use:   "summary",
		Short: "One sprint/PR-ready scorecard: health score + the top findings to fix",
		Long: `Produce a single, shareable scorecard from one analysis pass — the threat-model
health score (0-100 / A-F) plus the top findings to fix first with their
remediation. Ideal as a recurring sprint artifact or a pull-request comment, so a
team tracks one number and a short, actionable to-do list instead of wading
through a full report. Deterministic, no AI.

Examples:
  threagile summary --model threagile.yaml
  threagile summary --model threagile.yaml --format markdown --output summary.md
  threagile summary --model threagile.yaml --top 3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("summary: failed to read and analyze model: %w", err)
			}

			// One analysis pass feeds both the score and the prioritized findings.
			sc := score.Compute(r.ParsedModel)
			pr := prioritize.Analyze(r.ParsedModel)
			items := pr.Top(top)

			var rendered string
			switch strings.ToLower(format) {
			case "", "markdown", "md":
				rendered = renderSummaryMarkdown(r.ParsedModel.Title, sc, pr, items)
			case "text":
				rendered = renderSummaryText(r.ParsedModel.Title, sc, pr, items)
			case "json":
				rendered, err = renderSummaryJSON(sc, pr, items)
			default:
				return fmt.Errorf("summary: unknown --format %q (want markdown, text, or json)", format)
			}
			if err != nil {
				return fmt.Errorf("summary: render: %w", err)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(filepath.Clean(outputFile), []byte(rendered), 0600); writeErr != nil { // #nosec G304 -- operator-supplied --output path
					return fmt.Errorf("summary: write %q: %w", outputFile, writeErr)
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "markdown", "output format: markdown, text, or json")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the scorecard to this file")
	cmd.Flags().IntVar(&top, "top", 5, "number of top findings to list (0 = all)")

	what.rootCmd.AddCommand(cmd)
	return what
}

func renderSummaryMarkdown(title string, sc *score.Report, pr *prioritize.Result, items []prioritize.Item) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Threat-model summary: %s\n\n", title)
	fmt.Fprintf(&b, "**Score: %d/100 (grade %s)** · completeness %.0f%% · posture %.0f%% · %d still at risk\n",
		sc.Overall, sc.Grade, sc.Completeness*100, sc.Posture*100, pr.TotalAtRisk)
	for _, n := range sc.Notes {
		fmt.Fprintf(&b, "\n> ⚠️ %s\n", n)
	}
	b.WriteString("\n")
	b.WriteString(prioritize.FormatMarkdown(items, pr.TotalAtRisk))
	return b.String()
}

func renderSummaryText(title string, sc *score.Report, pr *prioritize.Result, items []prioritize.Item) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Threat-model summary: %s\n", title)
	fmt.Fprintf(&b, "Score: %d/100 (grade %s) · completeness %.0f%% · posture %.0f%% · %d still at risk\n",
		sc.Overall, sc.Grade, sc.Completeness*100, sc.Posture*100, pr.TotalAtRisk)
	for _, n := range sc.Notes {
		fmt.Fprintf(&b, "  ! %s\n", n)
	}
	b.WriteString("\n")
	b.WriteString(prioritize.FormatText(items, pr.TotalAtRisk))
	return b.String()
}

func renderSummaryJSON(sc *score.Report, pr *prioritize.Result, items []prioritize.Item) (string, error) {
	out, err := json.MarshalIndent(map[string]any{
		"score":         sc.Overall,
		"grade":         sc.Grade,
		"completeness":  sc.Completeness,
		"posture":       sc.Posture,
		"still_at_risk": pr.TotalAtRisk,
		"notes":         sc.Notes,
		"top_findings":  items,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}
