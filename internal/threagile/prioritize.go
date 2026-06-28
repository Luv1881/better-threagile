package threagile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/prioritize"
	"github.com/threagile/threagile/pkg/source"
	"github.com/threagile/threagile/pkg/types"
)

func (what *Threagile) initPrioritize() *Threagile {
	var format string
	var outputFile string
	var top int
	var minSeverity string

	cmd := &cobra.Command{
		Use:   "prioritize",
		Short: "Rank still-at-risk findings by exploitability and show how to fix them",
		Long: `Answer the question developers actually ask — "which of these do I fix first,
and how?" — by ranking still-at-risk findings on a composite exploitability score
and attaching each rule's remediation guidance.

The score is additive over normalized factors: severity, internet exposure,
attack-path reachability to crown-jewel data (from the real graph, not
self-declared metadata), data sensitivity, and confidence. No AI.

Examples:
  threagile prioritize --model threagile.yaml
  threagile prioritize --model threagile.yaml --top 5
  threagile prioritize --model threagile.yaml --min-severity high --format markdown`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("prioritize: failed to read and analyze model: %w", err)
			}

			result := prioritize.Analyze(r.ParsedModel)

			// Annotate each finding with the source file:line of its asset so the
			// reader can jump straight to what needs fixing (best-effort).
			locs := source.EntityLines(what.config.GetInputFile())
			for i := range result.Items {
				it := &result.Items[i]
				if l, ok := locs[it.AssetTitle]; ok {
					it.SourceFile, it.SourceLine = l.File, l.Line
				} else if l, ok := locs[it.AssetID]; ok {
					it.SourceFile, it.SourceLine = l.File, l.Line
				}
			}

			items := result.Items
			if minSeverity != "" {
				threshold, parseErr := types.ParseRiskSeverity(strings.ToLower(minSeverity))
				if parseErr != nil {
					return fmt.Errorf("prioritize: invalid --min-severity %q", minSeverity)
				}
				items = filterByMinSeverity(items, threshold)
			}
			if top > 0 && top < len(items) {
				items = items[:top]
			}

			var rendered string
			switch strings.ToLower(format) {
			case "", "text":
				rendered = prioritize.FormatText(items, result.TotalAtRisk)
			case "markdown", "md":
				rendered = prioritize.FormatMarkdown(items, result.TotalAtRisk)
			case "json":
				rendered, err = prioritize.FormatJSON(items, result.TotalAtRisk)
			default:
				return fmt.Errorf("prioritize: unknown --format %q (want text, markdown, or json)", format)
			}
			if err != nil {
				return fmt.Errorf("prioritize: render: %w", err)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(filepath.Clean(outputFile), []byte(rendered), 0600); writeErr != nil { // #nosec G304 -- operator-supplied --output path
					return fmt.Errorf("prioritize: write %q: %w", outputFile, writeErr)
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "text", "output format: text, markdown, or json")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the rendered report to this file")
	cmd.Flags().IntVar(&top, "top", 10, "show only the top N findings (0 = all)")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "only include findings at or above this severity (low/medium/elevated/high/critical)")

	what.rootCmd.AddCommand(cmd)
	return what
}

func filterByMinSeverity(items []prioritize.Item, threshold types.RiskSeverity) []prioritize.Item {
	out := make([]prioritize.Item, 0, len(items))
	for _, it := range items {
		sev, err := types.ParseRiskSeverity(strings.ToLower(it.Severity))
		if err == nil && sev >= threshold {
			out = append(out, it)
		}
	}
	return out
}
