package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/attackpath"
	"github.com/threagile/threagile/pkg/model"
)

func (what *Threagile) initPaths() *Threagile {
	var from string
	var to string
	var maxPaths int
	var format string
	var outputFile string

	cmd := &cobra.Command{
		Use:   "paths",
		Short: "Find attack paths from internet-facing assets to crown-jewel data",
		Long: `Analyze the model and compute the shortest attack paths an attacker can take
from an internet-facing asset to a "crown-jewel" asset — one that stores or
processes confidential or strictly-confidential data — following communication
links in their call direction.

By default every internet-facing asset is an entry point and every crown-jewel
asset is a target. Narrow with --from (an asset ID) and --to (a data-asset ID or
technical-asset ID).

Examples:
  threagile paths --model threagile.yaml
  threagile paths --model threagile.yaml --to customer-accounts --format markdown
  threagile paths --model threagile.yaml --from load-balancer --max-paths 20`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("paths: failed to read and analyze model: %w", err)
			}

			result := attackpath.Analyze(r.ParsedModel, attackpath.Options{
				FromAssetID: from,
				ToTarget:    to,
				MaxPaths:    maxPaths,
			})

			var rendered string
			switch strings.ToLower(format) {
			case "", "text":
				rendered = attackpath.FormatText(result)
			case "markdown", "md":
				rendered = attackpath.FormatMarkdown(result)
			case "json":
				jsonBytes, marshalErr := json.MarshalIndent(result, "", "  ")
				if marshalErr != nil {
					return fmt.Errorf("paths: marshal result: %w", marshalErr)
				}
				rendered = string(jsonBytes) + "\n"
			default:
				return fmt.Errorf("paths: unknown --format %q (want text, markdown, or json)", format)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(outputFile, []byte(rendered), 0600); writeErr != nil {
					return fmt.Errorf("paths: write %q: %w", outputFile, writeErr)
				}
			}
			cmd.Print(rendered)
			return nil
		},
	}

	cmd.Flags().StringVar(&from, "from", "internet", "entry point: an asset ID, or 'internet' for all internet-facing assets")
	cmd.Flags().StringVar(&to, "to", "", "target: a data-asset ID or technical-asset ID (default: all crown-jewel assets)")
	cmd.Flags().IntVar(&maxPaths, "max-paths", 0, "cap the number of paths reported (0 = no cap)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, markdown, or json")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the rendered report to this file")

	what.rootCmd.AddCommand(cmd)
	return what
}
