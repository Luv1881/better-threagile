package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/attacktree"
	"github.com/threagile/threagile/pkg/model"
)

func (what *Threagile) initAttackTree() *Threagile {
	var from string
	var to string
	var maxPaths int
	var format string
	var outputFile string

	cmd := &cobra.Command{
		Use:   "attack-tree",
		Short: "Generate goal-oriented attack trees toward crown-jewel data",
		Long: `Analyze the model and build a goal-oriented attack tree per crown-jewel asset
(one storing/processing confidential or strictly-confidential data). The root of
each tree is the attacker's goal; the OR-branches are the routes that reach it,
with internet-facing entry points as the leaves. Reuses the deterministic
attack-path analysis — no AI.

Output formats: text (default), markdown, json, or dot (Graphviz — render with
'dot -Tpng tree.dot -o tree.png').

Examples:
  threagile attack-tree --model threagile.yaml
  threagile attack-tree --model threagile.yaml --to customer-accounts --format dot --output tree.dot`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("attack-tree: failed to read and analyze model: %w", err)
			}
			parsedModel := r.ParsedModel

			// Validate selectors (mirror the paths command).
			if from != "" && from != "internet" {
				if _, ok := parsedModel.TechnicalAssets[from]; !ok {
					return fmt.Errorf("attack-tree: --from %q is not a technical asset ID", from)
				}
			}
			if to != "" {
				_, isAsset := parsedModel.TechnicalAssets[to]
				_, isData := parsedModel.DataAssets[to]
				if !isAsset && !isData {
					return fmt.Errorf("attack-tree: --to %q is not a technical-asset or data-asset ID", to)
				}
			}

			result := attacktree.Build(parsedModel, attacktree.Options{To: to, MaxPaths: maxPaths, FromAssetID: from})

			var rendered string
			switch strings.ToLower(format) {
			case "", "text":
				rendered = attacktree.FormatText(result)
			case "markdown", "md":
				rendered = attacktree.FormatMarkdown(result)
			case "dot":
				rendered = attacktree.FormatDOT(result)
			case "json":
				jsonBytes, marshalErr := json.MarshalIndent(result, "", "  ")
				if marshalErr != nil {
					return fmt.Errorf("attack-tree: marshal result: %w", marshalErr)
				}
				rendered = string(jsonBytes) + "\n"
			default:
				return fmt.Errorf("attack-tree: unknown --format %q (want text, markdown, json, or dot)", format)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(filepath.Clean(outputFile), []byte(rendered), 0600); writeErr != nil { // #nosec G703 -- operator-supplied --output path
					return fmt.Errorf("attack-tree: write %q: %w", outputFile, writeErr)
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)
			return nil
		},
	}

	cmd.Flags().StringVar(&from, "from", "internet", "entry point: an asset ID, or 'internet' for all internet-facing assets")
	cmd.Flags().StringVar(&to, "to", "", "goal: a data-asset ID or technical-asset ID (default: all crown-jewel assets)")
	cmd.Flags().IntVar(&maxPaths, "max-paths", 0, "cap the number of paths considered (0 = no cap)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, markdown, json, or dot")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the rendered tree to this file")

	what.rootCmd.AddCommand(cmd)
	return what
}
