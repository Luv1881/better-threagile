package threagile

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/attack"
	"github.com/threagile/threagile/pkg/model"
)

func (what *Threagile) initAttackNavigator() *Threagile {
	var outputFile string
	var includeMitigated bool

	cmd := &cobra.Command{
		Use:   "attack-navigator",
		Short: "Export a MITRE ATT&CK Navigator layer from the model's risk findings",
		Long: `Analyze the model and map every generated risk to MITRE ATT&CK (Enterprise)
techniques, writing an ATT&CK Navigator layer JSON. Import the file at
https://mitre-attack.github.io/attack-navigator/ to see the techniques your
threat model exercises highlighted on the ATT&CK matrix (score = number of
findings, color = highest severity).

Example:
  threagile attack-navigator --model threagile.yaml --output attack-layer.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("attack-navigator: failed to read and analyze model: %w", err)
			}

			// By default only map findings that are still at risk — a layer
			// highlighting mitigated/false-positive techniques would misrepresent
			// the live attack surface.
			risks := r.ParsedModel.AllRisks()
			if !includeMitigated {
				active := risks[:0:0]
				for _, risk := range risks {
					if risk.RiskStatus.IsStillAtRisk() {
						active = append(active, risk)
					}
				}
				risks = active
			}

			result := attack.BuildLayer(r.ParsedModel.Title, risks)

			jsonBytes, marshalErr := json.MarshalIndent(result.Layer, "", "  ")
			if marshalErr != nil {
				return fmt.Errorf("attack-navigator: marshal layer: %w", marshalErr)
			}
			if outputFile != "" {
				if writeErr := os.WriteFile(outputFile, append(jsonBytes, '\n'), 0600); writeErr != nil {
					return fmt.Errorf("attack-navigator: write %q: %w", outputFile, writeErr)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "ATT&CK Navigator layer written to %s (%d technique(s))\n", outputFile, len(result.Layer.Techniques))
			} else {
				// The layer JSON is the command's data output — stdout, so
				// `attack-navigator > layer.json` produces a valid file.
				fmt.Fprintln(cmd.OutOrStdout(), string(jsonBytes))
			}

			if len(result.UnmappedCategories) > 0 {
				// To stderr so it never corrupts `attack-navigator > layer.json`.
				fmt.Fprintf(cmd.ErrOrStderr(), "Note: %d finding category/categories have no ATT&CK mapping yet: %v\n",
					len(result.UnmappedCategories), result.UnmappedCategories)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outputFile, "output", "", "write the Navigator layer JSON to this file (default: stdout)")
	cmd.Flags().BoolVar(&includeMitigated, "include-mitigated", false, "also map mitigated/false-positive findings (default: only still-at-risk)")

	what.rootCmd.AddCommand(cmd)
	return what
}
