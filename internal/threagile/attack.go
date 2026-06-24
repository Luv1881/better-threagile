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

			result := attack.BuildLayer(r.ParsedModel.Title, r.ParsedModel.AllRisks())

			jsonBytes, marshalErr := json.MarshalIndent(result.Layer, "", "  ")
			if marshalErr != nil {
				return fmt.Errorf("attack-navigator: marshal layer: %w", marshalErr)
			}
			if outputFile != "" {
				if writeErr := os.WriteFile(outputFile, append(jsonBytes, '\n'), 0600); writeErr != nil {
					return fmt.Errorf("attack-navigator: write %q: %w", outputFile, writeErr)
				}
				cmd.Printf("ATT&CK Navigator layer written to %s (%d technique(s))\n", outputFile, len(result.Layer.Techniques))
			} else {
				cmd.Println(string(jsonBytes))
			}

			if len(result.UnmappedCategories) > 0 {
				cmd.Printf("Note: %d finding category/categories have no ATT&CK mapping yet: %v\n",
					len(result.UnmappedCategories), result.UnmappedCategories)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outputFile, "output", "", "write the Navigator layer JSON to this file (default: stdout)")

	what.rootCmd.AddCommand(cmd)
	return what
}
