package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/stix"
)

func (what *Threagile) initSTIX() *Threagile {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "stix",
		Short: "Export the analyzed model as a STIX 2.1 bundle for threat-intel interop",
		Long: `Analyze the model and export it as a deterministic STIX 2.1 bundle:
an identity for the model, an infrastructure object per technical asset, a
vulnerability per generated risk (with a CWE external reference), attack-pattern
objects for the MITRE ATT&CK techniques and CAPEC patterns the risk categories
map to, course-of-action objects from the categories' mitigations, and the
relationships between them (vulnerability targets asset, attack-pattern targets
asset, course-of-action mitigates vulnerability).

Object IDs are deterministic (UUIDv5), so the same model yields byte-identical
output. Load the bundle into a TIP / OpenCTI / the ATT&CK Navigator.

Example:
  threagile stix --model threagile.yaml --output stix-bundle.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("stix: failed to read and analyze model: %w", err)
			}

			result := stix.Build(r.ParsedModel, r.ParsedModel.AllRisks())

			jsonBytes, marshalErr := json.MarshalIndent(result.Bundle, "", "  ")
			if marshalErr != nil {
				return fmt.Errorf("stix: marshal bundle: %w", marshalErr)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(filepath.Clean(outputFile), append(jsonBytes, '\n'), 0600); writeErr != nil { // #nosec G703 -- operator-supplied --output path
					return fmt.Errorf("stix: write %q: %w", outputFile, writeErr)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "STIX 2.1 bundle written to %s (%d object(s))\n", outputFile, len(result.Bundle.Objects))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), string(jsonBytes))
			}

			if len(result.UnmappedCategories) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "Note: %d finding category/categories have no ATT&CK/CAPEC mapping: %v\n",
					len(result.UnmappedCategories), result.UnmappedCategories)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outputFile, "output", "", "write the STIX 2.1 bundle JSON to this file (default: stdout)")

	what.rootCmd.AddCommand(cmd)
	return what
}
