package threagile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/oscal"
)

func (what *Threagile) initOSCAL() *Threagile {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "oscal",
		Short: "Export the analyzed model as a NIST OSCAL assessment-results document",
		Long: `Analyze the model and export a deterministic NIST OSCAL assessment-results
document: one finding per generated risk, mapped to its risk-category objective,
with a satisfied / not-satisfied status driven by the risk's tracking state.

This turns a threat-model run into machine-readable compliance evidence that a
GRC tool can ingest directly, instead of being copied into spreadsheets. IDs are
deterministic (UUIDv5), so the same model yields byte-identical output.

Example:
  threagile oscal --model threagile.yaml --output assessment-results.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("oscal: failed to read and analyze model: %w", err)
			}

			doc := oscal.Build(r.ParsedModel, r.ParsedModel.AllRisks(),
				what.config.GetThreagileVersion(), fileSHA256(what.config.GetInputFile()))
			jsonBytes, marshalErr := json.MarshalIndent(doc, "", "  ")
			if marshalErr != nil {
				return fmt.Errorf("oscal: marshal document: %w", marshalErr)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(filepath.Clean(outputFile), append(jsonBytes, '\n'), 0600); writeErr != nil { // #nosec G304 -- operator-supplied --output path
					return fmt.Errorf("oscal: write %q: %w", outputFile, writeErr)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "OSCAL assessment-results written to %s (%d finding(s))\n",
					outputFile, len(doc.AssessmentResults.Results[0].Findings))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), string(jsonBytes))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outputFile, "output", "", "write the OSCAL JSON to this file (default: stdout)")

	what.rootCmd.AddCommand(cmd)
	return what
}

// fileSHA256 returns the hex SHA-256 of a file, or "" if it cannot be read.
func fileSHA256(path string) string {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied model path
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
