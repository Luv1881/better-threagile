package threagile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/mermaid"
	"github.com/threagile/threagile/pkg/model"
)

func (what *Threagile) initMermaid() *Threagile {
	var format string
	var direction string
	var outputFile string
	var withRisks bool

	cmd := &cobra.Command{
		Use:   "mermaid",
		Short: "Render the model's data-flow diagram as a Mermaid flowchart",
		Long: `Render the model as a Mermaid flowchart — text that GitHub, GitLab and most
Markdown renderers display natively, so you get an architecture / data-flow
picture in a pull-request comment, README or CI summary without the Graphviz
'dot' binary or any image toolchain.

Trust boundaries become subgraphs, technical assets become shaped nodes
(datastores as cylinders, external entities as stadiums, processes as boxes),
and communication links become edges in their call direction (solid when
encrypted/VPN, dashed when cleartext). With --with-risks (default), each asset is
coloured by the highest severity of its still-at-risk findings. Deterministic, no AI.

Examples:
  threagile mermaid --model threagile.yaml
  threagile mermaid --model threagile.yaml --format markdown --output diagram.md
  threagile mermaid --model threagile.yaml --direction LR --with-risks=false`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("mermaid: failed to read and analyze model: %w", err)
			}

			flowchart := mermaid.DataFlowDiagram(r.ParsedModel, mermaid.Options{
				Direction: direction,
				WithRisks: withRisks,
			})

			var rendered string
			switch strings.ToLower(format) {
			case "", "flowchart", "mermaid":
				rendered = flowchart
			case "markdown", "md":
				rendered = "```mermaid\n" + flowchart + "```\n"
			default:
				return fmt.Errorf("mermaid: unknown --format %q (want flowchart or markdown)", format)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(filepath.Clean(outputFile), []byte(rendered), 0600); writeErr != nil { // #nosec G703 -- operator-supplied --output path
					return fmt.Errorf("mermaid: write %q: %w", outputFile, writeErr)
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "flowchart", "output format: flowchart (raw) or markdown (fenced ```mermaid block)")
	cmd.Flags().StringVar(&direction, "direction", "TB", "flow direction: TB (top-bottom) or LR (left-right)")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the rendered diagram to this file")
	cmd.Flags().BoolVar(&withRisks, "with-risks", true, "colour assets by highest still-at-risk severity")

	what.rootCmd.AddCommand(cmd)
	return what
}
