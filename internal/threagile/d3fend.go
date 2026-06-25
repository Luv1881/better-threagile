package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/attack"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/types"
)

type d3fendRec struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Addresses   []string `json:"addresses_categories"`
	FindingHits int      `json:"finding_count"`
}

type d3fendReport struct {
	Recommendations    []d3fendRec `json:"recommendations"`
	UnmappedCategories []string    `json:"unmapped_categories,omitempty"`
}

func (what *Threagile) initD3FEND() *Threagile {
	var format string
	var outputFile string
	var includeMitigated bool

	cmd := &cobra.Command{
		Use:   "d3fend",
		Short: "Recommend MITRE D3FEND defensive countermeasures for the model's findings",
		Long: `Analyze the model and map its still-at-risk findings to MITRE D3FEND defensive
countermeasures (the defensive complement of the ATT&CK/CAPEC offensive
mappings). Output lists each recommended D3FEND technique, the risk categories it
addresses, and how many findings it would help defend. No AI.

Examples:
  threagile d3fend --model threagile.yaml
  threagile d3fend --model threagile.yaml --format json --output d3fend.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			builtinRules := what.loadRiskRules(progressReporter)
			r, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("d3fend: failed to read and analyze model: %w", err)
			}

			report := buildD3FENDReport(r.ParsedModel.AllRisks(), includeMitigated)

			var rendered string
			switch strings.ToLower(format) {
			case "", "text":
				rendered = formatD3FENDText(report)
			case "markdown", "md":
				rendered = formatD3FENDMarkdown(report)
			case "json":
				jsonBytes, marshalErr := json.MarshalIndent(report, "", "  ")
				if marshalErr != nil {
					return fmt.Errorf("d3fend: marshal report: %w", marshalErr)
				}
				rendered = string(jsonBytes) + "\n"
			default:
				return fmt.Errorf("d3fend: unknown --format %q (want text, markdown, or json)", format)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(filepath.Clean(outputFile), []byte(rendered), 0600); writeErr != nil { // #nosec G703 -- operator-supplied --output path
					return fmt.Errorf("d3fend: write %q: %w", outputFile, writeErr)
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "text", "output format: text, markdown, or json")
	cmd.Flags().StringVar(&outputFile, "output", "", "also write the rendered report to this file")
	cmd.Flags().BoolVar(&includeMitigated, "include-mitigated", false, "include mitigated/false-positive findings (default: only still-at-risk)")

	what.rootCmd.AddCommand(cmd)
	return what
}

func buildD3FENDReport(risks []*types.Risk, includeMitigated bool) *d3fendReport {
	// Per D3FEND id: which categories it addresses + how many findings it covers.
	addresses := map[string]map[string]bool{}
	hits := map[string]int{}
	unmapped := map[string]bool{}

	for _, risk := range risks {
		if !includeMitigated && !risk.RiskStatus.IsStillAtRisk() {
			continue
		}
		ids := attack.CategoryD3FEND[risk.CategoryId]
		if len(ids) == 0 {
			unmapped[risk.CategoryId] = true
			continue
		}
		for _, id := range ids {
			if addresses[id] == nil {
				addresses[id] = map[string]bool{}
			}
			addresses[id][risk.CategoryId] = true
			hits[id]++
		}
	}

	report := &d3fendReport{UnmappedCategories: sortedKeysBool(unmapped)}
	for _, id := range sortedKeysIntMap(hits) {
		report.Recommendations = append(report.Recommendations, d3fendRec{
			ID:          id,
			Name:        attack.D3FENDName(id),
			URL:         attack.D3FENDURL(id),
			Addresses:   sortedKeysBool(addresses[id]),
			FindingHits: hits[id],
		})
	}
	// Sort recommendations by coverage desc, then id, for a stable, useful order.
	sort.Slice(report.Recommendations, func(i, j int) bool {
		if report.Recommendations[i].FindingHits != report.Recommendations[j].FindingHits {
			return report.Recommendations[i].FindingHits > report.Recommendations[j].FindingHits
		}
		return report.Recommendations[i].ID < report.Recommendations[j].ID
	})
	return report
}

func formatD3FENDText(r *d3fendReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "D3FEND defensive recommendations: %d countermeasure(s)\n\n", len(r.Recommendations))
	for _, rec := range r.Recommendations {
		fmt.Fprintf(&sb, "  %-9s %s  (%d finding(s))\n", rec.ID, rec.Name, rec.FindingHits)
		fmt.Fprintf(&sb, "            addresses: %s\n", strings.Join(rec.Addresses, ", "))
		fmt.Fprintf(&sb, "            %s\n", rec.URL)
	}
	if len(r.UnmappedCategories) > 0 {
		fmt.Fprintf(&sb, "\nNote: %d finding category/categories have no D3FEND mapping: %v\n",
			len(r.UnmappedCategories), r.UnmappedCategories)
	}
	return sb.String()
}

func formatD3FENDMarkdown(r *d3fendReport) string {
	var sb strings.Builder
	sb.WriteString("## D3FEND defensive recommendations\n\n")
	if len(r.Recommendations) == 0 {
		sb.WriteString("No mappable findings.\n")
		return sb.String()
	}
	sb.WriteString("| Countermeasure | Findings | Addresses |\n|----------------|---------:|-----------|\n")
	for _, rec := range r.Recommendations {
		fmt.Fprintf(&sb, "| [%s %s](%s) | %d | %s |\n", rec.ID, rec.Name, rec.URL, rec.FindingHits, strings.Join(rec.Addresses, ", "))
	}
	if len(r.UnmappedCategories) > 0 {
		fmt.Fprintf(&sb, "\n_%d finding category/categories have no D3FEND mapping: %s_\n",
			len(r.UnmappedCategories), strings.Join(r.UnmappedCategories, ", "))
	}
	return sb.String()
}

func sortedKeysBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysIntMap(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
