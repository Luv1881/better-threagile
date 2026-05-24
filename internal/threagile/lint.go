package threagile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/input"
)

type LintFinding struct {
	Severity string `json:"severity"`
	Asset    string `json:"asset,omitempty"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

func (what *Threagile) initLint() *Threagile {
	var jsonOutput bool

	lint := &cobra.Command{
		Use:   LintCommand,
		Short: "Check the model for style and best-practice issues without failing the build",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			modelFile := what.config.GetInputFile()
			findings := lintModel(modelFile)

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(findings)
			}

			if len(findings) == 0 {
				cmd.Println("✓ No lint findings")
				return nil
			}

			warnings, infos := 0, 0
			for _, f := range findings {
				icon := "⚠"
				if f.Severity == "info" {
					icon = "ℹ"
					infos++
				} else {
					warnings++
				}
				if f.Asset != "" {
					cmd.Printf("%s [%s] %s\n", icon, f.Asset, f.Message)
				} else {
					cmd.Printf("%s %s\n", icon, f.Message)
				}
				if f.Fix != "" {
					cmd.Printf("   → %s\n", f.Fix)
				}
			}
			cmd.Printf("\n%d warning(s), %d info(s)\n", warnings, infos)
			return nil
		},
	}

	lint.Flags().BoolVar(&jsonOutput, "json", false, "output findings as JSON")
	what.rootCmd.AddCommand(lint)
	return what
}

func lintModel(modelFile string) []LintFinding {
	var findings []LintFinding
	warn := func(asset, msg, fix string) {
		findings = append(findings, LintFinding{Severity: "warning", Asset: asset, Message: msg, Fix: fix})
	}
	info := func(asset, msg, fix string) {
		findings = append(findings, LintFinding{Severity: "info", Asset: asset, Message: msg, Fix: fix})
	}

	modelInput := new(input.Model).Defaults()
	if err := modelInput.Load(modelFile); err != nil {
		warn("", fmt.Sprintf("failed to load model: %v", err), "")
		return findings
	}

	// Technical asset checks
	for title, ta := range modelInput.TechnicalAssets {
		if strings.TrimSpace(ta.Description) == "" {
			info(title, "technical asset has no description", "add a description field explaining the asset's role")
		}
		if len(ta.CommunicationLinks) > 0 {
			for linkTitle, link := range ta.CommunicationLinks {
				if len(link.DataAssetsSent) == 0 && len(link.DataAssetsReceived) == 0 {
					info(title, fmt.Sprintf("communication link %q has no data assets — consider declaring data_assets_sent or data_assets_received", linkTitle),
						"add data_assets_sent/data_assets_received to document what flows over this link")
				}
			}
		}
		if ta.Owner == "" {
			info(title, "technical asset has no owner declared", "add owner: <team or person> for accountability")
		}
	}

	// Data asset checks
	for title, da := range modelInput.DataAssets {
		if strings.TrimSpace(da.Description) == "" {
			info(title, "data asset has no description", "add a description explaining the nature of this data")
		}
		if da.JustificationCiaRating == "" {
			info(title, "data asset has no CIA rating justification", "add justification_cia_rating to explain the confidentiality/integrity/availability ratings")
		}
	}

	// Trust boundary checks
	for title, tb := range modelInput.TrustBoundaries {
		if len(tb.TechnicalAssetsInside) < 2 {
			info(title, "trust boundary contains only one (or zero) technical assets — verify this is intentional",
				"trust boundaries usually group 2+ assets; consider merging or removing if redundant")
		}
	}

	// Model-level checks
	if modelInput.ManagementSummaryComment == "" {
		warn("", "model has no management_summary_comment", "add a management_summary_comment describing the application and its security posture")
	}
	if len(modelInput.TagsAvailable) == 0 {
		info("", "no tags_available declared", "declare technology tags to enable tag-based risk rule filtering")
	}
	if modelInput.Author.Name == "" {
		info("", "no author declared in model", "add author: name/homepage to document model ownership")
	}

	// Methodology-specific checks
	internetAssets := 0
	for _, ta := range modelInput.TechnicalAssets {
		if ta.Internet {
			internetAssets++
			if ta.EntryPointType == "" {
				warn(ta.ID, "internet-exposed asset has no entry_point_type declared",
					"declare entry_point_type: api|web_ui|cli|file_upload|webhook|cron for PASTA analysis")
			}
		}
	}

	if internetAssets > 0 && len(modelInput.ThreatScenarios) == 0 {
		info("", "model has internet-exposed assets but no threat_scenarios defined",
			"add threat_scenarios for PASTA analysis (use discover-attack-surface macro to seed them)")
	}

	// Business process checks
	for title, bp := range modelInput.BusinessProcesses {
		if bp.Owner == "" {
			warn(title, "business process has no owner declared",
				"add owner: <person or team> — required for risk accountability under VAST")
		}
		if len(bp.SupportedByTechnicalAssets) == 0 {
			warn(title, "business process has no supported_by_technical_assets declared",
				"link the process to the technical assets that implement it")
		}
	}

	return findings
}
