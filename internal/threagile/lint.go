package threagile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/source"
)

type LintFinding struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule,omitempty"`
	Asset    string `json:"asset,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

func (what *Threagile) initLint() *Threagile {
	var jsonOutput bool
	var format string

	lint := &cobra.Command{
		Use:   LintCommand,
		Short: "Check the model for style and best-practice issues without failing the build",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			modelFile := what.config.GetInputFile()
			findings := lintModel(modelFile)

			if jsonOutput && format == "" {
				format = "json" // --json is a back-compat alias for --format json
			}
			switch format {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(findings)
			case "sarif":
				sarif, err := lintSARIF(findings, modelFile)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), sarif)
				return nil
			case "", "text":
				// fall through to text rendering below
			default:
				return fmt.Errorf("lint: unknown --format %q (want text, json, or sarif)", format)
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
				where := f.Asset
				if f.Line > 0 {
					if f.File != "" {
						where = fmt.Sprintf("%s (%s:%d)", f.Asset, f.File, f.Line)
					} else {
						where = fmt.Sprintf("%s:line %d", f.Asset, f.Line)
					}
				}
				if f.Asset != "" {
					cmd.Printf("%s [%s] %s\n", icon, where, f.Message)
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

	lint.Flags().BoolVar(&jsonOutput, "json", false, "output findings as JSON (alias for --format json)")
	lint.Flags().StringVar(&format, "format", "", "output format: text (default), json, or sarif")
	what.rootCmd.AddCommand(lint)
	return what
}

// lintSARIF renders lint findings as a SARIF 2.1.0 document so model-hygiene
// issues can be uploaded to GitHub/GitLab code scanning, located at file:line.
func lintSARIF(findings []LintFinding, modelFile string) (string, error) {
	type message struct {
		Text string `json:"text"`
	}
	type region struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type physicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *region `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   message    `json:"message"`
		Locations []location `json:"locations,omitempty"`
	}
	type rule struct {
		ID               string  `json:"id"`
		Name             string  `json:"name"`
		ShortDescription message `json:"shortDescription"`
	}

	dir := filepath.Dir(modelFile)
	level := func(sev string) string {
		if sev == "info" {
			return "note"
		}
		return "warning"
	}

	seen := map[string]bool{}
	var rules []rule
	var results []result
	for _, f := range findings {
		rid := f.Rule
		if rid == "" {
			rid = "lint"
		}
		if !seen[rid] {
			seen[rid] = true
			rules = append(rules, rule{ID: rid, Name: rid, ShortDescription: message{Text: strings.ReplaceAll(rid, "-", " ")}})
		}
		uri := modelFile
		if f.File != "" {
			uri = filepath.Join(dir, f.File)
		}
		var loc location
		loc.PhysicalLocation.ArtifactLocation.URI = filepath.ToSlash(uri)
		if f.Line > 0 {
			loc.PhysicalLocation.Region = &region{StartLine: f.Line}
		}
		results = append(results, result{RuleID: rid, Level: level(f.Severity), Message: message{Text: f.Message}, Locations: []location{loc}})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "threagile-lint",
				"informationUri": "https://github.com/Luv1881/better-threagile",
				"rules":          rules,
			}},
			"results": results,
		}},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func lintModel(modelFile string) []LintFinding {
	var findings []LintFinding
	// Best-effort source line per named entity (0 => omitted), so lint findings
	// point at the offending element just like validate.
	entityLines := source.EntityLines(modelFile)
	add := func(sev, rule, asset, msg, fix string) {
		l := entityLines[asset]
		findings = append(findings, LintFinding{Severity: sev, Rule: rule, Asset: asset, File: l.File, Line: l.Line, Message: msg, Fix: fix})
	}
	warn := func(rule, asset, msg, fix string) { add("warning", rule, asset, msg, fix) }
	info := func(rule, asset, msg, fix string) { add("info", rule, asset, msg, fix) }

	modelInput := new(input.Model).Defaults()
	if err := modelInput.Load(modelFile); err != nil {
		warn("model-load-failed", "", fmt.Sprintf("failed to load model: %v", err), "")
		return findings
	}

	// Technical asset checks
	for title, ta := range modelInput.TechnicalAssets {
		if strings.TrimSpace(ta.Description) == "" {
			info("tech-asset-no-description", title, "technical asset has no description", "add a description field explaining the asset's role")
		}
		if len(ta.CommunicationLinks) > 0 {
			for linkTitle, link := range ta.CommunicationLinks {
				if len(link.DataAssetsSent) == 0 && len(link.DataAssetsReceived) == 0 {
					info("comm-link-no-data-assets", title, fmt.Sprintf("communication link %q has no data assets — consider declaring data_assets_sent or data_assets_received", linkTitle),
						"add data_assets_sent/data_assets_received to document what flows over this link")
				}
			}
		}
		if ta.Owner == "" {
			info("tech-asset-no-owner", title, "technical asset has no owner declared", "add owner: <team or person> for accountability")
		}
	}

	// Data asset checks
	for title, da := range modelInput.DataAssets {
		if strings.TrimSpace(da.Description) == "" {
			info("data-asset-no-description", title, "data asset has no description", "add a description explaining the nature of this data")
		}
		if da.JustificationCiaRating == "" {
			info("data-asset-no-cia-justification", title, "data asset has no CIA rating justification", "add justification_cia_rating to explain the confidentiality/integrity/availability ratings")
		}
	}

	// Trust boundary checks
	for title, tb := range modelInput.TrustBoundaries {
		if len(tb.TechnicalAssetsInside) < 2 {
			info("trust-boundary-too-few-assets", title, "trust boundary contains only one (or zero) technical assets — verify this is intentional",
				"trust boundaries usually group 2+ assets; consider merging or removing if redundant")
		}
	}

	// Model-level checks
	if modelInput.ManagementSummaryComment == "" {
		warn("model-no-management-summary", "", "model has no management_summary_comment", "add a management_summary_comment describing the application and its security posture")
	}
	if len(modelInput.TagsAvailable) == 0 {
		info("model-no-tags-available", "", "no tags_available declared", "declare technology tags to enable tag-based risk rule filtering")
	}
	if modelInput.Author.Name == "" {
		info("model-no-author", "", "no author declared in model", "add author: name/homepage to document model ownership")
	}

	// Methodology-specific checks
	internetAssets := 0
	for _, ta := range modelInput.TechnicalAssets {
		if ta.Internet {
			internetAssets++
			if ta.EntryPointType == "" {
				warn("internet-asset-no-entry-point-type", ta.ID, "internet-exposed asset has no entry_point_type declared",
					"declare entry_point_type: api|web_ui|cli|file_upload|webhook|cron for PASTA analysis")
			}
		}
	}

	if internetAssets > 0 && len(modelInput.ThreatScenarios) == 0 {
		info("internet-assets-no-threat-scenarios", "", "model has internet-exposed assets but no threat_scenarios defined",
			"add threat_scenarios for PASTA analysis (use discover-attack-surface macro to seed them)")
	}

	// Business process checks
	for title, bp := range modelInput.BusinessProcesses {
		if bp.Owner == "" {
			warn("business-process-no-owner", title, "business process has no owner declared",
				"add owner: <person or team> — required for risk accountability under VAST")
		}
		if len(bp.SupportedByTechnicalAssets) == 0 {
			warn("business-process-no-supported-assets", title, "business process has no supported_by_technical_assets declared",
				"link the process to the technical assets that implement it")
		}
	}

	// Findings are collected while iterating maps, so sort for deterministic,
	// diffable output (same reasoning as validate).
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Asset != b.Asset {
			return a.Asset < b.Asset
		}
		if a.Message != b.Message {
			return a.Message < b.Message
		}
		return a.Severity < b.Severity
	})
	return findings
}
