package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/prioritize"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

func (what *Threagile) initDiff() *Threagile {
	var format string
	var outputFile string

	diff := &cobra.Command{
		Use:   DiffCommand + " <old-model.yaml> <new-model.yaml>",
		Short: "Show the risk delta between two versions of a threat model",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			oldFile := args[0]
			newFile := args[1]

			methodology := what.config.GetMethodology()
			progressReporter := DefaultProgressReporter{Verbose: false}
			builtinRules := risks.GetBuiltInRiskRules()

			// Temporarily override input file to run analysis on each model
			originalInput := what.config.GetInputFile()
			defer what.config.SetInputFile(originalInput)

			what.config.SetInputFile(oldFile)
			oldRisks, err := analyzeForDiff(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("failed to analyze old model: %w", err)
			}

			what.config.SetInputFile(newFile)
			newRisks, err := analyzeForDiff(what.config, builtinRules, progressReporter)
			if err != nil {
				return fmt.Errorf("failed to analyze new model: %w", err)
			}

			added, removed, changed, unchanged := diffRisks(oldRisks, newRisks)
			d := riskDiff{
				OldFile:        filepath.Base(oldFile),
				NewFile:        filepath.Base(newFile),
				Methodology:    methodology,
				Added:          added,
				Removed:        removed,
				Changed:        changed,
				Unchanged:      unchanged,
				Remediation:    remediationByCategory(builtinRules),
				CategoryTitles: categoryTitles(builtinRules),
			}

			var rendered string
			switch strings.ToLower(format) {
			case "", "text":
				rendered = d.formatText()
			case "markdown", "md":
				rendered = d.formatMarkdown()
			case "json":
				jsonBytes, marshalErr := json.MarshalIndent(d.toJSON(), "", "  ")
				if marshalErr != nil {
					return fmt.Errorf("diff: marshal result: %w", marshalErr)
				}
				rendered = string(jsonBytes) + "\n"
			default:
				return fmt.Errorf("diff: unknown --format %q (want text, markdown, or json)", format)
			}

			if outputFile != "" {
				if writeErr := os.WriteFile(outputFile, []byte(rendered), 0600); writeErr != nil {
					return fmt.Errorf("diff: write %q: %w", outputFile, writeErr)
				}
			}
			fmt.Fprint(cmd.OutOrStdout(), rendered)
			return nil
		},
	}

	diff.Flags().StringVar(&format, "format", "text", "output format: text, markdown, or json")
	diff.Flags().StringVar(&outputFile, "output", "", "also write the rendered delta to this file")

	what.rootCmd.AddCommand(diff)
	return what
}

// riskDiff holds the computed delta between two analyzed models.
type riskDiff struct {
	OldFile     string
	NewFile     string
	Methodology string
	Added       []*types.Risk
	Removed     []*types.Risk
	Changed     []riskChange // same risk, different severity (escalated/de-escalated)
	Unchanged   []*types.Risk
	// Remediation maps a risk category ID to its fix guidance, so a PR comment
	// can tell developers how to resolve the findings their change introduced.
	Remediation    map[string]prioritize.Remediation
	CategoryTitles map[string]string
}

// riskChange is a risk present in both models whose severity changed.
type riskChange struct {
	Risk        *types.Risk
	OldSeverity types.RiskSeverity
	NewSeverity types.RiskSeverity
}

func (c riskChange) escalated() bool { return c.NewSeverity > c.OldSeverity }

func (d *riskDiff) formatText() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Computing risk delta: %s → %s\n", d.OldFile, d.NewFile)
	fmt.Fprintf(&sb, "Methodology: %s\n\n", d.Methodology)

	if len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0 {
		sb.WriteString("No risk changes detected.\n")
		return sb.String()
	}
	if len(d.Added) > 0 {
		fmt.Fprintf(&sb, "+ %d new risk(s):\n", len(d.Added))
		for _, r := range d.Added {
			fmt.Fprintf(&sb, "  + [%s] %s\n", r.Severity.String(), r.SyntheticId)
		}
		sb.WriteString("\n")
	}
	if len(d.Removed) > 0 {
		fmt.Fprintf(&sb, "- %d resolved risk(s):\n", len(d.Removed))
		for _, r := range d.Removed {
			fmt.Fprintf(&sb, "  - [%s] %s\n", r.Severity.String(), r.SyntheticId)
		}
		sb.WriteString("\n")
	}
	if len(d.Changed) > 0 {
		fmt.Fprintf(&sb, "~ %d severity change(s):\n", len(d.Changed))
		for _, c := range d.Changed {
			arrow := "↓"
			if c.escalated() {
				arrow = "↑"
			}
			fmt.Fprintf(&sb, "  ~ [%s %s %s] %s\n", c.OldSeverity.String(), arrow, c.NewSeverity.String(), c.Risk.SyntheticId)
		}
		sb.WriteString("\n")
	}
	fmt.Fprintf(&sb, "= %d unchanged risk(s)\n", len(d.Unchanged))
	fmt.Fprintf(&sb, "\nSummary: +%d added, -%d resolved, ~%d changed, =%d unchanged\n",
		len(d.Added), len(d.Removed), len(d.Changed), len(d.Unchanged))
	return sb.String()
}

// formatMarkdown renders a PR-comment-ready risk delta.
func (d *riskDiff) formatMarkdown() string {
	var sb strings.Builder
	sb.WriteString("## Threat-model risk delta\n\n")
	fmt.Fprintf(&sb, "`%s` → `%s` · methodology: **%s**\n\n", d.OldFile, d.NewFile, d.Methodology)
	fmt.Fprintf(&sb, "**+%d added, −%d resolved, ~%d changed, =%d unchanged**\n",
		len(d.Added), len(d.Removed), len(d.Changed), len(d.Unchanged))

	if len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0 {
		sb.WriteString("\nNo risk changes detected. ✅\n")
		return sb.String()
	}
	if len(d.Added) > 0 {
		fmt.Fprintf(&sb, "\n### ❌ %d new risk(s)\n\n", len(d.Added))
		writeRiskTable(&sb, d.Added)
		d.writeRemediation(&sb)
	}
	if len(d.Changed) > 0 {
		fmt.Fprintf(&sb, "\n### ⚠️ %d severity change(s)\n\n", len(d.Changed))
		sb.WriteString("| Change | Risk |\n|--------|------|\n")
		for _, c := range d.Changed {
			arrow := "↓"
			if c.escalated() {
				arrow = "↑"
			}
			fmt.Fprintf(&sb, "| %s %s %s | `%s` |\n", c.OldSeverity.Title(), arrow, c.NewSeverity.Title(), c.Risk.SyntheticId)
		}
	}
	if len(d.Removed) > 0 {
		fmt.Fprintf(&sb, "\n### ✅ %d resolved risk(s)\n\n", len(d.Removed))
		writeRiskTable(&sb, d.Removed)
	}
	return sb.String()
}

func writeRiskTable(sb *strings.Builder, riskList []*types.Risk) {
	sb.WriteString("| Severity | Risk |\n|----------|------|\n")
	for _, r := range riskList {
		fmt.Fprintf(sb, "| %s | `%s` |\n", r.Severity.Title(), r.SyntheticId)
	}
}

// writeRemediation lists, once per category, how to fix the newly-introduced
// findings — so a PR comment is actionable, not just a list of problems.
func (d *riskDiff) writeRemediation(sb *strings.Builder) {
	if len(d.Remediation) == 0 {
		return
	}
	seen := map[string]bool{}
	var lines []string
	for _, r := range d.Added {
		if seen[r.CategoryId] {
			continue
		}
		seen[r.CategoryId] = true
		if fix := prioritize.FixLine(d.Remediation[r.CategoryId]); fix != "" {
			title := d.CategoryTitles[r.CategoryId]
			if title == "" {
				title = r.CategoryId
			}
			lines = append(lines, "- **"+title+"** — "+fix)
		}
	}
	if len(lines) == 0 {
		return
	}
	sb.WriteString("\n**How to fix the new findings:**\n\n")
	for _, l := range lines {
		sb.WriteString(l + "\n")
	}
}

// remediationByCategory builds a category-ID → remediation map from the rule set.
func remediationByCategory(rules types.RiskRules) map[string]prioritize.Remediation {
	out := map[string]prioritize.Remediation{}
	for _, rule := range rules {
		if cat := rule.Category(); cat != nil {
			out[cat.ID] = prioritize.RemediationFromCategory(cat)
		}
	}
	return out
}

// categoryTitles builds a category-ID → human title map from the rule set.
func categoryTitles(rules types.RiskRules) map[string]string {
	out := map[string]string{}
	for _, rule := range rules {
		if cat := rule.Category(); cat != nil {
			out[cat.ID] = cat.Title
		}
	}
	return out
}

type riskDiffJSON struct {
	OldModel       string            `json:"old_model"`
	NewModel       string            `json:"new_model"`
	Methodology    string            `json:"methodology"`
	Added          []diffRiskEntry   `json:"added"`
	Removed        []diffRiskEntry   `json:"removed"`
	Changed        []diffChangeEntry `json:"changed"`
	UnchangedCount int               `json:"unchanged_count"`
}

type diffRiskEntry struct {
	SyntheticId string `json:"synthetic_id"`
	Severity    string `json:"severity"`
}

type diffChangeEntry struct {
	SyntheticId string `json:"synthetic_id"`
	OldSeverity string `json:"old_severity"`
	NewSeverity string `json:"new_severity"`
}

func (d *riskDiff) toJSON() riskDiffJSON {
	toEntries := func(rs []*types.Risk) []diffRiskEntry {
		out := make([]diffRiskEntry, 0, len(rs))
		for _, r := range rs {
			out = append(out, diffRiskEntry{SyntheticId: r.SyntheticId, Severity: r.Severity.String()})
		}
		return out
	}
	changes := make([]diffChangeEntry, 0, len(d.Changed))
	for _, c := range d.Changed {
		changes = append(changes, diffChangeEntry{
			SyntheticId: c.Risk.SyntheticId,
			OldSeverity: c.OldSeverity.String(),
			NewSeverity: c.NewSeverity.String(),
		})
	}
	return riskDiffJSON{
		OldModel:       d.OldFile,
		NewModel:       d.NewFile,
		Methodology:    d.Methodology,
		Added:          toEntries(d.Added),
		Removed:        toEntries(d.Removed),
		Changed:        changes,
		UnchangedCount: len(d.Unchanged),
	}
}

func analyzeForDiff(config *Config, rules types.RiskRules, reporter types.ProgressReporter) (map[string]*types.Risk, error) {
	result, err := model.ReadAndAnalyzeModel(config, rules, reporter)
	if err != nil {
		return nil, err
	}
	riskMap := make(map[string]*types.Risk)
	for _, risk := range result.ParsedModel.GeneratedRisksBySyntheticId {
		riskMap[risk.SyntheticId] = risk
	}
	return riskMap, nil
}

func diffRisks(oldRisks, newRisks map[string]*types.Risk) (added, removed []*types.Risk, changed []riskChange, unchanged []*types.Risk) {
	for id, r := range newRisks {
		old, exists := oldRisks[id]
		switch {
		case !exists:
			added = append(added, r)
		case old.Severity != r.Severity:
			// Same finding, different severity (escalated or de-escalated) — a
			// material change a PR reviewer needs to see, not "unchanged".
			changed = append(changed, riskChange{Risk: r, OldSeverity: old.Severity, NewSeverity: r.Severity})
		default:
			unchanged = append(unchanged, r)
		}
	}
	for id, r := range oldRisks {
		if _, exists := newRisks[id]; !exists {
			removed = append(removed, r)
		}
	}
	sortBySeverityThenID := func(s []*types.Risk) {
		sort.Slice(s, func(i, j int) bool {
			if s[i].Severity != s[j].Severity {
				return s[i].Severity > s[j].Severity // highest severity first
			}
			return s[i].SyntheticId < s[j].SyntheticId
		})
	}
	sortBySeverityThenID(added)
	sortBySeverityThenID(removed)
	sortBySeverityThenID(unchanged)
	sort.Slice(changed, func(i, j int) bool {
		if changed[i].NewSeverity != changed[j].NewSeverity {
			return changed[i].NewSeverity > changed[j].NewSeverity
		}
		return changed[i].Risk.SyntheticId < changed[j].Risk.SyntheticId
	})
	return
}
