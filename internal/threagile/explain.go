package threagile

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

func (what *Threagile) initExplain() *Threagile {
	return what.initExplainNew()
}

func (what *Threagile) initExplainNew() *Threagile {
	explainCmd := &cobra.Command{
		Use:   ExplainCommand,
		Short: "Explain an item",
	}

	what.rootCmd.AddCommand(explainCmd)

	explainCmd.AddCommand(
		&cobra.Command{
			Use:        RiskItem,
			Short:      "Detailed explanation of why a risk was flagged",
			Args:       cobra.MinimumNArgs(1),
			ArgAliases: []string{"risk_id", "..."},
			RunE:       what.explainRisk,
		},
		&cobra.Command{
			Use:   RulesItem,
			Short: "Detailed explanation of all the risk rules",
			RunE:  what.explainRules,
		},
		&cobra.Command{
			Use:   MacrosItem,
			Short: "Explain model macros",
			Run:   what.explainMacros,
		},
		&cobra.Command{
			Use:   TypesItem,
			Short: "Print type information (enum values to be used in models)",
			Run:   what.explainTypes,
		})

	return what
}

func (what *Threagile) explainRisk(cmd *cobra.Command, args []string) error {
	what.processArgs(cmd, args)

	progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}
	builtinRules := risks.GetBuiltInRiskRules()

	if dir := what.config.GetRulesDir(); dir != "" {
		if extRules, err := risks.LoadExternalScriptRiskRules(dir); err == nil {
			builtinRules = builtinRules.Merge(extRules)
		}
	}

	result, runError := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
	if runError != nil {
		return fmt.Errorf("failed to analyze model: %w", runError)
	}

	for _, riskID := range args {
		risk, ok := result.ParsedModel.GeneratedRisksBySyntheticId[riskID]
		if !ok {
			cmd.Printf("Risk %q not found in model analysis.\n\nKnown risk IDs:\n", riskID)
			for id := range result.ParsedModel.GeneratedRisksBySyntheticId {
				cmd.Printf("  %s\n", id)
			}
			return fmt.Errorf("risk %q not found", riskID)
		}

		category := result.ParsedModel.GetRiskCategory(risk.CategoryId)

		cmd.Printf("Risk: %s\n", risk.SyntheticId)
		cmd.Printf("Severity:   %s\n", risk.Severity.String())
		cmd.Printf("Status:     %s\n", risk.RiskStatus.String())
		cmd.Println()

		if category != nil {
			cmd.Printf("Category:   %s (%s)\n", category.Title, category.ID)
			cmd.Printf("Function:   %s\n", category.Function.String())
			cmd.Printf("STRIDE:     %s\n", category.STRIDE.String())
			if category.CWE > 0 {
				cmd.Printf("CWE:        CWE-%d\n", category.CWE)
			}
			if category.ASVS != "" {
				cmd.Printf("ASVS:       %s\n", category.ASVS)
			}
			cmd.Println()
			cmd.Printf("Description:\n  %s\n\n", wordWrap(category.Description, 78, "  "))
			cmd.Printf("Impact:\n  %s\n\n", wordWrap(category.Impact, 78, "  "))
			cmd.Printf("Mitigation:\n  %s\n\n", wordWrap(category.Mitigation, 78, "  "))
			if category.FalsePositives != "" {
				cmd.Printf("False Positives:\n  %s\n\n", wordWrap(category.FalsePositives, 78, "  "))
			}
			if category.CheatSheet != "" {
				cmd.Printf("Cheat Sheet: %s\n\n", category.CheatSheet)
			}
		}

		// Show matching risk tracking entry if one exists
		if tracking, exists := result.ParsedModel.RiskTracking[risk.SyntheticId]; exists {
			cmd.Printf("Risk Tracking:\n")
			cmd.Printf("  Status:     %s\n", tracking.Status.String())
			cmd.Printf("  Justification: %s\n", tracking.Justification)
			if tracking.Ticket != "" {
				cmd.Printf("  Ticket:     %s\n", tracking.Ticket)
			}
			if !tracking.Date.IsZero() {
				cmd.Printf("  Date:       %s\n", tracking.Date.Format("2006-01-02"))
			}
			if tracking.CheckedBy != "" {
				cmd.Printf("  Checked by: %s\n", tracking.CheckedBy)
			}
			cmd.Println()
		}

		if len(risk.RiskExplanation) > 0 {
			cmd.Printf("Why it was flagged:\n")
			for _, line := range risk.RiskExplanation {
				cmd.Printf("  %s\n", line)
			}
			cmd.Println()
		}
	}

	return nil
}

// wordWrap wraps text at maxWidth, indenting continuation lines with indent.
func wordWrap(text string, maxWidth int, indent string) string {
	if len(text) <= maxWidth {
		return text
	}
	var result strings.Builder
	lineLen := 0
	for _, word := range strings.Fields(text) {
		if lineLen > 0 && lineLen+1+len(word) > maxWidth {
			result.WriteString("\n" + indent)
			lineLen = len(indent)
		} else if lineLen > 0 {
			result.WriteByte(' ')
			lineLen++
		}
		result.WriteString(word)
		lineLen += len(word)
	}
	return result.String()
}

func (what *Threagile) explainRules(cmd *cobra.Command, args []string) error {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	cmd.Println("Explanation for risk rules:")
	cmd.Println()
	cmd.Println("----------------------")
	cmd.Println("Custom risk rules:")
	cmd.Println("----------------------")
	customRiskRules := model.LoadCustomRiskRules(what.config.GetPluginFolder(), what.config.GetRiskRulePlugins(), DefaultProgressReporter{Verbose: what.config.GetVerbose()})
	for _, rule := range customRiskRules {
		cmd.Printf("%v: %v\n", rule.Category().ID, rule.Category().Description)
	}
	cmd.Println()
	cmd.Println("--------------------")
	cmd.Println("Built-in risk rules:")
	cmd.Println("--------------------")
	cmd.Println()
	for _, rule := range risks.GetBuiltInRiskRules() {
		cmd.Printf("%v: %v\n", rule.Category().ID, rule.Category().Description)
	}
	cmd.Println()

	return nil
}

func (what *Threagile) explainMacros(cmd *cobra.Command, args []string) {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	cmd.Println("Explanation for the model macros:")
	cmd.Println()
	/* TODO finish plugin stuff
	cmd.Println("Custom model macros:")
	for _, macros := range macros.ListCustomMacros() {
		details := macros.GetMacroDetails()
		cmd.Println(details.ID, "-->", details.Title)
	}
	cmd.Println()
	*/
	cmd.Println("----------------------")
	cmd.Println("Built-in model macros:")
	cmd.Println("----------------------")
	for _, macroList := range macros.ListBuiltInMacros() {
		details := macroList.GetMacroDetails()
		cmd.Printf("%v: %v\n", details.ID, details.Title)
	}

	cmd.Println()
}

func (what *Threagile) explainTypes(cmd *cobra.Command, args []string) {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	fmt.Println("Explanation for the types:")
	cmd.Println()
	cmd.Println("The following types are available (can be extended for custom rules):")
	cmd.Println()
	for name, values := range types.GetBuiltinTypeValues(what.config) {
		cmd.Println(name)
		for _, candidate := range values {
			cmd.Printf("\t %v: %v\n", candidate, candidate.Explain())
		}
	}
}
