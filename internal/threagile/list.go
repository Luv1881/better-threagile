package threagile

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
	"strings"
)

func (what *Threagile) initList() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListRiskRulesCommand,
		Short: "Print available risk rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
			cmd.Println("The following risk rules are available (can be extended via custom risk rules):")
			cmd.Println()
			cmd.Println("----------------------")
			cmd.Println("Custom risk rules:")
			cmd.Println("----------------------")
			customRiskRules := model.LoadCustomRiskRules(what.config.GetPluginFolder(), what.config.GetRiskRulePlugins(), DefaultProgressReporter{Verbose: what.config.GetVerbose()})
			for id, customRule := range customRiskRules {
				cmd.Println(id, "-->", customRule.Category().Title, "--> with tags:", customRule.SupportedTags())
			}
			cmd.Println()
			cmd.Println("--------------------")
			cmd.Println("Built-in risk rules:")
			cmd.Println("--------------------")
			cmd.Println()
			for _, rule := range risks.GetBuiltInRiskRules() {
				cmd.Println(rule.Category().ID, "-->", rule.Category().Title, "--> with tags:", rule.SupportedTags())
			}

			return nil
		},
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListModelMacrosCommand,
		Short: "Print model macros",
		Run: func(cmd *cobra.Command, args []string) {
			what.processArgs(cmd, args)

			cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
			cmd.Println("The following model macros are available (can be extended via custom model macros):")
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
				cmd.Println(details.ID, "-->", details.Title)
			}
			cmd.Println()
		},
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListTypesCommand,
		Short: "Print type information (enum values to be used in models)",
		Run: func(cmd *cobra.Command, args []string) {
			what.processArgs(cmd, args)

			cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
			cmd.Println()
			cmd.Println()
			cmd.Println("The following types are available (can be extended for custom rules):")
			cmd.Println()
			for name, values := range types.GetBuiltinTypeValues(what.config) {
				cmd.Println(fmt.Sprintf("  %v: %v", name, values))
			}
		},
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListMethodologiesCommand,
		Short: "Print supported threat modeling methodologies and which built-in rules cover each",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
			cmd.Println("Supported threat modeling methodologies:")
			cmd.Println()
			for _, m := range types.MethodologyValues() {
				meth := m.(types.Methodology)
				cmd.Printf("  %-10s  %s\n", meth.String(), meth.Explain())
			}
			cmd.Println()
			cmd.Println("Built-in rules by methodology coverage:")
			cmd.Println()

			allRules := risks.GetBuiltInRiskRules()
			coverage := make(map[string][]string) // methodology name -> rule IDs
			for _, m := range types.MethodologyValues() {
				meth := m.(types.Methodology)
				for id, rule := range allRules {
					if rule.Category().HasClassification(meth) {
						coverage[meth.String()] = append(coverage[meth.String()], id)
					}
				}
			}

			for _, m := range types.MethodologyValues() {
				meth := m.(types.Methodology)
				ids := coverage[meth.String()]
				cmd.Printf("  %-10s  %d built-in rule(s)", meth.String(), len(ids))
				if len(ids) > 0 {
					cmd.Printf(": %s", strings.Join(ids, ", "))
				}
				cmd.Println()
			}

			cmd.Println()
			cmd.Println("Available built-in rule packs (use --rule-pack=<name>):")
			for _, pack := range risks.AvailableBuiltinPacks {
				cmd.Printf("  %s\n", pack)
			}

			return nil
		},
	})

	return what
}
