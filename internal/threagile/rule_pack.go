package threagile

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/risks"
)

func (what *Threagile) initRulePack() *Threagile {
	rulePack := &cobra.Command{
		Use:   RulePackCommand,
		Short: "List, show, install, or update curated rule packs",
	}

	rulePack.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List curated rule packs",
			RunE: func(cmd *cobra.Command, args []string) error {
				what.processArgs(cmd, args)
				for _, pack := range risks.ListRulePacks() {
					kind := "remote"
					if pack.Embedded {
						kind = "embedded"
					}
					cmd.Printf("%-12s %-10s %-8s %s\n", pack.Name, pack.Methodology, kind, pack.Description)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "show <pack-name>",
			Short: "Show a curated rule pack",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				what.processArgs(cmd, args)
				description, err := risks.DescribeRulePack(strings.ToLower(args[0]))
				if err != nil {
					return err
				}
				cmd.Println(description)
				return nil
			},
		},
		&cobra.Command{
			Use:     "install <pack-name>",
			Aliases: []string{"update"},
			Short:   "Install or refresh a curated rule pack",
			Args:    cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				what.processArgs(cmd, args)
				return what.installRulePack(cmd, strings.ToLower(args[0]))
			},
		},
	)

	what.rootCmd.AddCommand(rulePack)
	return what
}

func (what *Threagile) installRulePack(cmd *cobra.Command, name string) error {
	entry := risks.LookupRulePack(name)
	if entry == nil {
		return fmt.Errorf("unknown rule pack %q", name)
	}

	if entry.Embedded {
		rules, err := risks.LoadRulePack(name)
		if err != nil {
			return err
		}
		cmd.Printf("Rule pack %q is embedded and ready (%d rules).\n", name, len(rules))
		return nil
	}

	cacheDir := filepath.Join(what.config.GetAppFolder(), "rules-cache")
	opts := risks.FetchOptions{
		TrustedKeys:   what.config.GetRulesTrustedKeys(),
		RequireSigned: what.config.GetRulesRequireSigned(),
	}
	localDir, err := risks.FetchAndCacheRulesWithOptions(entry.URL, cacheDir, opts)
	if err != nil {
		return err
	}
	cmd.Printf("Installed rule pack %q into %s\n", name, localDir)
	return nil
}
