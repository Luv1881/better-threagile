package threagile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/gate"
)

func (what *Threagile) initPolicy() *Threagile {
	policyCmd := &cobra.Command{
		Use:   "policy",
		Short: "Work with gate policies (secure-by-default starter templates)",
		Long: `Scaffold and inspect policy.yaml files for the 'gate' command.

The bundled profiles give teams a sensible, secure-by-default gate without
needing a security expert to hand-write thresholds — pick one, drop it in CI,
tighten over time.`,
	}

	var profile string
	var output string
	var force bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a secure-by-default starter gate policy",
		Long: `Write one of the bundled secure-by-default gate policies to a file (or stdout).

Profiles, loosest to strictest: prototype, balanced (default), strict, regulated.
Run 'threagile policy list' to see what each enforces.

Examples:
  threagile policy init                              # balanced -> policy.yaml
  threagile policy init --profile strict --output ci/policy.yaml
  threagile policy init --profile regulated -o -     # print to stdout`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := gate.ProfileTemplate(profile)
			if err != nil {
				return fmt.Errorf("policy init: %w", err)
			}
			if output == "" || output == "-" {
				fmt.Fprint(cmd.OutOrStdout(), string(data))
				return nil
			}
			clean := filepath.Clean(output)
			if _, statErr := os.Stat(clean); statErr == nil && !force {
				return fmt.Errorf("policy init: %q already exists (use --force to overwrite)", clean)
			}
			if parent := filepath.Dir(clean); parent != "." && parent != "" {
				if mkErr := os.MkdirAll(parent, 0750); mkErr != nil {
					return fmt.Errorf("policy init: create %q: %w", parent, mkErr)
				}
			}
			if writeErr := os.WriteFile(clean, data, 0600); writeErr != nil { // #nosec G304 -- operator-supplied --output path
				return fmt.Errorf("policy init: write %q: %w", clean, writeErr)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %q gate policy to %s\nNext: threagile gate --model <model.yaml> --policy %s\n", profile, clean, clean)
			return nil
		},
	}
	initCmd.Flags().StringVar(&profile, "profile", "balanced", "policy profile: "+strings.Join(gate.ProfileNames(), ", "))
	initCmd.Flags().StringVarP(&output, "output", "o", "policy.yaml", "file to write (use '-' for stdout)")
	initCmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List the bundled secure-by-default policy profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			var sb strings.Builder
			sb.WriteString("Bundled gate policy profiles (loosest to strictest):\n\n")
			for _, name := range gate.ProfileNames() {
				fmt.Fprintf(&sb, "  %-10s %s\n", name, gate.ProfileDescription(name))
			}
			sb.WriteString("\nWrite one with:  threagile policy init --profile <name>\n")
			fmt.Fprint(cmd.OutOrStdout(), sb.String())
			return nil
		},
	}

	policyCmd.AddCommand(initCmd, listCmd)
	what.rootCmd.AddCommand(policyCmd)
	return what
}
