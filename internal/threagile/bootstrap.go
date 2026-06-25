package threagile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/bootstrap"
	"github.com/threagile/threagile/pkg/gate"
	"gopkg.in/yaml.v3"
)

func (what *Threagile) initBootstrap() *Threagile {
	var dir string
	var output string
	var policyProfile string
	var force bool
	var withHooks bool

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Zero-config onboarding: scan a repo and scaffold a starter threat model",
		Long: `Scan a repository for infrastructure it already describes — docker-compose,
Kubernetes manifests, OpenAPI specs — and assemble a starter threat model from
it, so a team gets a useful model in one command instead of transcribing their
architecture by hand. Also drops a secure-by-default gate policy and (optionally)
git hooks, then prints the next steps. Deterministic, no AI.

Examples:
  threagile bootstrap
  threagile bootstrap --dir ./infra --with-hooks
  threagile bootstrap --output threagile.yaml --policy-profile strict`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			out := cmd.OutOrStdout()

			sources, err := bootstrap.Detect(dir)
			if err != nil {
				return fmt.Errorf("bootstrap: %w", err)
			}
			model, notes, err := bootstrap.BuildModel(dir, sources)
			if err != nil {
				return fmt.Errorf("bootstrap: %w", err)
			}

			fmt.Fprintf(out, "Scanned %q\n", dir)
			printDetected(out, sources)

			if len(model.TechnicalAssets) == 0 {
				fmt.Fprintln(out, "\nNo importable infrastructure found.")
				for _, n := range notes {
					fmt.Fprintf(out, "  - %s\n", n)
				}
				fmt.Fprintln(out, "Try `threagile init` (interactive) or point --dir at your IaC, then re-run.")
				return nil
			}

			// Write the starter model in the authoring (analyzable) format.
			modelBytes, err := yaml.Marshal(modelToInput(model))
			if err != nil {
				return fmt.Errorf("bootstrap: marshal model: %w", err)
			}
			modelPath := filepath.Clean(output)
			if err := writeNew(modelPath, modelBytes, force); err != nil {
				return fmt.Errorf("bootstrap: %w", err)
			}
			fmt.Fprintf(out, "\nWrote starter model: %s (%d assets, %d data assets, %d trust boundaries)\n",
				modelPath, len(model.TechnicalAssets), len(model.DataAssets), len(model.TrustBoundaries))

			// Secure-by-default gate policy.
			if policyProfile != "" {
				policyBytes, perr := gate.ProfileTemplate(policyProfile)
				if perr != nil {
					return fmt.Errorf("bootstrap: %w", perr)
				}
				if werr := writeNew("policy.yaml", policyBytes, force); werr != nil {
					fmt.Fprintf(out, "Kept existing policy.yaml (use --force to replace)\n")
				} else {
					fmt.Fprintf(out, "Wrote gate policy: policy.yaml (%s profile)\n", policyProfile)
				}
			}

			if withHooks {
				hooksDir, herr := gitHooksDir()
				if herr != nil {
					fmt.Fprintf(out, "Skipped hooks: %v\n", herr)
				} else {
					installed := installHooks(hooksDir, threagileBinaryPath(), absModel(modelPath), []string{"pre-commit", "pre-push"}, force)
					for _, h := range installed {
						fmt.Fprintf(out, "Installed git hook: %s\n", h)
					}
				}
			}

			for _, n := range notes {
				fmt.Fprintf(out, "Note: %s\n", n)
			}
			printNextSteps(out, modelPath, withHooks)
			return nil
		},
	}

	cmd.Flags().StringVar(&dir, "dir", ".", "repository directory to scan")
	cmd.Flags().StringVar(&output, "output", "threagile.yaml", "starter model file to write")
	cmd.Flags().StringVar(&policyProfile, "policy-profile", "balanced", "gate policy profile to scaffold (empty to skip)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	cmd.Flags().BoolVar(&withHooks, "with-hooks", false, "also install git pre-commit/pre-push hooks")

	what.rootCmd.AddCommand(cmd)
	return what
}

func printDetected(out io.Writer, sources []bootstrap.Source) {
	if len(sources) == 0 {
		fmt.Fprintln(out, "  (no recognised infrastructure files)")
		return
	}
	byKind := map[bootstrap.Kind][]string{}
	for _, s := range sources {
		byKind[s.Kind] = append(byKind[s.Kind], s.Path)
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		paths := byKind[bootstrap.Kind(k)]
		fmt.Fprintf(out, "  %-11s %d file(s): %v\n", k, len(paths), paths)
	}
}

// writeNew writes data unless the file exists and force is false.
func writeNew(path string, data []byte, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%q already exists (use --force to overwrite)", path)
	}
	if parent := filepath.Dir(path); parent != "." && parent != "" {
		if err := os.MkdirAll(parent, 0750); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0600) // #nosec G304 -- operator-supplied output path
}

func absModel(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func printNextSteps(out io.Writer, modelPath string, hooksInstalled bool) {
	fmt.Fprintln(out, "\nNext steps:")
	fmt.Fprintf(out, "  1. Review & refine the generated model: %s\n", modelPath)
	fmt.Fprintf(out, "  2. See where you stand:   threagile score --model %s\n", modelPath)
	fmt.Fprintf(out, "  3. Enforce it in CI:      threagile gate  --model %s --policy policy.yaml\n", modelPath)
	if !hooksInstalled {
		fmt.Fprintln(out, "  4. Local guardrails:      threagile hooks install")
	}
}
