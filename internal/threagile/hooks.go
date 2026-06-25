package threagile

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// supportedHooks are the git hooks this installer knows how to generate.
var supportedHooks = map[string]bool{"pre-commit": true, "pre-push": true}

func (what *Threagile) initHooks() *Threagile {
	hooksCmd := &cobra.Command{
		Use:   "hooks",
		Short: "Install git hooks that run threat-model checks before commit/push",
		Long: `Wire the threat model into the normal git workflow so problems surface on the
developer's machine — before CI, not after. Pre-commit runs the fast checks
(validate + lint); pre-push additionally runs the security 'gate' when a
policy.yaml is present.`,
	}

	var which []string
	var dir string
	var force, printOnly bool
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install pre-commit / pre-push git hooks for the threat model",
		Long: `Generate git hook scripts that run threagile against your model.

  pre-commit : threagile validate + lint        (fast feedback)
  pre-push   : threagile validate + gate         (gate runs if policy.yaml exists)

The scripts call the current threagile binary by absolute path. Existing hook
files are not overwritten unless you pass --force.

Examples:
  threagile hooks install
  threagile hooks install --hook pre-commit
  threagile hooks install --print          # preview without installing`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			for _, h := range which {
				if !supportedHooks[h] {
					return fmt.Errorf("hooks install: unknown hook %q (supported: pre-commit, pre-push)", h)
				}
			}

			model := what.config.GetInputFile()
			if model == "" {
				model = InputFile
			}
			// Git hooks always run from the repo root, but the user may install
			// from a subdirectory. Absolutise the model path so the hook's
			// existence check and analysis target the intended file rather than
			// silently no-opping against a wrong relative path. (Hooks live in
			// .git and are per-clone, so an absolute local path is appropriate.)
			if abs, absErr := filepath.Abs(model); absErr == nil {
				model = abs
			}
			bin := threagileBinaryPath()

			if printOnly {
				for _, h := range which {
					fmt.Fprintf(cmd.OutOrStdout(), "# === %s ===\n%s\n", h, renderHookScript(h, bin, model))
				}
				return nil
			}

			hooksDir := dir
			if hooksDir == "" {
				detected, err := gitHooksDir()
				if err != nil {
					return fmt.Errorf("hooks install: %w", err)
				}
				hooksDir = detected
			}
			if err := os.MkdirAll(hooksDir, 0750); err != nil {
				return fmt.Errorf("hooks install: create %q: %w", hooksDir, err)
			}

			for _, h := range which {
				path := filepath.Join(hooksDir, h)
				if _, statErr := os.Stat(path); statErr == nil && !force {
					return fmt.Errorf("hooks install: %q already exists (use --force to overwrite)", path)
				}
				script := renderHookScript(h, bin, model)
				if err := os.WriteFile(path, []byte(script), 0700); err != nil { // #nosec G306 -- git hooks must be executable
					return fmt.Errorf("hooks install: write %q: %w", path, err)
				}
				// os.WriteFile keeps a pre-existing file's mode on overwrite, so
				// re-assert tight, owner-only-executable perms explicitly.
				if chmodErr := os.Chmod(path, 0700); chmodErr != nil { // #nosec G302 -- a hook must be executable by its owner
					return fmt.Errorf("hooks install: chmod %q: %w", path, chmodErr)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Installed %s hook: %s\n", h, path)
			}
			return nil
		},
	}
	installCmd.Flags().StringSliceVar(&which, "hook", []string{"pre-commit", "pre-push"}, "git hooks to install: pre-commit, pre-push")
	installCmd.Flags().StringVar(&dir, "dir", "", "hooks directory to write to (default: the repo's git hooks dir)")
	installCmd.Flags().BoolVar(&force, "force", false, "overwrite existing hook files")
	installCmd.Flags().BoolVar(&printOnly, "print", false, "print the hook script(s) instead of installing")

	hooksCmd.AddCommand(installCmd)
	what.rootCmd.AddCommand(hooksCmd)
	return what
}

// threagileBinaryPath returns the absolute path of the running binary so the
// installed hook keeps working regardless of the user's PATH. Falls back to the
// bare command name if it cannot be resolved.
func threagileBinaryPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "threagile"
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

// gitHooksDir asks git where this repo's hooks live (honouring worktrees and
// core.hooksPath) so the installer works in non-standard layouts too.
func gitHooksDir() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		return "", fmt.Errorf("not inside a git repository (run from your repo, or pass --dir): %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// renderHookScript returns a portable POSIX-sh hook script for the given hook.
func renderHookScript(hook, binary, model string) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&b, "# Managed by 'threagile hooks install' — threat-model guardrail (%s).\n", hook)
	b.WriteString("# Re-run 'threagile hooks install --force' to regenerate, or delete this file.\n")
	b.WriteString("set -e\n")
	fmt.Fprintf(&b, "THREAGILE=%s\n", shQuote(binary))
	fmt.Fprintf(&b, "MODEL=%s\n", shQuote(model))
	b.WriteString("# No model in this repo yet? Then there is nothing to check.\n")
	b.WriteString("[ -f \"$MODEL\" ] || exit 0\n")
	b.WriteString(`echo "threagile: checking threat model $MODEL"` + "\n")
	b.WriteString("\"$THREAGILE\" validate --model \"$MODEL\"\n")
	switch hook {
	case "pre-commit":
		b.WriteString("\"$THREAGILE\" lint --model \"$MODEL\"\n")
	case "pre-push":
		b.WriteString("if [ -f policy.yaml ]; then\n")
		b.WriteString("  echo \"threagile: running security gate (policy.yaml)\"\n")
		b.WriteString("  \"$THREAGILE\" gate --model \"$MODEL\" --policy policy.yaml\n")
		b.WriteString("fi\n")
	}
	return b.String()
}

// shQuote single-quotes a string for safe embedding in a POSIX shell script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
