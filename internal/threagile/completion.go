package threagile

import (
	"github.com/spf13/cobra"
)

func (what *Threagile) initCompletion() *Threagile {
	completion := &cobra.Command{
		Use:   "completion bash|zsh|fish|powershell",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for Bash, Zsh, Fish, or PowerShell.

Bash:
  source <(threagile completion bash)
  # Or add to ~/.bashrc:
  echo 'source <(threagile completion bash)' >> ~/.bashrc

Zsh:
  threagile completion zsh > "${fpath[1]}/_threagile"
  # Or with oh-my-zsh:
  threagile completion zsh > ~/.oh-my-zsh/completions/_threagile

Fish:
  threagile completion fish | source
  # Or:
  threagile completion fish > ~/.config/fish/completions/threagile.fish
`,
	}

	bash := &cobra.Command{
		Use:   "bash",
		Short: "Generate Bash completion script",
		RunE: func(cmd *cobra.Command, args []string) error {
			return what.rootCmd.GenBashCompletion(cmd.OutOrStdout())
		},
	}

	zsh := &cobra.Command{
		Use:   "zsh",
		Short: "Generate Zsh completion script",
		RunE: func(cmd *cobra.Command, args []string) error {
			return what.rootCmd.GenZshCompletion(cmd.OutOrStdout())
		},
	}

	fish := &cobra.Command{
		Use:   "fish",
		Short: "Generate Fish completion script",
		RunE: func(cmd *cobra.Command, args []string) error {
			return what.rootCmd.GenFishCompletion(cmd.OutOrStdout(), true)
		},
	}

	powershell := &cobra.Command{
		Use:   "powershell",
		Short: "Generate PowerShell completion script",
		RunE: func(cmd *cobra.Command, args []string) error {
			return what.rootCmd.GenPowerShellCompletion(cmd.OutOrStdout())
		},
	}

	completion.AddCommand(bash, zsh, fish, powershell)
	what.rootCmd.AddCommand(completion)
	return what
}
