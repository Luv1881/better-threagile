package threagile

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func (what *Threagile) initPrint() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   Print3rdPartyCommand,
		Short: "Print 3rd-party license information",
		Long:  "\n" + Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp) + "\n\n" + ThirdPartyLicenses,
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   PrintLicenseCommand,
		Short: "Print license information",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			appDir, err := cmd.Flags().GetString(appDirFlagName)
			if err != nil {
				return fmt.Errorf("unable to read app-dir flag: %w", err)
			}

			cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
			if appDir != filepath.Clean(appDir) {
				// TODO: do we need this check here?
				cmd.Printf("weird app folder %v", appDir)
				return fmt.Errorf("weird app folder")
			}

			content, err := os.ReadFile(filepath.Clean(filepath.Join(appDir, "LICENSE.txt")))
			if err != nil {
				return fmt.Errorf("unable to read license file: %w", err)
			}

			cmd.Print(string(content))
			cmd.Println()

			return nil
		},
	})

	return what
}
