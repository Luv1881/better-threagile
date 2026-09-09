package threagile

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/server"
)

func (what *Threagile) initServer() *Threagile {
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Run server",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			return what.runServer()
		},
	}

	serverCmd.PersistentFlags().IntVar(&what.flags.ServerPortValue, serverPortFlagName, what.config.GetServerPort(), "server port")
	serverCmd.PersistentFlags().StringVar(&what.flags.ServerFolderValue, serverDirFlagName, what.config.GetDataFolder(), "base folder for server mode (default: "+DataDir+")")

	what.rootCmd.AddCommand(serverCmd)

	return what
}

func (what *Threagile) runServer() error {
	what.config.SetServerMode(true)

	// Seed the embedded static assets into the server folder before the folder
	// is validated, so that a fresh (e.g. non-Docker) deployment starts with a
	// complete static tree while existing files are never overwritten.
	if _, statErr := os.Stat(what.config.GetServerFolder()); os.IsNotExist(statErr) {
		fmt.Printf("Creating server folder %q and populating it with the built-in static assets\n", what.config.GetServerFolder())
	}
	seedError := server.SeedServerStaticAssets(what.config.GetServerFolder())
	if seedError != nil {
		return fmt.Errorf("failed to seed static assets into server folder %q: %w", what.config.GetServerFolder(), seedError)
	}

	serverError := what.config.CheckServerFolder()
	if serverError != nil {
		return serverError
	}

	server.RunServer(what.config, risks.GetBuiltInRiskRules())
	return nil
}
