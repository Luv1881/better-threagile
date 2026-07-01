package threagile

import (
	"errors"
	"os"

	"github.com/spf13/cobra"
)

type Threagile struct {
	flags          Flags
	config         *Config
	rootCmd        *cobra.Command
	buildTimestamp string
}

func (what *Threagile) Execute() {
	err := what.rootCmd.Execute()
	if err != nil {
		var ec *exitCodeError
		if errors.As(err, &ec) {
			what.rootCmd.PrintErrln(ec.msg)
			os.Exit(ec.code)
		}
		what.rootCmd.PrintErrln(err)
		os.Exit(1)
	}

	if what.config.GetServerMode() {
		serverError := what.runServer()
		if serverError != nil {
			what.rootCmd.PrintErrln(serverError)
		}
	} else if what.config.GetInteractive() {
		what.run(what.rootCmd, nil)
	}
}

func (what *Threagile) Init(buildTimestamp string) *Threagile {
	what.buildTimestamp = buildTimestamp
	return what.initRoot().
		initImport().
		initImportData().
		initAnalyze().
		initCreate().
		initExecute().
		initExplain().
		initList().
		initPrint().
		initQuit().
		initServer().
		initVersion().
		initGenerateCI().
		initValidate().
		initLint().
		initDiff().
		initInit().
		initFmt().
		initRulePack().
		initTestRules().
		initCoverage().
		initIntel().
		initQuantify().
		initGate().
		initPaths().
		initAttackTree().
		initSBOM().
		initMermaid().
		initPolicy().
		initHooks().
		initScore().
		initBootstrap().
		initPrioritize().
		initSummary().
		initRequirements().
		initDrift().
		initCompletion().
		initLSP().
		processSystemArgs(what.rootCmd)
}
