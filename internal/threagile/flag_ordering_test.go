package threagile

import (
	"strings"
	"testing"
)

// TestRootFlagAfterCommandLocalFlag is the regression test for the pflag-ordering
// wart: a root persistent flag (--model) placed AFTER a command-local flag
// (--policy) used to be silently dropped because the extraction pass halted at
// the first unknown (command-local) flag. It must now be honoured.
func TestRootFlagAfterCommandLocalFlag(t *testing.T) {
	model := demoModelPath(t)
	app := newTestAppWithArgs("gate", "--policy", "some-policy.yaml", "--model", model)
	if got := app.config.GetInputFile(); !strings.HasSuffix(got, model) && got != model {
		t.Fatalf("--model placed after --policy was dropped: GetInputFile()=%q want %q", got, model)
	}
}

// And the conventional ordering (root flag first) must still work.
func TestRootFlagBeforeCommandLocalFlag(t *testing.T) {
	model := demoModelPath(t)
	app := newTestAppWithArgs("gate", "--model", model, "--policy", "some-policy.yaml")
	if got := app.config.GetInputFile(); got != model {
		t.Fatalf("--model before --policy not honoured: %q want %q", got, model)
	}
}
