package threagile

import (
	"bytes"
	"strings"
	"testing"
)

// newTestApp creates a fully-initialized Threagile instance for testing.
// It wires all commands (the same as production) but uses a zeroed build timestamp.
func newTestApp() *Threagile {
	app := new(Threagile)
	app.Init("")
	return app
}

// executeCmd drives the root cobra command with the given args and captures stdout/stderr.
func executeCmd(app *Threagile, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	app.rootCmd.SetOut(buf)
	app.rootCmd.SetErr(buf)
	app.rootCmd.SetArgs(args)
	err := app.rootCmd.Execute()
	return buf.String(), err
}

// --- version ----------------------------------------------------------------

func TestVersionCommand_Outputs(t *testing.T) {
	app := newTestApp()
	out, err := executeCmd(app, PrintVersionCommand)
	if err != nil {
		t.Fatalf("version command error: %v", err)
	}
	// Should contain the version string defined in consts
	if !strings.Contains(out, ThreagileVersion) {
		t.Errorf("version output missing version string: %q", out)
	}
}

// --- help -------------------------------------------------------------------

func TestHelpFlag(t *testing.T) {
	app := newTestApp()
	out, _ := executeCmd(app, "--help")
	if !strings.Contains(out, "threagile") {
		t.Errorf("--help output doesn't mention threagile: %q", out)
	}
}

// --- list subcommands -------------------------------------------------------

func TestListRiskRules_Runs(t *testing.T) {
	app := newTestApp()
	out, err := executeCmd(app, ListRiskRulesCommand)
	if err != nil {
		t.Fatalf("list-risk-rules error: %v", err)
	}
	if !strings.Contains(out, "risk rules") {
		t.Errorf("list-risk-rules output unexpected: %q", out)
	}
}

func TestListModelMacros_Runs(t *testing.T) {
	app := newTestApp()
	out, err := executeCmd(app, ListModelMacrosCommand)
	if err != nil {
		t.Fatalf("list-model-macros error: %v", err)
	}
	if !strings.Contains(out, "macros") {
		t.Errorf("list-model-macros output unexpected: %q", out)
	}
}

func TestListTypes_Runs(t *testing.T) {
	app := newTestApp()
	out, err := executeCmd(app, ListTypesCommand)
	if err != nil {
		t.Fatalf("list-types error: %v", err)
	}
	// Should output type name → values lines
	if out == "" {
		t.Error("list-types output was empty")
	}
}

func TestListMethodologies_Runs(t *testing.T) {
	app := newTestApp()
	out, err := executeCmd(app, ListMethodologiesCommand)
	if err != nil {
		t.Fatalf("list-methodologies error: %v", err)
	}
	// Each supported methodology should appear
	for _, meth := range []string{"stride", "linddun", "pasta"} {
		if !strings.Contains(strings.ToLower(out), meth) {
			t.Errorf("list-methodologies missing %q in output", meth)
		}
	}
}

// --- llm command must not exist ---------------------------------------------

func TestLLMCommand_NotRegistered(t *testing.T) {
	app := newTestApp()
	for _, sub := range app.rootCmd.Commands() {
		if sub.Name() == "llm" {
			t.Error("llm command should have been removed but is still registered")
		}
	}
}

// --- unknown command --------------------------------------------------------

func TestUnknownCommand_ReturnsError(t *testing.T) {
	app := newTestApp()
	_, err := executeCmd(app, "does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

// --- generate-ci ------------------------------------------------------------

func TestGenerateCICommand_ExistsAndHasFlags(t *testing.T) {
	app := newTestApp()
	var found bool
	for _, cmd := range app.rootCmd.Commands() {
		if cmd.Name() == GenerateCICommand {
			found = true
			// --target flag selects the CI backend (github, gitlab, jenkins, generic)
			if cmd.Flags().Lookup("target") == nil {
				t.Error("generate-ci missing --target flag")
			}
		}
	}
	if !found {
		t.Errorf("command %q not found", GenerateCICommand)
	}
}
