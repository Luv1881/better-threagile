package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun_DefaultScriptAndModel(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()

	// Should run without panicking, generating risks for the default
	// accidental-secret-leak script against the bundled parsed model.
	run("")
}

func TestRun_MissingScriptFile(t *testing.T) {
	run(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
}
