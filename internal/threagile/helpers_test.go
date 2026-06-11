package threagile

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestProgressReporter_InfoVerbose(t *testing.T) {
	r := DefaultProgressReporter{Verbose: true}
	r.Info("hello")
	r.Infof("hello %s", "world")
}

func TestProgressReporter_InfoQuiet(t *testing.T) {
	r := DefaultProgressReporter{Verbose: false}
	r.Info("hello")
	r.Infof("hello %s", "world")
}

func TestProgressReporter_Warn(t *testing.T) {
	r := DefaultProgressReporter{}
	r.Warn("warning")
	r.Warnf("warning %s", "details")
}

func TestProgressReporter_ErrorSuppressed(t *testing.T) {
	r := DefaultProgressReporter{SuppressError: true}
	// With SuppressError set, Error/Errorf degrade to Warn instead of log.Fatal.
	r.Error("error")
	r.Errorf("error %s", "details")
}

func TestConfig_ExpandPath(t *testing.T) {
	c := new(Config).Defaults("test")

	home := c.UserHomeDir()
	assert.Equal(t, home+"/foo", c.ExpandPath("~/foo"))
	assert.Equal(t, home+"/bar", c.ExpandPath("$HOME/bar"))
	assert.Equal(t, "/absolute/path", c.ExpandPath("/absolute/path"))
}

func TestConfig_CleanPath(t *testing.T) {
	c := new(Config).Defaults("test")

	home := c.UserHomeDir()
	assert.Equal(t, home+"/foo", c.CleanPath("~/foo/"))
	assert.Equal(t, "/a/b", c.CleanPath("/a/./b/"))
}

func TestConfig_UserHomeDir(t *testing.T) {
	c := new(Config).Defaults("test")
	assert.Equal(t, os.Getenv("HOME"), c.UserHomeDir())
}

func TestConfig_CheckServerFolder(t *testing.T) {
	c := new(Config).Defaults("test")
	c.SetServerMode(true)

	dir := t.TempDir()
	c.SetServerFolder(dir)
	assert.NoError(t, c.CheckServerFolder())

	c.SetServerFolder("/does/not/exist/anywhere")
	assert.Error(t, c.CheckServerFolder())
}

func TestSeverityChanged(t *testing.T) {
	oldRisks := map[string]*types.Risk{
		"risk-1": {Severity: types.LowSeverity},
		"risk-2": {Severity: types.MediumSeverity},
	}
	newRisks := map[string]*types.Risk{
		"risk-1": {Severity: types.HighSeverity},
		"risk-2": {Severity: types.MediumSeverity},
		"risk-3": {Severity: types.CriticalSeverity},
	}

	changes := severityChanged(oldRisks, newRisks)
	assert.Len(t, changes, 1)
	assert.Equal(t, "risk-1", changes[0].id)
	assert.Equal(t, types.LowSeverity.String(), changes[0].oldSev)
	assert.Equal(t, types.HighSeverity.String(), changes[0].newSev)
}

func TestHasHighOrCritical(t *testing.T) {
	assert.False(t, hasHighOrCritical([]*types.Risk{{Severity: types.LowSeverity}}))
	assert.True(t, hasHighOrCritical([]*types.Risk{{Severity: types.HighSeverity}}))
	assert.True(t, hasHighOrCritical([]*types.Risk{{Severity: types.CriticalSeverity}}))
}

func TestHasCritical(t *testing.T) {
	assert.False(t, hasCritical([]*types.Risk{{Severity: types.HighSeverity}}))
	assert.True(t, hasCritical([]*types.Risk{{Severity: types.CriticalSeverity}}))
}

func TestWordWrap(t *testing.T) {
	short := "short text"
	assert.Equal(t, short, wordWrap(short, 80))

	long := "one two three four five six seven eight nine ten"
	wrapped := wordWrap(long, 10)
	assert.Contains(t, wrapped, "\n  ")

	for _, line := range bytes.Split([]byte(wrapped), []byte("\n")) {
		_ = line
	}
}

func TestCheckDir(t *testing.T) {
	c := new(Config).Defaults("test")

	dir := t.TempDir()
	assert.NoError(t, c.checkDir(dir, "test"))

	assert.Error(t, c.checkDir(dir+"/does-not-exist", "test"))

	file := dir + "/somefile"
	assert.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	assert.Error(t, c.checkDir(file, "test"))
}
