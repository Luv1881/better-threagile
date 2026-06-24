package threagile

// exitCodeError lets a command request a specific process exit code while still
// returning a normal error (so the RunE remains unit-testable). Execute()
// translates it into os.Exit(code). A distinct code lets CI distinguish a
// policy/gate failure from a usage or analysis error (which exit 1).
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

func (e *exitCodeError) ExitCode() int { return e.code }
