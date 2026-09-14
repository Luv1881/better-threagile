package threagile

import (
	"io"

	"github.com/pmezard/go-difflib/difflib"
)

// writeUnifiedDiff writes a unified diff between oldData and newData for the
// named file and reports whether the two differ. The a/ and b/ prefixes make
// the output applyable with `patch -p1` (or `git apply` from the repo root).
// It is shared by the --dry-run previews of fmt, hooks install and bootstrap
// so a preview and the corresponding real write cannot drift apart.
func writeUnifiedDiff(out io.Writer, name string, oldData, newData []byte) (bool, error) {
	if string(oldData) == string(newData) {
		return false, nil
	}
	diff, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(oldData)),
		B:        difflib.SplitLines(string(newData)),
		FromFile: "a/" + name,
		ToFile:   "b/" + name,
		Context:  3,
	})
	if err != nil {
		return false, err
	}
	if _, writeErr := io.WriteString(out, diff); writeErr != nil {
		return true, writeErr
	}
	return true, nil
}
