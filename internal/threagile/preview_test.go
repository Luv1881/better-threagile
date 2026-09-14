package threagile

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteUnifiedDiff_Changed(t *testing.T) {
	var buf bytes.Buffer
	changed, err := writeUnifiedDiff(&buf, "model.yaml", []byte("title: old\nkey: same\n"), []byte("title: new\nkey: same\n"))
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Contains(t, buf.String(), "--- a/model.yaml")
	assert.Contains(t, buf.String(), "+++ b/model.yaml")
	assert.Contains(t, buf.String(), "-title: old")
	assert.Contains(t, buf.String(), "+title: new")
	assert.Contains(t, buf.String(), " key: same")
}

func TestWriteUnifiedDiff_Unchanged(t *testing.T) {
	var buf bytes.Buffer
	changed, err := writeUnifiedDiff(&buf, "model.yaml", []byte("same\n"), []byte("same\n"))
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Empty(t, buf.String(), "identical data must not render a diff")
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write refused") }

func TestWriteUnifiedDiff_WriteError(t *testing.T) {
	changed, err := writeUnifiedDiff(failingWriter{}, "model.yaml", []byte("a\n"), []byte("b\n"))
	require.Error(t, err)
	assert.True(t, changed)
}
