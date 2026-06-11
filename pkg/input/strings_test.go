package input

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeSingleton(t *testing.T) {
	s := new(Strings)

	value, err := s.MergeSingleton("", "second")
	assert.NoError(t, err)
	assert.Equal(t, "second", value)

	value, err = s.MergeSingleton("first", "")
	assert.NoError(t, err)
	assert.Equal(t, "first", value)

	value, err = s.MergeSingleton("same", "SAME")
	assert.NoError(t, err)
	assert.Equal(t, "same", value)

	_, err = s.MergeSingleton("first", "second")
	assert.Error(t, err)
}

func TestMergeMultiline(t *testing.T) {
	s := new(Strings)

	assert.Equal(t, "second", s.MergeMultiline("", "second"))
	assert.Equal(t, "first", s.MergeMultiline("first", ""))
	assert.Equal(t, "same", s.MergeMultiline("same", "SAME"))
	assert.Equal(t, "first"+lineSeparator+"second", s.MergeMultiline("first", "second"))
}

func TestMergeMap(t *testing.T) {
	s := new(Strings)

	merged, err := s.MergeMap(map[string]string{"a": "1"}, map[string]string{"b": "2"})
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"a": "1", "b": "2"}, merged)

	_, err = s.MergeMap(map[string]string{"a": "1"}, map[string]string{"a": "2"})
	assert.Error(t, err)
}

func TestMergeUniqueSlice(t *testing.T) {
	s := new(Strings)

	merged := s.MergeUniqueSlice([]string{"a", "b"}, []string{"b", "c"})
	assert.Equal(t, []string{"a", "b", "c"}, merged)
}
