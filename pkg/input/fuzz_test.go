package input

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzModelUnmarshal exercises YAML parsing of an untrusted threagile model
// file. The model file is the primary untrusted-input surface of pkg/input,
// so this fuzz target only checks that unmarshalling never panics.
func FuzzModelUnmarshal(f *testing.F) {
	f.Add([]byte(`
title: Example
tags_available:
  - foo
  - bar
data_assets:
  Some Data:
    id: some-data
    description: an example data asset
technical_assets:
  Some Asset:
    id: some-asset
    type: process
    usage: business
`))
	f.Add([]byte(""))
	f.Add([]byte("title: [unterminated"))
	f.Add([]byte("not: !!binary invalid base64"))
	f.Add([]byte("a: &anchor\nb: *anchor"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var model Model
		_ = yaml.Unmarshal(data, &model)
	})
}
