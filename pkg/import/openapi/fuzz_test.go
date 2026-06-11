package openapi

import "testing"

// FuzzImport exercises the OpenAPI spec importer against arbitrary
// (untrusted) input, checking only that it never panics.
func FuzzImport(f *testing.F) {
	f.Add([]byte(sampleSpec))
	f.Add([]byte("not yaml: [unterminated"))
	f.Add([]byte(""))
	f.Add([]byte("openapi: 3.0.0"))
	f.Add([]byte("paths:\n  /x:\n    get: {}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Import(data, ImportOptions{SourceLabel: "fuzz"})
	})
}
