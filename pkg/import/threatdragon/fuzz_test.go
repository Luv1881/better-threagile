package threatdragon

import "testing"

// FuzzImport exercises the Threat Dragon importer against arbitrary (untrusted)
// input, checking only that it never panics.
func FuzzImport(f *testing.F) {
	f.Add([]byte(sampleTD))
	f.Add([]byte(`{"detail":{"diagrams":[{"cells":[{"shape":"flow","source":{"cell":"x"},"target":{"cell":"y"}}]}]}}`))
	f.Add([]byte("not json"))
	f.Add([]byte("{}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Import(data, ImportOptions{SourceLabel: "fuzz"})
	})
}
