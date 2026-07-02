package otm

import "testing"

// FuzzImport exercises the OTM importer against arbitrary (untrusted) input,
// checking only that it never panics.
func FuzzImport(f *testing.F) {
	f.Add([]byte(sampleOTM))
	f.Add([]byte(`{"components":[{"id":"a","type":"database"}]}`))
	f.Add([]byte("not json"))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"trustZones":[{"id":"tz1","parent":{"trustZone":"tz1"}}],"components":[]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Import(data, ImportOptions{SourceLabel: "fuzz"})
	})
}
