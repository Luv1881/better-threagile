package drawio

import "testing"

// FuzzImport exercises the draw.io importer against arbitrary (untrusted) input,
// checking only that it never panics.
func FuzzImport(f *testing.F) {
	f.Add([]byte(sampleDrawio))
	f.Add([]byte(`<mxGraphModel><root><mxCell id="0"/></root></mxGraphModel>`))
	f.Add([]byte(`<mxfile><diagram>compressed</diagram></mxfile>`))
	f.Add([]byte("not xml"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Import(data, ImportOptions{SourceLabel: "fuzz"})
	})
}
