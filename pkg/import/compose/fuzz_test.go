package compose

import "testing"

// FuzzImport exercises the docker-compose importer against arbitrary (untrusted)
// input, checking only that it never panics.
func FuzzImport(f *testing.F) {
	f.Add([]byte(sampleCompose))
	f.Add([]byte("services:\n  a:\n    image: x\n"))
	f.Add([]byte("not: compose"))
	f.Add([]byte(""))
	f.Add([]byte("services:\n  a:\n    ports: [\"80:80\"]\n    depends_on: {b: {}}\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Import(data, ImportOptions{SourceLabel: "fuzz"})
	})
}
