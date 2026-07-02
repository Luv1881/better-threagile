package mermaid

import "testing"

// FuzzImport exercises the Mermaid flowchart importer against arbitrary
// (untrusted) input, checking only that it never panics.
func FuzzImport(f *testing.F) {
	f.Add([]byte(sampleMermaid))
	f.Add([]byte("flowchart TD\n  A --> B\n"))
	f.Add([]byte("not mermaid"))
	f.Add([]byte(""))
	f.Add([]byte("subgraph\nend\nend\n"))
	f.Add([]byte("graph LR\n  A[(db)] -->|SQL| B([user])\n"))
	f.Add([]byte("flowchart TD\n  X{y}\n  X --> X\n"))
	f.Add([]byte("flowchart\n%% comment\nA-->|x|B"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Import(data, ImportOptions{SourceLabel: "fuzz"})
	})
}
