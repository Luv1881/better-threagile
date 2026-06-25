package kubernetes

import "testing"

// FuzzImport exercises the Kubernetes manifest importer against arbitrary
// (untrusted) input, checking only that it never panics.
func FuzzImport(f *testing.F) {
	f.Add([]byte(sampleManifests))
	f.Add([]byte("kind: Deployment\n"))
	f.Add([]byte("not: yaml: ["))
	f.Add([]byte(""))
	f.Add([]byte("---\n---\n"))
	f.Add([]byte("apiVersion: v1\nkind: Service\nspec:\n  type: LoadBalancer\n  selector: {app: x}\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Import(data, ImportOptions{SourceLabel: "fuzz"})
	})
}
