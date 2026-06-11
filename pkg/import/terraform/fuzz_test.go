package terraform

import "testing"

// FuzzImport exercises the Terraform plan-JSON importer against arbitrary
// (untrusted) input, checking only that it never panics.
func FuzzImport(f *testing.F) {
	f.Add([]byte(samplePlan))
	f.Add([]byte(`{"format_version":"1.0"}`))
	f.Add([]byte("not json"))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"format_version":"1.0","values":{"root_module":{"resources":[{}]}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Import(data, ImportOptions{SourceLabel: "fuzz"})
	})
}
