package sbom

import "testing"

// FuzzParse exercises the CycloneDX parser + correlation against arbitrary
// (untrusted) input, checking only that it never panics.
func FuzzParse(f *testing.F) {
	f.Add([]byte(sampleSBOM))
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`))
	f.Add([]byte(`{"bomFormat":"SPDX"}`))
	f.Add([]byte("not json"))
	f.Add([]byte(`{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-2021-44228"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		bom, err := Parse(data)
		if err != nil {
			return
		}
		_ = Correlate(bom, func(string) bool { return true }, func(string) (float64, bool) { return 0.5, true }, Options{IncludeSuppressed: true})
		_ = bom.CVEIDs()
	})
}
