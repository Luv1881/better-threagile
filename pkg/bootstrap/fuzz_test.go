package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzDetect exercises the repo scanner against arbitrary file contents, checking
// only that detection + model assembly never panic on hostile input.
func FuzzDetect(f *testing.F) {
	f.Add([]byte("services:\n  a:\n    image: x\n"), "docker-compose.yml")
	f.Add([]byte("openapi: 3.0.0\n"), "api.yaml")
	f.Add([]byte("apiVersion: v1\nkind: Pod\n"), "pod.yaml")
	f.Add([]byte("resource \"x\" \"y\" {}"), "main.tf")
	f.Add([]byte("\xff\xfe\x00 garbage"), "weird.yaml")

	f.Fuzz(func(t *testing.T, content []byte, name string) {
		// keep the filename a single safe path segment
		base := filepath.Base(name)
		if base == "." || base == ".." || base == "/" || base == "" {
			base = "f.yaml"
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, base), content, 0600); err != nil {
			return
		}
		sources, err := Detect(dir)
		if err != nil {
			return
		}
		_, _, _ = BuildModel(dir, sources)
	})
}
