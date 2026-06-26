package secretscan

import "testing"

// FuzzScan exercises the secret scanner against arbitrary (untrusted) model-file
// bytes, checking only that it never panics and that previews stay redacted.
func FuzzScan(f *testing.F) {
	f.Add([]byte("password: hunter2hunter2\n"))
	f.Add([]byte("api_key: ${SECRET}\n"))
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\n"))
	f.Add([]byte("just some: yaml\nwith: values\n"))
	f.Add([]byte(""))
	f.Add([]byte("token: \xff\xfe binary \x00 data"))

	f.Fuzz(func(t *testing.T, data []byte) {
		findings := Scan(data)
		for _, fnd := range findings {
			if fnd.Line < 1 {
				t.Errorf("finding has non-positive line %d", fnd.Line)
			}
			if len(fnd.Preview) > 16 {
				t.Errorf("preview not redacted: %q", fnd.Preview)
			}
		}
	})
}
