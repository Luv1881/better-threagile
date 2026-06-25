package secretscan

import (
	"strings"
	"testing"
)

// Fake credentials assembled from concatenated literals so static scanners
// (gosec G101) don't flag the test file itself; the scanner under test still
// sees the full assembled value.
var (
	fakeAWS    = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeGitHub = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
	fakeGoogle = "AIza" + "SyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"
	fakeJWT    = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxIn0" + ".abcDEF123456"
)

func TestDetectsHighConfidenceSecrets(t *testing.T) {
	cases := map[string]string{
		"aws-access-key-id": `  description: "` + fakeAWS + ` is the key"`,
		"github-token":      `  note: ` + fakeGitHub,
		"private-key":       `  blob: -----BEGIN RSA ` + "PRIVATE KEY-----",
		"google-api-key":    `  key: ` + fakeGoogle,
		"jwt":               `  jwt: ` + fakeJWT,
	}
	for wantRule, line := range cases {
		findings := Scan([]byte(line))
		if len(findings) == 0 {
			t.Errorf("%s: expected a finding for %q", wantRule, line)
			continue
		}
		if findings[0].Rule != wantRule {
			t.Errorf("expected rule %q, got %q (line %q)", wantRule, findings[0].Rule, line)
		}
		if strings.Contains(findings[0].Preview, "EXAMPLE") || len(findings[0].Preview) > 12 {
			t.Errorf("preview should be redacted, got %q", findings[0].Preview)
		}
	}
}

func TestDetectsHardcodedHighEntropyPassword(t *testing.T) {
	findings := Scan([]byte(`  password: "G7x!q9Zk2Lm4Wp8Bd3Rt"`))
	if len(findings) != 1 || !strings.HasPrefix(findings[0].Rule, "hardcoded-password") {
		t.Fatalf("expected a hardcoded-password finding, got %+v", findings)
	}
}

func TestDetectsStripeAndConnectionString(t *testing.T) {
	stripe := "sk_live_" + "0123456789abcdefghij"
	if f := Scan([]byte("  key: " + stripe)); len(f) != 1 || f[0].Rule != "stripe-key" {
		t.Errorf("expected stripe-key finding, got %+v", f)
	}
	conn := "  db: postgres://admin:" + "S3cr3tP@ssw0rd" + "@db.internal:5432/app"
	if f := Scan([]byte(conn)); len(f) != 1 || f[0].Rule != "connection-string-credentials" {
		t.Errorf("expected connection-string finding, got %+v", f)
	}
}

func TestNosecretSuppressesLine(t *testing.T) {
	line := "  password: G7x!q9Zk2Lm4Wp8Bd3Rt  # nosecret: documented example"
	if f := Scan([]byte(line)); len(f) != 0 {
		t.Errorf("nosecret should suppress the finding, got %+v", f)
	}
}

func TestIgnoresPlaceholdersAndReferences(t *testing.T) {
	benign := []string{
		`  password: changeme`,
		`  password: ""`,
		`  api_key: ${API_KEY}`,
		`  secret: <your-secret-here>`,
		`  token: {{ vault_token }}`,
		`  password: xxxxxxxx`,
		`  description: "The API server validates the token before access"`,
		`  passwd: example`,
		`  token: bearer-validation-flow`,
		`  secret: oauth-client-credentials-flow`,
	}
	for _, line := range benign {
		if f := Scan([]byte(line)); len(f) != 0 {
			t.Errorf("benign line should not flag: %q -> %+v", line, f)
		}
	}
}

func TestLineNumbersAreReported(t *testing.T) {
	doc := "line one\nline two\n  aws: " + fakeAWS + "\nline four\n"
	findings := Scan([]byte(doc))
	if len(findings) != 1 || findings[0].Line != 3 {
		t.Fatalf("expected one finding on line 3, got %+v", findings)
	}
}

func TestEntropyThresholdAvoidsLowEntropyValues(t *testing.T) {
	// A low-entropy but >=8-char value assigned to a secret key should not flag.
	if f := Scan([]byte(`  password: aaaaaaaabbbb`)); len(f) != 0 {
		t.Errorf("low-entropy value should not flag: %+v", f)
	}
}

func TestDeterministic(t *testing.T) {
	doc := "  password: G7x!q9Zk2Lm4Wp8Bd3Rt\n  aws: " + fakeAWS + "\n"
	first := Scan([]byte(doc))
	for i := 0; i < 10; i++ {
		got := Scan([]byte(doc))
		if len(got) != len(first) {
			t.Fatal("non-deterministic secret scan")
		}
	}
}
