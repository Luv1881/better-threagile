// Package secretscan looks for credentials accidentally committed into a threat
// model file. A model describes architecture, not secrets — so a private key,
// cloud access key or hard-coded password in the YAML is almost always a
// mistake, and the model file is exactly the kind of "harmless config" that
// slips past secret scanners. This pass is deterministic and uses no AI.
package secretscan

import (
	"math"
	"regexp"
	"strings"
)

// Finding is one suspected secret, located by line, with a redacted preview.
type Finding struct {
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Preview string `json:"preview"`
}

type patternRule struct {
	name string
	re   *regexp.Regexp
}

// High-confidence patterns: a match is almost certainly a real secret.
var patternRules = []patternRule{
	{"private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"aws-access-key-id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github-token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b`)},
	{"github-fine-grained-token", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{40,}\b`)},
	{"slack-token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"stripe-key", regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b`)},
	// JWT: require long header/payload segments so short base64 (e.g. embedded
	// diagram data) doesn't false-positive.
	{"jwt", regexp.MustCompile(`\beyJ[0-9A-Za-z_-]{15,}\.[0-9A-Za-z_-]{15,}\.[0-9A-Za-z_-]{8,}\b`)},
	{"slack-webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`)},
	// Connection string with embedded credentials, e.g. postgres://user:pass@host.
	{"connection-string-credentials", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.\-]*://[^:@/\s]+:[^:@/\s]+@`)},
}

// lowercaseIdentifier matches descriptive slugs like "bearer-validation-flow"
// that are common in architecture text and are not literal secrets.
var lowercaseIdentifier = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// secretAssign matches "<secret-ish key> : <value>"; the value is then entropy-
// checked so only high-entropy (i.e. real-looking) credentials are reported.
var secretAssign = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*["']?([^"'\s#]{8,})`)

// placeholders are obviously-fake values we never report.
var placeholders = map[string]bool{
	"changeme": true, "change-me": true, "example": true, "placeholder": true,
	"password": true, "secret": true, "redacted": true, "none": true, "null": true,
	"true": true, "false": true, "test": true, "dummy": true, "sample": true,
	"your-secret-here": true, "todo": true, "xxxxxxxx": true,
}

const minEntropy = 3.2

// Scan returns suspected secrets in data, line by line.
func Scan(data []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		lineNo := i + 1
		// Inline suppression for reviewed false positives.
		if strings.Contains(strings.ToLower(line), "nosecret") {
			continue
		}
		matched := false
		for _, r := range patternRules {
			if m := r.re.FindString(line); m != "" {
				findings = append(findings, Finding{Line: lineNo, Rule: r.name, Preview: redact(m)})
				matched = true
				break // one high-confidence hit per line is enough
			}
		}
		if matched {
			continue
		}
		if m := secretAssign.FindStringSubmatch(line); m != nil {
			val := m[2]
			if !isPlaceholder(val) && shannonEntropy(val) >= minEntropy {
				findings = append(findings, Finding{Line: lineNo, Rule: "hardcoded-" + strings.ToLower(m[1]), Preview: redact(val)})
			}
		}
	}
	return findings
}

func isPlaceholder(v string) bool {
	lower := strings.ToLower(v)
	if placeholders[lower] {
		return true
	}
	// references / templated values are not literal secrets
	if strings.HasPrefix(v, "$") || strings.Contains(v, "${") || strings.Contains(v, "{{") ||
		strings.HasPrefix(v, "<") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "ENC[") {
		return true
	}
	// descriptive lowercase slugs (e.g. "bearer-validation-flow") read as prose,
	// not credentials.
	if lowercaseIdentifier.MatchString(v) {
		return true
	}
	// a single repeated character (xxxxxxxx, 00000000) is a placeholder
	if isRepeatedChar(v) {
		return true
	}
	return false
}

func isRepeatedChar(v string) bool {
	if v == "" {
		return false
	}
	for i := 1; i < len(v); i++ {
		if v[i] != v[0] {
			return false
		}
	}
	return true
}

// shannonEntropy returns the Shannon entropy (bits per char) of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// redact keeps only a short prefix so the scanner output never echoes a full
// secret into logs.
func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 4 {
		return "****"
	}
	return s[:3] + strings.Repeat("*", 7)
}
