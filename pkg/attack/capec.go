package attack

// CategoryCAPEC maps a Threagile risk-category ID to MITRE CAPEC attack-pattern
// IDs. Like CategoryTechniques (ATT&CK), this is a curated, conservative table:
// only well-established category→pattern links are included; categories with no
// defensible CAPEC equivalent are deliberately left unmapped (and reported).
var CategoryCAPEC = map[string][]string{
	// Injection
	"sql-nosql-injection":         {"CAPEC-66", "CAPEC-7"},
	"ldap-injection":              {"CAPEC-136"},
	"path-traversal":              {"CAPEC-126"},
	"cross-site-scripting":        {"CAPEC-63"},
	"cross-site-request-forgery":  {"CAPEC-62"},
	"server-side-request-forgery": {"CAPEC-664"},
	"xml-external-entity":         {"CAPEC-221"},
	"untrusted-deserialization":   {"CAPEC-586"},

	// Authentication & secrets
	"exposed-default-credentials":          {"CAPEC-70"},
	"missing-authentication":               {"CAPEC-115"},
	"missing-authentication-second-factor": {"CAPEC-115"},
	"accidental-secret-leak":               {"CAPEC-37"},
	"missing-vault":                        {"CAPEC-37"},
	"missing-vault-isolation":              {"CAPEC-37"},

	// Network / data exposure
	"unencrypted-communication":              {"CAPEC-157", "CAPEC-117"},
	"unencrypted-asset":                      {"CAPEC-37"},
	"dos-risky-access-across-trust-boundary": {"CAPEC-125"},

	// Lateral movement & supply chain. Backdooring source/base-images is a
	// pre-deployment supply-chain integrity attack (CAPEC-184), not post-deployment
	// "Infected Software" (CAPEC-442).
	"lateral-movement-credential-reuse": {"CAPEC-560"},
	"code-backdooring":                  {"CAPEC-184"},
	"container-baseimage-backdooring":   {"CAPEC-184"},
}

// capecNames provides a human-readable name for every CAPEC ID referenced above.
var capecNames = map[string]string{
	"CAPEC-7":   "Blind SQL Injection",
	"CAPEC-37":  "Retrieve Embedded Sensitive Data",
	"CAPEC-62":  "Cross Site Request Forgery",
	"CAPEC-63":  "Cross-Site Scripting (XSS)",
	"CAPEC-66":  "SQL Injection",
	"CAPEC-70":  "Try Common or Default Usernames and Passwords",
	"CAPEC-115": "Authentication Bypass",
	"CAPEC-117": "Interception",
	"CAPEC-125": "Flooding",
	"CAPEC-126": "Path Traversal",
	"CAPEC-136": "LDAP Injection",
	"CAPEC-157": "Sniffing Attacks",
	"CAPEC-184": "Software Integrity Attack",
	"CAPEC-221": "Data Serialization External Entities Blowup",
	"CAPEC-560": "Use of Known Domain Credentials",
	"CAPEC-586": "Object Injection",
	"CAPEC-664": "Server Side Request Forgery",
}

// CAPECName returns the human-readable name for a CAPEC ID, or "" if unknown.
func CAPECName(id string) string { return capecNames[id] }

// CAPECNumber returns the numeric portion of a "CAPEC-<n>" ID (e.g. "66"), used
// to build the canonical capec.mitre.org URL. Returns "" for a malformed ID.
func CAPECNumber(id string) string {
	const prefix = "CAPEC-"
	if len(id) > len(prefix) && id[:len(prefix)] == prefix {
		return id[len(prefix):]
	}
	return ""
}
