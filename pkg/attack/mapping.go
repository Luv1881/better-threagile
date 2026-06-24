// Package attack maps Threagile risk categories to MITRE ATT&CK (Enterprise)
// techniques and exports an ATT&CK Navigator layer for a threat model, so the
// generated findings can be viewed in the same language a SOC/detection team
// already uses.
//
// The mapping is a deliberately curated, decoupled lookup table keyed by risk
// category ID (rather than a field on every rule) so it can evolve
// independently and cover script-pack categories too. It is intentionally
// conservative: only well-defended category→technique links are included, and
// categories with no clean ATT&CK equivalent (e.g. XSS, missing CSP header —
// ATT&CK has no defensible Enterprise technique for these) are deliberately left
// unmapped and reported, rather than asserting a weak link.
package attack

// CategoryTechniques maps a Threagile risk-category ID to the MITRE ATT&CK
// Enterprise technique IDs it most directly corresponds to. Many web-exploitable
// injection/validation flaws map to T1190 (Exploit Public-Facing Application),
// which is the accurate ATT&CK abstraction for "attacker exploits an app bug".
var CategoryTechniques = map[string][]string{
	// Credentials & secrets
	"accidental-secret-leak":      {"T1552", "T1552.001"},
	"exposed-default-credentials": {"T1078.001"},
	"missing-vault":               {"T1552"},
	"missing-vault-isolation":     {"T1552"},

	// Authentication / identity — weak/missing auth enables valid-account abuse
	"missing-authentication":               {"T1190", "T1078"},
	"missing-authentication-second-factor": {"T1078"},
	"missing-identity-propagation":         {"T1078"},
	"missing-identity-provider-isolation":  {"T1078"},
	"missing-identity-store":               {"T1078"},

	// Injection & app exploitation — exploit of a public-facing application bug
	"sql-nosql-injection":         {"T1190"},
	"ldap-injection":              {"T1190"},
	"search-query-injection":      {"T1190"},
	"untrusted-deserialization":   {"T1190"},
	"server-side-request-forgery": {"T1190"},
	"cross-site-request-forgery":  {"T1190"},
	"missing-file-validation":     {"T1190"},
	// File-read flaws: exploit (T1190) leading to local data access (T1005)
	"xml-external-entity": {"T1190", "T1005"},
	"path-traversal":      {"T1190", "T1005"},

	// Hardening / exposure
	"unguarded-access-from-internet":    {"T1190"},
	"unguarded-direct-datastore-access": {"T1190"},
	"missing-hardening":                 {"T1190"},
	"missing-cloud-hardening":           {"T1190"},
	"missing-waf":                       {"T1190"},

	// Network
	"unencrypted-communication":              {"T1040", "T1557"},
	"unencrypted-asset":                      {"T1005"},
	"missing-network-segmentation":           {"T1021"},
	"dos-risky-access-across-trust-boundary": {"T1499"},

	// Lateral movement
	"lateral-movement-credential-reuse":            {"T1078", "T1550"},
	"lateral-movement-service-account-scope-creep": {"T1078", "T1098"},
	"lateral-movement-shared-runtime":              {"T1021"},
	"lateral-movement-transitive-access":           {"T1021"},
	"mixed-targets-on-shared-runtime":              {"T1611"},

	// Supply chain / build / deploy
	"code-backdooring":                {"T1195.002", "T1554"},
	"container-baseimage-backdooring": {"T1195.002"},
	"unchecked-deployment":            {"T1195"},
	"push-instead-of-pull-deployment": {"T1195"},
	"missing-build-infrastructure":    {"T1195"},
	"service-registry-poisoning":      {"T1195", "T1557"},

	// Containers
	"container-platform-escape": {"T1611"},
}

// techniqueNames provides a human-readable name for every technique referenced
// above, used for Navigator comments and the layer legend.
var techniqueNames = map[string]string{
	"T1005":     "Data from Local System",
	"T1021":     "Remote Services",
	"T1040":     "Network Sniffing",
	"T1078":     "Valid Accounts",
	"T1078.001": "Valid Accounts: Default Accounts",
	"T1098":     "Account Manipulation",
	"T1190":     "Exploit Public-Facing Application",
	"T1195":     "Supply Chain Compromise",
	"T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
	"T1499":     "Endpoint Denial of Service",
	"T1550":     "Use Alternate Authentication Material",
	"T1552":     "Unsecured Credentials",
	"T1552.001": "Unsecured Credentials: Credentials In Files",
	"T1554":     "Compromise Host Software Binary",
	"T1557":     "Adversary-in-the-Middle",
	"T1611":     "Escape to Host",
}

// TechniqueName returns the human-readable name for a technique ID, or "" if the
// ID is not in the catalogue.
func TechniqueName(id string) string { return techniqueNames[id] }
