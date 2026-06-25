package attack

// CategoryD3FEND maps a Threagile risk-category ID to MITRE D3FEND defensive
// countermeasure technique IDs — the defensive complement of the ATT&CK/CAPEC
// (offensive) mappings. Like those tables it is a curated, conservative starter
// set: each entry names the countermeasure(s) that most directly address the
// category. Categories with no clear D3FEND technique are left unmapped.
var CategoryD3FEND = map[string][]string{
	// Authentication & credentials
	"missing-authentication":               {"D3-MFA", "D3-SPP"},
	"missing-authentication-second-factor": {"D3-MFA"},
	"exposed-default-credentials":          {"D3-SPP", "D3-MFA"},

	// Injection / message analysis
	"sql-nosql-injection":       {"D3-DQSA", "D3-MA"},
	"ldap-injection":            {"D3-MA"},
	"search-query-injection":    {"D3-MA"},
	"cross-site-scripting":      {"D3-MA"},
	"path-traversal":            {"D3-MA"},
	"untrusted-deserialization": {"D3-MA"},
	"xml-external-entity":       {"D3-MA"},

	// Encryption
	"unencrypted-communication": {"D3-MENCR", "D3-ET"},
	"unencrypted-asset":         {"D3-FE"},

	// Network exposure / hardening
	"unguarded-access-from-internet":         {"D3-ITF", "D3-NTA"},
	"missing-waf":                            {"D3-ITF", "D3-MA"},
	"missing-hardening":                      {"D3-ITF"},
	"server-side-request-forgery":            {"D3-OTF"},
	"dos-risky-access-across-trust-boundary": {"D3-ITF", "D3-NTA"},
	"missing-network-segmentation":           {"D3-ITF"},

	// Supply chain / integrity
	"code-backdooring":                {"D3-EAL"},
	"container-baseimage-backdooring": {"D3-EAL"},
}

// d3fendInfo carries the display name and the d3fend.mitre.org artifact name
// (CamelCase, used to build the canonical technique URL) for each ID.
type d3fendTechnique struct {
	Name   string // human-readable
	D3FRef string // d3f: artifact name for the URL
}

var d3fendInfo = map[string]d3fendTechnique{
	"D3-MFA":   {"Multi-factor Authentication", "Multi-factorAuthentication"},
	"D3-SPP":   {"Strong Password Policy", "StrongPasswordPolicy"},
	"D3-DQSA":  {"Database Query String Analysis", "DatabaseQueryStringAnalysis"},
	"D3-MA":    {"Message Analysis", "MessageAnalysis"},
	"D3-MENCR": {"Message Encryption", "MessageEncryption"},
	"D3-ET":    {"Encrypted Tunnels", "EncryptedTunnels"},
	"D3-FE":    {"File Encryption", "FileEncryption"},
	"D3-ITF":   {"Inbound Traffic Filtering", "InboundTrafficFiltering"},
	"D3-OTF":   {"Outbound Traffic Filtering", "OutboundTrafficFiltering"},
	"D3-NTA":   {"Network Traffic Analysis", "NetworkTrafficAnalysis"},
	"D3-EAL":   {"Executable Allowlisting", "ExecutableAllowlisting"},
}

// D3FENDName returns the human-readable name for a D3FEND ID, or "" if unknown.
func D3FENDName(id string) string { return d3fendInfo[id].Name }

// D3FENDURL returns the canonical d3fend.mitre.org technique URL, or "" if unknown.
func D3FENDURL(id string) string {
	info, ok := d3fendInfo[id]
	if !ok || info.D3FRef == "" {
		return ""
	}
	return "https://d3fend.mitre.org/technique/d3f:" + info.D3FRef + "/"
}
