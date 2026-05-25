package openapi

import "strings"

// piiFieldPatterns are substrings that, when found in a schema property name
// (case-insensitive), indicate the field likely contains personally identifiable
// information.
var piiFieldPatterns = []string{
	"email", "e_mail", "e-mail",
	"phone", "mobile", "cell",
	"address", "street", "city", "zip", "postal",
	"birth", "dob", "birthday",
	"ssn", "sin", "national_id", "national-id",
	"passport", "license",
	"password", "passwd", "secret",
	"first_name", "firstname", "last_name", "lastname",
	"full_name", "fullname", "display_name",
	"username", "user_name",
	"gender", "sex", "race", "ethnicity",
	"health", "medical", "diagnosis", "prescription",
	"salary", "wage", "income",
	"credit_card", "card_number", "cvv", "iban", "bank",
	"ip_address", "ipaddress", "ip_addr",
	"geolocation", "latitude", "longitude",
	"cookie", "session", "token",
}

// looksLikePII returns true if the property name matches a PII heuristic pattern.
func looksLikePII(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range piiFieldPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// schemaContainsPII returns true if the schema or any of its properties contain
// field names matching PII heuristics. Resolves $ref names using the components map.
func schemaContainsPII(schema *OASchema, schemas map[string]*OASchema, depth int) bool {
	if schema == nil || depth > 5 {
		return false
	}

	// Resolve $ref
	if schema.Ref != "" {
		refName := refToName(schema.Ref)
		if resolved, ok := schemas[refName]; ok {
			return schemaContainsPII(resolved, schemas, depth+1)
		}
		return false
	}

	// Check property names
	for propName, propSchema := range schema.Properties {
		if looksLikePII(propName) {
			return true
		}
		if schemaContainsPII(propSchema, schemas, depth+1) {
			return true
		}
	}

	// Check array items
	if schema.Items != nil {
		return schemaContainsPII(schema.Items, schemas, depth+1)
	}

	return false
}

// refToName converts a $ref like "#/components/schemas/User" to "User".
func refToName(ref string) string {
	parts := strings.Split(ref, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ref
}
