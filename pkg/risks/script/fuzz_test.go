package script

import "testing"

// FuzzRiskRuleParseFromData exercises parsing of an untrusted risk-DSL rule
// file, checking only that it never panics.
func FuzzRiskRuleParseFromData(f *testing.F) {
	f.Add([]byte(minimalTestYAML))
	f.Add([]byte(""))
	f.Add([]byte("id: [unterminated"))
	f.Add([]byte("risk:\n  match:\n    do:\n      - if:\n          true: \"{tech_asset.id}\"\n"))
	f.Add([]byte("risk:\n  id:\n    parameter: tech_asset\n    id: \"{$risk.id}@{tech_asset.id}\"\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		rule := new(RiskRule).Init()
		_, _ = rule.ParseFromData(data)
	})
}
