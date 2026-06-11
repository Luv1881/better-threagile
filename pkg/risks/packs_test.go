package risks

import (
	"testing"
)

// TestAllBuiltinPacksLoadAndProduceRules guards against silent pack drift:
// every pack in AvailableBuiltinPacks must load without error and yield at
// least one rule. If a pack's directory is missing or empty the test fails here
// rather than at runtime for a user.
func TestAllBuiltinPacksLoadAndProduceRules(t *testing.T) {
	for _, name := range AvailableBuiltinPacks {
		name := name
		t.Run(name, func(t *testing.T) {
			rules, err := LoadRulePack(name)
			if err != nil {
				t.Fatalf("LoadRulePack(%q) error: %v", name, err)
			}
			if len(rules) == 0 {
				t.Fatalf("LoadRulePack(%q) returned 0 rules", name)
			}
			t.Logf("%s: %d rules loaded", name, len(rules))
		})
	}
}

// TestLoadRulePackUnknownName ensures a clear error is returned for an unknown pack.
func TestLoadRulePackUnknownName(t *testing.T) {
	_, err := LoadRulePack("does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown pack name, got nil")
	}
}
